package zone

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type node struct {
	sets  map[uint16][]dns.RR
	order []uint16
}

type cut struct {
	ns   []dns.RR
	glue []dns.RR
}

// Compiled is an immutable, query-optimised view of an enabled zone.
type Compiled struct {
	Origin     string
	Type       string
	Serial     uint32
	Forwarders []string

	soa        *dns.SOA
	negSOA     *dns.SOA
	nodes      map[string]*node
	exists     map[string]struct{}
	cuts       map[string]*cut
	apexLabels int
}

// Compile builds the lookup structure from z (enabled records only).
func Compile(z *Zone) (*Compiled, error) {
	c := &Compiled{Origin: z.Name, Type: z.Type, Serial: z.Serial, Forwarders: z.Forwarders,
		nodes: map[string]*node{}, exists: map[string]struct{}{}, cuts: map[string]*cut{},
		apexLabels: dns.CountLabel(z.Name)}
	if z.Type != TypePrimary {
		return c, nil
	}
	c.soa = z.SOARR()
	neg := *c.soa
	if neg.Minttl < neg.Hdr.Ttl {
		neg.Hdr.Ttl = neg.Minttl
	}
	c.negSOA = &neg
	c.add(c.soa)
	for i := range z.Records {
		r := &z.Records[i]
		if r.Disabled {
			continue
		}
		rr, err := r.RR(z.Name)
		if err != nil {
			return nil, fmt.Errorf("zone %s record %s: %w", z.Name, r.ID, err)
		}
		c.add(rr)
	}
	// delegations (NS below the apex) with in-bailiwick glue
	for name, n := range c.nodes {
		if name == c.Origin {
			continue
		}
		if ns := n.sets[dns.TypeNS]; len(ns) > 0 {
			ct := &cut{ns: ns}
			for _, rr := range ns {
				t := strings.ToLower(rr.(*dns.NS).Ns)
				if dns.IsSubDomain(name, t) {
					if g := c.nodes[t]; g != nil {
						ct.glue = append(ct.glue, g.sets[dns.TypeA]...)
						ct.glue = append(ct.glue, g.sets[dns.TypeAAAA]...)
					}
				}
			}
			c.cuts[name] = ct
		}
	}
	return c, nil
}

func (c *Compiled) add(rr dns.RR) {
	name := strings.ToLower(rr.Header().Name)
	n := c.nodes[name]
	if n == nil {
		n = &node{sets: map[uint16][]dns.RR{}}
		c.nodes[name] = n
	}
	t := rr.Header().Rrtype
	if _, ok := n.sets[t]; !ok {
		n.order = append(n.order, t)
	}
	n.sets[t] = append(n.sets[t], rr)
	// the owner and every ancestor up to the apex exist (empty non-terminals)
	for {
		c.exists[name] = struct{}{}
		if name == c.Origin {
			break
		}
		off, end := dns.NextLabel(name, 0)
		if end || !strings.HasSuffix(name, c.Origin) {
			break
		}
		name = name[off:]
	}
}

// Result of an authoritative lookup.
type Result struct {
	Rcode         int
	Authoritative bool
	Referral      bool
	Answer        []dns.RR
	Ns            []dns.RR
	Extra         []dns.RR
	// Dangling is an out-of-zone CNAME target the caller may resolve further.
	Dangling string
	Zone     string
}

type step struct {
	res         Result
	cnameTarget string
}

func (c *Compiled) ancestors(name string) (idx []int, n int) {
	idx = dns.Split(name)
	return idx, len(idx)
}

// lookup answers name/qtype inside this zone (name lower-case, inside zone).
func (c *Compiled) lookup(name string, qtype uint16) step {
	idx, n := c.ancestors(name)
	// zone cuts: walk from just below the apex down to name
	if len(c.cuts) > 0 {
		for j := c.apexLabels + 1; j <= n; j++ {
			anc := name[idx[n-j]:]
			if ct := c.cuts[anc]; ct != nil {
				if j == n && qtype == dns.TypeDS {
					break // DS is answered by the parent side (NODATA without DNSSEC)
				}
				return step{res: Result{Rcode: dns.RcodeSuccess, Referral: true, Ns: ct.ns, Extra: ct.glue}}
			}
		}
	}
	if nd := c.nodes[name]; nd != nil {
		return c.fromNode(nd, name, qtype, false)
	}
	if _, ok := c.exists[name]; ok {
		return c.nodata()
	}
	// wildcard synthesis (RFC 4592): closest encloser is the deepest existing ancestor
	for j := n - 1; j >= c.apexLabels; j-- {
		var anc string
		if j == 0 {
			anc = "."
		} else {
			anc = name[idx[n-j]:]
		}
		if _, ok := c.exists[anc]; ok {
			if wn := c.nodes["*."+anc]; wn != nil {
				return c.fromNode(wn, name, qtype, true)
			}
			break
		}
	}
	return step{res: Result{Rcode: dns.RcodeNameError, Authoritative: true, Ns: []dns.RR{c.negSOA}}}
}

func (c *Compiled) nodata() step {
	return step{res: Result{Rcode: dns.RcodeSuccess, Authoritative: true, Ns: []dns.RR{c.negSOA}}}
}

func synth(rrs []dns.RR, owner string) []dns.RR {
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		cp := dns.Copy(rr)
		cp.Header().Name = owner
		out[i] = cp
	}
	return out
}

func (c *Compiled) fromNode(nd *node, name string, qtype uint16, wildcard bool) step {
	pick := func(rrs []dns.RR) []dns.RR {
		if wildcard {
			return synth(rrs, name)
		}
		return rrs
	}
	if qtype == dns.TypeANY {
		var ans []dns.RR
		for _, t := range nd.order {
			ans = append(ans, pick(nd.sets[t])...)
		}
		if len(ans) == 0 {
			return c.nodata()
		}
		return step{res: Result{Rcode: dns.RcodeSuccess, Authoritative: true, Answer: ans}}
	}
	if set := nd.sets[qtype]; len(set) > 0 {
		r := Result{Rcode: dns.RcodeSuccess, Authoritative: true, Answer: pick(set)}
		r.Extra = c.additional(set)
		return step{res: r}
	}
	if cn := nd.sets[dns.TypeCNAME]; len(cn) > 0 {
		return step{res: Result{Rcode: dns.RcodeSuccess, Authoritative: true, Answer: pick(cn)},
			cnameTarget: strings.ToLower(cn[0].(*dns.CNAME).Target)}
	}
	return c.nodata()
}

// additional returns in-zone address records for MX/SRV/NS targets.
func (c *Compiled) additional(set []dns.RR) []dns.RR {
	var out []dns.RR
	for _, rr := range set {
		var t string
		switch v := rr.(type) {
		case *dns.MX:
			t = v.Mx
		case *dns.SRV:
			t = v.Target
		case *dns.NS:
			t = v.Ns
		default:
			return nil
		}
		t = strings.ToLower(t)
		if !dns.IsSubDomain(c.Origin, t) || c.occluded(t) {
			continue
		}
		if nd := c.nodes[t]; nd != nil {
			out = append(out, nd.sets[dns.TypeA]...)
			out = append(out, nd.sets[dns.TypeAAAA]...)
		}
	}
	return out
}

func (c *Compiled) occluded(name string) bool {
	if len(c.cuts) == 0 {
		return false
	}
	idx, n := c.ancestors(name)
	for j := c.apexLabels + 1; j <= n; j++ {
		if c.cuts[name[idx[n-j]:]] != nil {
			return true
		}
	}
	return false
}

// SOA returns the zone SOA (nil for forwarder zones).
func (c *Compiled) SOA() *dns.SOA { return c.soa }

// Set is an immutable collection of compiled zones.
type Set struct {
	zones     map[string]*Compiled
	maxLabels int
}

// NewSet builds a Set from compiled zones.
func NewSet(zs []*Compiled) *Set {
	s := &Set{zones: make(map[string]*Compiled, len(zs))}
	for _, z := range zs {
		s.zones[z.Origin] = z
		if l := dns.CountLabel(z.Origin); l > s.maxLabels {
			s.maxLabels = l
		}
	}
	return s
}

// Len returns the number of zones.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.zones)
}

// Find returns the deepest zone enclosing qname (lower-case FQDN), or nil.
func (s *Set) Find(qname string) *Compiled {
	if s == nil || len(s.zones) == 0 {
		return nil
	}
	idx := dns.Split(qname)
	n := len(idx)
	start := 0
	if n > s.maxLabels {
		start = n - s.maxLabels
	}
	for i := start; i < n; i++ {
		if z := s.zones[qname[idx[i]:]]; z != nil {
			return z
		}
	}
	if z := s.zones["."]; z != nil {
		return z
	}
	return nil
}

// MaxChain bounds CNAME chasing (loop protection).
const MaxChain = 16

// Answer resolves qname/qtype from primary zones, chasing in-zone and
// cross-zone CNAMEs. ok is false when no primary zone is the deepest match.
func (s *Set) Answer(qname string, qtype uint16) (res Result, ok bool) {
	name := qname
	var seen map[string]bool
	for i := 0; i < MaxChain; i++ {
		z := s.Find(name)
		if z == nil || z.Type != TypePrimary {
			if i == 0 {
				return res, false
			}
			res.Dangling = name
			return res, true
		}
		st := z.lookup(name, qtype)
		if i == 0 {
			res = st.res
			res.Zone = z.Origin
		} else {
			if st.res.Referral {
				res.Dangling = name
				return res, true
			}
			res.Answer = append(res.Answer, st.res.Answer...)
			res.Rcode = st.res.Rcode // RFC 6604: rcode of the last name in the chain
			res.Ns = st.res.Ns
			res.Extra = append(res.Extra, st.res.Extra...)
		}
		if st.cnameTarget == "" {
			return res, true
		}
		if seen == nil {
			seen = map[string]bool{qname: true}
		}
		if seen[st.cnameTarget] {
			return res, true // loop: return the chain so far
		}
		seen[st.cnameTarget] = true
		name = st.cnameTarget
	}
	return res, true
}
