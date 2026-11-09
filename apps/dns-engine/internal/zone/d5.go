package zone

import (
	"bytes"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// TypeSecondary is a zone transferred from primaries (docs/41 §2.1).
const TypeSecondary = "secondary"

// TransferConfig is the outgoing AXFR/IXFR policy of a zone (docs/41 §2.2).
// An empty allow list means transfers are closed.
type TransferConfig struct {
	Allow   []string `json:"allow"`
	TSIGKey string   `json:"tsig_key,omitempty"`
}

// NotifyConfig lists the servers notified after every change (RFC 1996).
type NotifyConfig struct {
	Targets []string `json:"targets"`
	Enabled bool     `json:"enabled"`
	// TSIGKey signs the NOTIFY messages (default: transfer.tsig_key).
	TSIGKey string `json:"tsig_key,omitempty"`
}

// UpdateConfig is the RFC 2136 dynamic update policy (docs/41 §2.4).
type UpdateConfig struct {
	Enabled     bool     `json:"enabled"`
	Allow       []string `json:"allow"`
	TSIGKey     string   `json:"tsig_key,omitempty"`
	RequireTSIG bool     `json:"require_tsig"`
}

// NSEC3Config are the NSEC3 parameters (RFC 5155, RFC 9276).
type NSEC3Config struct {
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	OptOut     bool   `json:"opt_out"`
}

// SigningConfig is the automatic DNSSEC signing policy (docs/41 §2.5).
type SigningConfig struct {
	Enabled               bool        `json:"enabled"`
	Algorithm             string      `json:"algorithm"`
	Denial                string      `json:"denial"`
	NSEC3                 NSEC3Config `json:"nsec3"`
	SignatureValidityDays int         `json:"signature_validity_days"`
	RefreshDays           int         `json:"refresh_days"`
}

// DefaultSigning returns the signing defaults.
func DefaultSigning() SigningConfig {
	return SigningConfig{Algorithm: "ECDSAP256SHA256", Denial: "nsec", SignatureValidityDays: 14, RefreshDays: 3}
}

// D5Config holds the zone settings added in docs/41 §2 (embedded in Zone so
// the JSON document stays flat). Slices are replaced, never mutated.
type D5Config struct {
	// secondary zones
	Primaries   []string `json:"primaries,omitempty"`
	TSIGKey     string   `json:"tsig_key,omitempty"`
	NotifyAllow []string `json:"notify_allow,omitempty"`
	// primary (and secondary for transfer/notify)
	Transfer *TransferConfig `json:"transfer,omitempty"`
	Notify   *NotifyConfig   `json:"notify,omitempty"`
	Update   *UpdateConfig   `json:"update,omitempty"`
	DNSSEC   *SigningConfig  `json:"dnssec,omitempty"`
}

// Signed reports whether automatic signing is on.
func (z *Zone) Signed() bool {
	return z.Type == TypePrimary && z.DNSSEC != nil && z.DNSSEC.Enabled
}

// ---------------------------------------------------------------- compiled raw zones

// D5Data is the extra state of a zone compiled from a full RR list
// (secondary data or a signed primary): DNSSEC records for answers and the
// transfer content.
type D5Data struct {
	// Unavailable: a secondary that never loaded or expired (SERVFAIL).
	Unavailable bool
	// All is the zone content without the SOA (transfer order).
	All []dns.RR

	sigs       map[string][]dns.RR // owner|type -> RRSIGs
	nsec       map[string]*dns.NSEC
	nsecOwners []string // canonical order
	nsec3      []*dns.NSEC3
	n3hash     []string // upper-case base32hex labels, sorted
	n3iter     uint16
	n3salt     string
}

// Authoritative reports whether the zone answers from its own data.
func (c *Compiled) Authoritative() bool {
	return c.Type == TypePrimary || c.Type == TypeSecondary
}

// Unavailable reports a secondary without usable data.
func (c *Compiled) Unavailable() bool { return c.D5 != nil && c.D5.Unavailable }

// SignedZone reports whether answers carry DNSSEC records.
func (c *Compiled) SignedZone() bool {
	return c.D5 != nil && len(c.D5.sigs) > 0
}

// SOARR returns the zone SOA (nil when unavailable).
func (c *Compiled) SOARR() *dns.SOA { return c.soa }

// Unavailable compiles a placeholder answering SERVFAIL.
func UnavailableZone(origin, typ string) *Compiled {
	return &Compiled{Origin: origin, Type: typ, nodes: map[string]*node{}, exists: map[string]struct{}{},
		cuts: map[string]*cut{}, apexLabels: dns.CountLabel(origin), D5: &D5Data{Unavailable: true}}
}

func sigKey(owner string, t uint16) string { return strings.ToLower(owner) + "|" + dns.TypeToString[t] }

// CompileRaw builds the lookup structure from a complete RR list that
// contains exactly one SOA at the apex. RRSIG, NSEC and NSEC3 records are
// kept aside and attached to answers by AddDNSSEC.
func CompileRaw(origin, typ string, rrs []dns.RR) (*Compiled, error) {
	c := &Compiled{Origin: origin, Type: typ, nodes: map[string]*node{}, exists: map[string]struct{}{},
		cuts: map[string]*cut{}, apexLabels: dns.CountLabel(origin)}
	d := &D5Data{sigs: map[string][]dns.RR{}, nsec: map[string]*dns.NSEC{}}
	c.D5 = d
	for _, rr := range rrs {
		h := rr.Header()
		h.Name = strings.ToLower(h.Name)
		switch v := rr.(type) {
		case *dns.SOA:
			if h.Name != origin {
				continue
			}
			c.soa = v
			c.Serial = v.Serial
			continue
		case *dns.RRSIG:
			k := sigKey(h.Name, v.TypeCovered)
			d.sigs[k] = append(d.sigs[k], v)
		case *dns.NSEC:
			d.nsec[h.Name] = v
		case *dns.NSEC3:
			d.nsec3 = append(d.nsec3, v)
		default:
			c.add(rr)
		}
		d.All = append(d.All, rr)
	}
	if c.soa == nil {
		return UnavailableZone(origin, typ), nil
	}
	c.add(c.soa)
	neg := *c.soa
	if neg.Minttl < neg.Hdr.Ttl {
		neg.Hdr.Ttl = neg.Minttl
	}
	c.negSOA = &neg
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
	for n := range d.nsec {
		d.nsecOwners = append(d.nsecOwners, n)
	}
	sort.Slice(d.nsecOwners, func(i, j int) bool { return CanonicalCompare(d.nsecOwners[i], d.nsecOwners[j]) < 0 })
	sort.Slice(d.nsec3, func(i, j int) bool { return n3label(d.nsec3[i]) < n3label(d.nsec3[j]) })
	for _, n := range d.nsec3 {
		d.n3hash = append(d.n3hash, n3label(n))
	}
	if len(d.nsec3) > 0 {
		d.n3iter, d.n3salt = d.nsec3[0].Iterations, d.nsec3[0].Salt
	}
	return c, nil
}

func n3label(n *dns.NSEC3) string {
	return strings.ToUpper(strings.SplitN(n.Hdr.Name, ".", 2)[0])
}

// CanonicalCompare orders names canonically (RFC 4034 §6.1).
func CanonicalCompare(a, b string) int {
	la, lb := dns.SplitDomainName(strings.ToLower(a)), dns.SplitDomainName(strings.ToLower(b))
	for i, j := len(la)-1, len(lb)-1; i >= 0 || j >= 0; i, j = i-1, j-1 {
		if i < 0 {
			return -1
		}
		if j < 0 {
			return 1
		}
		if c := bytes.Compare([]byte(unescapeLabel(la[i])), []byte(unescapeLabel(lb[j]))); c != 0 {
			return c
		}
	}
	return 0
}

func unescapeLabel(l string) string {
	if !strings.Contains(l, `\`) {
		return l
	}
	var b strings.Builder
	for i := 0; i < len(l); i++ {
		if l[i] == '\\' && i+1 < len(l) {
			if i+3 < len(l) && isDigit(l[i+1]) && isDigit(l[i+2]) && isDigit(l[i+3]) {
				b.WriteByte((l[i+1]-'0')*100 + (l[i+2]-'0')*10 + (l[i+3] - '0'))
				i += 3
				continue
			}
			b.WriteByte(l[i+1])
			i++
			continue
		}
		b.WriteByte(l[i])
	}
	return b.String()
}

// Get returns the compiled zone with exactly this origin.
func (s *Set) Get(origin string) *Compiled {
	if s == nil {
		return nil
	}
	return s.zones[origin]
}

// ---------------------------------------------------------------- DNSSEC in answers

// AddDNSSEC adds RRSIGs and denial-of-existence proofs from signed zones to
// m, the response to qname/qtype built by Answer (the client set DO).
func (s *Set) AddDNSSEC(m *dns.Msg, qname string, qtype uint16) {
	if s == nil {
		return
	}
	signedFor := func(owner string) *Compiled {
		c := s.Find(owner)
		if c == nil || !c.Authoritative() || !c.SignedZone() {
			return nil
		}
		return c
	}
	// answer section: signatures (wildcard expansions get the wildcard's)
	var ans, wildProof []dns.RR
	for _, set := range groupSets(m.Answer) {
		ans = append(ans, set...)
		h := set[0].Header()
		if h.Rrtype == dns.TypeRRSIG {
			continue
		}
		c := signedFor(h.Name)
		if c == nil {
			continue
		}
		owner := strings.ToLower(h.Name)
		if sigs := c.D5.sigs[sigKey(owner, h.Rrtype)]; len(sigs) > 0 {
			ans = append(ans, sigs...)
			continue
		}
		if _, ok := c.exists[owner]; ok {
			continue
		}
		ce := c.closestEncloser(owner)
		for _, sg := range c.D5.sigs[sigKey(wildOf(ce), h.Rrtype)] {
			cp := dns.Copy(sg)
			cp.Header().Name = h.Name
			ans = append(ans, cp)
		}
		wildProof = c.appendProof(wildProof, c.proveWildcardAnswer(owner, ce))
	}
	m.Answer = ans
	m.Ns = append(m.Ns, wildProof...)

	// final name of the CNAME chain
	final := strings.ToLower(qname)
	for i := 0; i < MaxChain; i++ {
		next := ""
		for _, rr := range m.Answer {
			if cn, ok := rr.(*dns.CNAME); ok && strings.EqualFold(cn.Hdr.Name, final) && qtype != dns.TypeCNAME {
				next = strings.ToLower(cn.Target)
			}
		}
		if next == "" || next == final {
			break
		}
		final = next
	}
	positive := false
	for _, rr := range m.Answer {
		h := rr.Header()
		if strings.EqualFold(h.Name, final) && (h.Rrtype == qtype || qtype == dns.TypeANY) {
			positive = true
		}
	}
	var ns []dns.RR
	hasSOA := false
	var referral string
	for _, set := range groupSets(m.Ns) {
		ns = append(ns, set...)
		h := set[0].Header()
		switch h.Rrtype {
		case dns.TypeSOA:
			hasSOA = true
			if c := signedFor(h.Name); c != nil {
				ns = append(ns, c.D5.sigs[sigKey(h.Name, dns.TypeSOA)]...)
			}
		case dns.TypeNS:
			if !m.Authoritative || len(m.Answer) == 0 {
				referral = strings.ToLower(h.Name)
			}
		}
	}
	m.Ns = ns
	if referral != "" && !hasSOA {
		if c := s.Find(parentOf(referral)); c != nil && c.Authoritative() && c.SignedZone() {
			if nd := c.nodes[referral]; nd != nil && len(nd.sets[dns.TypeDS]) > 0 {
				m.Ns = append(m.Ns, nd.sets[dns.TypeDS]...)
				m.Ns = append(m.Ns, c.D5.sigs[sigKey(referral, dns.TypeDS)]...)
			} else {
				m.Ns = c.appendProof(m.Ns, c.proveNoData(referral, dns.TypeDS)...)
			}
		}
		return
	}
	if positive || !hasSOA {
		return
	}
	c := signedFor(final)
	if c == nil {
		return
	}
	if m.Rcode == dns.RcodeNameError {
		m.Ns = c.appendProof(m.Ns, c.proveNX(final)...)
		return
	}
	m.Ns = c.appendProof(m.Ns, c.proveNoData(final, qtype)...)
}

func parentOf(n string) string {
	off, end := dns.NextLabel(n, 0)
	if end {
		return "."
	}
	return n[off:]
}

func groupSets(rrs []dns.RR) [][]dns.RR {
	var out [][]dns.RR
	idx := map[string]int{}
	for _, rr := range rrs {
		h := rr.Header()
		t := h.Rrtype
		k := strings.ToLower(h.Name) + "|" + dns.TypeToString[t]
		if t == dns.TypeRRSIG {
			k += "|" + dns.TypeToString[rr.(*dns.RRSIG).TypeCovered]
		}
		if i, ok := idx[k]; ok {
			out[i] = append(out[i], rr)
			continue
		}
		idx[k] = len(out)
		out = append(out, []dns.RR{rr})
	}
	return out
}

// appendProof adds proof records (with their signatures) not yet in dst.
func (c *Compiled) appendProof(dst []dns.RR, proof ...dns.RR) []dns.RR {
	for _, p := range proof {
		if p == nil {
			continue
		}
		dup := false
		for _, rr := range dst {
			if rr.Header().Rrtype == p.Header().Rrtype && strings.EqualFold(rr.Header().Name, p.Header().Name) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		dst = append(dst, p)
		dst = append(dst, c.D5.sigs[sigKey(p.Header().Name, p.Header().Rrtype)]...)
	}
	return dst
}

// closestEncloser returns the deepest existing ancestor of name (or the apex).
func (c *Compiled) closestEncloser(name string) string {
	for a := parentOf(name); ; a = parentOf(a) {
		if _, ok := c.exists[a]; ok || a == c.Origin || a == "." {
			return a
		}
	}
}

func nextCloser(ce, name string) string {
	idx := dns.Split(name)
	cl := dns.CountLabel(ce)
	if len(idx)-cl-1 < 0 {
		return name
	}
	return name[idx[len(idx)-cl-1]:]
}

func (c *Compiled) nsecCovering(name string) *dns.NSEC {
	d := c.D5
	if len(d.nsecOwners) == 0 {
		return nil
	}
	i := sort.Search(len(d.nsecOwners), func(i int) bool { return CanonicalCompare(d.nsecOwners[i], name) > 0 })
	if i == 0 {
		return d.nsec[d.nsecOwners[len(d.nsecOwners)-1]]
	}
	return d.nsec[d.nsecOwners[i-1]]
}

func (c *Compiled) hash(name string) string {
	return strings.ToUpper(dns.HashName(name, dns.SHA1, c.D5.n3iter, c.D5.n3salt))
}

func (c *Compiled) n3Match(name string) *dns.NSEC3 {
	d := c.D5
	h := c.hash(name)
	i := sort.SearchStrings(d.n3hash, h)
	if i < len(d.n3hash) && d.n3hash[i] == h {
		return d.nsec3[i]
	}
	return nil
}

func (c *Compiled) n3Cover(name string) *dns.NSEC3 {
	d := c.D5
	if len(d.n3hash) == 0 {
		return nil
	}
	h := c.hash(name)
	i := sort.SearchStrings(d.n3hash, h)
	if i < len(d.n3hash) && d.n3hash[i] == h {
		return nil // matches, does not cover
	}
	if i == 0 {
		return d.nsec3[len(d.nsec3)-1]
	}
	return d.nsec3[i-1]
}

// n3 and ns1 avoid typed nils inside dns.RR.
func n3(v *dns.NSEC3) dns.RR {
	if v == nil {
		return nil
	}
	return v
}

func ns1(v *dns.NSEC) dns.RR {
	if v == nil {
		return nil
	}
	return v
}

func wildOf(ce string) string {
	if ce == "." {
		return "*."
	}
	return "*." + ce
}

// proveNX: name does not exist and no wildcard could have matched.
func (c *Compiled) proveNX(name string) []dns.RR {
	ce := c.closestEncloser(name)
	wild := wildOf(ce)
	if len(c.D5.nsec3) > 0 {
		return []dns.RR{n3(c.n3Match(ce)), n3(c.n3Cover(nextCloser(ce, name))), n3(c.n3Cover(wild))}
	}
	return []dns.RR{ns1(c.nsecCovering(name)), ns1(c.nsecCovering(wild))}
}

// proveNoData: name exists (or a wildcard matched) without qtype.
func (c *Compiled) proveNoData(name string, qtype uint16) []dns.RR {
	_, exists := c.exists[name]
	if len(c.D5.nsec3) > 0 {
		if m := c.n3Match(name); m != nil {
			return []dns.RR{m}
		}
		ce := c.closestEncloser(name)
		out := []dns.RR{n3(c.n3Match(ce)), n3(c.n3Cover(nextCloser(ce, name)))}
		if !exists {
			out = append(out, n3(c.n3Match(wildOf(ce)))) // wildcard NODATA
		}
		return out
	}
	if n := c.D5.nsec[name]; n != nil {
		return []dns.RR{n}
	}
	if exists {
		return []dns.RR{ns1(c.nsecCovering(name))} // empty non-terminal
	}
	ce := c.closestEncloser(name)
	return []dns.RR{ns1(c.nsecCovering(name)), ns1(c.D5.nsec[wildOf(ce)])}
}

// proveWildcardAnswer: no closer match than the wildcard at ce.
func (c *Compiled) proveWildcardAnswer(owner, ce string) dns.RR {
	if len(c.D5.nsec3) > 0 {
		return n3(c.n3Cover(nextCloser(ce, owner)))
	}
	return ns1(c.nsecCovering(owner))
}
