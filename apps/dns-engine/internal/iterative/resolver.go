// Package iterative resolves names from the root (docs/40 §2.1): root hints
// and priming (RFC 8109), referrals with bailiwick checks, a delegation cache
// kept in the engine cache under private key types, an infra cache of
// per-server RTT/EDNS/0x20 state, QNAME minimisation (RFC 9156), 0x20 case
// randomisation, TCP after truncation, EDNS fallback, CNAME chains and loop
// and budget limits.
package iterative

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/cache"
	"mrk/dns-engine/internal/resolver"
	"mrk/dns-engine/internal/trace"
	"mrk/dns-engine/internal/wire"
)

// Private cache key types (RFC 6895 private use range) for delegations and
// name-server addresses: they never collide with client cache keys.
const (
	keyDeleg  = 0xFF01
	keyNSAddr = 0xFF02 // + 0 for A, +1 for AAAA
)

// Limits that are not settings.
const (
	maxCNAME    = 16
	maxNSDepth  = 4
	minimiseMax = 10 // RFC 9156 MAX_MINIMISE_COUNT
	ednsSize    = 1232
)

// Errors.
var (
	ErrNoReachable      = errors.New("iterative: no reachable authority")
	ErrBudget           = errors.New("iterative: query budget exhausted")
	ErrLoop             = errors.New("iterative: referral or CNAME loop")
	ErrTooManyReferrals = errors.New("iterative: too many referrals")
	ErrLame             = errors.New("iterative: lame or bogus response")
)

// Config is the hot-swappable configuration (from settings resolution).
type Config struct {
	QNameMin     string // off | relaxed | strict
	UseV4, UseV6 bool
	CaseRandom   bool
	AllowPrivate bool
	MaxReferrals int
	MaxQueries   int
	MaxNSPerZone int
	QueryTimeout time.Duration
	DO           bool     // set the DO bit (validation on)
	Hints        []Server // nil/empty = built-in named.root
	MaxTTL       uint32   // delegation TTL cap (cache.max_ttl)
	Self         map[netip.AddrPort]struct{}
	Port         uint16 // authoritative port (53; tests may change)
}

// Resolver is safe for concurrent use.
type Resolver struct {
	cfg   atomic.Pointer[Config]
	lim   atomic.Pointer[resolver.Limiter]
	Infra *Infra
	cache *cache.Cache
	tr    Transport
	roots atomic.Pointer[[]Server] // primed root set; nil = hints
	now   func() time.Time

	primeMu sync.Mutex
	prime   PrimeStatus
}

// New returns a resolver storing delegations in c.
func New(c *cache.Cache, tr Transport, infraMax int) *Resolver {
	if tr == nil {
		tr = NetTransport{}
	}
	r := &Resolver{Infra: NewInfra(infraMax, nil), cache: c, tr: tr, now: time.Now}
	r.cfg.Store(&Config{QNameMin: "relaxed", UseV4: true, CaseRandom: true, MaxReferrals: 30, MaxQueries: 100,
		MaxNSPerZone: 13, QueryTimeout: 1500 * time.Millisecond, MaxTTL: 86400, Port: 53})
	return r
}

// Configure swaps the configuration. Changed hints drop the primed set.
func (r *Resolver) Configure(c Config, lim *resolver.Limiter, infraMax int) {
	if c.Port == 0 {
		c.Port = 53
	}
	old := r.cfg.Load()
	if old != nil && !sameServers(old.Hints, c.Hints) {
		r.roots.Store(nil)
	}
	r.cfg.Store(&c)
	if lim != nil {
		r.lim.Store(lim)
	}
	r.Infra.SetMax(infraMax)
}

func sameServers(a, b []Server) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Config returns the current configuration.
func (r *Resolver) Config() Config { return *r.cfg.Load() }

func (r *Resolver) hints() []Server {
	c := r.cfg.Load()
	if len(c.Hints) > 0 {
		return c.Hints
	}
	return BuiltinRoots()
}

func (r *Resolver) rootServers() []Server {
	if p := r.roots.Load(); p != nil && len(*p) > 0 {
		return *p
	}
	return r.hints()
}

// ---------------------------------------------------------------- state

type state struct {
	cfg       *Config
	queries   int
	referrals int
	depth     int
	resolving map[string]bool
	tr        *trace.Trace
	noCache   bool
}

func (r *Resolver) newState(ctx context.Context) *state {
	return &state{cfg: r.cfg.Load(), resolving: map[string]bool{}, tr: trace.From(ctx), noCache: trace.NoCache(ctx)}
}

// Resolve resolves qname/qtype from the closest known delegation (or the
// root) and returns a response with Rcode, the answer chain (with RRSIGs)
// and the final authority section. Extra is empty.
func (r *Resolver) Resolve(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	st := r.newState(ctx)
	return r.resolve(ctx, st, strings.ToLower(dns.Fqdn(qname)), qtype)
}

func (r *Resolver) resolve(ctx context.Context, st *state, qname string, qtype uint16) (*dns.Msg, error) {
	name := qname
	var chain []dns.RR
	seen := map[string]bool{qname: true}
	for i := 0; i <= maxCNAME; i++ {
		resp, err := r.lookup(ctx, st, name, qtype)
		if err != nil {
			return nil, err
		}
		ans, next := followChain(resp, name, qtype)
		chain = append(chain, ans...)
		if next == "" {
			out := new(dns.Msg)
			out.SetQuestion(qname, qtype)
			out.Response = true
			out.Rcode = resp.Rcode
			out.Authoritative = resp.Authoritative
			out.Answer = chain
			out.Ns = resp.Ns
			return out, nil
		}
		if seen[next] {
			return nil, ErrLoop
		}
		seen[next] = true
		name = next
	}
	return nil, ErrLoop
}

// followChain extracts the CNAME chain starting at name plus the final data.
// next is the name still to resolve ("" when resp is conclusive).
func followChain(resp *dns.Msg, name string, qtype uint16) (ans []dns.RR, next string) {
	cur := name
	inChain := map[string]bool{}
	for hop := 0; hop <= maxCNAME; hop++ {
		inChain[cur] = true
		var data, cn []dns.RR
		for _, rr := range resp.Answer {
			h := rr.Header()
			if !strings.EqualFold(h.Name, cur) {
				continue
			}
			switch {
			case h.Rrtype == dns.TypeRRSIG:
			case h.Rrtype == qtype || qtype == dns.TypeANY:
				data = append(data, rr)
			case h.Rrtype == dns.TypeCNAME:
				cn = append(cn, rr)
			}
		}
		if len(data) > 0 || qtype == dns.TypeCNAME {
			ans = append(ans, data...)
			ans = append(ans, sigsFor(resp.Answer, cur, qtype)...)
			return withDNAME(resp, ans, inChain), ""
		}
		if len(cn) == 0 {
			if cur == name || resp.Rcode == dns.RcodeNameError || hasSOAFor(resp, cur) {
				return withDNAME(resp, ans, inChain), "" // negative answer (for the chain end)
			}
			return withDNAME(resp, ans, inChain), cur
		}
		ans = append(ans, cn[0])
		ans = append(ans, sigsFor(resp.Answer, cur, dns.TypeCNAME)...)
		target := strings.ToLower(cn[0].(*dns.CNAME).Target)
		if inChain[target] {
			return ans, "" // loop inside one response: stop here
		}
		cur = target
	}
	return ans, ""
}

func sigsFor(rrs []dns.RR, owner string, covered uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == covered && strings.EqualFold(s.Hdr.Name, owner) {
			out = append(out, rr)
		}
	}
	return out
}

func withDNAME(resp *dns.Msg, ans []dns.RR, chain map[string]bool) []dns.RR {
	var pre []dns.RR
	for _, rr := range resp.Answer {
		d, ok := rr.(*dns.DNAME)
		if !ok {
			continue
		}
		owner := strings.ToLower(d.Hdr.Name)
		for n := range chain {
			if n != owner && dns.IsSubDomain(owner, n) {
				pre = append(pre, rr)
				pre = append(pre, sigsFor(resp.Answer, d.Hdr.Name, dns.TypeDNAME)...)
				break
			}
		}
	}
	if len(pre) == 0 {
		return ans
	}
	return append(pre, ans...)
}

func hasSOAFor(resp *dns.Msg, name string) bool {
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeSOA && dns.IsSubDomain(strings.ToLower(rr.Header().Name), name) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- delegations

type delegation struct {
	zone  string
	ns    []string
	addrs map[string][]netip.Addr
	ttl   uint32
}

func parent(name string) string {
	if name == "." {
		return "."
	}
	off, end := dns.NextLabel(name, 0)
	if end {
		return "."
	}
	return name[off:]
}

func key(name string, t uint16) []byte {
	buf := make([]byte, 256)
	n, err := dns.PackDomainName(strings.ToLower(name), buf, 0, nil, false)
	if err != nil {
		return nil
	}
	return wire.AppendKey(make([]byte, 0, n+2), buf[:n], t)
}

func (r *Resolver) getDeleg(zone string) *delegation {
	if r.cache == nil {
		return nil
	}
	k := key(zone, keyDeleg)
	now := r.now().UnixNano()
	ent := r.cache.Get(k, now)
	if ent == nil || !ent.Fresh(now) {
		return nil
	}
	m := new(dns.Msg)
	if m.Unpack(ent.T.Wire) != nil {
		return nil
	}
	d := &delegation{zone: zone, addrs: map[string][]netip.Addr{}}
	for _, rr := range m.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			d.ns = append(d.ns, strings.ToLower(ns.Ns))
		}
	}
	addGlue(d, m.Extra)
	return d
}

func addGlue(d *delegation, extra []dns.RR) {
	in := map[string]bool{}
	for _, n := range d.ns {
		in[n] = true
	}
	for _, rr := range extra {
		name := strings.ToLower(rr.Header().Name)
		if !in[name] {
			continue
		}
		var a netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			a, _ = netip.AddrFromSlice(v.A.To4())
		case *dns.AAAA:
			a, _ = netip.AddrFromSlice(v.AAAA)
		}
		if a.IsValid() && !contains(d.addrs[name], a) {
			d.addrs[name] = append(d.addrs[name], a.Unmap())
		}
	}
}

func contains(l []netip.Addr, a netip.Addr) bool {
	for _, x := range l {
		if x == a {
			return true
		}
	}
	return false
}

func (r *Resolver) putDeleg(st *state, d *delegation, nsRRs, glue []dns.RR) {
	if r.cache == nil || len(nsRRs) == 0 {
		return
	}
	ttl := d.ttl
	if st.cfg.MaxTTL > 0 && ttl > st.cfg.MaxTTL {
		ttl = st.cfg.MaxTTL
	}
	if ttl == 0 {
		return
	}
	m := new(dns.Msg)
	m.SetQuestion(d.zone, dns.TypeNS)
	m.Response = true
	m.Ns = nsRRs
	m.Extra = glue
	b, err := m.Pack()
	if err != nil {
		return
	}
	t, err := wire.NewTemplate(b)
	if err != nil {
		return
	}
	r.cache.Put(key(d.zone, keyDeleg), d.zone, t, ttl, 0, false, r.now().UnixNano())
}

func (r *Resolver) rootDeleg() *delegation {
	d := &delegation{zone: ".", addrs: map[string][]netip.Addr{}}
	for _, s := range r.rootServers() {
		if _, ok := d.addrs[s.Name]; !ok {
			d.ns = append(d.ns, s.Name)
		}
		d.addrs[s.Name] = append(d.addrs[s.Name], s.Addr)
	}
	return d
}

// usable reports whether d can be queried without resolving its own
// in-zone name server names (which would loop).
func usable(d *delegation) bool {
	for _, n := range d.ns {
		if len(d.addrs[n]) > 0 || !dns.IsSubDomain(d.zone, n) {
			return true
		}
	}
	return false
}

func (r *Resolver) closest(st *state, qname string, qtype uint16) *delegation {
	start := qname
	if qtype == dns.TypeDS && qname != "." {
		start = parent(qname) // the DS lives in the parent zone
	}
	if !st.noCache {
		for n := start; n != "."; n = parent(n) {
			if d := r.getDeleg(n); d != nil && usable(d) {
				return d
			}
		}
	}
	return r.rootDeleg()
}

// ---------------------------------------------------------------- lookup

type kind int

const (
	kAnswer kind = iota
	kNegative
	kReferral
	kLame
)

// sanitize drops out-of-bailiwick data: answer and authority records must be
// at or below zone; additional data is kept only as glue at or below zone.
func sanitize(resp *dns.Msg, zone string) {
	keep := func(rrs []dns.RR, glueOnly bool) []dns.RR {
		out := rrs[:0]
		for _, rr := range rrs {
			h := rr.Header()
			if h.Class != dns.ClassINET || h.Rrtype == dns.TypeOPT {
				continue
			}
			if glueOnly && h.Rrtype != dns.TypeA && h.Rrtype != dns.TypeAAAA {
				continue
			}
			if dns.IsSubDomain(zone, strings.ToLower(h.Name)) {
				out = append(out, rr)
			}
		}
		return out
	}
	resp.Answer = keep(resp.Answer, false)
	resp.Ns = keep(resp.Ns, false)
	resp.Extra = keep(resp.Extra, true)
}

func classify(resp *dns.Msg, zone, qn string) (kind, string) {
	switch resp.Rcode {
	case dns.RcodeNameError:
		return kNegative, ""
	case dns.RcodeSuccess:
	default:
		return kLame, ""
	}
	for _, rr := range resp.Answer {
		if strings.EqualFold(rr.Header().Name, qn) {
			return kAnswer, ""
		}
	}
	if len(resp.Answer) > 0 {
		return kAnswer, "" // DNAME-synthesised chains start above qn
	}
	soa, cut := false, ""
	for _, rr := range resp.Ns {
		h := rr.Header()
		owner := strings.ToLower(h.Name)
		switch h.Rrtype {
		case dns.TypeSOA:
			soa = true
		case dns.TypeNS:
			if owner != zone && dns.IsSubDomain(zone, owner) && dns.IsSubDomain(owner, qn) {
				cut = owner
			} else if cut == "" {
				cut = "-" // upward or sideways referral
			}
		}
	}
	switch {
	case soa:
		return kNegative, ""
	case cut != "" && cut != "-":
		return kReferral, cut
	case cut == "-":
		return kLame, ""
	case resp.Authoritative:
		return kNegative, "" // NODATA without SOA from an authoritative server
	}
	return kLame, ""
}

// minimised returns the query name extra labels below zone toward qname.
func minimised(zone, qname string, extra int) string {
	zl := dns.CountLabel(zone)
	ql := dns.CountLabel(qname)
	if zl+extra >= ql {
		return qname
	}
	idx := dns.Split(qname)
	return qname[idx[ql-zl-extra]:]
}

func (r *Resolver) lookup(ctx context.Context, st *state, qname string, qtype uint16) (*dns.Msg, error) {
	d := r.closest(st, qname, qtype)
	minimise := st.cfg.QNameMin != "off" && st.cfg.QNameMin != ""
	extra := 1
	zones := map[string]bool{d.zone: true}
	exclude := map[netip.Addr]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		qn, qt := qname, qtype
		if minimise && extra <= minimiseMax {
			if qn = minimised(d.zone, qname, extra); qn != qname {
				qt = dns.TypeA
			}
		} else {
			minimise = false
		}
		resp, srv, err := r.query(ctx, st, d, qn, qt, exclude)
		if err != nil {
			return nil, err
		}
		sanitize(resp, d.zone)
		k, cut := classify(resp, d.zone, qn)
		if k == kReferral && qtype == dns.TypeDS && cut == qname {
			k = kLame // a DS question must be answered by the parent side
		}
		switch k {
		case kAnswer, kNegative:
			if qn == qname {
				return resp, nil
			}
			hasCNAME := false
			for _, rr := range resp.Answer {
				if rr.Header().Rrtype == dns.TypeCNAME || rr.Header().Rrtype == dns.TypeDNAME {
					hasCNAME = true
				}
			}
			switch {
			case resp.Rcode == dns.RcodeNameError && st.cfg.QNameMin == "strict":
				out := resp.Copy()
				out.Answer = nil
				return out, nil // RFC 9156 §2.3: the whole subtree does not exist
			case resp.Rcode == dns.RcodeNameError || hasCNAME:
				minimise = false // relaxed: retry with the full name
			default:
				extra++
			}
		case kReferral:
			if zones[cut] {
				return nil, ErrLoop
			}
			st.referrals++
			if st.referrals > st.cfg.MaxReferrals {
				return nil, ErrTooManyReferrals
			}
			nd, nsRRs, glue := referral(resp, cut)
			if len(nd.ns) == 0 {
				exclude[srv] = true
				continue
			}
			r.putDeleg(st, nd, nsRRs, glue)
			zones[cut] = true
			d = nd
			extra = 1
			exclude = map[netip.Addr]bool{}
		default:
			exclude[srv] = true // lame: try another server of the same zone
		}
	}
}

func referral(resp *dns.Msg, cut string) (*delegation, []dns.RR, []dns.RR) {
	d := &delegation{zone: cut, addrs: map[string][]netip.Addr{}, ttl: ^uint32(0)}
	var nsRRs, glue []dns.RR
	seen := map[string]bool{}
	for _, rr := range resp.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok || !strings.EqualFold(ns.Hdr.Name, cut) {
			continue
		}
		n := strings.ToLower(ns.Ns)
		if seen[n] {
			continue
		}
		seen[n] = true
		d.ns = append(d.ns, n)
		nsRRs = append(nsRRs, rr)
		if ns.Hdr.Ttl < d.ttl {
			d.ttl = ns.Hdr.Ttl
		}
	}
	for _, rr := range resp.Extra {
		if seen[strings.ToLower(rr.Header().Name)] {
			glue = append(glue, rr)
		}
	}
	addGlue(d, glue)
	if d.ttl == ^uint32(0) {
		d.ttl = 0
	}
	return d, nsRRs, glue
}

// ---------------------------------------------------------------- servers

type cand struct {
	name  string
	addr  netip.Addr
	score time.Duration
}

func (r *Resolver) allowed(st *state, a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
		return false
	}
	if a.Is4() && !st.cfg.UseV4 || a.Is6() && !st.cfg.UseV6 {
		return false
	}
	if _, self := st.cfg.Self[netip.AddrPortFrom(a, st.cfg.Port)]; self {
		return false // never query ourselves
	}
	if !st.cfg.AllowPrivate && acl.Private(a) {
		return false
	}
	return true
}

func (r *Resolver) candidates(st *state, d *delegation, exclude map[netip.Addr]bool) []cand {
	var out []cand
	now := r.now()
	names := d.ns
	if len(names) > st.cfg.MaxNSPerZone {
		names = names[:st.cfg.MaxNSPerZone]
	}
	for _, n := range names {
		for _, a := range d.addrs[n] {
			if exclude[a] {
				continue
			}
			if d.zone != "." || len(st.cfg.Hints) == 0 {
				if !r.allowed(st, a) {
					continue
				}
			} else if a.Is4() && !st.cfg.UseV4 || a.Is6() && !st.cfg.UseV6 {
				continue // configured root hints are trusted, only the family applies
			}
			// jitter spreads load over servers of similar speed
			s := r.Infra.Get(a).score(now) + time.Duration(rand.Int64N(int64(5*time.Millisecond)))
			out = append(out, cand{name: n, addr: a, score: s})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].score < out[j].score })
	return out
}

func (r *Resolver) query(ctx context.Context, st *state, d *delegation, qn string, qt uint16,
	exclude map[netip.Addr]bool) (*dns.Msg, netip.Addr, error) {
	tried := map[string]bool{}
	lastErr := ErrNoReachable
	for {
		for _, c := range r.candidates(st, d, exclude) {
			resp, err := r.send(ctx, st, d.zone, c, qn, qt)
			if err != nil {
				if errors.Is(err, ErrBudget) || errors.Is(err, resolver.ErrOverloaded) || ctx.Err() != nil {
					return nil, c.addr, err
				}
				exclude[c.addr] = true
				continue
			}
			switch resp.Rcode {
			case dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeFormatError:
				exclude[c.addr] = true
				lastErr = ErrNoReachable
				continue
			}
			return resp, c.addr, nil
		}
		// every known address failed: resolve name servers without addresses
		progress := false
		names := d.ns
		if len(names) > st.cfg.MaxNSPerZone {
			names = names[:st.cfg.MaxNSPerZone]
		}
		for _, n := range names {
			if tried[n] || len(d.addrs[n]) > 0 {
				continue
			}
			tried[n] = true
			if dns.IsSubDomain(d.zone, n) && d.zone != "." {
				continue // in-zone name without glue: resolving it would ask this zone
			}
			addrs, err := r.nsAddrs(ctx, st, n)
			if err != nil && (errors.Is(err, ErrBudget) || errors.Is(err, resolver.ErrOverloaded) || ctx.Err() != nil) {
				return nil, netip.Addr{}, err
			}
			if len(addrs) > 0 {
				d.addrs[n] = addrs
				progress = true
				break
			}
		}
		if !progress {
			return nil, netip.Addr{}, lastErr
		}
	}
}

// nsAddrs resolves a name server's addresses (cached separately).
func (r *Resolver) nsAddrs(ctx context.Context, st *state, ns string) ([]netip.Addr, error) {
	var out []netip.Addr
	var types []uint16
	if st.cfg.UseV4 {
		types = append(types, dns.TypeA)
	}
	if st.cfg.UseV6 {
		types = append(types, dns.TypeAAAA)
	}
	now := r.now().UnixNano()
	var missing []uint16
	for _, t := range types {
		k := key(ns, nsAddrType(t))
		if r.cache != nil && !st.noCache {
			if ent := r.cache.Get(k, now); ent != nil && ent.Fresh(now) {
				m := new(dns.Msg)
				if m.Unpack(ent.T.Wire) == nil {
					out = append(out, addrsOf(m.Answer)...)
					continue
				}
			}
		}
		missing = append(missing, t)
	}
	if len(missing) == 0 {
		return out, nil
	}
	if st.depth >= maxNSDepth || st.resolving[ns] {
		return out, nil
	}
	st.depth++
	st.resolving[ns] = true
	defer func() { st.depth--; delete(st.resolving, ns) }()
	var lastErr error
	for _, t := range missing {
		m, err := r.resolve(ctx, st, ns, t)
		if err != nil {
			lastErr = err
			if errors.Is(err, ErrBudget) || errors.Is(err, resolver.ErrOverloaded) || ctx.Err() != nil {
				return out, err
			}
			continue
		}
		var rrs []dns.RR
		ttl := ^uint32(0)
		for _, rr := range m.Answer {
			if rr.Header().Rrtype == t {
				rrs = append(rrs, rr)
				if rr.Header().Ttl < ttl {
					ttl = rr.Header().Ttl
				}
			}
		}
		out = append(out, addrsOf(rrs)...)
		if len(rrs) > 0 && r.cache != nil {
			if st.cfg.MaxTTL > 0 && ttl > st.cfg.MaxTTL {
				ttl = st.cfg.MaxTTL
			}
			c := new(dns.Msg)
			c.SetQuestion(ns, t)
			c.Response = true
			c.Answer = rrs
			if b, err := c.Pack(); err == nil {
				if tpl, err := wire.NewTemplate(b); err == nil && ttl > 0 {
					r.cache.Put(key(ns, nsAddrType(t)), ns, tpl, ttl, 0, false, r.now().UnixNano())
				}
			}
		}
	}
	return out, lastErr
}

func nsAddrType(t uint16) uint16 {
	if t == dns.TypeAAAA {
		return keyNSAddr + 1
	}
	return keyNSAddr
}

func addrsOf(rrs []dns.RR) []netip.Addr {
	var out []netip.Addr
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
				out = append(out, a)
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				out = append(out, a)
			}
		}
	}
	return out
}

func randomCase(name string) string {
	b := []byte(name)
	for i, c := range b {
		if c >= 'a' && c <= 'z' && rand.IntN(2) == 0 {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

func (r *Resolver) timeout(st *state, info ServerInfo) time.Duration {
	to := st.cfg.QueryTimeout
	if info.Successes > 0 {
		if t := 4*info.RTT + 100*time.Millisecond; t < to {
			to = max(t, 300*time.Millisecond)
		}
	}
	return to
}

// send performs one exchange with fallbacks (TCP after TC, plain DNS after
// FORMERR, no 0x20 for servers that do not preserve case).
func (r *Resolver) send(ctx context.Context, st *state, zone string, c cand, qn string, qt uint16) (*dns.Msg, error) {
	info := r.Infra.Get(c.addr)
	useEDNS := !info.NoEDNS && !(info.Timeouts >= 2 && info.Successes == 0)
	use0x20 := st.cfg.CaseRandom && !info.No0x20
	tcp := false
	for attempt := 0; attempt < 4; attempt++ {
		if st.queries >= st.cfg.MaxQueries {
			return nil, ErrBudget
		}
		st.queries++
		m := new(dns.Msg)
		m.Id = dns.Id()
		name := qn
		if use0x20 {
			name = randomCase(qn)
		}
		m.Question = []dns.Question{{Name: name, Qtype: qt, Qclass: dns.ClassINET}}
		if useEDNS {
			m.SetEdns0(ednsSize, st.cfg.DO)
		}
		lim := r.lim.Load()
		if lim != nil && !lim.TryAcquire() {
			return nil, resolver.ErrOverloaded
		}
		to := r.timeout(st, info)
		cctx, cancel := context.WithTimeout(ctx, to)
		start := time.Now()
		resp, err := r.tr.Exchange(cctx, netip.AddrPortFrom(c.addr, st.cfg.Port), m, tcp)
		rtt := time.Since(start)
		cancel()
		if lim != nil {
			lim.Release()
		}
		step := trace.Step{Zone: zone, Server: c.addr.String(), ServerName: strings.TrimSuffix(c.name, "."), QName: qn,
			QType: dns.TypeToString[qt], RTTMS: float64(rtt.Microseconds()) / 1000}
		if err == nil {
			err = checkResponse(m, resp)
		}
		if err != nil {
			if errors.Is(err, errCase) {
				// the server does not echo our case: remember and retry without 0x20
				r.Infra.SetNo0x20(c.addr)
				use0x20 = false
				step.Error = "case mismatch (0x20 disabled for this server)"
				st.tr.Add(step)
				continue
			}
			if ctx.Err() == nil {
				r.Infra.Failure(c.addr, to)
			}
			step.Error = err.Error()
			st.tr.Add(step)
			return nil, err
		}
		step.Rcode = dns.RcodeToString[resp.Rcode]
		if resp.Truncated && !tcp {
			step.Error = "truncated, retrying over TCP"
			st.tr.Add(step)
			tcp = true
			continue
		}
		if useEDNS && (resp.Rcode == dns.RcodeFormatError || resp.Rcode == dns.RcodeNotImplemented ||
			resp.Rcode == dns.RcodeBadVers) {
			step.Error = "EDNS not supported, retrying without"
			st.tr.Add(step)
			useEDNS = false
			continue
		}
		r.Infra.Success(c.addr, rtt)
		if !useEDNS && !info.NoEDNS && resp.Rcode != dns.RcodeFormatError {
			r.Infra.SetNoEDNS(c.addr)
		}
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
			var refs []string
			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					refs = append(refs, strings.TrimSuffix(strings.ToLower(ns.Ns), "."))
				}
			}
			if !resp.Authoritative {
				step.Referral = refs
			}
		}
		st.tr.Add(step)
		return resp, nil
	}
	return nil, ErrLame
}

var (
	errCase     = errors.New("iterative: question case mismatch")
	errQuestion = errors.New("iterative: response question does not match")
)

func checkResponse(q, r *dns.Msg) error {
	if r == nil || !r.Response || r.Id != q.Id || r.Opcode != dns.OpcodeQuery {
		return errQuestion
	}
	if len(r.Question) != 1 {
		if r.Truncated && len(r.Question) == 0 {
			return nil
		}
		return errQuestion
	}
	a, b := q.Question[0], r.Question[0]
	if a.Qtype != b.Qtype || a.Qclass != b.Qclass {
		return errQuestion
	}
	if a.Name != b.Name {
		if strings.EqualFold(a.Name, b.Name) {
			return errCase
		}
		return errQuestion
	}
	return nil
}
