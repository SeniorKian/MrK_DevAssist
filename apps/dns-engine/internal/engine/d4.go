package engine

// D4 (docs/40 §2.1, §2.2, §3): resolution from the root, DNSSEC validation,
// trust anchor maintenance, priming, the extended resolve/status/dnssec
// views and the related events.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/dnssec"
	"mrk/dns-engine/internal/events"
	"mrk/dns-engine/internal/iterative"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/querylog"
	"mrk/dns-engine/internal/resolver"
	"mrk/dns-engine/internal/trace"
	"mrk/dns-engine/internal/wire"
)

// Schedules.
const (
	taRefreshEvery = 12 * time.Hour
	taRetry        = time.Hour
	taFirst        = time.Minute
	primeRetry     = 5 * time.Minute
	spikeWindow    = 5 * time.Minute
	spikeMinBogus  = 100
	spikeMinPct    = 5
)

// d4policy is the part of the policy snapshot used by D4.
type d4policy struct {
	insecure       map[string]struct{} // wire suffixes answered without validation (auto_insecure_local)
	resolveTimeout time.Duration
}

// d4state is the engine-lifetime D4 state.
type d4state struct {
	kick chan struct{} // ask the loop to prime / refresh now

	mu        sync.Mutex
	primeOK   bool
	primed    bool
	primeErr  bool // the last priming failed (event already sent)
	nextTA    time.Time
	spikeFrom time.Time
	spikeTot  uint64
	spikeBog  uint64
	spikeSent bool
	spikeName map[string]uint64
}

func (e *Engine) openD4() {
	e.d4.kick = make(chan struct{}, 1)
	e.d4.spikeName = map[string]uint64{}
	e.iter = iterative.New(e.Cache, e.opts.IterTransport, e.settings.Resolution.InfraCacheEntries)
	ta := dnssec.OpenAnchorsWith(filepath.Join(e.opts.DataDir, "trust-anchors.json"), e.opts.TrustAnchors, nil)
	e.val = dnssec.New(ta, nil)
}

func needsRecursion(mode string) bool {
	return mode == config.ModeRecursive || mode == config.ModeForwardThenRecursive
}

// selfAddrs lists the addresses the engine listens on (never queried).
func selfAddrs(s config.Settings) map[netip.AddrPort]struct{} {
	out := map[netip.AddrPort]struct{}{}
	var ifaces []netip.Addr
	loaded := false
	for _, l := range s.Listen {
		ap, err := netip.ParseAddrPort(l.Address)
		if err != nil {
			continue
		}
		if !ap.Addr().IsUnspecified() {
			out[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = struct{}{}
			continue
		}
		if !loaded {
			loaded = true
			if as, err := net.InterfaceAddrs(); err == nil {
				for _, a := range as {
					if pn, ok := a.(*net.IPNet); ok {
						if ip, ok := netip.AddrFromSlice(pn.IP); ok {
							ifaces = append(ifaces, ip.Unmap())
						}
					}
				}
			}
		}
		for _, ip := range ifaces {
			out[netip.AddrPortFrom(ip, ap.Port())] = struct{}{}
		}
	}
	return out
}

// configureD4Locked prepares the D4 parts of p and reconfigures the
// long-lived resolver and validator (e.mu held, before p is published).
func (e *Engine) configureD4Locked(p *policy, old *policy) {
	s := p.s
	r := s.Resolution
	p.d4.resolveTimeout = time.Duration(r.ResolveTimeoutMS) * time.Millisecond
	if p.d4.resolveTimeout <= 0 {
		p.d4.resolveTimeout = 4 * time.Second
	}
	qt := time.Duration(r.QueryTimeoutMS) * time.Millisecond
	if qt > 0 {
		p.group.AttemptTimeout = qt
		for _, g := range p.fwd {
			g.AttemptTimeout = qt
		}
	}
	p.d4.insecure = map[string]struct{}{}
	if s.DNSSEC.AutoInsecureLocal {
		for name := range e.zones {
			p.d4.insecure[wireName(name)] = struct{}{}
		}
		for _, n := range localNames {
			p.d4.insecure[wireName(n)] = struct{}{}
		}
	}
	var hints []iterative.Server
	for _, h := range r.RootHints {
		if h.IPv4 != "" {
			hints = append(hints, iterative.Server{Name: h.Name, Addr: netip.MustParseAddr(h.IPv4)})
		}
		if h.IPv6 != "" {
			hints = append(hints, iterative.Server{Name: h.Name, Addr: netip.MustParseAddr(h.IPv6)})
		}
	}
	e.iter.Configure(iterative.Config{QNameMin: r.QNameMinimization,
		UseV4: r.IPVersions != config.IPv6Only, UseV6: r.IPVersions != config.IPv4Only,
		CaseRandom: r.CaseRandomization, AllowPrivate: r.AllowPrivateNS, MaxReferrals: r.MaxReferrals,
		MaxQueries: r.MaxQueriesPerResolution, MaxNSPerZone: r.MaxNSPerZone, QueryTimeout: qt,
		DO: s.DNSSEC.Mode != config.DNSSECOff, Hints: hints, MaxTTL: s.Cache.MaxTTL, Self: selfAddrs(s)},
		e.limiter, r.InfraCacheEntries)
	var ntas []dnssec.NTA
	for _, n := range s.DNSSEC.NegativeTrustAnchors {
		ntas = append(ntas, dnssec.NTA{Domain: strings.ToLower(dns.Fqdn(n.Domain)), Expires: n.Expires()})
	}
	e.val.Configure(dnssec.Config{NSEC3MaxIter: s.DNSSEC.NSEC3MaxIterations,
		Skew: time.Duration(s.DNSSEC.SigSkewSeconds) * time.Second, BogusTTL: time.Duration(s.DNSSEC.BogusTTL) * time.Second,
		MaxTTL: time.Duration(s.Cache.MaxTTL) * time.Second, Aggressive: s.DNSSEC.AggressiveNSEC, NTAs: ntas})
	if old != nil && (!needsRecursion(old.s.Resolution.Mode) && needsRecursion(r.Mode) ||
		old.s.DNSSEC.Mode == config.DNSSECOff && s.DNSSEC.Mode != config.DNSSECOff) {
		select {
		case e.d4.kick <- struct{}{}:
		default:
		}
	}
}

// d4FlushNeeded reports whether a settings change invalidates cached
// answers (their DNSSEC status or resolution path).
func d4FlushNeeded(prev, next config.Settings) bool {
	if prev.DNSSEC.Mode != next.DNSSEC.Mode || prev.Resolution.Mode != next.Resolution.Mode ||
		prev.DNSSEC.AutoInsecureLocal != next.DNSSEC.AutoInsecureLocal ||
		prev.DNSSEC.NSEC3MaxIterations != next.DNSSEC.NSEC3MaxIterations ||
		prev.DNSSEC.SigSkewSeconds != next.DNSSEC.SigSkewSeconds ||
		len(prev.DNSSEC.NegativeTrustAnchors) != len(next.DNSSEC.NegativeTrustAnchors) {
		return true
	}
	for i := range prev.DNSSEC.NegativeTrustAnchors {
		if prev.DNSSEC.NegativeTrustAnchors[i] != next.DNSSEC.NegativeTrustAnchors[i] {
			return true
		}
	}
	return false
}

// flushD4 drops answers and validator state after such a change.
func (e *Engine) flushD4() {
	e.Cache.Flush("")
	e.val.Flush()
}

// ---------------------------------------------------------------- background

func (e *Engine) d4Loop() {
	defer e.wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	e.d4.mu.Lock()
	e.d4.nextTA = time.Now().Add(taFirst)
	e.d4.mu.Unlock()
	if p := e.pol.Load(); needsRecursion(p.s.Resolution.Mode) {
		e.prime()
	}
	for {
		select {
		case <-e.bg.Done():
			return
		case <-t.C:
		case <-e.d4.kick:
		}
		p := e.pol.Load()
		if needsRecursion(p.s.Resolution.Mode) {
			ps := e.iter.PrimeStatus()
			due := !ps.Done || time.Since(ps.At) >= iterative.PrimeInterval || !ps.OK && time.Since(ps.At) >= primeRetry
			if due {
				e.prime()
			}
		}
		e.d4.mu.Lock()
		taDue := time.Now().After(e.d4.nextTA)
		e.d4.mu.Unlock()
		if taDue && p.s.DNSSEC.Mode != config.DNSSECOff && p.s.DNSSEC.TrustAnchorAutoUpdate {
			_ = e.refreshTrustAnchors()
		}
	}
}

func (e *Engine) prime() {
	ctx, cancel := context.WithTimeout(e.bg, 10*time.Second)
	defer cancel()
	ps := e.iter.Prime(ctx)
	e.d4.mu.Lock()
	failedBefore := e.d4.primeErr
	e.d4.primed, e.d4.primeOK, e.d4.primeErr = true, ps.OK, !ps.OK
	e.d4.mu.Unlock()
	if !ps.OK && !failedBefore && e.mon != nil {
		e.mon.ev.Emit(events.ResolutionPrimingFailed, events.Error, map[string]any{"error": ps.Error})
	}
}

// fetcherFor returns the DS/DNSKEY fetcher of a resolution path.
func (e *Engine) fetcherFor(g *resolver.Group, viaRecursion bool) dnssec.Fetcher {
	if viaRecursion {
		return func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
			return e.iter.Resolve(ctx, name, qtype)
		}
	}
	return func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		q := resolver.NewQuery(name, qtype)
		dnssecQuery(q)
		start := time.Now()
		r, u, err := g.Exchange(ctx, q)
		traceForward(ctx, u, name, qtype, r, err, start)
		return r, err
	}
}

// refreshTrustAnchors runs RFC 5011 once (also POST /v1/dnssec/refresh).
func (e *Engine) refreshTrustAnchors() error {
	ctx, cancel := context.WithTimeout(e.bg, 15*time.Second)
	defer cancel()
	p := e.pol.Load()
	f := e.fetcherFor(p.group, p.s.Resolution.Mode == config.ModeRecursive)
	keys, self, err := e.val.RootKeySet(ctx, f)
	if err == nil {
		var changed bool
		changed, err = e.val.TA.Observe(keys, self)
		if err == nil && changed {
			e.val.Flush()
			e.mon.ev.Emit(events.DNSSECTrustAnchorUpdated, events.Info, map[string]any{"anchors": e.val.TA.Views()})
		}
	}
	e.d4.mu.Lock()
	if err != nil {
		e.d4.nextTA = time.Now().Add(taRetry)
	} else {
		e.d4.nextTA = time.Now().Add(taRefreshEvery)
	}
	e.d4.mu.Unlock()
	if err != nil {
		e.val.TA.SetError(err.Error())
		e.mon.ev.Emit(events.DNSSECTrustAnchorFailed, events.Error, map[string]any{"error": err.Error()})
	}
	return err
}

// ---------------------------------------------------------------- query path

// dnssecQuery asks with DO=1 and CD=1 so this resolver validates itself
// (and sees bogus data to explain it).
func dnssecQuery(q *dns.Msg) {
	if o := q.IsEdns0(); o != nil {
		o.SetDo() // SetEdns0 would add a second OPT record (FORMERR)
	} else {
		q.SetEdns0(resolver.EDNSSize, true)
	}
	q.CheckingDisabled = true
}

func traceForward(ctx context.Context, u *resolver.Upstream, name string, qtype uint16, r *dns.Msg, err error, start time.Time) {
	tr := trace.From(ctx)
	if tr == nil {
		return
	}
	s := trace.Step{Zone: ".", QName: name, QType: dns.TypeToString[qtype], RTTMS: float64(time.Since(start).Microseconds()) / 1000}
	if u != nil {
		s.Server, s.ServerName = u.Raw, u.ID
	} else {
		s.Server = "forwarders"
	}
	if err != nil {
		s.Error = err.Error()
	} else {
		s.Rcode = dns.RcodeToString[r.Rcode]
	}
	tr.Add(s)
}

// exchange resolves qname/qtype on the path of the resolution mode. It
// reports whether the answer came from the root (recursive) path.
func (e *Engine) exchange(ctx context.Context, p *policy, qname string, qtype uint16, g *resolver.Group) (*dns.Msg, *resolver.Upstream, bool, error) {
	public := g == p.group
	mode := p.s.Resolution.Mode
	if public && mode == config.ModeRecursive {
		r, err := e.iter.Resolve(ctx, qname, qtype)
		return r, nil, true, err
	}
	q := resolver.NewQuery(qname, qtype)
	if p.s.DNSSEC.Mode != config.DNSSECOff {
		dnssecQuery(q)
	}
	fctx := ctx
	if public && mode == config.ModeForwardThenRecursive {
		// leave the root path enough of the resolution time
		var cancel context.CancelFunc
		fctx, cancel = context.WithTimeout(ctx, p.d4.resolveTimeout/2)
		defer cancel()
	}
	start := time.Now()
	r, u, err := g.Exchange(fctx, q)
	traceForward(ctx, u, qname, qtype, r, err, start)
	if public && mode == config.ModeForwardThenRecursive && !errors.Is(err, resolver.ErrOverloaded) &&
		(err != nil || r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused) {
		rr, ierr := e.iter.Resolve(ctx, qname, qtype)
		if ierr == nil {
			return rr, nil, true, nil
		}
		if err == nil {
			return r, u, false, nil // pass the forwarder's own error rcode through
		}
		return nil, nil, true, ierr
	}
	return r, u, false, err
}

// localInsecure reports whether qname is answered without validation.
func (p *policy) localInsecure(qname string) bool {
	if len(p.d4.insecure) == 0 {
		return false
	}
	return wire.HasSuffix([]byte(wireName(qname)), p.d4.insecure)
}

// validate returns the DNSSEC status of a fresh upstream/recursive answer.
func (e *Engine) validate(ctx context.Context, p *policy, qname string, qtype uint16, r *dns.Msg, g *resolver.Group,
	viaRecursion bool) dnssec.Result {
	if p.s.DNSSEC.Mode == config.DNSSECOff || r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return dnssec.Result{EDE: dnssec.NoEDE}
	}
	if p.s.DNSSEC.AutoInsecureLocal && (g != p.group || p.localInsecure(qname)) {
		return dnssec.Result{State: dnssec.Insecure, EDE: dnssec.NoEDE, Reason: dnssec.ReasonLocal}
	}
	res := e.val.Validate(ctx, e.fetcherFor(g, viaRecursion), qname, qtype, r)
	e.val.Count(res.State)
	e.observeSpike(qname, res.State)
	if res.State == dnssec.Bogus {
		e.log.Debug("dnssec bogus", "name", qname, "type", dns.TypeToString[qtype], "reason", res.Reason, "detail", res.Detail)
	}
	return res
}

func secInfo(r dnssec.Result) wire.SecInfo {
	si := wire.SecInfo{State: uint8(r.State), Reason: r.Reason, Text: r.Detail}
	if r.EDE != dnssec.NoEDE {
		si.EDE, si.HasEDE = uint16(r.EDE), true
	}
	return si
}

// synthesize answers from validated NSEC ranges (RFC 8198) on a cache miss.
func (e *Engine) synthesize(p *policy, qname string, qtype uint16, g *resolver.Group) *fetchResult {
	if p.s.DNSSEC.Mode == config.DNSSECOff || !p.s.DNSSEC.AggressiveNSEC || g != p.group || p.localInsecure(qname) {
		return nil
	}
	m := e.val.Synthesize(qname, qtype)
	if m == nil {
		return nil
	}
	res := dnssec.Result{State: dnssec.Secure, EDE: dnssec.NoEDE}
	e.val.Count(dnssec.Secure)
	out := e.store(p, qname, qtype, m, res)
	return &fetchResult{msg: out, sec: secInfo(res)}
}

// stripDNSSEC removes DNSSEC records for DO=0 clients (RFC 4035 §3.2.1),
// keeping records of an explicitly asked type.
func stripDNSSEC(m *dns.Msg, qtype uint16) {
	keep := func(rrs []dns.RR, answer bool) []dns.RR {
		out := rrs[:0:0]
		for _, rr := range rrs {
			t := rr.Header().Rrtype
			switch t {
			case dns.TypeRRSIG:
				if answer && (qtype == dns.TypeRRSIG || qtype == dns.TypeANY) {
					break
				}
				continue
			case dns.TypeNSEC, dns.TypeNSEC3:
				if answer && qtype == t {
					break
				}
				if !answer {
					continue
				}
			}
			out = append(out, rr)
		}
		return out
	}
	m.Answer = keep(m.Answer, true)
	m.Ns = keep(m.Ns, false)
}

func hasDNSSECRecords(m *dns.Msg) bool {
	for _, sec := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range sec {
			switch rr.Header().Rrtype {
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
				return true
			}
		}
	}
	return false
}

func addEDE(p *policy, req, resp *dns.Msg, code uint16, text string) {
	if req.IsEdns0() == nil {
		return
	}
	o := resp.IsEdns0()
	if o == nil {
		resp.SetEdns0(uint16(p.s.Limits.UDPMaxSize), req.IsEdns0().Do())
		o = resp.IsEdns0()
	}
	for _, x := range o.Option {
		if ed, ok := x.(*dns.EDNS0_EDE); ok && ed.InfoCode == code {
			return
		}
	}
	o.Option = append(o.Option, &dns.EDNS0_EDE{InfoCode: code, ExtraText: text})
}

// present applies the DNSSEC status to a recursive answer: SERVFAIL+EDE for
// bogus (unless CD=1 or log_only), AD for secure answers to DO/AD clients.
func (e *Engine) present(p *policy, req, resp *dns.Msg, m *answerMeta) {
	sec := m.sec
	resp.AuthenticatedData = false
	if p.s.DNSSEC.Mode == config.DNSSECOff {
		return
	}
	do := req.IsEdns0() != nil && req.IsEdns0().Do()
	switch dnssec.State(sec.State) {
	case dnssec.Bogus:
		if req.CheckingDisabled || p.s.DNSSEC.Mode == config.DNSSECLogOnly {
			return
		}
		resp.Rcode = dns.RcodeServerFailure
		resp.Answer, resp.Ns, resp.Extra = nil, nil, nil
		code := sec.EDE
		if !sec.HasEDE {
			code = dns.ExtendedErrorCodeDNSBogus
		}
		addEDE(p, req, resp, code, strings.TrimSpace(sec.Reason+" "+sec.Text))
	case dnssec.Secure:
		resp.AuthenticatedData = do || req.AuthenticatedData
	case dnssec.Insecure:
		if sec.HasEDE {
			addEDE(p, req, resp, sec.EDE, strings.TrimSpace(sec.Reason+" "+sec.Text))
		}
	}
}

// secFlags maps a status to query-log flags.
func secFlags(state uint8) uint8 {
	switch dnssec.State(state) {
	case dnssec.Secure:
		return querylog.FlagSecure
	case dnssec.Bogus:
		return querylog.FlagBogus
	case dnssec.Insecure, dnssec.Indeterminate:
		return querylog.FlagInsecure
	}
	return 0
}

// observeSpike raises dnssec.bogus_spike when bogus answers exceed 100 and
// 5 % of validations within 5 minutes.
func (e *Engine) observeSpike(name string, st dnssec.State) {
	if st == dnssec.None {
		return
	}
	d := &e.d4
	d.mu.Lock()
	now := time.Now()
	if now.Sub(d.spikeFrom) > spikeWindow {
		d.spikeFrom, d.spikeTot, d.spikeBog, d.spikeSent = now, 0, 0, false
		d.spikeName = map[string]uint64{}
	}
	d.spikeTot++
	if st != dnssec.Bogus {
		d.mu.Unlock()
		return
	}
	d.spikeBog++
	if _, ok := d.spikeName[name]; ok || len(d.spikeName) < 1000 {
		d.spikeName[name]++
	}
	fire := !d.spikeSent && d.spikeBog > spikeMinBogus && d.spikeBog*100 > spikeMinPct*d.spikeTot
	var data map[string]any
	if fire {
		d.spikeSent = true
		type nc struct {
			n string
			c uint64
		}
		var l []nc
		for n, c := range d.spikeName {
			l = append(l, nc{n, c})
		}
		sort.Slice(l, func(i, j int) bool { return l[i].c > l[j].c || l[i].c == l[j].c && l[i].n < l[j].n })
		names := []string{}
		for i := 0; i < len(l) && i < 10; i++ {
			names = append(names, strings.TrimSuffix(l[i].n, "."))
		}
		data = map[string]any{"count": d.spikeBog, "names": names}
	}
	d.mu.Unlock()
	if fire && e.mon != nil {
		e.mon.ev.Emit(events.DNSSECBogusSpike, events.Warning, data)
	}
}

// ---------------------------------------------------------------- views

// PrimingView is status resolution.root_priming.
type PrimingView struct {
	OK               bool       `json:"ok"`
	At               *time.Time `json:"at"`
	ServersReachable int        `json:"servers_reachable"`
	Error            string     `json:"error,omitempty"`
}

// ResolutionStatus is status.resolution.
type ResolutionStatus struct {
	Mode              string      `json:"mode"`
	RootPriming       PrimingView `json:"root_priming"`
	InfraCacheEntries int         `json:"infra_cache_entries"`
}

// DNSSECCounters are validation counts since start.
type DNSSECCounters struct {
	Secure        uint64 `json:"secure"`
	Insecure      uint64 `json:"insecure"`
	Bogus         uint64 `json:"bogus"`
	Indeterminate uint64 `json:"indeterminate"`
}

// DNSSECStatus is status.dnssec.
type DNSSECStatus struct {
	Mode                 string              `json:"mode"`
	TrustAnchors         []dnssec.AnchorView `json:"trust_anchors"`
	TrustAnchorUpdatedAt *time.Time          `json:"trust_anchor_updated_at"`
	TrustAnchorError     string              `json:"trust_anchor_error,omitempty"`
	Counters             DNSSECCounters      `json:"counters"`
}

// DNSSECView is GET /v1/dnssec.
type DNSSECView struct {
	Mode                 string              `json:"mode"`
	TrustAnchors         []dnssec.AnchorView `json:"trust_anchors"`
	UpdatedAt            *time.Time          `json:"updated_at"`
	Error                string              `json:"error,omitempty"`
	NegativeTrustAnchors []config.NTA        `json:"negative_trust_anchors"`
	Counters             DNSSECCounters      `json:"counters"`
}

func (e *Engine) resolutionStatus(p *policy) ResolutionStatus {
	ps := e.iter.PrimeStatus()
	v := PrimingView{OK: ps.OK, ServersReachable: ps.ServersReachable, Error: ps.Error}
	if ps.Done {
		at := ps.At
		v.At = &at
	}
	return ResolutionStatus{Mode: p.s.Resolution.Mode, RootPriming: v, InfraCacheEntries: e.iter.Infra.Len()}
}

func (e *Engine) counters() DNSSECCounters {
	a, b, c, d := e.val.Counters()
	return DNSSECCounters{Secure: a, Insecure: b, Bogus: c, Indeterminate: d}
}

func (e *Engine) dnssecStatus(p *policy) DNSSECStatus {
	at, errS := e.val.TA.Status()
	st := DNSSECStatus{Mode: p.s.DNSSEC.Mode, TrustAnchors: e.val.TA.Views(), TrustAnchorError: errS, Counters: e.counters()}
	if !at.IsZero() {
		st.TrustAnchorUpdatedAt = &at
	}
	return st
}

// DNSSEC returns GET /v1/dnssec.
func (e *Engine) DNSSEC() DNSSECView {
	p := e.pol.Load()
	at, errS := e.val.TA.Status()
	v := DNSSECView{Mode: p.s.DNSSEC.Mode, TrustAnchors: e.val.TA.Views(), Error: errS,
		NegativeTrustAnchors: append([]config.NTA{}, p.s.DNSSEC.NegativeTrustAnchors...), Counters: e.counters()}
	if !at.IsZero() {
		v.UpdatedAt = &at
	}
	return v
}

// RefreshTrustAnchors runs the RFC 5011 update now (POST /v1/dnssec/refresh).
// A failure is reported in the returned view's error, like a scheduled one.
func (e *Engine) RefreshTrustAnchors() DNSSECView {
	_ = e.refreshTrustAnchors()
	return e.DNSSEC()
}

func (e *Engine) d4Gauges() []metrics.Gauge {
	a, b, c, d := e.val.Counters()
	g := []metrics.Gauge{
		{Name: "mrk_dns_infra_cache_entries", Help: "Authoritative servers known to the infra cache.", Value: float64(e.iter.Infra.Len())},
	}
	for _, x := range []struct {
		s string
		v uint64
	}{{"secure", a}, {"insecure", b}, {"bogus", c}, {"indeterminate", d}} {
		g = append(g, metrics.Gauge{Name: "mrk_dns_dnssec_validations_total", Help: "DNSSEC validations by result.",
			Labels: fmt.Sprintf("result=%q", x.s), Value: float64(x.v)})
	}
	ok := 0.0
	if e.iter.PrimeStatus().OK {
		ok = 1
	}
	g = append(g, metrics.Gauge{Name: "mrk_dns_root_priming_ok", Help: "Last root priming succeeded (1).", Value: ok})
	return g
}

// ---------------------------------------------------------------- resolve tool

// ResolveRequest is POST /v1/resolve (docs/40 §3).
type ResolveRequest struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	ClientIP string `json:"client_ip"`
	DNSSEC   *bool  `json:"dnssec"`
	CD       bool   `json:"cd"`
	Trace    bool   `json:"trace"`
	NoCache  bool   `json:"no_cache"`
}

// ResolveDNSSEC is resolve.dnssec.
type ResolveDNSSEC struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// EDEView is one extended DNS error.
type EDEView struct {
	Code uint16 `json:"code"`
	Text string `json:"text"`
}

func resolveDNSSECView(p *policy, meta answerMeta, resp *dns.Msg) ResolveDNSSEC {
	if p.s.DNSSEC.Mode == config.DNSSECOff {
		return ResolveDNSSEC{Status: "insecure", Reason: "validation_off"}
	}
	switch dnssec.State(meta.sec.State) {
	case dnssec.None:
		switch meta.src {
		case metrics.SrcAuthoritative, metrics.SrcLocal, metrics.SrcOverride:
			return ResolveDNSSEC{Status: "insecure", Reason: dnssec.ReasonLocal}
		}
		return ResolveDNSSEC{Status: "indeterminate", Reason: strings.ToLower(dns.RcodeToString[resp.Rcode])}
	default:
		return ResolveDNSSEC{Status: dnssec.State(meta.sec.State).String(), Reason: meta.sec.Reason}
	}
}

func edeViews(resp *dns.Msg) []EDEView {
	out := []EDEView{}
	if o := resp.IsEdns0(); o != nil {
		for _, x := range o.Option {
			if ed, ok := x.(*dns.EDNS0_EDE); ok {
				t := dns.ExtendedErrorCodeToString[ed.InfoCode]
				if ed.ExtraText != "" {
					t += ": " + ed.ExtraText
				}
				out = append(out, EDEView{Code: ed.InfoCode, Text: t})
			}
		}
	}
	return out
}
