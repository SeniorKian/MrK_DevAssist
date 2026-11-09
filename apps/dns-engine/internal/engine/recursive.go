package engine

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/cache"
	"mrk/dns-engine/internal/dnssec"
	"mrk/dns-engine/internal/iterative"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/mitigate"
	"mrk/dns-engine/internal/resolver"
	"mrk/dns-engine/internal/trace"
	"mrk/dns-engine/internal/wire"
)

const (
	// staleAnswerTTL is the TTL of stale answers (RFC 8767 §4 recommends 30 s).
	staleAnswerTTL = 30
	// staleRetry is the failure-recheck timer after a failed refresh.
	staleRetry = 30 * time.Second
	// clientResponseTimer: how long to wait for a refresh before answering stale.
	clientResponseTimer = 1800 * time.Millisecond
	// failureTTL caches upstream SERVFAIL (RFC 2308 §7.1 allows up to 5 min).
	failureTTL = 5
	// noSOANegativeTTL applies to negative answers without SOA.
	noSOANegativeTTL = 60
	// prefetchMinTTL is the minimum original TTL for prefetch eligibility.
	prefetchMinTTL = 10
)

// nxType is the cache key type of a name-wide NXDOMAIN entry (RFC 2308 §5).
const nxType = 0

func cacheKey(qname string, qtype uint16) []byte {
	buf := make([]byte, 0, wire.MaxKey)
	return wire.AppendKey(buf, []byte(wireName(qname)), qtype)
}

// recurse fills resp from cache/upstream for qname/qtype.
func (e *Engine) recurse(ctx context.Context, p *policy, req, resp *dns.Msg, qname string, qtype uint16, g *resolver.Group, rebind bool) (*dns.Msg, answerMeta) {
	meta := answerMeta{src: metrics.SrcUpstream}
	if !req.RecursionDesired {
		// RD=0: cache only (RFC 1034 §4.3.1), never trigger resolution
		if r, sec := e.cacheOnly(p, qname, qtype); r != nil {
			copySections(resp, r)
			meta.src = metrics.SrcCache
			meta.sec = sec
			e.present(p, req, resp, &meta)
			return resp, meta
		}
		resp.Rcode = dns.RcodeRefused
		meta.src = metrics.SrcRefused
		return resp, meta
	}
	r, m := e.resolveCached(ctx, p, qname, qtype, g, rebind)
	if r == nil && m.mitigated {
		resp.Rcode = dns.RcodeRefused
		meta.src = metrics.SrcMitigated
		return resp, meta
	}
	if r == nil {
		resp.Rcode = dns.RcodeServerFailure
		meta.src = metrics.SrcError
		if m.ede != 0 {
			addEDE(p, req, resp, m.ede, "")
		}
		return resp, meta
	}
	copySections(resp, r)
	if m.stale {
		if opt := req.IsEdns0(); opt != nil {
			resp.SetEdns0(uint16(p.s.Limits.UDPMaxSize), opt.Do())
			o := resp.IsEdns0()
			o.Option = append(o.Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeStaleAnswer})
		}
	}
	e.present(p, req, resp, &m)
	return resp, m
}

func copySections(dst, src *dns.Msg) {
	dst.Rcode = src.Rcode
	dst.Answer = src.Answer
	dst.Ns = src.Ns
	dst.Extra = nil
}

// fromEntry renders a cache entry (the variant with DNSSEC records; finish
// strips them for DO=0 clients) into a message for the question name.
func fromEntry(ent *cache.Entry, qname string, qtype uint16, now int64, stale bool) *dns.Msg {
	o := &wire.RenderOpts{Elapsed: ent.Elapsed(now), QType: qtype}
	if stale {
		o.StaleTTL = staleAnswerTTL
	}
	t := ent.T
	if t.DNSSEC != nil {
		t = t.DNSSEC
	}
	b := t.Render(nil, o)
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return nil
	}
	_ = qname
	return m
}

func (e *Engine) cacheOnly(p *policy, qname string, qtype uint16) (*dns.Msg, wire.SecInfo) {
	now := time.Now().UnixNano()
	if ent := e.Cache.Get(cacheKey(qname, qtype), now); ent != nil && ent.Fresh(now) {
		return fromEntry(ent, qname, qtype, now, false), ent.T.Sec
	}
	if ent := e.Cache.Get(cacheKey(qname, nxType), now); ent != nil && ent.Fresh(now) {
		return fromEntry(ent, qname, qtype, now, false), ent.T.Sec
	}
	return nil, wire.SecInfo{}
}

func cachedMeta(ent *cache.Entry, stale bool) answerMeta {
	return answerMeta{src: metrics.SrcCache, stale: stale, sec: ent.T.Sec}
}

// resolveCached answers from cache (fresh, then name-wide NXDOMAIN, then
// stale) or resolves upstream with single-flight.
func (e *Engine) resolveCached(ctx context.Context, p *policy, qname string, qtype uint16, g *resolver.Group, rebind bool) (*dns.Msg, answerMeta) {
	if trace.NoCache(ctx) {
		// POST /v1/resolve no_cache/trace: bypass the cache and single-flight
		fctx, cancel := context.WithTimeout(ctx, p.d4.resolveTimeout)
		defer cancel()
		fr, err := e.fetchCtx(fctx, p, qname, qtype, g, rebind)
		if err != nil {
			m := answerMeta{src: metrics.SrcError}
			if fr != nil {
				m.ede = fr.ede
				if fr.msg != nil {
					return fr.msg, fr.meta() // the upstream's own SERVFAIL
				}
			}
			return nil, m
		}
		return fr.msg, fr.meta()
	}
	now := time.Now().UnixNano()
	key := cacheKey(qname, qtype)
	ent := e.Cache.Get(key, now)
	if ent != nil && ent.Fresh(now) {
		e.maybePrefetchName(p, ent, qname, qtype, g, rebind, now)
		return fromEntry(ent, qname, qtype, now, false), cachedMeta(ent, false)
	}
	if nx := e.Cache.Get(cacheKey(qname, nxType), now); nx != nil && nx.Fresh(now) {
		return fromEntry(nx, qname, qtype, now, false), cachedMeta(nx, false)
	}
	stale := ent != nil && p.s.Cache.ServeStale && dnssec.State(ent.T.Sec.State) != dnssec.Bogus
	if stale && ent.RetryAfter.Load() > now {
		e.M.Source(metrics.SrcStale)
		return fromEntry(ent, qname, qtype, now, true), cachedMeta(ent, true)
	}
	if stale && e.acts().PreferStale {
		// pressure action prefer_stale: answer stale now, refresh in the background
		if ent.Refreshing.CompareAndSwap(false, true) {
			e.prefetch(p, ent, qname, qtype, g, rebind)
		}
		e.M.Source(metrics.SrcStale)
		return fromEntry(ent, qname, qtype, now, true), cachedMeta(ent, true)
	}
	if x := e.mon.mit.Index(); x.HasDomains() {
		// domain throttles cap upstream work only: cached answers above are always served
		if l := x.Domain(key[:len(key)-2]); l != nil && l.Action == mitigate.DoThrottle && !l.Hit(now) {
			e.M.Drop(metrics.DropMitigation)
			if stale {
				return fromEntry(ent, qname, qtype, now, true), cachedMeta(ent, true)
			}
			return nil, answerMeta{src: metrics.SrcMitigated, mitigated: true}
		}
	}
	if fr := e.synthesize(p, qname, qtype, g); fr != nil {
		return fr.msg, answerMeta{src: metrics.SrcCache, sec: fr.sec}
	}
	ch := e.flight.DoChan(string(key), func() (any, error) {
		return e.fetch(p, qname, qtype, g, rebind)
	})
	var timer <-chan time.Time
	if stale {
		t := time.NewTimer(clientResponseTimer)
		defer t.Stop()
		timer = t.C
	}
	select {
	case res := <-ch:
		if res.Err == nil {
			fr := res.Val.(*fetchResult)
			return fr.msg, fr.meta()
		}
		if stale {
			ent.RetryAfter.Store(time.Now().Add(staleRetry).UnixNano())
			return fromEntry(ent, qname, qtype, time.Now().UnixNano(), true), cachedMeta(ent, true)
		}
		m := answerMeta{src: metrics.SrcError}
		if fr, ok := res.Val.(*fetchResult); ok && fr != nil {
			m.ede = fr.ede
		}
		return nil, m
	case <-timer:
		return fromEntry(ent, qname, qtype, time.Now().UnixNano(), true), cachedMeta(ent, true)
	case <-ctx.Done():
		if stale {
			return fromEntry(ent, qname, qtype, time.Now().UnixNano(), true), cachedMeta(ent, true)
		}
		return nil, answerMeta{src: metrics.SrcError}
	}
}

type fetchResult struct {
	msg       *dns.Msg
	upstream  string
	recursive bool
	sec       wire.SecInfo
	ede       uint16 // extended error of a failed resolution (RFC 8914)
}

func (fr *fetchResult) meta() answerMeta {
	m := answerMeta{src: metrics.SrcUpstream, upstream: fr.upstream, sec: fr.sec}
	if fr.recursive {
		m.src = metrics.SrcRecursive
	}
	return m
}

var errUpstreamFailed = errors.New("upstream resolution failed")

// fetch resolves upstream, scrubs, filters, caches and returns the answer.
// It runs detached from any one client's context.
func (e *Engine) fetch(p *policy, qname string, qtype uint16, g *resolver.Group, rebind bool) (*fetchResult, error) {
	ctx, cancel := context.WithTimeout(e.bg, p.d4.resolveTimeout)
	defer cancel()
	return e.fetchCtx(ctx, p, qname, qtype, g, rebind)
}

// fetchCtx resolves on the configured path (forwarders, root or both),
// validates, scrubs, filters and caches.
func (e *Engine) fetchCtx(ctx context.Context, p *policy, qname string, qtype uint16, g *resolver.Group, rebind bool) (*fetchResult, error) {
	e.M.Inflight.Add(1)
	r, u, viaRec, err := e.exchange(ctx, p, qname, qtype, g)
	e.M.Inflight.Add(-1)
	if err != nil {
		if errors.Is(err, resolver.ErrOverloaded) {
			e.M.Drop(metrics.DropOverload)
		}
		if !errors.Is(err, resolver.ErrOverloaded) {
			// cache the failure briefly so a dead upstream is not hammered
			fail := new(dns.Msg)
			fail.SetQuestion(qname, qtype)
			fail.Response = true
			fail.Rcode = dns.RcodeServerFailure
			e.store(p, qname, qtype, fail, dnssec.Result{EDE: dnssec.NoEDE})
		}
		fr := &fetchResult{recursive: viaRec}
		if viaRec && (errors.Is(err, iterative.ErrNoReachable) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, iterative.ErrTimeout)) {
			fr.ede = dns.ExtendedErrorCodeNoReachableAuthority
		}
		return fr, errUpstreamFailed
	}
	sec := e.validate(ctx, p, qname, qtype, r, g, viaRec)
	scrub(r, qname, qtype)
	if rebind && rebindFilter(r) {
		e.M.Rebinding.Add(1)
	}
	m := e.store(p, qname, qtype, r, sec)
	res := &fetchResult{msg: m, recursive: viaRec, sec: secInfo(sec)}
	if u != nil {
		res.upstream = u.ID
	}
	if r.Rcode == dns.RcodeServerFailure {
		return res, errUpstreamFailed // lets callers fall back to a stale answer
	}
	return res, nil
}

func sigKey(owner string, t uint16) string {
	return strings.ToLower(owner) + "|" + strconv.Itoa(int(t))
}

// scrub keeps only the CNAME chain for qname (with its signatures) and, for
// negative or wildcard answers, the SOA and the NSEC/NSEC3 proof: no
// additional data, no NS — minimal responses limit cache poisoning.
func scrub(r *dns.Msg, qname string, qtype uint16) {
	chain := map[string]bool{qname: true}
	signed := map[string]bool{} // owner|type of kept RRsets
	var ans []dns.RR
	name := qname
	final := false
	for i := 0; i < 16; i++ {
		var next string
		for _, rr := range r.Answer {
			h := rr.Header()
			if h.Class != dns.ClassINET || !strings.EqualFold(h.Name, name) {
				continue
			}
			if h.Rrtype == dns.TypeRRSIG && qtype != dns.TypeRRSIG {
				continue
			}
			if h.Rrtype == qtype || qtype == dns.TypeANY {
				ans = append(ans, rr)
				signed[sigKey(name, h.Rrtype)] = true
				final = true
			} else if h.Rrtype == dns.TypeCNAME {
				ans = append(ans, rr)
				signed[sigKey(name, dns.TypeCNAME)] = true
				next = strings.ToLower(rr.(*dns.CNAME).Target)
			}
		}
		if next == "" || chain[next] {
			break
		}
		chain[next] = true
		name = next
	}
	// keep DNAMEs that synthesised a chain link
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeDNAME {
			owner := strings.ToLower(rr.Header().Name)
			for n := range chain {
				if dns.IsSubDomain(owner, n) && n != owner {
					ans = append([]dns.RR{rr}, ans...)
					signed[sigKey(owner, dns.TypeDNAME)] = true
					break
				}
			}
		}
	}
	wildcard := false
	if qtype != dns.TypeRRSIG {
		for _, rr := range r.Answer {
			sig, ok := rr.(*dns.RRSIG)
			if !ok || !signed[sigKey(sig.Hdr.Name, sig.TypeCovered)] {
				continue
			}
			ans = append(ans, rr)
			labels := dns.CountLabel(sig.Hdr.Name)
			if strings.HasPrefix(sig.Hdr.Name, "*.") {
				labels--
			}
			if int(sig.Labels) < labels {
				wildcard = true
			}
		}
	}
	r.Answer = ans
	var ns []dns.RR
	if len(ans) == 0 || r.Rcode == dns.RcodeNameError || !final || wildcard {
		soa := false
		var denial []dns.RR
		for _, rr := range r.Ns {
			switch rr.Header().Rrtype {
			case dns.TypeSOA:
				if !soa && dns.IsSubDomain(strings.ToLower(rr.Header().Name), name) {
					ns = append(ns, rr)
					soa = true
				}
			case dns.TypeNSEC, dns.TypeNSEC3:
				denial = append(denial, rr)
			case dns.TypeRRSIG:
				switch rr.(*dns.RRSIG).TypeCovered {
				case dns.TypeSOA:
					ns = append(ns, rr)
				case dns.TypeNSEC, dns.TypeNSEC3:
					denial = append(denial, rr)
				}
			}
		}
		if wildcard && !(len(ans) == 0 || r.Rcode == dns.RcodeNameError || !final) {
			ns = denial // positive wildcard answer: only the proof
		} else if soa {
			ns = append(ns, denial...)
		} else {
			ns = nil // denial records without the SOA are of no use
		}
	}
	r.Ns = ns
	r.Extra = nil
	r.AuthenticatedData = false
}

// rebindFilter removes private addresses from a public name's answer
// (DNS rebinding protection). It reports whether anything was removed.
func rebindFilter(r *dns.Msg) bool {
	removed := false
	out := r.Answer[:0]
	for _, rr := range r.Answer {
		var a netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			a, _ = netip.AddrFromSlice(v.A)
		case *dns.AAAA:
			a, _ = netip.AddrFromSlice(v.AAAA)
		}
		if a.IsValid() && acl.Private(a) {
			removed = true
			continue
		}
		out = append(out, rr)
	}
	r.Answer = out
	return removed
}

func packTemplate(m *dns.Msg) (*wire.Template, error) {
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	return wire.NewTemplate(packed)
}

// store caches r (TTL policy per settings, DNSSEC status sec) and returns
// the message to serve.
func (e *Engine) store(p *policy, qname string, qtype uint16, r *dns.Msg, sec dnssec.Result) *dns.Msg {
	c := p.s.Cache
	m := new(dns.Msg)
	m.MsgHdr = r.MsgHdr
	m.Id = 0
	m.AuthenticatedData, m.CheckingDisabled = false, false
	m.Question = []dns.Question{{Name: qname, Qtype: qtype, Qclass: dns.ClassINET}}
	m.Answer, m.Ns = r.Answer, r.Ns
	m.Compress = true
	full, err := packTemplate(m)
	if err != nil {
		return m
	}
	t := full
	if hasDNSSECRecords(m) {
		plain := m.Copy()
		stripDNSSEC(plain, qtype)
		plain.Compress = true
		pt, err := packTemplate(plain)
		if err != nil {
			return m
		}
		pt.DNSSEC = full
		t = pt
	}
	si := secInfo(sec)
	t.Sec, full.Sec = si, si
	clamp := func(lo, hi uint32) {
		t.ClampTTLs(lo, hi)
		if t.DNSSEC != nil {
			t.DNSSEC.ClampTTLs(lo, hi)
		}
	}
	maxTTL := c.MaxTTL
	if sec.MaxTTL > 0 && sec.MaxTTL < maxTTL {
		maxTTL = sec.MaxTTL // never beyond the signature expiration
	}
	var ttl, stale uint32
	negative := false
	bogus := sec.State == dnssec.Bogus
	switch {
	case bogus:
		ttl = uint32(p.s.DNSSEC.BogusTTL)
		if ttl == 0 {
			return m
		}
		clamp(ttl, ttl)
	case r.Rcode == dns.RcodeServerFailure:
		// never replace a usable (possibly stale) answer with a failure
		if old := e.Cache.Get(cacheKey(qname, qtype), time.Now().UnixNano()); old != nil && old.T.Rcode != dns.RcodeServerFailure {
			return m
		}
		ttl = failureTTL
	case r.Rcode == dns.RcodeNameError || (r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0):
		negative = true
		ttl = noSOANegativeTTL
		for _, rr := range r.Ns {
			if s, ok := rr.(*dns.SOA); ok {
				ttl = s.Hdr.Ttl
				if s.Minttl < ttl {
					ttl = s.Minttl // RFC 2308 §5
				}
			}
		}
		if ttl > c.NegativeMaxTTL {
			ttl = c.NegativeMaxTTL
		}
		if ttl > maxTTL {
			ttl = maxTTL
		}
		clamp(ttl, ttl)
		stale = c.StaleTTL
	case r.Rcode == dns.RcodeSuccess:
		clamp(c.MinTTL, maxTTL)
		ttl = t.MinTTL
		if t.DNSSEC != nil && t.DNSSEC.MinTTL < ttl {
			ttl = t.DNSSEC.MinTTL
		}
		stale = c.StaleTTL
	default:
		return m // REFUSED/NOTIMP etc. are not cached
	}
	if !c.ServeStale || bogus {
		stale = 0
	}
	if ttl == 0 && stale == 0 {
		return m
	}
	now := time.Now().UnixNano()
	ent := e.Cache.Put(cacheKey(qname, qtype), qname, t, ttl, stale, negative, now)
	if r.Rcode == dns.RcodeNameError && !bogus {
		e.Cache.Put(cacheKey(qname, nxType), qname, t, ttl, stale, true, now)
	}
	if ent != nil {
		if out := fromEntry(ent, qname, qtype, now, false); out != nil {
			return out
		}
	}
	return m
}

func (e *Engine) prefetchDue(p *policy, ent *cache.Entry, now int64) bool {
	if !p.s.Cache.Prefetch || e.acts().DisablePrefetch || ent.Negative || ent.OrigTTL < prefetchMinTTL || ent.Hits.Load() < 2 {
		return false
	}
	return uint64(ent.Remaining(now))*10 < uint64(ent.OrigTTL)
}

// maybePrefetch is the fast-path variant (name taken from the packet).
func (e *Engine) maybePrefetch(p *policy, ent *cache.Entry, pkt []byte, q *wire.Query, now int64) {
	if !e.prefetchDue(p, ent, now) || !ent.Refreshing.CompareAndSwap(false, true) {
		return
	}
	name, _, err := dns.UnpackDomainName(pkt, wire.HeaderSz)
	if err != nil {
		ent.Refreshing.Store(false)
		return
	}
	e.prefetch(p, ent, strings.ToLower(name), q.QType, p.group, p.s.RebindingProtection)
}

func (e *Engine) maybePrefetchName(p *policy, ent *cache.Entry, qname string, qtype uint16, g *resolver.Group, rebind bool, now int64) {
	if !e.prefetchDue(p, ent, now) || !ent.Refreshing.CompareAndSwap(false, true) {
		return
	}
	e.prefetch(p, ent, qname, qtype, g, rebind)
}

func (e *Engine) prefetch(p *policy, ent *cache.Entry, qname string, qtype uint16, g *resolver.Group, rebind bool) {
	e.M.Prefetches.Add(1)
	go func() {
		defer ent.Refreshing.Store(false)
		_, _, _ = e.flight.Do(string(cacheKey(qname, qtype)), func() (any, error) {
			return e.fetch(p, qname, qtype, g, rebind)
		})
	}()
}
