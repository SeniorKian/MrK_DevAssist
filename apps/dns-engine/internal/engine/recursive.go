package engine

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/cache"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/mitigate"
	"mrk/dns-engine/internal/resolver"
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
	// resolveTimeout bounds one recursive resolution.
	resolveTimeout = 4 * time.Second
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
		if r := e.cacheOnly(p, qname, qtype); r != nil {
			copySections(resp, r)
			meta.src = metrics.SrcCache
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
		return resp, meta
	}
	copySections(resp, r)
	if m.stale {
		if opt := req.IsEdns0(); opt != nil {
			resp.SetEdns0(uint16(p.s.Limits.UDPMaxSize), false)
			o := resp.IsEdns0()
			o.Option = append(o.Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeStaleAnswer})
		}
	}
	return resp, m
}

func copySections(dst, src *dns.Msg) {
	dst.Rcode = src.Rcode
	dst.Answer = src.Answer
	dst.Ns = src.Ns
	dst.Extra = nil
}

// fromEntry renders a cache entry into a message for the question name.
func fromEntry(ent *cache.Entry, qname string, qtype uint16, now int64, stale bool) *dns.Msg {
	o := &wire.RenderOpts{Elapsed: ent.Elapsed(now), QType: qtype}
	if stale {
		o.StaleTTL = staleAnswerTTL
	}
	b := ent.T.Render(nil, o)
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return nil
	}
	_ = qname
	return m
}

func (e *Engine) cacheOnly(p *policy, qname string, qtype uint16) *dns.Msg {
	now := time.Now().UnixNano()
	if ent := e.Cache.Get(cacheKey(qname, qtype), now); ent != nil && ent.Fresh(now) {
		return fromEntry(ent, qname, qtype, now, false)
	}
	if ent := e.Cache.Get(cacheKey(qname, nxType), now); ent != nil && ent.Fresh(now) {
		return fromEntry(ent, qname, qtype, now, false)
	}
	return nil
}

// resolveCached answers from cache (fresh, then name-wide NXDOMAIN, then
// stale) or resolves upstream with single-flight.
func (e *Engine) resolveCached(ctx context.Context, p *policy, qname string, qtype uint16, g *resolver.Group, rebind bool) (*dns.Msg, answerMeta) {
	now := time.Now().UnixNano()
	key := cacheKey(qname, qtype)
	ent := e.Cache.Get(key, now)
	if ent != nil && ent.Fresh(now) {
		e.maybePrefetchName(p, ent, qname, qtype, g, rebind, now)
		return fromEntry(ent, qname, qtype, now, false), answerMeta{src: metrics.SrcCache}
	}
	if nx := e.Cache.Get(cacheKey(qname, nxType), now); nx != nil && nx.Fresh(now) {
		return fromEntry(nx, qname, qtype, now, false), answerMeta{src: metrics.SrcCache}
	}
	stale := ent != nil && p.s.Cache.ServeStale
	if stale && ent.RetryAfter.Load() > now {
		e.M.Source(metrics.SrcStale)
		return fromEntry(ent, qname, qtype, now, true), answerMeta{src: metrics.SrcCache, stale: true}
	}
	if stale && e.acts().PreferStale {
		// pressure action prefer_stale: answer stale now, refresh in the background
		if ent.Refreshing.CompareAndSwap(false, true) {
			e.prefetch(p, ent, qname, qtype, g, rebind)
		}
		e.M.Source(metrics.SrcStale)
		return fromEntry(ent, qname, qtype, now, true), answerMeta{src: metrics.SrcCache, stale: true}
	}
	if x := e.mon.mit.Index(); x.HasDomains() {
		// domain throttles cap upstream work only: cached answers above are always served
		if l := x.Domain(key[:len(key)-2]); l != nil && l.Action == mitigate.DoThrottle && !l.Hit(now) {
			e.M.Drop(metrics.DropMitigation)
			if stale {
				return fromEntry(ent, qname, qtype, now, true), answerMeta{src: metrics.SrcCache, stale: true}
			}
			return nil, answerMeta{src: metrics.SrcMitigated, mitigated: true}
		}
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
			return fr.msg, answerMeta{src: metrics.SrcUpstream, upstream: fr.upstream}
		}
		if stale {
			ent.RetryAfter.Store(time.Now().Add(staleRetry).UnixNano())
			return fromEntry(ent, qname, qtype, time.Now().UnixNano(), true), answerMeta{src: metrics.SrcCache, stale: true}
		}
		return nil, answerMeta{src: metrics.SrcError}
	case <-timer:
		return fromEntry(ent, qname, qtype, time.Now().UnixNano(), true), answerMeta{src: metrics.SrcCache, stale: true}
	case <-ctx.Done():
		if stale {
			return fromEntry(ent, qname, qtype, time.Now().UnixNano(), true), answerMeta{src: metrics.SrcCache, stale: true}
		}
		return nil, answerMeta{src: metrics.SrcError}
	}
}

type fetchResult struct {
	msg      *dns.Msg
	upstream string
}

var errUpstreamFailed = errors.New("upstream resolution failed")

// fetch resolves upstream, scrubs, filters, caches and returns the answer.
// It runs detached from any one client's context.
func (e *Engine) fetch(p *policy, qname string, qtype uint16, g *resolver.Group, rebind bool) (*fetchResult, error) {
	ctx, cancel := context.WithTimeout(e.bg, resolveTimeout)
	defer cancel()
	q := resolver.NewQuery(qname, qtype)
	e.M.Inflight.Add(1)
	r, u, err := g.Exchange(ctx, q)
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
			e.store(p, qname, qtype, fail)
		}
		return nil, errUpstreamFailed
	}
	scrub(r, qname, qtype)
	if rebind && rebindFilter(r) {
		e.M.Rebinding.Add(1)
	}
	m := e.store(p, qname, qtype, r)
	res := &fetchResult{msg: m}
	if u != nil {
		res.upstream = u.ID
	}
	if r.Rcode == dns.RcodeServerFailure {
		return nil, errUpstreamFailed // lets callers fall back to a stale answer
	}
	return res, nil
}

// scrub keeps only the CNAME chain for qname and, for negative answers, the
// SOA: no additional data, no NS — minimal responses limit cache poisoning.
func scrub(r *dns.Msg, qname string, qtype uint16) {
	chain := map[string]bool{qname: true}
	var ans []dns.RR
	name := qname
	for i := 0; i < 16; i++ {
		var next string
		for _, rr := range r.Answer {
			h := rr.Header()
			if h.Class != dns.ClassINET || !strings.EqualFold(h.Name, name) {
				continue
			}
			if h.Rrtype == qtype || qtype == dns.TypeANY {
				ans = append(ans, rr)
			} else if h.Rrtype == dns.TypeCNAME {
				ans = append(ans, rr)
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
			for n := range chain {
				if dns.IsSubDomain(strings.ToLower(rr.Header().Name), n) && n != strings.ToLower(rr.Header().Name) {
					ans = append([]dns.RR{rr}, ans...)
					break
				}
			}
		}
	}
	r.Answer = ans
	var ns []dns.RR
	if len(ans) == 0 || r.Rcode == dns.RcodeNameError {
		for _, rr := range r.Ns {
			if rr.Header().Rrtype == dns.TypeSOA && dns.IsSubDomain(strings.ToLower(rr.Header().Name), name) {
				ns = append(ns, rr)
				break
			}
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

// store caches r (TTL policy per settings) and returns the message to serve.
func (e *Engine) store(p *policy, qname string, qtype uint16, r *dns.Msg) *dns.Msg {
	c := p.s.Cache
	m := new(dns.Msg)
	m.MsgHdr = r.MsgHdr
	m.Id = 0
	m.Question = []dns.Question{{Name: qname, Qtype: qtype, Qclass: dns.ClassINET}}
	m.Answer, m.Ns = r.Answer, r.Ns
	m.Compress = true
	packed, err := m.Pack()
	if err != nil {
		return m
	}
	t, err := wire.NewTemplate(packed)
	if err != nil {
		return m
	}
	var ttl, stale uint32
	negative := false
	switch {
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
		t.ClampTTLs(ttl, ttl)
		stale = c.StaleTTL
	case r.Rcode == dns.RcodeSuccess:
		t.ClampTTLs(c.MinTTL, c.MaxTTL)
		ttl = t.MinTTL
		stale = c.StaleTTL
	default:
		return m // REFUSED/NOTIMP etc. are not cached
	}
	if !c.ServeStale {
		stale = 0
	}
	if ttl == 0 && stale == 0 {
		return m
	}
	now := time.Now().UnixNano()
	ent := e.Cache.Put(cacheKey(qname, qtype), qname, t, ttl, stale, negative, now)
	if r.Rcode == dns.RcodeNameError {
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
