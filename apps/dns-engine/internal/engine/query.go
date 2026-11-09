package engine

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/dnssec"
	"mrk/dns-engine/internal/limits"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/querylog"
	"mrk/dns-engine/internal/tokens"
	"mrk/dns-engine/internal/wire"
)

// Proto identifies the transport of a query.
type Proto int

// Transports.
const (
	UDP Proto = iota
	TCP
	API
)

func (p Proto) String() string {
	switch p {
	case UDP:
		return "udp"
	case TCP:
		return "tcp"
	case DoT:
		return "dot"
	case DoH:
		return "doh"
	case DoQ:
		return "doq"
	}
	return "api"
}

// Scratch holds per-worker buffers for the fast path (not shared).
type Scratch struct {
	Key [wire.MaxKey + 8]byte
	Out []byte
	// Shard selects the statistics / query-log shard of this worker.
	Shard uint32
}

// NewScratch allocates worker buffers.
func NewScratch() *Scratch { return &Scratch{Out: make([]byte, 0, 4096), Shard: scratchCtr.Add(1)} }

// Verdict of the fast path.
type Verdict int

// Fast-path outcomes.
const (
	Reply         Verdict = iota // send the returned bytes
	DropIt                       // send nothing
	Slow                         // run Slow (on a worker); admission was already checked
	SlowUnchecked                // run Slow; admission (ACL/limits) not yet checked
)

// Fast handles the common cases without decoding into dns.Msg: admission
// (ACL, client rate limit) and fresh cache hits. The returned slice aliases
// sc.Out.
func (e *Engine) Fast(pkt []byte, client netip.Addr, proto Proto, sc *Scratch) ([]byte, Verdict) {
	q, ok := wire.ParseQuery(pkt, sc.Key[:0])
	if !ok {
		return nil, SlowUnchecked
	}
	now := time.Now().UnixNano()
	p := e.pol.Load()
	if proto == UDP {
		e.M.QueriesUDP.Add(1)
	} else {
		e.M.QueriesTCP.Add(1)
	}
	udpMax := p.s.Limits.UDPMaxSize
	name := q.Key[:len(q.Key)-2]
	if !p.admit(client, proto) {
		return e.fastRefuse(p, pkt, &q, name, client, proto, sc, udpMax, now, querylog.SrcRefused)
	}
	// docs/38 §3 order: ACL, mitigation, rate limit, the rest
	if x := e.mon.mit.Index(); !x.Empty() {
		if out, v, done := e.fastMitigate(x, pkt, &q, name, client, proto, sc, udpMax, now); done {
			return out, v
		}
	}
	if !p.clientLim.Allow(client, now) {
		e.M.Drop(metrics.DropClientLimit)
		if proto == UDP {
			e.M.Source(metrics.SrcRateLimited)
			e.record(sc.Shard, now, client, proto, q.QType, name, dns.RcodeRefused, querylog.SrcRateLimited, 0, 0, "")
			return nil, DropIt
		}
		return e.fastRefuse(p, pkt, &q, name, client, proto, sc, udpMax, now, querylog.SrcRateLimited)
	}
	if !p.recursionFor(client, proto, false) || e.heavyClient(client) {
		if p.zones.Len() == 0 && !wire.HasSuffix(name, p.local) {
			src := querylog.SrcRefused
			if p.recursionFor(client, proto, false) {
				src = querylog.SrcMitigated // refuse_heavy_clients
			}
			return e.fastRefuse(p, pkt, &q, name, client, proto, sc, udpMax, now, src)
		}
		return nil, Slow
	}
	if !q.RD() || q.QType == dns.TypeANY || q.QType == dns.TypeAXFR || q.QType == dns.TypeIXFR ||
		wire.HasSuffix(name, p.local) {
		return nil, Slow
	}
	ent := e.Cache.Get(q.Key, now)
	if ent == nil || !ent.Fresh(now) {
		return nil, Slow
	}
	t := ent.T
	validating := p.s.DNSSEC.Mode != config.DNSSECOff
	if validating && dnssec.State(t.Sec.State) == dnssec.Bogus || t.Sec.HasEDE {
		return nil, Slow // SERVFAIL+EDE or EDE options are built on the full path
	}
	if q.DO && t.DNSSEC != nil {
		t = t.DNSSEC
	}
	ad := validating && dnssec.State(t.Sec.State) == dnssec.Secure && (q.DO || q.Flags&wire.FlagAD != 0)
	maxSize := 65535
	if proto == UDP {
		maxSize = wire.ClientUDPSize(&q, udpMax)
	}
	out := t.Render(sc.Out, &wire.RenderOpts{ID: q.ID, ReqFlags: q.Flags, QName: q.QName(pkt),
		Elapsed: ent.Elapsed(now), EDNS: q.HasEDNS, UDPSize: uint16(udpMax), DO: q.DO, AD: ad, MaxSize: maxSize})
	sc.Out = out[:0]
	e.M.Source(metrics.SrcCache)
	e.M.Rcode(t.Rcode)
	flags := querylog.FlagCached | secFlags(t.Sec.State)
	if proto == UDP && len(out) > 0 && out[2]&0x02 != 0 {
		e.M.Truncated.Add(1)
		flags |= querylog.FlagTC
	}
	e.record(sc.Shard, now, client, proto, q.QType, name, ent.T.Rcode, querylog.SrcCache, len(out), flags, "")
	e.maybePrefetch(p, ent, pkt, &q, now)
	return out, Reply
}

func (e *Engine) fastRefuse(p *policy, pkt []byte, q *wire.Query, name []byte, client netip.Addr, proto Proto, sc *Scratch,
	udpMax int, start int64, src uint8) ([]byte, Verdict) {
	e.M.Source(metrics.SrcRefused)
	e.M.Rcode(dns.RcodeRefused)
	if proto == UDP && !p.recACL.Allowed(client) {
		switch p.rrl.Check(client, limits.ClassHash("refused"), time.Now().UnixNano()) {
		case limits.Drop:
			e.M.Drop(metrics.DropRRL)
			e.record(sc.Shard, start, client, proto, q.QType, name, dns.RcodeRefused, querylog.SrcRateLimited, 0, 0, "")
			return nil, DropIt
		case limits.Slip:
			e.M.RRLSlips.Add(1)
			out := wire.TruncatedResponse(sc.Out, pkt, q, uint16(udpMax))
			sc.Out = out[:0]
			e.record(sc.Shard, start, client, proto, q.QType, name, dns.RcodeRefused, querylog.SrcRateLimited, len(out), querylog.FlagTC, "")
			return out, Reply
		}
	}
	out := wire.ErrorResponse(sc.Out, pkt, q, dns.RcodeRefused, false, uint16(udpMax))
	sc.Out = out[:0]
	e.record(sc.Shard, start, client, proto, q.QType, name, dns.RcodeRefused, src, len(out), 0, "")
	return out, Reply
}

// Slow fully decodes and answers pkt. It returns nil to drop.
func (e *Engine) Slow(ctx context.Context, pkt []byte, client netip.Addr, proto Proto, checked bool) []byte {
	return e.slow(ctx, pkt, client, proto, checked, nil)
}

// slow is Slow; tok is the DoH token admitting the client (SlowToken).
func (e *Engine) slow(ctx context.Context, pkt []byte, client netip.Addr, proto Proto, checked bool, tok *tokens.Token) []byte {
	start := time.Now()
	if len(pkt) < 12 || pkt[2]&0x80 != 0 { // too short or a response: never answer
		e.M.Drop(metrics.DropMalformed)
		return nil
	}
	p := e.pol.Load()
	if !checked {
		if proto == UDP {
			e.M.QueriesUDP.Add(1)
		} else {
			e.M.QueriesTCP.Add(1)
		}
	}
	req := new(dns.Msg)
	if err := req.Unpack(pkt); err != nil {
		e.M.Drop(metrics.DropMalformed)
		if !checked && tok == nil && !p.admit(client, proto) {
			return nil
		}
		// FORMERR with the header only (RFC 1035 §4.1.1)
		out := make([]byte, 12)
		copy(out, pkt[:2])
		out[2] = 0x80 | pkt[2]&0x79 // QR + opcode + RD
		out[3] = dns.RcodeFormatError
		e.M.Rcode(dns.RcodeFormatError)
		return out
	}
	tag := ""
	if tok != nil {
		tag = tok.Tag()
		tok.Used(start)
	}
	if !checked {
		if tok == nil && !p.admit(client, proto) {
			resp := refused(req)
			return e.finish(p, req, resp, client, proto, answerMeta{src: metrics.SrcRefused}, start)
		}
		if resp, drop, ok := e.slowMitigate(req, client, proto); ok {
			if drop {
				e.recordMsg(req, client, proto, start, dns.RcodeRefused, querylog.SrcMitigated, 0, 0, tag)
				return nil
			}
			return e.finish(p, req, resp, client, proto, answerMeta{src: metrics.SrcMitigated, upstream: tag}, start)
		}
		if tok != nil {
			if !tok.Allow(start.UnixNano()) {
				return e.tokenLimited(p, req, client, proto, tok, start)
			}
		} else if !p.clientLim.Allow(client, time.Now().UnixNano()) {
			e.M.Drop(metrics.DropClientLimit)
			if proto == UDP {
				e.M.Source(metrics.SrcRateLimited)
				e.recordMsg(req, client, proto, start, dns.RcodeRefused, querylog.SrcRateLimited, 0, 0, "")
				return nil
			}
			return e.finish(p, req, refused(req), client, proto, answerMeta{src: metrics.SrcRateLimited}, start)
		}
	}
	resp, meta := e.answer(ctx, p, req, client, proto)
	if resp == nil {
		return nil
	}
	if tag != "" {
		meta.upstream = tag // docs/40 §4: the token id replaces the upstream
	}
	return e.finish(p, req, resp, client, proto, meta, start)
}

// recordMsg records a decoded query (slow path).
func (e *Engine) recordMsg(req *dns.Msg, client netip.Addr, proto Proto, start time.Time, rcode int, src uint8, size int,
	flags uint8, upstream string) {
	if len(req.Question) != 1 {
		return
	}
	var nb [256]byte
	name := lowerWire(req.Question[0].Name, nb[:])
	e.record(slowShard(), start.UnixNano(), client, proto, req.Question[0].Qtype, name, rcode, src, size, flags, upstream)
}

func refused(req *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(req, dns.RcodeRefused)
	r.RecursionAvailable = false
	return r
}

// finish applies EDNS, truncation and RRL, then packs and records.
func (e *Engine) finish(p *policy, req, resp *dns.Msg, client netip.Addr, proto Proto, meta answerMeta, start time.Time) []byte {
	src := meta.src
	udpMax := p.s.Limits.UDPMaxSize
	size := 65535
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
		if resp.IsEdns0() == nil {
			resp.SetEdns0(uint16(udpMax), do)
		}
		if proto == UDP {
			size = int(opt.UDPSize())
			if size < 512 {
				size = 512
			}
			if size > udpMax {
				size = udpMax
			}
		}
	} else if proto == UDP {
		size = 512
	}
	if proto == UDP && !p.recACL.Allowed(client) {
		switch p.rrl.Check(client, rrlClass(resp), time.Now().UnixNano()) {
		case limits.Drop:
			e.M.Drop(metrics.DropRRL)
			e.recordMsg(req, client, proto, start, resp.Rcode, querylog.SrcRateLimited, 0, 0, "")
			return nil
		case limits.Slip:
			e.M.RRLSlips.Add(1)
			tc := new(dns.Msg)
			tc.SetReply(req)
			tc.Truncated = true
			if req.IsEdns0() != nil {
				tc.SetEdns0(uint16(udpMax), false)
			}
			b, _ := tc.Pack()
			e.recordMsg(req, client, proto, start, resp.Rcode, querylog.SrcRateLimited, len(b), querylog.FlagTC, "")
			return b
		}
	}
	if !do && len(req.Question) == 1 {
		stripDNSSEC(resp, req.Question[0].Qtype)
	}
	resp.Compress = true
	if proto == UDP {
		resp.Truncate(size)
		if resp.Truncated {
			e.M.Truncated.Add(1)
		}
	}
	out, err := resp.Pack()
	if err != nil {
		fail := new(dns.Msg)
		fail.SetRcode(req, dns.RcodeServerFailure)
		out, _ = fail.Pack()
		src = metrics.SrcError
	}
	e.M.Source(src)
	e.M.Rcode(resp.Rcode)
	if proto != API {
		var flags uint8
		if resp.Truncated {
			flags |= querylog.FlagTC
		}
		if meta.stale {
			flags |= querylog.FlagStale
		}
		if src == metrics.SrcCache || src == metrics.SrcStale {
			flags |= querylog.FlagCached
		}
		flags |= secFlags(meta.sec.State)
		e.recordMsg(req, client, proto, start, resp.Rcode, qlSource(meta), len(out), flags, meta.upstream)
	}
	return out
}

// qlSource maps an answer source to the query-log source.
func qlSource(m answerMeta) uint8 {
	switch m.src {
	case metrics.SrcAuthoritative, metrics.SrcLocal:
		return querylog.SrcAuthoritative
	case metrics.SrcOverride:
		return querylog.SrcOverride
	case metrics.SrcCache, metrics.SrcStale:
		return querylog.SrcCache
	case metrics.SrcRefused:
		return querylog.SrcRefused
	case metrics.SrcMitigated:
		return querylog.SrcMitigated
	case metrics.SrcRateLimited:
		return querylog.SrcRateLimited
	case metrics.SrcRecursive:
		return querylog.SrcRecursive
	}
	if m.forwarder {
		return querylog.SrcForwarder
	}
	return querylog.SrcUpstream
}

// rrlClass identifies "identical responses" (BIND RRL): positive answers by
// qname+qtype; NXDOMAIN and referrals by zone so random-subdomain floods
// aggregate; errors by rcode.
func rrlClass(r *dns.Msg) uint64 {
	if len(r.Question) == 0 {
		return limits.ClassHash("noq")
	}
	q := r.Question[0]
	switch {
	case r.Rcode == dns.RcodeNameError:
		owner := ""
		for _, rr := range r.Ns {
			if rr.Header().Rrtype == dns.TypeSOA {
				owner = strings.ToLower(rr.Header().Name)
			}
		}
		return limits.ClassHash("nx", owner)
	case r.Rcode != dns.RcodeSuccess:
		return limits.ClassHash("err", dns.RcodeToString[r.Rcode])
	case len(r.Answer) == 0 && len(r.Ns) > 0 && r.Ns[0].Header().Rrtype == dns.TypeNS:
		return limits.ClassHash("ref", strings.ToLower(r.Ns[0].Header().Name))
	}
	return limits.ClassHash("ok", strings.ToLower(q.Name), dns.TypeToString[q.Qtype])
}

func sourceName(src int) string {
	switch src {
	case metrics.SrcAuthoritative, metrics.SrcLocal:
		return "authoritative"
	case metrics.SrcOverride:
		return "override"
	case metrics.SrcCache, metrics.SrcStale:
		return "cache"
	case metrics.SrcRefused:
		return "refused"
	case metrics.SrcMitigated:
		return "mitigated"
	case metrics.SrcRateLimited:
		return "rate_limited"
	case metrics.SrcRecursive:
		return "recursive"
	}
	return "upstream"
}

type answerMeta struct {
	src       int
	upstream  string
	stale     bool
	forwarder bool
	mitigated bool         // a domain throttle refused upstream work
	sec       wire.SecInfo // DNSSEC status of the answer (D4)
	ede       uint16       // extended error of a failed resolution
}

// answer computes the response for a decoded request. nil means drop.
func (e *Engine) answer(ctx context.Context, p *policy, req *dns.Msg, client netip.Addr, proto Proto) (*dns.Msg, answerMeta) {
	meta := answerMeta{src: metrics.SrcLocal}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = false
	trusted := tokenFrom(ctx) != nil
	recOK := p.recursionFor(client, proto, trusted)
	heavy := recOK && e.heavyClient(client) // pressure action refuse_heavy_clients
	if heavy {
		recOK = false
	}
	resp.RecursionAvailable = recOK
	minANY := p.s.MinimalANY || e.acts().MinimalANY

	if req.Opcode != dns.OpcodeQuery {
		resp.Question = nil
		resp.SetRcode(req, dns.RcodeNotImplemented)
		return resp, meta
	}
	opts := 0
	for _, rr := range req.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			opts++
		}
	}
	if len(req.Question) != 1 || opts > 1 || len(req.Answer) > 0 || len(req.Ns) > 0 {
		r := new(dns.Msg)
		r.SetRcode(req, dns.RcodeFormatError)
		r.Question = nil
		return r, meta
	}
	if opt := req.IsEdns0(); opt != nil && opt.Version() != 0 {
		r := new(dns.Msg)
		r.SetReply(req)
		r.SetEdns0(uint16(p.s.Limits.UDPMaxSize), false)
		r.Rcode = dns.RcodeBadVers // extended rcode carried in OPT
		return r, meta
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET {
		resp.Rcode = dns.RcodeRefused // CHAOS (version.bind, id.server) and others: RFC 4892 deny
		meta.src = metrics.SrcRefused
		return resp, meta
	}
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		resp.Rcode = dns.RcodeRefused // zone transfer is not offered in D1
		meta.src = metrics.SrcRefused
		return resp, meta
	case dns.TypeOPT, dns.TypeTSIG, dns.TypeTKEY:
		resp.Rcode = dns.RcodeFormatError
		return resp, meta
	case dns.TypeMAILA, dns.TypeMAILB:
		resp.Rcode = dns.RcodeNotImplemented
		return resp, meta
	}
	if q.Qtype == dns.TypeANY && p.s.RefuseANY {
		resp.Rcode = dns.RcodeRefused
		meta.src = metrics.SrcRefused
		return resp, meta
	}
	qname := strings.ToLower(q.Name)

	// 1. overrides (resolver policy: only for recursion-allowed clients)
	if len(p.overrides) > 0 && p.recACLFor(client, proto, trusted) {
		if rrs, ok := e.override(p, qname); ok {
			meta.src = metrics.SrcOverride
			e.fillOverride(ctx, p, resp, qname, q.Qtype, rrs, recOK && req.RecursionDesired, 0)
			return resp, meta
		}
	}
	// 2. zones (deepest match wins between primary and forwarder zones)
	if z := p.zones.Find(qname); z != nil {
		if z.Type == "primary" {
			res, _ := p.zones.Answer(qname, q.Qtype)
			resp.Authoritative = res.Authoritative
			resp.Rcode = res.Rcode
			resp.Answer = res.Answer
			resp.Ns = res.Ns
			resp.Extra = res.Extra
			meta.src = metrics.SrcAuthoritative
			if q.Qtype == dns.TypeANY && (p.s.MinimalANY && proto == UDP || e.acts().MinimalANY) {
				minimalANY(resp)
			}
			if res.Dangling != "" && recOK && req.RecursionDesired {
				e.chase(ctx, p, resp, res.Dangling, q.Qtype, 1)
			}
			return resp, meta
		}
		if !recOK {
			resp.Rcode = dns.RcodeRefused
			meta.src = metrics.SrcRefused
			if heavy {
				meta.src = metrics.SrcMitigated
			}
			return resp, meta
		}
		r, m := e.recurse(ctx, p, req, resp, qname, q.Qtype, p.fwd[z.Origin], false)
		m.forwarder = true
		return r, m
	}
	// 3. locally served names (RFC 6761, RFC 6303)
	if wantLocal(qname) {
		localAnswer(resp, qname, q.Qtype)
		meta.src = metrics.SrcLocal
		resp.Authoritative = true
		return resp, meta
	}
	// 4. recursion
	if !recOK {
		resp.Rcode = dns.RcodeRefused
		meta.src = metrics.SrcRefused
		if heavy {
			meta.src = metrics.SrcMitigated
		}
		return resp, meta
	}
	if q.Qtype == dns.TypeANY && minANY {
		// RFC 8482 §4.2: synthesised HINFO instead of forwarding ANY
		resp.Answer = []dns.RR{&dns.HINFO{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: 3600},
			Cpu: "RFC8482", Os: ""}}
		meta.src = metrics.SrcLocal
		return resp, meta
	}
	return e.recurse(ctx, p, req, resp, qname, q.Qtype, p.group, p.s.RebindingProtection)
}

func minimalANY(resp *dns.Msg) {
	if len(resp.Answer) == 0 {
		return
	}
	t := resp.Answer[0].Header().Rrtype
	var keep []dns.RR
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == t {
			keep = append(keep, rr)
		}
	}
	resp.Answer = keep
	resp.Extra = nil
}

func (e *Engine) override(p *policy, qname string) (map[uint16][]dns.RR, bool) {
	if m, ok := p.overrides[qname]; ok {
		return m, true
	}
	if !p.wildOverrides {
		return nil, false
	}
	for off, end := dns.NextLabel(qname, 0); !end; off, end = dns.NextLabel(qname, off) {
		if m, ok := p.overrides["*."+qname[off:]]; ok {
			return m, true
		}
	}
	return nil, false
}

func rename(rrs []dns.RR, owner string) []dns.RR {
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		if strings.EqualFold(rr.Header().Name, owner) {
			out[i] = rr
			continue
		}
		c := dns.Copy(rr)
		c.Header().Name = owner
		out[i] = c
	}
	return out
}

// fillOverride answers from override data, following an override CNAME.
func (e *Engine) fillOverride(ctx context.Context, p *policy, resp *dns.Msg, qname string, qtype uint16, m map[uint16][]dns.RR, mayRecurse bool, depth int) {
	if set := m[qtype]; len(set) > 0 {
		resp.Answer = append(resp.Answer, rename(set, qname)...)
		return
	}
	if cn := m[dns.TypeCNAME]; len(cn) > 0 && qtype != dns.TypeCNAME {
		resp.Answer = append(resp.Answer, rename(cn, qname)...)
		target := strings.ToLower(cn[0].(*dns.CNAME).Target)
		if mm, ok := e.override(p, target); ok && depth < 8 {
			e.fillOverride(ctx, p, resp, target, qtype, mm, mayRecurse, depth+1)
			return
		}
		if z := p.zones.Find(target); z != nil && z.Type == "primary" {
			res, _ := p.zones.Answer(target, qtype)
			resp.Answer = append(resp.Answer, res.Answer...)
			resp.Rcode = res.Rcode
			if res.Dangling != "" && mayRecurse {
				e.chase(ctx, p, resp, res.Dangling, qtype, 1)
			}
			return
		}
		if mayRecurse {
			e.chase(ctx, p, resp, target, qtype, 1)
		}
	}
	// name overridden but not for this type: NODATA (never leak upstream data)
}

// chase resolves an out-of-zone CNAME target recursively and appends it.
func (e *Engine) chase(ctx context.Context, p *policy, resp *dns.Msg, target string, qtype uint16, depth int) {
	if depth > 8 {
		return
	}
	group := p.group
	rebind := p.s.RebindingProtection
	if z := p.zones.Find(target); z != nil && z.Type == "forwarder" {
		group, rebind = p.fwd[z.Origin], false
	}
	r, _ := e.resolveCached(ctx, p, target, qtype, group, rebind)
	if r == nil {
		resp.Rcode = dns.RcodeServerFailure
		return
	}
	resp.Answer = append(resp.Answer, r.Answer...)
	resp.Rcode = r.Rcode
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
		resp.Ns = r.Ns
	}
}

func wantLocal(qname string) bool {
	if qname == "localhost." || strings.HasSuffix(qname, ".localhost.") {
		return true
	}
	if qname == "invalid." || strings.HasSuffix(qname, ".invalid.") {
		return true
	}
	for _, n := range localNames[2:] {
		if qname == n || strings.HasSuffix(qname, "."+n) {
			return true
		}
	}
	return false
}

var localSOA = &dns.SOA{Hdr: dns.RR_Header{Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
	Ns: "localhost.", Mbox: "nobody.invalid.", Serial: 1, Refresh: 3600, Retry: 1200, Expire: 604800, Minttl: 300}

func localAnswer(resp *dns.Msg, qname string, qtype uint16) {
	if qname == "localhost." || strings.HasSuffix(qname, ".localhost.") {
		switch qtype {
		case dns.TypeA:
			resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: resp.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{127, 0, 0, 1}}}
			return
		case dns.TypeAAAA:
			resp.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: resp.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: netip.IPv6Loopback().AsSlice()}}
			return
		}
		soa := *localSOA
		soa.Hdr.Name = "localhost."
		resp.Ns = []dns.RR{&soa}
		return
	}
	// reverse private ranges and .invalid: NXDOMAIN, never forwarded
	soa := *localSOA
	soa.Hdr.Name = "invalid."
	resp.Rcode = dns.RcodeNameError
	resp.Ns = []dns.RR{&soa}
}
