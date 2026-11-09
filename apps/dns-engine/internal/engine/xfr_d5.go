package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/querylog"
	"mrk/dns-engine/internal/tsig"
	"mrk/dns-engine/internal/xfr"
	"mrk/dns-engine/internal/zone"
)

// ---------------------------------------------------------------- secondary refresh

// RefreshZone refreshes a secondary now (POST /v1/zones/{zone}/refresh).
func (e *Engine) RefreshZone(ctx context.Context, name string) (SecondaryStatus, error) {
	e.mu.Lock()
	z, err := e.zoneLocked(name)
	e.mu.Unlock()
	if err != nil {
		return SecondaryStatus{}, err
	}
	if z.Type != zone.TypeSecondary {
		return SecondaryStatus{}, fielderr.New(CodeZoneTypeMismatch, "only secondary zones are refreshed")
	}
	st, err := e.refreshSecondaryCtx(ctx, z.Name)
	if err != nil && !isTransferErr(err) {
		return st, err
	}
	return st, nil
}

type transferErr struct{ error }

func isTransferErr(err error) bool {
	var te transferErr
	return errors.As(err, &te)
}

func (e *Engine) refreshSecondary(fq string) (SecondaryStatus, error) {
	ctx, cancel := context.WithTimeout(e.bg, xfr.Timeout)
	defer cancel()
	return e.refreshSecondaryCtx(ctx, fq)
}

// refreshSecondaryCtx checks the primaries' SOA and transfers when newer.
func (e *Engine) refreshSecondaryCtx(ctx context.Context, fq string) (SecondaryStatus, error) {
	s := e.secFor(fq)
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	defer func() {
		e.d5.mu.Lock()
		s.running = false
		e.d5.mu.Unlock()
	}()
	z := e.zoneDoc(fq)
	if z == nil || z.Type != zone.TypeSecondary {
		return SecondaryStatus{}, fielderr.New(CodeZoneNotFound, "zone not found")
	}
	t := e.timing()
	sg := e.xfrSigner(z.TSIGKey)
	e.d5.mu.Lock()
	cur, data := s.soa, s.rrs
	e.d5.mu.Unlock()
	var lastErr error
	var used string
	var res xfr.Result
	ok := false
	for _, addr := range z.Primaries {
		used = addr
		remote, err := xfr.QuerySOA(ctx, addr, fq, sg)
		if err != nil {
			lastErr = err
			continue
		}
		if cur != nil && !xfr.SerialLess(cur.Serial, remote.Serial) {
			res = xfr.Result{SOA: cur, RRs: data, UpToDate: true}
			ok = true
			break
		}
		res, err = xfr.Fetch(ctx, addr, fq, cur, data, sg)
		if err != nil && cur != nil {
			e.log.Info("IXFR failed; trying AXFR", "zone", fq, "primary", addr, "err", err)
			res, err = xfr.Fetch(ctx, addr, fq, nil, nil, sg)
		}
		if err != nil {
			lastErr = err
			continue
		}
		ok = true
		break
	}
	now := t.Now()
	e.d5.mu.Lock()
	s.st.LastRefresh = &now
	s.st.Primary = used
	e.d5.mu.Unlock()
	if !ok {
		if lastErr == nil {
			lastErr = errors.New("no primaries")
		}
		return e.refreshFailed(fq, s, t, now, lastErr)
	}
	changed := !res.UpToDate
	soa := res.SOA
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.zones[fq] != z && (e.zones[fq] == nil || e.zones[fq].Type != zone.TypeSecondary) {
		return SecondaryStatus{}, fielderr.New(CodeZoneNotFound, "zone not found")
	}
	e.d5.mu.Lock()
	wasUnavailable := s.soa == nil || s.st.Expired
	if changed {
		s.soa, s.rrs = soa, res.RRs
		s.st.LastTransfer = "axfr"
		if res.Incremental {
			s.st.LastTransfer = "ixfr"
		}
	}
	s.st.Loaded = true
	s.st.Serial = s.soa.Serial
	s.st.LastSuccess = &now
	next := now.Add(clampDur(s.soa.Refresh, t.MinRefresh))
	exp := now.Add(time.Duration(s.soa.Expire) * time.Second)
	s.st.NextRefresh, s.st.ExpiresAt = &next, &exp
	s.st.Error, s.st.Expired = "", false
	s.expiredEv = false
	recovered := s.failing
	s.failing = false
	st := s.st
	e.d5.mu.Unlock()
	if err := e.saveSecondary(fq, s, changed); err != nil {
		e.log.Error("save secondary", "zone", fq, "err", err)
	}
	if changed || wasUnavailable {
		cur := e.zones[fq]
		e.compiled[fq] = e.compileSecondary(cur)
		if err := e.rebuildLocked(); err != nil {
			e.log.Error("rebuild after transfer", "zone", fq, "err", err)
		}
		e.Cache.Flush(fq)
		e.log.Info("secondary zone loaded", "zone", fq, "serial", soa.Serial, "records", len(res.RRs), "incremental", res.Incremental)
		if changed {
			e.sendNotifies(cur)
		}
	}
	if recovered {
		e.EventRing().Emit(EventTransferRecovered, "info", map[string]any{"zone": zone.Display(fq), "serial": st.Serial})
	}
	return st, nil
}

func (e *Engine) refreshFailed(fq string, s *secondary, t ZoneTiming, now time.Time, err error) (SecondaryStatus, error) {
	e.d5.mu.Lock()
	retry := uint32(600)
	if s.soa != nil {
		retry = s.soa.Retry
	}
	next := now.Add(clampDur(retry, t.MinRefresh))
	s.st.NextRefresh = &next
	s.st.Error = err.Error()
	first := !s.failing
	s.failing = true
	st := s.st
	e.d5.mu.Unlock()
	_ = e.saveSecondary(fq, s, false)
	if first {
		e.EventRing().Emit(EventTransferFailed, "warning", map[string]any{"zone": zone.Display(fq), "primary": st.Primary,
			"error": err.Error()})
	}
	e.log.Warn("secondary refresh failed", "zone", fq, "primary", st.Primary, "err", err)
	return st, transferErr{err}
}

// ---------------------------------------------------------------- NOTIFY out

// sendNotifies notifies the zone's targets (RFC 1996) with retries.
func (e *Engine) sendNotifies(z *zone.Zone) {
	if z.Notify == nil || !z.Notify.Enabled || len(z.Notify.Targets) == 0 {
		return
	}
	key := z.Notify.TSIGKey
	if key == "" && z.Transfer != nil {
		key = z.Transfer.TSIGKey
	}
	e.d5.mu.Lock()
	e.d5.notifyID[z.Name]++
	gen := e.d5.notifyID[z.Name]
	e.d5.mu.Unlock()
	soa := z.SOARR()
	if c := e.compiled[z.Name]; c != nil && c.SOARR() != nil {
		soa = c.SOARR()
	}
	for _, target := range z.Notify.Targets {
		e.wg.Add(1)
		go func(target string) {
			defer e.wg.Done()
			e.notifyOne(z.Name, gen, target, key, soa)
		}(target)
	}
}

func (e *Engine) notifyOne(fq string, gen uint64, target, key string, soa *dns.SOA) {
	t := e.timing()
	delay := t.NotifyRetry
	var lastErr error
	for attempt := 1; attempt <= notifyAttempts; attempt++ {
		e.d5.mu.Lock()
		stale := e.d5.notifyID[fq] != gen
		e.d5.mu.Unlock()
		if stale || e.bg.Err() != nil {
			return
		}
		m := new(dns.Msg)
		m.SetNotify(fq)
		m.Answer = []dns.RR{dns.Copy(soa)}
		sg := e.xfrSigner(key)
		c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
		if sg != nil {
			m.SetTsig(sg.Key, sg.Algorithm, tsig.Fudge, time.Now().Unix())
			c.TsigSecret = sg.Secrets
		}
		ctx, cancel := context.WithTimeout(e.bg, 3*time.Second)
		r, _, err := c.ExchangeContext(ctx, m, target)
		cancel()
		if err == nil && r.Rcode == dns.RcodeSuccess && r.Opcode == dns.OpcodeNotify {
			return
		}
		if err == nil {
			err = errors.New("NOTIFY answered " + dns.RcodeToString[r.Rcode])
		}
		lastErr = err
		if attempt == notifyAttempts {
			break
		}
		select {
		case <-e.bg.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
	}
	e.EventRing().Emit(EventNotifyFailed, "warning", map[string]any{"zone": zone.Display(fq), "target": target,
		"error": lastErr.Error()})
	e.log.Warn("NOTIFY failed", "zone", fq, "target", target, "err", lastErr)
}

// ---------------------------------------------------------------- transfers out

// IsTransfer reports whether pkt is an AXFR or IXFR query (cheap check for
// the TCP listener, which streams transfers itself).
func IsTransfer(pkt []byte) bool {
	if len(pkt) < 17 || pkt[2]&0x80 != 0 || (pkt[2]>>3)&0x0f != 0 || binary.BigEndian.Uint16(pkt[4:]) != 1 {
		return false
	}
	off := 12
	for {
		if off >= len(pkt) {
			return false
		}
		l := int(pkt[off])
		if l == 0 {
			off++
			break
		}
		if l > 63 {
			return false
		}
		off += 1 + l
	}
	if off+4 > len(pkt) {
		return false
	}
	t := binary.BigEndian.Uint16(pkt[off:])
	return t == dns.TypeAXFR || t == dns.TypeIXFR
}

// transferAllowed applies a zone's transfer policy (closed when empty).
func transferAllowed(cfg *zone.TransferConfig, client netip.Addr, v tsig.Verdict) bool {
	if cfg == nil || len(cfg.Allow) == 0 {
		return false
	}
	l, err := acl.Compile(cfg.Allow)
	if err != nil || !l.Allowed(client) {
		return false
	}
	if cfg.TSIGKey != "" {
		return v.OK && strings.EqualFold(v.Key, dns.Fqdn(cfg.TSIGKey))
	}
	return !v.Signed || v.OK
}

// packSigned packs resp, signing it when the request was TSIG-verified.
func (e *Engine) packSigned(resp *dns.Msg, v tsig.Verdict, prevMAC string, timersOnly bool) ([]byte, string) {
	if v.OK {
		mac := v.MAC
		if prevMAC != "" {
			mac = prevMAC
		}
		b, m, err := e.d5.tsig.Sign(resp, v.Key, mac, timersOnly)
		if err == nil {
			return b, m
		}
		e.log.Warn("tsig sign failed", "err", err)
	}
	b, err := resp.Pack()
	if err != nil {
		return nil, ""
	}
	return b, ""
}

// ServeTransfer answers an AXFR/IXFR query on a TCP connection, writing
// every message with write. It returns false when the connection should be
// closed.
func (e *Engine) ServeTransfer(pkt []byte, client netip.Addr, write func([]byte) bool) bool {
	start := time.Now()
	req := new(dns.Msg)
	if err := req.Unpack(pkt); err != nil || len(req.Question) != 1 {
		return false
	}
	q := req.Question[0]
	resp := new(dns.Msg)
	resp.SetReply(req)
	v := e.d5.tsig.Check(pkt, req)
	reply := func(rcode int, src uint8) bool {
		resp.Rcode = rcode
		b, _ := e.packSigned(resp, v, "", false)
		e.recordMsg(req, client, TCP, start, rcode, src, len(b), 0, "")
		return b != nil && write(b)
	}
	if v.Signed && !v.OK {
		b := tsig.ErrorResponse(resp, req, v)
		e.recordMsg(req, client, TCP, start, dns.RcodeNotAuth, querylog.SrcRefused, len(b), 0, "")
		return b != nil && write(b)
	}
	name := strings.ToLower(q.Name)
	// the zone document and the compiled zone of the same version
	e.mu.Lock()
	z := e.zones[name]
	c := e.pol.Load().zones.Get(name)
	e.mu.Unlock()
	if c == nil || !c.Authoritative() || q.Qclass != dns.ClassINET {
		return reply(dns.RcodeNotAuth, querylog.SrcRefused)
	}
	if z == nil || !transferAllowed(z.Transfer, client, v) {
		return reply(dns.RcodeRefused, querylog.SrcRefused)
	}
	if c.Unavailable() {
		return reply(dns.RcodeServerFailure, querylog.SrcAuthoritative)
	}
	select {
	case e.d5.xfr <- struct{}{}:
		defer func() { <-e.d5.xfr }()
	default:
		return reply(dns.RcodeServerFailure, querylog.SrcRateLimited) // MaxConcurrentTransfers
	}
	soa := c.SOARR()
	var seq []dns.RR
	if q.Qtype == dns.TypeIXFR {
		var cs *dns.SOA
		for _, rr := range req.Ns {
			if s, ok := rr.(*dns.SOA); ok {
				cs = s
			}
		}
		if cs == nil {
			return reply(dns.RcodeFormatError, querylog.SrcAuthoritative)
		}
		if !xfr.SerialLess(cs.Serial, soa.Serial) {
			seq = []dns.RR{soa} // up to date
		} else if c.D5 == nil && z.Type == zone.TypePrimary {
			seq = e.ixfrFromHistory(z, cs.Serial, soa)
		}
	}
	if seq == nil {
		seq = append([]dns.RR{soa}, e.transferRRs(c, z)...)
		seq = append(seq, soa)
	}
	total := 0
	prev := ""
	for i, chunk := range xfr.Chunk(seq) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.Compress = true
		if i > 0 {
			m.Question = nil
		}
		m.Answer = chunk
		b, mac := e.packSigned(m, v, prev, i > 0)
		if b == nil || len(b) > xfr.MaxMessage {
			return false
		}
		prev = mac
		total += len(b)
		if !write(b) {
			return false
		}
	}
	e.recordMsg(req, client, TCP, start, dns.RcodeSuccess, querylog.SrcAuthoritative, total, 0, "")
	return true
}

// transferRRs returns the zone content without the SOA.
func (e *Engine) transferRRs(c *zone.Compiled, z *zone.Zone) []dns.RR {
	if c.D5 != nil {
		return c.D5.All
	}
	rrs, err := unsignedRRs(z)
	if err != nil {
		return nil
	}
	return rrs[1:]
}

// ixfrFromHistory builds a condensed IXFR from the stored version with the
// client's serial (nil = not available, send AXFR form).
func (e *Engine) ixfrFromHistory(z *zone.Zone, serial uint32, soa *dns.SOA) []dns.RR {
	e.mu.Lock()
	hist, err := e.st.History(z.Name)
	e.mu.Unlock()
	if err != nil {
		return nil
	}
	for _, h := range hist {
		if h.Serial != serial {
			continue
		}
		old, err := e.st.LoadVersion(z.Name, h.Version)
		if err != nil || old.Signed() || old.Type != zone.TypePrimary {
			return nil
		}
		old.Name = z.Name
		oldRRs, err := unsignedRRs(old)
		if err != nil {
			return nil
		}
		curRRs, err := unsignedRRs(z)
		if err != nil {
			return nil
		}
		del, add := xfr.Diff(oldRRs[1:], curRRs[1:])
		seq := []dns.RR{soa, oldRRs[0]}
		seq = append(seq, del...)
		seq = append(seq, soa)
		seq = append(seq, add...)
		return append(seq, soa)
	}
	return nil
}

// ---------------------------------------------------------------- NOTIFY / UPDATE / UDP IXFR in

// zoneMessage handles NOTIFY, UPDATE and IXFR over UDP before the query
// pipeline (they have their own access rules). handled=false: continue.
func (e *Engine) zoneMessage(ctx context.Context, pkt []byte, req *dns.Msg, client netip.Addr, proto Proto) ([]byte, bool) {
	if proto == API {
		return nil, false
	}
	switch {
	case req.Opcode == dns.OpcodeNotify:
		return e.handleNotify(pkt, req, client, proto), true
	case req.Opcode == dns.OpcodeUpdate:
		return e.handleUpdate(pkt, req, client, proto), true
	case req.Opcode == dns.OpcodeQuery && len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeIXFR && proto != TCP:
		return e.udpIXFR(pkt, req, client, proto), true
	case req.Opcode == dns.OpcodeQuery && req.IsTsig() != nil:
		return e.signedQuery(ctx, pkt, req, client, proto), true
	}
	return nil, false
}

// signedQuery answers a TSIG-signed query (e.g. a secondary's SOA check)
// with a signed response (RFC 8945 §5.3).
func (e *Engine) signedQuery(ctx context.Context, pkt []byte, req *dns.Msg, client netip.Addr, proto Proto) []byte {
	start := time.Now()
	resp := new(dns.Msg)
	resp.SetReply(req)
	v := e.d5.tsig.Check(pkt, req)
	if !v.OK {
		return tsig.ErrorResponse(resp, req, v)
	}
	p := e.pol.Load()
	meta := answerMeta{src: metrics.SrcRefused}
	if !p.admit(client, proto) {
		resp = refused(req)
	} else if resp, meta = e.answer(ctx, p, req, client, proto); resp == nil {
		return nil
	}
	if opt := req.IsEdns0(); opt != nil {
		if resp.IsEdns0() == nil {
			resp.SetEdns0(uint16(p.s.Limits.UDPMaxSize), opt.Do())
		}
		if !opt.Do() && len(req.Question) == 1 {
			stripDNSSEC(resp, req.Question[0].Qtype)
		}
	}
	if proto == UDP {
		size := 512
		if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
			size = int(opt.UDPSize())
		}
		if size > p.s.Limits.UDPMaxSize {
			size = p.s.Limits.UDPMaxSize
		}
		resp.Truncate(size - 128) // room for the TSIG record
	}
	b, _ := e.packSigned(resp, v, "", false)
	e.recordMsg(req, client, proto, start, resp.Rcode, qlSource(meta), len(b), 0, "")
	return b
}

func (e *Engine) handleNotify(pkt []byte, req *dns.Msg, client netip.Addr, proto Proto) []byte {
	start := time.Now()
	resp := new(dns.Msg)
	resp.SetReply(req)
	if len(req.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		b, _ := resp.Pack()
		return b
	}
	v := e.d5.tsig.Check(pkt, req)
	if v.Signed && !v.OK {
		return tsig.ErrorResponse(resp, req, v)
	}
	name := strings.ToLower(req.Question[0].Name)
	z := e.zoneDoc(name)
	rcode := dns.RcodeSuccess
	switch {
	case z == nil || z.Type != zone.TypeSecondary:
		rcode = dns.RcodeNotAuth
	case !notifyAllowed(z, client, v):
		rcode = dns.RcodeRefused
	default:
		resp.Authoritative = true
		e.scheduleRefresh(name, e.now())
	}
	resp.Rcode = rcode
	b, _ := e.packSigned(resp, v, "", false)
	src := querylog.SrcAuthoritative
	if rcode != dns.RcodeSuccess {
		src = querylog.SrcRefused
	}
	e.recordMsg(req, client, proto, start, rcode, src, len(b), 0, "")
	return b
}

func notifyAllowed(z *zone.Zone, client netip.Addr, v tsig.Verdict) bool {
	if z.TSIGKey != "" && !(v.OK && strings.EqualFold(v.Key, dns.Fqdn(z.TSIGKey))) {
		return false
	}
	for _, p := range z.Primaries {
		if ap, err := netip.ParseAddrPort(p); err == nil && ap.Addr().Unmap() == client {
			return true
		}
	}
	if len(z.NotifyAllow) > 0 {
		if l, err := acl.Compile(z.NotifyAllow); err == nil && l.Allowed(client) {
			return true
		}
	}
	return false
}

// udpIXFR answers IXFR over UDP with the current SOA only (RFC 1995 §2:
// the client then uses TCP).
func (e *Engine) udpIXFR(pkt []byte, req *dns.Msg, client netip.Addr, proto Proto) []byte {
	start := time.Now()
	resp := new(dns.Msg)
	resp.SetReply(req)
	v := e.d5.tsig.Check(pkt, req)
	if v.Signed && !v.OK {
		return tsig.ErrorResponse(resp, req, v)
	}
	name := strings.ToLower(req.Question[0].Name)
	c := e.pol.Load().zones.Get(name)
	z := e.zoneDoc(name)
	switch {
	case c == nil || z == nil || !c.Authoritative():
		resp.Rcode = dns.RcodeNotAuth
	case !transferAllowed(z.Transfer, client, v):
		resp.Rcode = dns.RcodeRefused
	case c.Unavailable():
		resp.Rcode = dns.RcodeServerFailure
	default:
		resp.Authoritative = true
		resp.Answer = []dns.RR{c.SOARR()}
	}
	b, _ := e.packSigned(resp, v, "", false)
	e.recordMsg(req, client, proto, start, resp.Rcode, querylog.SrcAuthoritative, len(b), 0, "")
	return b
}
