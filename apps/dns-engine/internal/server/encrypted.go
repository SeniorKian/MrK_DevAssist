package server

// Incoming encrypted DNS (docs/40 §2.3): DoT (RFC 7858), DoH (RFC 8484) and
// DoQ (RFC 9250). Every query goes through the same engine path as UDP/TCP
// (ACL or encrypted.allow, client limits, pressure, mitigations, query log
// with proto dot/doh/doq). Connections are capped globally
// (encrypted.max_connections) and per client address
// (encrypted.max_connections_per_client); handshakes are bounded by
// handshake_timeout_ms and idle connections closed after idle_timeout_ms.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/engine"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/tokens"
)

// Encrypted protocol names (listener status proto).
const (
	protoDoT = "dot"
	protoDoH = "doh"
	protoDoQ = "doq"
)

// DoQ error codes (RFC 9250 §4.3).
const (
	doqNoError         = 0x0
	doqInternalError   = 0x1
	doqProtocolError   = 0x2
	doqRequestCanceled = 0x3
	doqExcessiveLoad   = 0x4
)

// maxDoHBody is the RFC 8484 message cap.
const maxDoHBody = 65535

// encConns tracks encrypted connections for the caps and status.
type encConns struct {
	mu        sync.Mutex
	perClient map[netip.Addr]int
	total     int
	byProto   [3]atomic.Int64 // dot, doh, doq
}

func protoIndex(p string) int {
	switch p {
	case protoDoT:
		return 0
	case protoDoH:
		return 1
	}
	return 2
}

// acquire admits one connection from client; perClient=false skips the
// per-client cap (a trusted reverse proxy carries many clients).
func (s *Server) encAcquire(client netip.Addr, proto string, perClient bool) bool {
	x := s.current().Encrypted
	t := &s.enc
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.total >= x.MaxConnections {
		return false
	}
	if perClient && t.perClient[client] >= x.MaxConnectionsPerClient {
		return false
	}
	t.total++
	t.perClient[client]++
	t.byProto[protoIndex(proto)].Add(1)
	return true
}

func (s *Server) encRelease(client netip.Addr, proto string) {
	t := &s.enc
	t.mu.Lock()
	t.total--
	if n := t.perClient[client] - 1; n <= 0 {
		delete(t.perClient, client)
	} else {
		t.perClient[client] = n
	}
	t.byProto[protoIndex(proto)].Add(-1)
	t.mu.Unlock()
}

// EncryptedConns reports open connections per protocol (status.encrypted).
func (s *Server) EncryptedConns() engine.EncryptedConns {
	return engine.EncryptedConns{DoT: s.enc.byProto[0].Load(), DoH: s.enc.byProto[1].Load(), DoQ: s.enc.byProto[2].Load()}
}

func isEncrypted(proto string) bool {
	return proto == protoDoT || proto == protoDoH || proto == protoDoQ
}

// encSig identifies the listener parameters fixed at start; a change restarts
// the listener. DoT reads its parameters per connection.
func encSig(proto string, st *config.Settings) string {
	x := st.Encrypted
	switch proto {
	case protoDoH:
		return fmt.Sprintf("%t|%d|%d|%d", x.DoH.TLS, x.IdleTimeoutMS, x.HandshakeTimeoutMS, x.MaxStreamsPerConnection)
	case protoDoQ:
		return fmt.Sprintf("%d|%d|%d", x.IdleTimeoutMS, x.HandshakeTimeoutMS, x.MaxStreamsPerConnection)
	}
	return ""
}

// wantEncrypted adds the enabled encrypted listeners of st to want.
func wantEncrypted(want map[key]bool, st config.Settings) {
	x := st.Encrypted
	add := func(on bool, list []string, proto string) {
		if !on {
			return
		}
		for _, a := range list {
			want[key{a, proto}] = true
		}
	}
	add(x.DoT.Enabled, x.DoT.Listen, protoDoT)
	add(x.DoH.Enabled, x.DoH.Listen, protoDoH)
	add(x.DoQ.Enabled, x.DoQ.Listen, protoDoQ)
}

func (s *Server) tlsConfig(alpn ...string) (*tls.Config, error) {
	cs := s.e.Certificates()
	if !cs.Present() {
		return nil, errors.New("no TLS certificate (PUT /v1/tls or POST /v1/tls/self-signed)")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: alpn, GetCertificate: cs.GetCertificate}, nil
}

func (s *Server) startEncrypted(l *listener) error {
	l.sig = encSig(l.key.proto, s.current())
	switch l.key.proto {
	case protoDoT:
		return s.startDoT(l)
	case protoDoH:
		return s.startDoH(l)
	}
	return s.startDoQ(l)
}

func ms(v int) time.Duration { return time.Duration(v) * time.Millisecond }

func remoteIP(a net.Addr) netip.Addr {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// ---------------------------------------------------------------- DoT

func (s *Server) startDoT(l *listener) error {
	cfg, err := s.tlsConfig("dot")
	if err != nil {
		return err
	}
	lc := net.ListenConfig{KeepAlive: -1}
	ln, err := lc.Listen(s.ctx, "tcp", l.key.addr)
	if err != nil {
		return err
	}
	l.tcp, l.bound = ln, ln.Addr().String()
	s.readers.Add(1)
	go func() {
		defer s.readers.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
			client := remoteIP(c.RemoteAddr())
			if !s.encAcquire(client, protoDoT, true) {
				s.e.M.Drop(metrics.DropTCPLimit)
				c.Close()
				continue
			}
			s.wg.Add(1)
			go s.serveDoT(tls.Server(c, cfg), client)
		}
	}()
	return nil
}

func (s *Server) serveDoT(c *tls.Conn, client netip.Addr) {
	s.conns.Store(net.Conn(c), struct{}{})
	defer func() {
		s.conns.Delete(net.Conn(c))
		c.Close()
		s.encRelease(client, protoDoT)
		s.wg.Done()
	}()
	x := s.current().Encrypted
	hctx, cancel := context.WithTimeout(s.ctx, ms(x.HandshakeTimeoutMS))
	err := c.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return
	}
	idle := ms(x.IdleTimeoutMS)
	var wmu sync.Mutex
	write := func(b []byte) bool {
		wmu.Lock()
		defer wmu.Unlock()
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		frame := make([]byte, 2+len(b))
		binary.BigEndian.PutUint16(frame, uint16(len(b)))
		copy(frame[2:], b)
		_, err := c.Write(frame)
		return err == nil
	}
	sem := make(chan struct{}, x.MaxStreamsPerConnection)
	var inner sync.WaitGroup
	defer inner.Wait()
	sc := engine.NewScratch()
	var lb [2]byte
	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < 12 {
			s.e.M.Drop(metrics.DropMalformed)
			return
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(c, pkt); err != nil {
			return
		}
		ka := wantsKeepalive(pkt)
		resp, v := s.e.Fast(pkt, client, engine.DoT, sc)
		switch v {
		case engine.Reply:
			if ka {
				resp = addKeepalive(resp, idle)
			}
			if !write(resp) {
				return
			}
			continue
		case engine.DropIt:
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-s.ctx.Done():
			return
		}
		select {
		case s.slow <- struct{}{}:
		default:
			<-sem
			s.e.M.Drop(metrics.DropOverload)
			continue
		}
		checked := v == engine.Slow
		inner.Add(1)
		go func() { // answers may leave out of order (RFC 7858 §3.3)
			defer func() { <-s.slow; <-sem; inner.Done() }()
			ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			out := s.e.Slow(ctx, pkt, client, engine.DoT, checked)
			cancel()
			if out != nil {
				if ka {
					out = addKeepalive(out, idle)
				}
				write(out)
			}
		}()
	}
}

// wantsKeepalive reports whether the query carries edns-tcp-keepalive (RFC 7828).
func wantsKeepalive(pkt []byte) bool {
	if len(pkt) < 12 || binary.BigEndian.Uint16(pkt[10:]) == 0 || !bytes.Contains(pkt[12:], []byte{0, dns.EDNS0TCPKEEPALIVE}) {
		return false
	}
	m := new(dns.Msg)
	if m.Unpack(pkt) != nil {
		return false
	}
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if o.Option() == dns.EDNS0TCPKEEPALIVE {
				return true
			}
		}
	}
	return false
}

// addKeepalive adds the server's idle timeout (units of 100 ms) to a response.
func addKeepalive(resp []byte, idle time.Duration) []byte {
	m := new(dns.Msg)
	if m.Unpack(resp) != nil {
		return resp
	}
	opt := m.IsEdns0()
	if opt == nil {
		return resp
	}
	t := idle / (100 * time.Millisecond)
	if t > 65535 {
		t = 65535
	}
	opt.Option = append(opt.Option, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: uint16(t)})
	m.Compress = true
	if b, err := m.Pack(); err == nil {
		return b
	}
	return resp
}

// ---------------------------------------------------------------- DoH

type capListener struct {
	net.Listener
	s *Server
}

type capConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *capConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (cl *capListener) Accept() (net.Conn, error) {
	for {
		c, err := cl.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := remoteIP(c.RemoteAddr())
		// a trusted reverse proxy multiplexes many clients: only the global cap applies
		perClient := !cl.s.trustedProxy(ip)
		if !cl.s.encAcquire(ip, protoDoH, perClient) {
			cl.s.e.M.Drop(metrics.DropTCPLimit)
			c.Close()
			continue
		}
		return &capConn{Conn: c, release: func() { cl.s.encRelease(ip, protoDoH) }}, nil
	}
}

func (s *Server) trustedProxy(ip netip.Addr) bool {
	if l := s.trusted.Load(); l != nil {
		return l.Allowed(ip)
	}
	return false
}

func (s *Server) setTrusted(st config.Settings) {
	l, err := acl.Compile(st.Encrypted.DoH.TrustedProxies)
	if err != nil {
		l = acl.MustCompile(nil)
	}
	s.trusted.Store(l)
}

func (s *Server) startDoH(l *listener) error {
	st := s.current()
	x := st.Encrypted
	var cfg *tls.Config
	if x.DoH.TLS {
		var err error
		if cfg, err = s.tlsConfig("h2", "http/1.1"); err != nil {
			return err
		}
	}
	lc := net.ListenConfig{KeepAlive: -1}
	raw, err := lc.Listen(s.ctx, "tcp", l.key.addr)
	if err != nil {
		return err
	}
	var ln net.Listener = &capListener{Listener: raw, s: s}
	if cfg != nil {
		ln = tls.NewListener(ln, cfg)
	}
	hs := ms(x.HandshakeTimeoutMS)
	wt := 15 * time.Second
	if hs+5*time.Second > wt {
		wt = hs + 5*time.Second
	}
	var protos http.Protocols
	protos.SetHTTP1(true)
	if cfg != nil {
		protos.SetHTTP2(true)
	} else {
		protos.SetUnencryptedHTTP2(true) // h2c from a reverse proxy
	}
	srv := &http.Server{Handler: s.dohHandler(), ReadHeaderTimeout: hs, ReadTimeout: hs + 10*time.Second,
		WriteTimeout: wt, IdleTimeout: ms(x.IdleTimeoutMS), MaxHeaderBytes: 16 << 10, Protocols: &protos,
		HTTP2:    &http.HTTP2Config{MaxConcurrentStreams: x.MaxStreamsPerConnection, MaxReadFrameSize: 1 << 16},
		ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return s.ctx }}
	l.http, l.bound = srv, raw.Addr().String()
	s.readers.Add(1)
	go func() {
		defer s.readers.Done()
		_ = srv.Serve(ln)
	}()
	return nil
}

var scratchPool = sync.Pool{New: func() any { return engine.NewScratch() }}

func (s *Server) dohHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := s.current()
		x := st.Encrypted.DoH
		var tok *tokens.Token
		if r.URL.Path != x.Path {
			secret, ok := strings.CutPrefix(r.URL.Path, x.Path+"/")
			if ok && secret != "" && !strings.Contains(secret, "/") {
				tok = s.e.LookupToken(secret)
			}
			if tok == nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
		}
		var pkt []byte
		switch r.Method {
		case http.MethodGet:
			if !x.AllowGET {
				w.Header().Set("Allow", "POST")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			q := r.URL.Query().Get("dns")
			if len(q) > maxDoHBody*4/3+4 {
				http.Error(w, "message too large", http.StatusRequestURITooLong)
				return
			}
			b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(q, "="))
			if err != nil {
				http.Error(w, "invalid dns parameter", http.StatusBadRequest)
				return
			}
			pkt = b
		case http.MethodPost:
			mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mt != "application/dns-message" {
				http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
				return
			}
			b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDoHBody))
			if err != nil {
				var mbe *http.MaxBytesError
				if errors.As(err, &mbe) {
					http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "cannot read body", http.StatusBadRequest)
				return
			}
			pkt = b
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if len(pkt) < 12 || len(pkt) > maxDoHBody {
			http.Error(w, "malformed DNS message", http.StatusBadRequest)
			return
		}
		client := s.dohClient(r)
		out, overloaded := s.answerEncrypted(r.Context(), pkt, client, engine.DoH, tok, func(b []byte) {
			w.Header().Set("Content-Type", "application/dns-message")
			w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(minTTL(b)), 10))
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			_, _ = w.Write(b)
		})
		switch {
		case overloaded:
			http.Error(w, "overloaded", http.StatusServiceUnavailable)
		case !out:
			http.Error(w, "malformed DNS message", http.StatusBadRequest)
		}
	})
}

// answerEncrypted runs a DoH/DoQ query through the engine and passes the
// response to reply (synchronously). It reports whether a response was sent
// and whether the slow path was full.
func (s *Server) answerEncrypted(ctx context.Context, pkt []byte, client netip.Addr, proto engine.Proto, tok *tokens.Token,
	reply func([]byte)) (sent, overloaded bool) {
	checked := false
	if tok == nil {
		sc := scratchPool.Get().(*engine.Scratch)
		resp, v := s.e.Fast(pkt, client, proto, sc)
		switch v {
		case engine.Reply:
			reply(resp)
			scratchPool.Put(sc)
			return true, false
		case engine.DropIt:
			scratchPool.Put(sc)
			return false, false
		}
		scratchPool.Put(sc)
		checked = v == engine.Slow
	}
	select {
	case s.slow <- struct{}{}:
	default:
		s.e.M.Drop(metrics.DropOverload)
		return false, true
	}
	defer func() { <-s.slow }()
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var out []byte
	if tok != nil {
		out = s.e.SlowToken(cctx, pkt, client, proto, tok)
	} else {
		out = s.e.Slow(cctx, pkt, client, proto, checked)
	}
	if out == nil {
		return false, false
	}
	reply(out)
	return true, false
}

// minTTL is the Cache-Control max-age of a DoH response (RFC 8484 §5.1).
func minTTL(b []byte) uint32 {
	m := new(dns.Msg)
	if m.Unpack(b) != nil {
		return 0
	}
	var min uint32
	found := false
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			t := rr.Header().Ttl
			if soa, ok := rr.(*dns.SOA); ok && soa.Minttl < t {
				t = soa.Minttl
			}
			if !found || t < min {
				min, found = t, true
			}
		}
	}
	return min
}

// dohClient is the client address: the connection's, or — from a trusted
// proxy — the nearest untrusted address in X-Forwarded-For / Forwarded.
func (s *Server) dohClient(r *http.Request) netip.Addr {
	ip := remoteIP(stringAddr(r.RemoteAddr))
	if !s.trustedProxy(ip) {
		return ip
	}
	var hops []string
	if v := r.Header.Values("X-Forwarded-For"); len(v) > 0 {
		for _, h := range v {
			for _, p := range strings.Split(h, ",") {
				hops = append(hops, strings.TrimSpace(p))
			}
		}
	} else {
		for _, h := range r.Header.Values("Forwarded") {
			for _, el := range strings.Split(h, ",") {
				for _, pair := range strings.Split(el, ";") {
					k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
					if ok && strings.EqualFold(k, "for") {
						hops = append(hops, strings.Trim(v, `"`))
					}
				}
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseHop(hops[i])
		if !ok {
			return ip // malformed chain: do not guess
		}
		ip = a
		if !s.trustedProxy(a) {
			return a
		}
	}
	return ip
}

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func parseHop(h string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(h); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return a.Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

// ---------------------------------------------------------------- DoQ

func (s *Server) startDoQ(l *listener) error {
	cfg, err := s.tlsConfig("doq")
	if err != nil {
		return err
	}
	cfg.MinVersion = tls.VersionTLS13
	x := s.current().Encrypted
	ln, err := quic.ListenAddr(l.key.addr, cfg, &quic.Config{HandshakeIdleTimeout: ms(x.HandshakeTimeoutMS),
		MaxIdleTimeout: ms(x.IdleTimeoutMS), MaxIncomingStreams: int64(x.MaxStreamsPerConnection), MaxIncomingUniStreams: -1})
	if err != nil {
		return err
	}
	l.quic, l.bound = ln, ln.Addr().String()
	s.readers.Add(1)
	go func() {
		defer s.readers.Done()
		for {
			c, err := ln.Accept(s.ctx)
			if err != nil {
				return
			}
			client := remoteIP(c.RemoteAddr())
			if !s.encAcquire(client, protoDoQ, true) {
				s.e.M.Drop(metrics.DropTCPLimit)
				_ = c.CloseWithError(doqExcessiveLoad, "")
				continue
			}
			l.qconns.Store(c, struct{}{})
			s.wg.Add(1)
			go s.serveDoQ(l, c, client)
		}
	}()
	return nil
}

func (s *Server) serveDoQ(l *listener, c *quic.Conn, client netip.Addr) {
	var inner sync.WaitGroup
	defer func() {
		inner.Wait()
		l.qconns.Delete(c)
		_ = c.CloseWithError(doqNoError, "")
		s.encRelease(client, protoDoQ)
		s.wg.Done()
	}()
	for {
		st, err := c.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		inner.Add(1)
		go func() {
			defer inner.Done()
			s.doqStream(c, st, client)
		}()
	}
}

func (s *Server) doqStream(c *quic.Conn, st *quic.Stream, client netip.Addr) {
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	var lb [2]byte
	if _, err := io.ReadFull(st, lb[:]); err != nil {
		st.CancelWrite(doqRequestCanceled)
		return
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n < 12 {
		s.e.M.Drop(metrics.DropMalformed)
		_ = c.CloseWithError(doqProtocolError, "short message")
		return
	}
	pkt := make([]byte, n)
	if _, err := io.ReadFull(st, pkt); err != nil {
		st.CancelWrite(doqRequestCanceled)
		return
	}
	if binary.BigEndian.Uint16(pkt) != 0 { // RFC 9250 §4.2.1: the message ID MUST be 0
		s.e.M.Drop(metrics.DropMalformed)
		_ = c.CloseWithError(doqProtocolError, "message id must be 0")
		return
	}
	sent, overloaded := s.answerEncrypted(c.Context(), pkt, client, engine.DoQ, nil, func(b []byte) {
		frame := make([]byte, 2+len(b))
		binary.BigEndian.PutUint16(frame, uint16(len(b)))
		copy(frame[2:], b)
		if _, err := st.Write(frame); err != nil {
			st.CancelWrite(doqInternalError)
			return
		}
		_ = st.Close()
	})
	switch {
	case overloaded:
		st.CancelRead(doqExcessiveLoad)
		st.CancelWrite(doqExcessiveLoad)
	case !sent:
		st.CancelRead(doqRequestCanceled)
		st.CancelWrite(doqRequestCanceled)
	}
}
