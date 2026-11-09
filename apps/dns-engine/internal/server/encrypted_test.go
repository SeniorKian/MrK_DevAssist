package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/engine"
	"mrk/dns-engine/internal/events"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/querylog"
	"mrk/dns-engine/internal/resolver"
)

type encHarness struct {
	*harness
	pool               *x509.CertPool
	dot, doh, doq      string
	dohURL, dohBaseURL string
}

// startEncrypted starts a harness with a self-signed certificate and DoT,
// DoH (TLS unless plainDoH) and DoQ listeners on 127.0.0.1.
func startEncrypted(t *testing.T, plainDoH bool, mut func(*config.Settings)) *encHarness {
	t.Helper()
	h := start(t, nil)
	if _, err := h.e.SelfSignedTLS([]string{"localhost", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	leaf, _ := h.e.Certificates().Leaf()
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	tlsAddr := freePort(t) // DoT (tcp) and DoQ (udp) share the port
	dohAddr := freePort(t)
	st, v := h.e.Settings()
	st.Encrypted.DoT = config.EncListener{Enabled: true, Listen: []string{tlsAddr}}
	st.Encrypted.DoQ = config.EncListener{Enabled: true, Listen: []string{tlsAddr}}
	st.Encrypted.DoH.Enabled, st.Encrypted.DoH.Listen, st.Encrypted.DoH.TLS = true, []string{dohAddr}, !plainDoH
	if mut != nil {
		mut(&st)
	}
	if _, _, err := h.e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		ok := 0
		for _, l := range h.srv.Status() {
			if isEncrypted(l.Proto) && l.OK {
				ok++
			}
		}
		return ok == 3
	})
	scheme := "https"
	if plainDoH {
		scheme = "http"
	}
	eh := &encHarness{harness: h, pool: pool, dot: h.srv.Addr(protoDoT), doh: h.srv.Addr(protoDoH), doq: h.srv.Addr(protoDoQ)}
	eh.dohBaseURL = scheme + "://" + eh.doh + st.Encrypted.DoH.Path
	eh.dohURL = eh.dohBaseURL
	return eh
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func (h *encHarness) tlsConf(alpn ...string) *tls.Config {
	return &tls.Config{RootCAs: h.pool, ServerName: "localhost", NextProtos: alpn}
}

func query(name string, qt uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qt)
	m.SetEdns0(1232, false)
	return m
}

func (h *encHarness) httpClient(h2 bool) *http.Client {
	tr := &http.Transport{TLSClientConfig: h.tlsConf(), ForceAttemptHTTP2: h2}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Transport: tr, Timeout: 3 * time.Second}
}

func dohPost(t *testing.T, c *http.Client, u string, m *dns.Msg, hdr map[string]string) (*http.Response, *dns.Msg) {
	t.Helper()
	b, _ := m.Pack()
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/dns-message")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return resp, nil
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		t.Fatal(err)
	}
	return resp, r
}

func doqExchange(t *testing.T, h *encHarness, m *dns.Msg) *dns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, h.doq, h.tlsConf("doq"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseWithError(0, "")
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m.Id = 0
	b, _ := m.Pack()
	frame := append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
	if _, err := s.Write(frame); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_ = s.SetReadDeadline(time.Now().Add(3 * time.Second))
	out, err := io.ReadAll(s)
	if err != nil || len(out) < 2 {
		t.Fatalf("doq read: %v (%d bytes)", err, len(out))
	}
	r := new(dns.Msg)
	if err := r.Unpack(out[2:]); err != nil {
		t.Fatal(err)
	}
	return r
}

func logItems(t *testing.T, e *engine.Engine, q string) []querylog.Item {
	t.Helper()
	e.FlushMonitor()
	v, _ := url.ParseQuery(q)
	f, err := querylog.ParseFilter(v)
	if err != nil {
		t.Fatal(err)
	}
	res := e.QueryLog().Search(context.Background(), f, 2*time.Second)
	out := []querylog.Item{}
	for i := range res.Rows {
		out = append(out, querylog.View(&res.Rows[i]))
	}
	return out
}

func wantA(t *testing.T, r *dns.Msg) {
	t.Helper()
	if r == nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("unexpected answer %v", r)
	}
}

func TestEncryptedEndToEnd(t *testing.T) {
	h := startEncrypted(t, false, nil)

	// DoT, then the same name again from the cache (fast path)
	dc := &dns.Client{Net: "tcp-tls", TLSConfig: h.tlsConf("dot"), Timeout: 3 * time.Second}
	for i := 0; i < 2; i++ {
		r, _, err := dc.Exchange(query("dot.example.", dns.TypeA), h.dot)
		if err != nil {
			t.Fatal(err)
		}
		wantA(t, r)
	}

	// DoT pipelining on one connection + EDNS keepalive (RFC 7828)
	conn, err := tls.Dial("tcp", h.dot, h.tlsConf("dot"))
	if err != nil {
		t.Fatal(err)
	}
	if p := conn.ConnectionState().NegotiatedProtocol; p != "dot" {
		t.Fatalf("ALPN %q", p)
	}
	ids := map[uint16]bool{}
	for i, n := range []string{"p1.example.", "p2.example.", "p3.example."} {
		m := query(n, dns.TypeA)
		m.Id = uint16(100 + i)
		if i == 0 {
			m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE})
		}
		b, _ := m.Pack()
		conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
		ids[m.Id] = true
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	keepalive := false
	for range 3 {
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		r := new(dns.Msg)
		if err := r.Unpack(buf); err != nil {
			t.Fatal(err)
		}
		if !ids[r.Id] {
			t.Fatalf("unexpected id %d", r.Id)
		}
		delete(ids, r.Id)
		if r.Id == 100 {
			for _, o := range r.IsEdns0().Option {
				if ka, ok := o.(*dns.EDNS0_TCP_KEEPALIVE); ok && ka.Timeout == 300 {
					keepalive = true
				}
			}
		}
	}
	conn.Close()
	if !keepalive {
		t.Fatal("no edns-tcp-keepalive in the response")
	}

	// DoH: POST over HTTP/2, GET over HTTP/1.1
	resp, r := dohPost(t, h.httpClient(true), h.dohURL, query("doh.example.", dns.TypeA), nil)
	wantA(t, r)
	if resp.ProtoMajor != 2 || resp.Header.Get("Content-Type") != "application/dns-message" ||
		resp.Header.Get("Cache-Control") != "max-age=300" {
		t.Fatalf("proto %s headers %v", resp.Proto, resp.Header)
	}
	m := query("get.example.", dns.TypeA)
	m.Id = 0
	b, _ := m.Pack()
	gr, err := h.httpClient(false).Get(h.dohURL + "?dns=" + base64.RawURLEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(gr.Body)
	gr.Body.Close()
	if gr.StatusCode != 200 || gr.ProtoMajor != 1 {
		t.Fatalf("GET %d %s", gr.StatusCode, gr.Proto)
	}
	if err := new(dns.Msg).Unpack(body); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/other", "/dns-query/not-a-token", "/dns-query/a/b"} {
		r, err := h.httpClient(true).Get("https://" + h.doh + p + "?dns=" + base64.RawURLEncoding.EncodeToString(b))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 404 {
			t.Fatalf("%s: %d", p, r.StatusCode)
		}
	}
	if r, _ := dohPost(t, h.httpClient(true), h.dohURL, query("x.example.", dns.TypeA), map[string]string{"Content-Type": "text/plain"}); r.StatusCode != 415 {
		t.Fatalf("content type: %d", r.StatusCode)
	}

	// DoQ
	wantA(t, doqExchange(t, h, query("doq.example.", dns.TypeA)))

	// outbound quic:// upstream against our own DoQ listener
	resolver.TestRootCAs = h.pool
	defer func() { resolver.TestRootCAs = nil }()
	u, err := resolver.NewUpstream("q", "quic://"+h.doq+"#localhost", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		r, _, err := u.Exchange(ctx, resolver.NewQuery("upstream-doq.example.", dns.TypeA))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		wantA(t, r)
	}

	// query log, stats and status
	for _, p := range []string{"dot", "doh", "doq"} {
		if items := logItems(t, h.e, "proto="+p+"&limit=100"); len(items) == 0 {
			t.Fatalf("no %s rows in the query log", p)
		}
	}
	res, _ := h.e.Stats("1h")
	if res.Totals.ByProto["dot"] < 5 || res.Totals.ByProto["doh"] < 2 || res.Totals.ByProto["doq"] < 3 {
		t.Fatalf("by_proto %v", res.Totals.ByProto)
	}
	st := h.e.Status(h.srv.Status())
	if !st.Encrypted.Certificate.Present || st.Encrypted.Certificate.DaysLeft == nil || *st.Encrypted.Certificate.DaysLeft < 390 {
		t.Fatalf("certificate status %+v", st.Encrypted.Certificate)
	}
	protos := map[string]bool{}
	for _, l := range st.Listeners {
		protos[l.Proto] = l.OK
	}
	if !protos["dot"] || !protos["doh"] || !protos["doq"] {
		t.Fatalf("listeners %v", st.Listeners)
	}
	if st.Encrypted.Connections.DoQ < 1 { // the quic:// upstream keeps its connection
		t.Fatalf("connections %+v", st.Encrypted.Connections)
	}

	// hot certificate reload: a new self-signed certificate is served without restart
	old, _ := h.e.Certificates().Leaf()
	if _, err := h.e.SelfSignedTLS([]string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	c2, err := tls.Dial("tcp", h.dot, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c2.ConnectionState().PeerCertificates[0].Raw, old.Raw) {
		t.Fatal("old certificate still served")
	}
	c2.Close()

	// the certificate cannot be deleted while DoT is on
	var fe *fielderr.Error
	if err := h.e.DeleteTLS(); !errors.As(err, &fe) || fe.Code != engine.CodeCertificateInUse {
		t.Fatalf("delete: %v", err)
	}
}

func TestDoHTokensAndTrustedProxy(t *testing.T) {
	h := startEncrypted(t, true, func(s *config.Settings) {
		// loopback is not allowed to recurse: only tokens (and allowed forwarded clients) work
		s.Recursion.Allow = []string{"10.0.0.0/8"}
		s.QueryAllow = []string{"127.0.0.0/8", "10.0.0.0/8", "203.0.113.0/24"}
	})
	c := &http.Client{Timeout: 3 * time.Second}
	if _, r := dohPost(t, c, h.dohURL, query("a.example.", dns.TypeA), nil); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("loopback without token: %v", r)
	}
	// forwarded by a trusted proxy (loopback is in trusted_proxies)
	if _, r := dohPost(t, c, h.dohURL, query("fwd.example.", dns.TypeA), map[string]string{"X-Forwarded-For": "10.1.1.1"}); r == nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("XFF allowed client: %v", r) // every hop trusted: the leftmost is the client
	}
	if _, r := dohPost(t, c, h.dohURL, query("fwd2.example.", dns.TypeA), map[string]string{"X-Forwarded-For": "10.1.1.1, 203.0.113.9"}); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("XFF refused client: %v", r)
	}
	if _, r := dohPost(t, c, h.dohURL, query("fwd3.example.", dns.TypeA), map[string]string{"Forwarded": `for="[2001:db8::7]:4711";proto=https`}); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("Forwarded: %v", r)
	}
	if items := logItems(t, h.e, "client=203.0.113.9&limit=10"); len(items) != 1 || items[0].Name != "fwd2.example" {
		t.Fatalf("forwarded client in log: %+v", items)
	}

	qps := 1
	tok, err := h.e.CreateToken("phone", &qps)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.Token) != 43 {
		t.Fatalf("token length %d", len(tok.Token))
	}
	tu := h.dohBaseURL + "/" + tok.Token
	for i := 0; i < 2; i++ { // burst = 2 s of qps
		if _, r := dohPost(t, c, tu, query("tok.example.", dns.TypeA), nil); r == nil || r.Rcode != dns.RcodeSuccess {
			t.Fatalf("token query %d: %v", i, r)
		}
	}
	if _, r := dohPost(t, c, tu, query("tok.example.", dns.TypeA), nil); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("token over qps: %v", r)
	}
	items := logItems(t, h.e, "name=tok.example&limit=10")
	if len(items) != 3 {
		t.Fatalf("token rows %d", len(items))
	}
	for _, it := range items {
		if it.Token != tok.ID || it.Upstream != "" || it.Client != "127.0.0.1" || it.Proto != "doh" {
			t.Fatalf("token row %+v", it)
		}
	}
	if v := h.e.Tokens(); len(v) != 1 || v[0].Queries != 3 || v[0].LastUsedAt == nil {
		t.Fatalf("token usage %+v", v)
	}
	if err := h.e.DeleteToken(tok.ID); err != nil {
		t.Fatal(err)
	}
	if r, _ := dohPost(t, c, tu, query("tok.example.", dns.TypeA), nil); r.StatusCode != 404 {
		t.Fatalf("deleted token: %d", r.StatusCode)
	}
}

func TestEncryptedAllowAndConnectionCaps(t *testing.T) {
	h := startEncrypted(t, false, func(s *config.Settings) {
		allow := []string{"10.0.0.0/8"}
		s.Encrypted.Allow = &allow // replaces query_allow / recursion.allow for encrypted clients
		s.Encrypted.MaxConnectionsPerClient = 1
	})
	dc := &dns.Client{Net: "tcp-tls", TLSConfig: h.tlsConf("dot"), Timeout: 3 * time.Second}
	r, _, err := dc.Exchange(query("deny.example.", dns.TypeA), h.dot)
	if err != nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("encrypted.allow: %v %v", r, err)
	}
	// plain DNS is unaffected
	wantA(t, exchange(t, "udp", h.addr, "plain.example.", dns.TypeA))

	c1, err := tls.Dial("tcp", h.dot, h.tlsConf("dot"))
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	waitFor(t, func() bool { return h.srv.EncryptedConns().DoT == 1 })
	raw, err := net.Dial("tcp", h.dot)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := raw.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("second connection not closed: %v", err)
	}
	raw.Close()
	c1.Close()
	waitFor(t, func() bool { return h.srv.EncryptedConns().DoT == 0 })

	// handshake timeout: a silent TCP connection is closed
	st, v := h.e.Settings()
	st.Encrypted.HandshakeTimeoutMS = 500
	if _, _, err := h.e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	silent, err := net.Dial("tcp", h.dot)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	start := time.Now()
	_ = silent.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := silent.Read(make([]byte, 1)); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("handshake timeout not applied: %v after %v", err, time.Since(start))
	}
}

func TestEncryptedSettingsNeedCertificate(t *testing.T) {
	h := start(t, nil)
	st, v := h.e.Settings()
	st.Encrypted.DoT = config.EncListener{Enabled: true, Listen: []string{freePort(t)}}
	_, _, err := h.e.PutSettings(st, v)
	var fe *fielderr.Error
	if !errors.As(err, &fe) || fe.Code != engine.CodeCertificateRequired || fe.Fields[0].Field != "encrypted.dot.enabled" {
		t.Fatalf("want certificate_required, got %v", err)
	}
	// plain DoH (behind a proxy) needs no certificate
	st, v = h.e.Settings()
	st.Encrypted.DoH = config.DoH{Enabled: true, Listen: []string{freePort(t)}, TLS: false, Path: "/dns-query",
		AllowGET: true, TrustedProxies: config.DefaultTrustedProxies}
	if _, _, err := h.e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
}

func TestListenerFailedEvent(t *testing.T) {
	h := start(t, nil)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	st, v := h.e.Settings()
	st.Encrypted.DoH = config.DoH{Enabled: true, Listen: []string{busy.Addr().String()}, TLS: false, Path: "/dns-query",
		TrustedProxies: []string{}}
	if _, _, err := h.e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		evs, _ := h.e.Events(0, 100)
		for _, e := range evs {
			if e.Type == events.ListenerFailed && e.Data["proto"] == "doh" && e.Data["address"] == busy.Addr().String() {
				return true
			}
		}
		return false
	})
	h.srv.RetryFailed() // the same failure is not reported twice
	n := 0
	evs, _ := h.e.Events(0, 100)
	for _, e := range evs {
		if e.Type == events.ListenerFailed {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d listener.failed events", n)
	}
}

func TestDoQRejectsNonZeroID(t *testing.T) {
	h := startEncrypted(t, false, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, h.doq, h.tlsConf("doq"), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.OpenStreamSync(ctx)
	m := query("id.example.", dns.TypeA)
	m.Id = 7
	b, _ := m.Pack()
	s.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
	s.Close()
	select {
	case <-c.Context().Done():
		var ae *quic.ApplicationError
		if !errors.As(context.Cause(c.Context()), &ae) || ae.ErrorCode != doqProtocolError {
			t.Fatalf("close reason %v", context.Cause(c.Context()))
		}
	case <-ctx.Done():
		t.Fatal("connection not closed")
	}
}
