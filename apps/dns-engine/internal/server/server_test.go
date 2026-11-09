package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/engine"
	"mrk/dns-engine/internal/testutil"
	"mrk/dns-engine/internal/zone"
)

func freePort(t *testing.T) string {
	t.Helper()
	for k := 0; k < 20; k++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		pc, err := net.ListenPacket("udp", addr)
		if err == nil {
			pc.Close()
			return addr
		}
	}
	t.Fatal("no free port")
	return ""
}

type harness struct {
	e    *engine.Engine
	srv  *Server
	addr string
	up   *testutil.Upstream
}

func start(t *testing.T, mut func(*config.Settings)) *harness {
	t.Helper()
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	addr := freePort(t)
	e, err := engine.Open(engine.Options{DataDir: t.TempDir(), DefaultListen: addr})
	if err != nil {
		t.Fatal(err)
	}
	st, v := e.Settings()
	st.Upstreams = []config.Upstream{{ID: "fake", Address: up.Addr, Enabled: true}}
	st.Limits.ClientQPS, st.Limits.ClientBurst = 0, 0
	st.DNSSEC.Mode = config.DNSSECOff // the fake upstream is not DNSSEC aware
	if mut != nil {
		mut(&st)
	}
	if _, _, err := e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(e, log)
	e.SetListenerHook(srv.Apply)
	st, _ = e.Settings()
	srv.Apply(st)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		srv.Shutdown(ctx)
		cancel()
		e.Close()
	})
	for _, l := range srv.Status() {
		if !l.OK {
			t.Fatalf("listener %v", l)
		}
	}
	return &harness{e: e, srv: srv, addr: addr, up: up}
}

func exchange(t *testing.T, netw, addr, name string, qt uint16) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: netw, Timeout: 2 * time.Second, UDPSize: 1232}
	m := new(dns.Msg)
	m.SetQuestion(name, qt)
	m.SetEdns0(1232, false)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s %s: %v", netw, name, err)
	}
	return r
}

func TestIntegration(t *testing.T) {
	h := start(t, nil)
	if h.srv.Sockets > 1 && len(h.srv.listeners[key{h.addr, "udp"}].udp) != h.srv.Sockets {
		t.Fatal("SO_REUSEPORT sockets not opened")
	}
	if _, err := h.e.CreateZone("example.com", "primary", nil); err != nil {
		t.Fatal(err)
	}
	for k := 0; k < 10; k++ {
		_, err := h.e.CreateRecord("example.com", zone.RecordInput{Name: strp("big"), Type: strp("TXT"),
			Data: json.RawMessage(`{"text":"` + strings.Repeat("z", 200) + string(rune('a'+k)) + `"}`)})
		if err != nil {
			t.Fatal(err)
		}
	}
	// recursion through the fake upstream, then cache
	r := exchange(t, "udp", h.addr, "www.example.org.", dns.TypeA)
	if r.Rcode != 0 || len(r.Answer) != 1 {
		t.Fatal(r)
	}
	r = exchange(t, "udp", h.addr, "www.example.org.", dns.TypeA)
	if len(r.Answer) != 1 || h.up.Queries.Load() != 1 {
		t.Fatalf("cache: upstream queries %d", h.up.Queries.Load())
	}
	// UDP truncation and TCP retry (miekg client does not retry; do it explicitly)
	r = exchange(t, "udp", h.addr, "big.example.com.", dns.TypeTXT)
	if !r.Truncated {
		t.Fatal("expected TC over UDP")
	}
	r = exchange(t, "tcp", h.addr, "big.example.com.", dns.TypeTXT)
	if r.Truncated || len(r.Answer) != 10 || !r.Authoritative {
		t.Fatalf("tcp: tc=%v n=%d", r.Truncated, len(r.Answer))
	}
	// TCP pipelining: several queries on one connection
	conn, err := dns.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	for k := 0; k < 5; k++ {
		m := new(dns.Msg)
		m.SetQuestion("www.example.org.", dns.TypeA)
		if err := conn.WriteMsg(m); err != nil {
			t.Fatal(err)
		}
	}
	for k := 0; k < 5; k++ {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.ReadMsg(); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close()
	// ACL change applied live: loopback no longer allowed
	st, v := h.e.Settings()
	st.QueryAllow = []string{"10.0.0.0/8"}
	if _, _, err := h.e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
	if r := exchange(t, "udp", h.addr, "www.example.org.", dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Fatalf("acl not applied: %v", r)
	}
}

func strp(s string) *string { return &s }

func TestHotReloadKeepsAnswering(t *testing.T) {
	h := start(t, nil)
	var stop atomic.Bool
	var fails, ok atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &dns.Client{Net: "udp", Timeout: time.Second}
			for !stop.Load() {
				m := new(dns.Msg)
				m.SetQuestion("reload.example.org.", dns.TypeA)
				if r, _, err := c.Exchange(m, h.addr); err != nil || r.Rcode != 0 {
					fails.Add(1)
				} else {
					ok.Add(1)
				}
			}
		}()
	}
	// many settings changes and zone writes while queries flow
	for k := 0; k < 20; k++ {
		st, v := h.e.Settings()
		st.Cache.Prefetch = k%2 == 0
		st.Limits.TCPIdleTimeoutMS = 5000 + k
		if _, _, err := h.e.PutSettings(st, v); err != nil {
			t.Fatal(err)
		}
		if _, err := h.e.CreateZone("z"+string(rune('a'+k))+".example", "primary", nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	if fails.Load() != 0 || ok.Load() == 0 {
		t.Fatalf("reload dropped queries: ok=%d fail=%d", ok.Load(), fails.Load())
	}
}

func TestTCPLimitsAndShutdown(t *testing.T) {
	h := start(t, func(s *config.Settings) {
		s.Limits.MaxTCPConnections = 2
		s.Limits.TCPIdleTimeoutMS = 300
	})
	c1, _ := net.Dial("tcp", h.addr)
	c2, _ := net.Dial("tcp", h.addr)
	time.Sleep(50 * time.Millisecond)
	c3, _ := net.Dial("tcp", h.addr)
	_ = c3.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c3.Read(make([]byte, 1)); err == nil {
		t.Fatal("third connection should be closed")
	}
	// idle timeout frees the slots
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c1.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle connection not closed")
	}
	c1.Close()
	c2.Close()
	c3.Close()
	time.Sleep(100 * time.Millisecond)
	if r := exchange(t, "tcp", h.addr, "after.example.org.", dns.TypeA); r.Rcode != 0 {
		t.Fatal(r)
	}
	// listener removal and failure reporting
	st, v := h.e.Settings()
	st.Listen = append(st.Listen, config.Listen{Address: "192.0.2.123:53", UDP: true, TCP: false})
	if _, _, err := h.e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
	h.srv.Apply(st)
	bad := false
	for _, l := range h.srv.Status() {
		if l.Address == "192.0.2.123:53" && !l.OK && l.Error != "" {
			bad = true
		}
	}
	if !bad {
		t.Fatalf("unbindable listener not reported: %v", h.srv.Status())
	}
	h.srv.RetryFailed()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	idle, _ := net.Dial("tcp", h.addr)
	start := time.Now()
	h.srv.Shutdown(ctx)
	if time.Since(start) > 900*time.Millisecond {
		t.Fatal("shutdown waited for idle TCP connection")
	}
	idle.Close()
	c := &dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}
	m := new(dns.Msg)
	m.SetQuestion("x.example.org.", dns.TypeA)
	if _, _, err := c.Exchange(m, h.addr); err == nil {
		t.Fatal("still answering after shutdown")
	}
}
