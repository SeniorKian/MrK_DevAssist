package resolver

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/testutil"
)

func mustUp(t *testing.T, id, raw string) *Upstream {
	t.Helper()
	u, err := NewUpstream(id, raw, true, nil, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(u.Close)
	return u
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestUDPAndTCPFallback(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg {
		if strings.HasPrefix(q.Name, "big.") {
			m := new(dns.Msg)
			for i := 0; i < 60; i++ {
				rr, _ := dns.NewRR(q.Name + " 60 IN TXT \"" + strings.Repeat("x", 100) + "\"")
				m.Answer = append(m.Answer, rr)
			}
			return m
		}
		return testutil.A(q, 60, "192.0.2.1")
	})
	u := mustUp(t, "u", up.Addr)
	r, rtt, err := u.Exchange(ctx(t), NewQuery("a.example.", dns.TypeA))
	if err != nil || len(r.Answer) != 1 || rtt <= 0 {
		t.Fatalf("%v %v", r, err)
	}
	r, _, err = u.Exchange(ctx(t), NewQuery("big.example.", dns.TypeTXT))
	if err != nil || r.Truncated || len(r.Answer) != 60 {
		t.Fatalf("TCP fallback failed: tc=%v n=%d err=%v", r != nil && r.Truncated, len(r.Answer), err)
	}
	tu := mustUp(t, "t", "tcp://"+up.Addr)
	for i := 0; i < 3; i++ { // pooled connection reuse
		if _, _, err := tu.Exchange(ctx(t), NewQuery("a.example.", dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSpoofedResponsesIgnored(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := new(dns.Msg)
		_ = q.Unpack(buf[:n])
		bad := new(dns.Msg)
		bad.SetReply(q)
		bad.Id = q.Id + 1 // wrong ID
		b, _ := bad.Pack()
		_, _ = pc.WriteTo(b, from)
		wrongQ := new(dns.Msg)
		wrongQ.SetReply(q)
		wrongQ.Question[0].Name = "evil.example."
		b, _ = wrongQ.Pack()
		_, _ = pc.WriteTo(b, from)
		good := new(dns.Msg)
		good.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.7")
		good.Answer = []dns.RR{rr}
		b, _ = good.Pack()
		_, _ = pc.WriteTo(b, from)
	}()
	u := mustUp(t, "u", pc.LocalAddr().String())
	r, _, err := u.Exchange(ctx(t), NewQuery("ok.example.", dns.TypeA))
	if err != nil || r.Answer[0].(*dns.A).A.String() != "192.0.2.7" {
		t.Fatalf("%v %v", r, err)
	}
}

func deadAddr(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() }) // bound but never answers
	return pc.LocalAddr().String()
}

func TestStrategiesAndHealth(t *testing.T) {
	good := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 60, "192.0.2.1") })
	slow := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 60, "192.0.2.2") })
	slow.SetDelay(80 * time.Millisecond)
	dead := deadAddr(t)
	for _, strat := range []string{config.StrategyFastest, config.StrategyInOrder, config.StrategyParallel} {
		d := mustUp(t, "dead", dead)
		g := NewGroup([]*Upstream{d, mustUp(t, "slow", slow.Addr), mustUp(t, "good", good.Addr)}, strat, NewLimiter(100))
		g.AttemptTimeout = 300 * time.Millisecond
		var answered *Upstream
		for i := 0; i < 6; i++ {
			r, u, err := g.Exchange(ctx(t), NewQuery("x.example.", dns.TypeA))
			if err != nil || len(r.Answer) != 1 {
				t.Fatalf("%s: %v", strat, err)
			}
			answered = u
		}
		if d.Healthy() && strat == config.StrategyInOrder {
			t.Errorf("%s: dead upstream still healthy", strat)
		}
		if strat == config.StrategyFastest && answered.ID != "good" {
			t.Errorf("fastest picked %s (rtt good=%v slow=%v)", answered.ID, g.Upstreams[2].RTT(), g.Upstreams[1].RTT())
		}
		if strat == config.StrategyInOrder && answered.ID != "slow" {
			t.Errorf("in_order picked %s", answered.ID)
		}
	}
	// health check revives an upstream that answers again
	u := mustUp(t, "g", good.Addr)
	u.healthy.Store(false)
	g := NewGroup([]*Upstream{u}, config.StrategyFastest, nil)
	g.HealthCheck(ctx(t), time.Second)
	if !u.Healthy() {
		t.Fatal("health check did not revive")
	}
	if _, _, err := NewGroup(nil, "fastest", nil).Exchange(ctx(t), NewQuery("x.", dns.TypeA)); err != ErrNoUpstream {
		t.Fatal(err)
	}
}

func TestServfailFailover(t *testing.T) {
	bad := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { m := new(dns.Msg); m.Rcode = dns.RcodeServerFailure; return m })
	good := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 60, "192.0.2.1") })
	g := NewGroup([]*Upstream{mustUp(t, "bad", bad.Addr), mustUp(t, "good", good.Addr)}, config.StrategyInOrder, nil)
	r, u, err := g.Exchange(ctx(t), NewQuery("x.example.", dns.TypeA))
	if err != nil || u.ID != "good" || r.Rcode != 0 {
		t.Fatalf("%v %v", u, err)
	}
}

func TestLimiterOverload(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 60, "192.0.2.1") })
	up.SetDelay(200 * time.Millisecond)
	lim := NewLimiter(2)
	g := NewGroup([]*Upstream{mustUp(t, "u", up.Addr)}, config.StrategyFastest, lim)
	var overloaded atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := g.Exchange(context.Background(), NewQuery("x.example.", dns.TypeA)); err == ErrOverloaded {
				overloaded.Add(1)
			}
		}()
	}
	wg.Wait()
	if overloaded.Load() < 7 || lim.InUse() != 0 {
		t.Fatalf("overloaded %d inuse %d", overloaded.Load(), lim.InUse())
	}
}

func TestFlight(t *testing.T) {
	var f Flight
	var calls atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	shared := atomic.Int32{}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			v, err, sh := f.Do("k", func() (any, error) {
				calls.Add(1)
				time.Sleep(50 * time.Millisecond)
				return 42, nil
			})
			if v.(int) != 42 || err != nil {
				t.Error("value")
			}
			if sh {
				shared.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 || shared.Load() != 49 || f.Pending() != 0 {
		t.Fatalf("calls %d shared %d", calls.Load(), shared.Load())
	}
	r := <-f.DoChan("x", func() (any, error) { return 1, nil })
	if r.Val.(int) != 1 {
		t.Fatal("DoChan")
	}
}

func dnsAnswer(req []byte) []byte {
	q := new(dns.Msg)
	if q.Unpack(req) != nil {
		return nil
	}
	r := new(dns.Msg)
	r.SetReply(q)
	rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.53")
	r.Answer = []dns.RR{rr}
	b, _ := r.Pack()
	return b
}

func TestDoHAndDoT(t *testing.T) {
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad", 400)
			return
		}
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dnsAnswer(b))
	}))
	defer doh.Close()
	TestRootCAs = doh.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	defer func() { TestRootCAs = nil }()

	u := mustUp(t, "doh", doh.URL+"/dns-query")
	r, _, err := u.Exchange(ctx(t), NewQuery("doh.example.", dns.TypeA))
	if err != nil || len(r.Answer) != 1 {
		t.Fatalf("doh: %v", err)
	}
	// DoH with a host name and bootstrap callback
	port := doh.Listener.Addr().(*net.TCPAddr).Port
	boot := func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	ub, err := NewUpstream("dohname", "https://example.com:"+itoa(port)+"/dns-query", true, boot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r, _, err := ub.Exchange(ctx(t), NewQuery("boot.example.", dns.TypeA)); err != nil || len(r.Answer) != 1 {
		t.Fatalf("doh bootstrap: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: doh.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		b, _ := m.Pack()
		r := new(dns.Msg)
		_ = r.Unpack(dnsAnswer(b))
		_ = w.WriteMsg(r)
	})}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	dot := mustUp(t, "dot", "tls://"+ln.Addr().String()+"#example.com")
	for i := 0; i < 2; i++ {
		if r, _, err := dot.Exchange(ctx(t), NewQuery("dot.example.", dns.TypeA)); err != nil || len(r.Answer) != 1 {
			t.Fatalf("dot: %v", err)
		}
	}
	bad := mustUp(t, "dotbad", "tls://"+ln.Addr().String()+"#wrong.invalid")
	if _, _, err := bad.Exchange(ctx(t), NewQuery("dot.example.", dns.TypeA)); err == nil {
		t.Fatal("certificate name mismatch accepted")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
