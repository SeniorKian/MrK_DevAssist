// Package testutil provides a scriptable upstream DNS server for tests.
package testutil

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Upstream is a fake recursive resolver on 127.0.0.1 (UDP and TCP, same port).
type Upstream struct {
	Addr    string
	Queries atomic.Int64
	mu      sync.Mutex
	handler func(q dns.Question) *dns.Msg
	delay   time.Duration
	udp     *dns.Server
	tcp     *dns.Server
}

// StartUpstream starts a fake upstream. handler returns the reply template
// (Id/question are filled in); nil means "do not answer" (timeout).
func StartUpstream(t testing.TB, handler func(q dns.Question) *dns.Msg) *Upstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	u := &Upstream{Addr: pc.LocalAddr().String(), handler: handler}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		u.Queries.Add(1)
		u.mu.Lock()
		hf, d := u.handler, u.delay
		u.mu.Unlock()
		if d > 0 {
			time.Sleep(d)
		}
		rep := hf(r.Question[0])
		if rep == nil {
			return
		}
		rep.Id = r.Id
		rep.Response = true
		rep.Question = r.Question
		rep.RecursionAvailable = true
		if _, tcp := w.RemoteAddr().(*net.TCPAddr); !tcp {
			size := 512
			if o := r.IsEdns0(); o != nil {
				size = int(o.UDPSize())
			}
			rep.Truncate(size)
		}
		_ = w.WriteMsg(rep)
	})
	u.udp = &dns.Server{PacketConn: pc, Handler: h}
	u.tcp = &dns.Server{Listener: ln, Handler: h}
	go u.udp.ActivateAndServe()
	go u.tcp.ActivateAndServe()
	t.Cleanup(u.Close)
	return u
}

// SetHandler swaps the handler.
func (u *Upstream) SetHandler(h func(q dns.Question) *dns.Msg) {
	u.mu.Lock()
	u.handler = h
	u.mu.Unlock()
}

// SetDelay delays every answer.
func (u *Upstream) SetDelay(d time.Duration) {
	u.mu.Lock()
	u.delay = d
	u.mu.Unlock()
}

// Close stops the server.
func (u *Upstream) Close() {
	_ = u.udp.Shutdown()
	_ = u.tcp.Shutdown()
}

// A returns a reply with one A record per address.
func A(q dns.Question, ttl uint32, addrs ...string) *dns.Msg {
	m := new(dns.Msg)
	for _, a := range addrs {
		rr, _ := dns.NewRR(q.Name + " " + itoa(ttl) + " IN A " + a)
		m.Answer = append(m.Answer, rr)
	}
	return m
}

// NX returns an NXDOMAIN reply with an SOA (minimum = ttl).
func NX(q dns.Question, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.Rcode = dns.RcodeNameError
	soa, _ := dns.NewRR("example. " + itoa(ttl) + " IN SOA ns.example. h.example. 1 3600 600 86400 " + itoa(ttl))
	m.Ns = []dns.RR{soa}
	return m
}

func itoa(v uint32) string {
	b := [10]byte{}
	i := len(b)
	if v == 0 {
		return "0"
	}
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
