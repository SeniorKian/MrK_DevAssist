package iterative

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/testutil"
)

func TestNetTransportUDPAndTCP(t *testing.T) {
	var big atomic.Bool
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg {
		m := testutil.A(q, 60, "203.0.113.5")
		if big.Load() {
			for i := 0; i < 60; i++ {
				rr, _ := dns.NewRR(q.Name + " 60 IN TXT \"padding padding padding padding padding\"")
				m.Answer = append(m.Answer, rr)
			}
		}
		return m
	})
	ap := netip.MustParseAddrPort(up.Addr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion("Www.Example.Org.", dns.TypeA)
	for _, tcp := range []bool{false, true} {
		r, err := NetTransport{}.Exchange(ctx, ap, q, tcp)
		if err != nil || r.Id != q.Id || len(r.Answer) == 0 || checkResponse(q, r) != nil {
			t.Fatalf("tcp=%v: %v %v", tcp, r, err)
		}
	}
	big.Store(true)
	r, err := NetTransport{}.Exchange(ctx, ap, q, false)
	if err != nil || !r.Truncated {
		t.Fatalf("large answer over UDP must be truncated: %v %v", r, err)
	}
	// nobody listening: timeout
	dead := netip.MustParseAddrPort("127.0.0.1:9")
	sctx, scancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer scancel()
	if _, err := (NetTransport{}).Exchange(sctx, dead, q, false); err == nil {
		t.Fatal("no error from a closed port")
	}
}
