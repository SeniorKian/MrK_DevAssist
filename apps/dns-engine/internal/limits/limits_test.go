package limits

import (
	"net/netip"
	"testing"
	"time"
)

func TestClientLimiter(t *testing.T) {
	if NewClientLimiter(0, 0, 0) != nil {
		t.Fatal("qps 0 means unlimited")
	}
	var nilLim *ClientLimiter
	if !nilLim.Allow(netip.MustParseAddr("1.2.3.4"), 1) {
		t.Fatal("nil limiter must allow")
	}
	l := NewClientLimiter(10, 20, 0)
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	now := time.Now().UnixNano()
	ok := 0
	for i := 0; i < 100; i++ {
		if l.Allow(a, now) {
			ok++
		}
	}
	if ok != 20 {
		t.Fatalf("burst: %d", ok)
	}
	if !l.Allow(b, now) {
		t.Fatal("another client must not be affected")
	}
	// refill: 10/s -> after 1 s, 10 more
	ok = 0
	for i := 0; i < 100; i++ {
		if l.Allow(a, now+int64(time.Second)) {
			ok++
		}
	}
	if ok != 10 {
		t.Fatalf("refill: %d", ok)
	}
	// IPv6 clients aggregate per /64
	v6a, v6b := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::ffff")
	for i := 0; i < 20; i++ {
		l.Allow(v6a, now)
	}
	if l.Allow(v6b, now) {
		t.Fatal("same /64 must share the bucket")
	}
	l.Sweep(now + int64(time.Hour))
	if l.Len() != 0 {
		t.Fatalf("sweep left %d", l.Len())
	}
}

func TestClientLimiterBounded(t *testing.T) {
	l := NewClientLimiter(1, 1, 640) // 11 per shard
	now := time.Now().UnixNano()
	for i := 0; i < 100000; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		l.Allow(a, now)
	}
	if n := l.Len(); n > 64*11 {
		t.Fatalf("table grew to %d", n)
	}
}

func TestRRL(t *testing.T) {
	if NewRRL(0, 2, 24, 56, 0) != nil {
		t.Fatal("disabled")
	}
	r := NewRRL(5, 2, 24, 56, 0)
	now := time.Now().UnixNano()
	class := ClassHash("ok", "example.com.", "A")
	sent, slipped, dropped := 0, 0, 0
	for i := 0; i < 25; i++ {
		// all from one /24: aggregated
		a := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
		switch r.Check(a, class, now) {
		case Send:
			sent++
		case Slip:
			slipped++
		case Drop:
			dropped++
		}
	}
	if sent != 5 || slipped != 10 || dropped != 10 {
		t.Fatalf("sent %d slip %d drop %d", sent, slipped, dropped)
	}
	// a different response class or prefix is independent
	if r.Check(netip.MustParseAddr("198.51.100.1"), ClassHash("ok", "other.", "A"), now) != Send {
		t.Fatal("class independence")
	}
	if r.Check(netip.MustParseAddr("203.0.113.1"), class, now) != Send {
		t.Fatal("prefix independence")
	}
	if r.Check(netip.MustParseAddr("198.51.100.9"), class, now+int64(time.Second)) != Send {
		t.Fatal("refill")
	}
	noSlip := NewRRL(1, 0, 24, 56, 0)
	noSlip.Check(netip.MustParseAddr("192.0.2.1"), 1, now)
	for i := 0; i < 10; i++ {
		if noSlip.Check(netip.MustParseAddr("192.0.2.1"), 1, now) != Drop {
			t.Fatal("slip 0 must always drop")
		}
	}
	if p := r.Prefix(netip.MustParseAddr("2001:db8:1:2:3::1")); p.String() != "2001:db8:1::" {
		t.Fatalf("v6 prefix %s", p)
	}
	r.Sweep(now + int64(time.Hour))
}
