package mitigate

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func wire(n string) []byte {
	b := make([]byte, 256)
	l, _ := dns.PackDomainName(dns.Fqdn(n), b, 0, nil, false)
	return b[:l]
}

func TestValidate(t *testing.T) {
	bad := []Input{
		{Kind: "x", Match: "1.2.3.4", Action: ActBlock, Minutes: 5},
		{Kind: KindClient, Match: "nope", Action: ActBlock, Minutes: 5},
		{Kind: KindClient, Match: "0.0.0.0/0", Action: ActBlock, Minutes: 5},
		{Kind: KindDomain, Match: "bad name!", Action: ActBlock, Minutes: 5},
		{Kind: KindDomain, Match: "a.example", Action: ActThrottle, Minutes: 5},
		{Kind: KindDomain, Match: "a.example", Action: "nuke", Minutes: 5},
		{Kind: KindDomain, Match: "a.example", Action: ActBlock, Minutes: 0},
	}
	for i, in := range bad {
		if l := Validate(&in); len(l) == 0 {
			t.Errorf("%d accepted", i)
		}
	}
	in := Input{Kind: KindDomain, Match: "*.Example.COM.", Action: ActRefuse, QPS: 9, Minutes: 1}
	if l := Validate(&in); len(l) > 0 || in.Match != "example.com" || in.QPS != 0 {
		t.Fatal(l, in)
	}
	in = Input{Kind: KindClient, Match: "10.1.2.3/16", Action: ActThrottle, QPS: 5, Minutes: 1}
	if l := Validate(&in); len(l) > 0 || in.Match != "10.1.0.0/16" {
		t.Fatal(l, in)
	}
}

func TestMatchExpiryPersist(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	path := filepath.Join(t.TempDir(), "mitigations.json")
	s, err := Open(path, ck.now)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Index().Empty() || s.Index().Client(netip.MustParseAddr("10.0.0.1")) != nil || s.Index().Domain(wire("x.example")) != nil {
		t.Fatal("empty index")
	}
	mk := func(kind, match, act string, qps, minutes int) Item {
		it, err := s.Create(Input{Kind: kind, Match: match, Action: act, QPS: qps, Minutes: minutes, Reason: "test"}, SourceUser)
		if err != nil {
			t.Fatal(err)
		}
		return it
	}
	wide := mk(KindClient, "10.0.0.0/8", ActThrottle, 2, 10)
	narrow := mk(KindClient, "10.1.2.3", ActBlock, 0, 5)
	v6 := mk(KindClient, "2001:db8::/32", ActRefuse, 0, 10)
	dom := mk(KindDomain, "victim.example", ActBlock, 0, 10)
	sub := mk(KindDomain, "www.victim.example", ActThrottle, 100, 10)
	x := s.Index()
	cases := []struct {
		a    string
		want string
	}{{"10.1.2.3", narrow.ID}, {"10.9.9.9", wide.ID}, {"::ffff:10.1.2.3", narrow.ID}, {"2001:db8:5::1", v6.ID}, {"11.0.0.1", ""}, {"2001:db9::1", ""}}
	for _, c := range cases {
		l := x.Client(netip.MustParseAddr(c.a))
		got := ""
		if l != nil {
			got = l.Item.ID
		}
		if got != c.want {
			t.Errorf("%s -> %q want %q", c.a, got, c.want)
		}
	}
	if l := x.Domain(wire("rnd123.victim.example")); l == nil || l.Item.ID != dom.ID {
		t.Fatal("suffix")
	}
	if l := x.Domain(wire("a.www.victim.example")); l == nil || l.Item.ID != sub.ID {
		t.Fatal("most specific")
	}
	if x.Domain(wire("victim.example.org")) != nil || x.Domain(wire("example")) != nil {
		t.Fatal("false match")
	}
	if n := testing.AllocsPerRun(100, func() { x.Domain(wire2) }); n != 0 {
		t.Fatal("allocs", n)
	}
	// throttle: 2 qps cap
	l := x.Client(netip.MustParseAddr("10.9.9.9"))
	now := ck.now().UnixNano()
	ok := 0
	for i := 0; i < 10; i++ {
		if l.Hit(now) {
			ok++
		}
	}
	if ok != 2 || l.HitCount() != 10 {
		t.Fatal(ok, l.HitCount())
	}
	if !l.Hit(now + int64(time.Second)) {
		t.Fatal("refill")
	}
	// replace same kind+match
	mk(KindClient, "10.0.0.0/8", ActRefuse, 0, 10)
	if len(s.List()) != 5 {
		t.Fatal(len(s.List()))
	}
	if err := s.Delete("nope"); err == nil {
		t.Fatal("delete missing")
	}
	if err := s.Delete(v6.ID); err != nil {
		t.Fatal(err)
	}
	ck.add(6 * time.Minute)
	gone := s.Sweep()
	if len(gone) != 1 || gone[0].ID != narrow.ID || gone[0].Hits != 0 {
		t.Fatal(gone)
	}
	if s.Index().Client(netip.MustParseAddr("10.1.2.3")).Item.Action != ActRefuse {
		t.Fatal("after expiry the wider one applies")
	}
	s2, err := Open(path, ck.now)
	if err != nil || len(s2.List()) != 3 {
		t.Fatal(err, len(s2.List()))
	}
	if _, ok := s2.Find(KindDomain, "victim.example"); !ok {
		t.Fatal("find")
	}
}

var wire2 = wire("a.b.c.victim.example")

func TestMax(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "m.json"), nil)
	for i := 0; i < Max; i++ {
		s.mu.Lock()
		l, _ := compileItem(Item{ID: fmt.Sprint(i), Kind: KindClient, Match: fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255),
			Action: ActBlock, ExpiresAt: time.Now().Add(time.Hour)})
		s.m[l.Item.ID] = l
		s.mu.Unlock()
	}
	if _, err := s.Create(Input{Kind: KindDomain, Match: "x.example", Action: ActBlock, Minutes: 1}, SourceUser); err == nil {
		t.Fatal("limit")
	}
}

func BenchmarkClientLookup(b *testing.B) {
	s, _ := Open(filepath.Join(b.TempDir(), "m.json"), nil)
	for i := 0; i < 1000; i++ {
		s.Create(Input{Kind: KindClient, Match: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), Action: ActBlock, Minutes: 10}, SourceUser)
	}
	x := s.Index()
	a := netip.MustParseAddr("10.3.7.9")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		x.Client(a)
	}
}
