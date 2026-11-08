package stats

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/querylog"
)

func TestLatBuckets(t *testing.T) {
	prev := -1
	for _, us := range []uint32{0, 1, 7, 8, 9, 15, 16, 100, 1000, 12345, 1 << 20, math.MaxUint32} {
		b := LatBucket(us)
		if b < prev || b >= NLat {
			t.Fatalf("%d -> %d", us, b)
		}
		prev = b
		if lo := latLower(b); lo > float64(us) || (b+1 < NLat && latLower(b+1) <= float64(us)) {
			t.Fatalf("%d not in bucket %d [%v,%v)", us, b, lo, latLower(b+1))
		}
	}
}

func TestPercentile(t *testing.T) {
	var h [NLat]uint64
	if Percentile(&h, 0.5) != 0 {
		t.Fatal("empty")
	}
	// 1..10000 µs uniformly
	for us := uint32(1); us <= 10000; us++ {
		h[LatBucket(us)]++
	}
	for _, c := range []struct{ q, want float64 }{{0.5, 5}, {0.95, 9.5}, {0.99, 9.9}} {
		got := Percentile(&h, c.q)
		if math.Abs(got-c.want)/c.want > 0.1 {
			t.Fatalf("p%v = %v want ~%v", c.q, got, c.want)
		}
	}
}

func TestCountersConcurrent(t *testing.T) {
	c := NewCounters(8)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				c.Observe(uint32(g), 3, querylog.SrcUpstream, dns.TypeHTTPS, 500)
			}
		}(g)
	}
	wg.Wait()
	s := c.snapshot()
	if s.Queries != 8000 || s.Rcode[3] != 8000 || s.QType[qtSlot(dns.TypeHTTPS)] != 8000 || s.Source[querylog.SrcUpstream] != 8000 {
		t.Fatalf("%+v", s.Queries)
	}
	if n := testing.AllocsPerRun(100, func() { c.Observe(1, 0, 0, 1, 10) }); n != 0 {
		t.Fatal(n)
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func TestRollupsQueryAndPersist(t *testing.T) {
	ck := &clock{t: time.Date(2026, 11, 8, 22, 0, 0, 0, time.UTC)}
	dir := t.TempDir()
	cfg := config.DefaultStats()
	cfg.TopK = 10
	s, err := Open(dir, cfg, 4, ck.now)
	if err != nil {
		t.Fatal(err)
	}
	// 3 hours (crossing midnight), 100 queries per minute: 90 cache + 10 upstream NXDOMAIN
	for m := 0; m < 180; m++ {
		for i := 0; i < 90; i++ {
			s.C.Observe(uint32(i), 0, querylog.SrcCache, dns.TypeA, 200)
			s.ObserveTop("popular.example", "10.0.0.1", 0, querylog.SrcCache)
		}
		for i := 0; i < 10; i++ {
			s.C.Observe(uint32(i), 3, querylog.SrcUpstream, dns.TypeAAAA, 20000)
			s.ObserveTop("nx.example", "10.0.0.2", 3, querylog.SrcUpstream)
		}
		ck.add(time.Minute)
		if !s.Tick() {
			t.Fatal("tick did not close a minute")
		}
	}
	if s.Tick() {
		t.Fatal("double close")
	}
	if len(s.minutes) != 180 || len(s.hours) != 3 || len(s.days) != 1 || len(s.topHour) != 3 || len(s.topDay) != 1 {
		t.Fatalf("minutes %d hours %d days %d tophours %d topdays %d", len(s.minutes), len(s.hours), len(s.days), len(s.topHour), len(s.topDay))
	}
	if s.hours[0].Queries != 6000 || s.days[0].Queries != 12000 { // day of 2026-11-08 had 2 hours
		t.Fatal(s.hours[0].Queries, s.days[0].Queries)
	}
	r, ok := s.Query("1h")
	if !ok || r.ResolutionSeconds != 60 || len(r.Points) != 60 {
		t.Fatal(ok, r.ResolutionSeconds, len(r.Points))
	}
	if r.Totals.Queries != 5900 && r.Totals.Queries != 6000 {
		t.Fatal(r.Totals.Queries)
	}
	p := r.Points[len(r.Points)-2]
	if p.Queries != 100 || p.QPS != 1.667 || p.CacheHitRatio != 0.9 || p.ByRcode["NXDOMAIN"] != 10 || p.BySource["cache"] != 90 {
		t.Fatalf("%+v", p)
	}
	if p.P50 > 0.25 || p.P99 < 15 {
		t.Fatalf("percentiles %v %v", p.P50, p.P99)
	}
	if r.Totals.ByQType["AAAA"] == 0 || r.Top.Domains[0].Name != "popular.example" || r.Top.NXDomain[0].Name != "nx.example" ||
		r.Top.Clients[0].Client != "10.0.0.1" {
		t.Fatalf("%+v", r.Top)
	}
	r24, _ := s.Query("24h")
	if r24.ResolutionSeconds != 900 || len(r24.Points) != 96 || r24.Totals.Queries != 18000 {
		t.Fatal(r24.ResolutionSeconds, len(r24.Points), r24.Totals.Queries)
	}
	// top lists over 24h: minute lists (6h) cover all 3 hours exactly once
	if r24.Top.Domains[0].Count != 180*90 {
		t.Fatal(r24.Top.Domains[0].Count)
	}
	r7, _ := s.Query("7d")
	if r7.ResolutionSeconds != 3600 || len(r7.Points) != 168 || r7.Totals.Queries != 18000 {
		t.Fatal(r7.ResolutionSeconds, len(r7.Points), r7.Totals.Queries)
	}
	r1y, _ := s.Query("1y")
	if r1y.ResolutionSeconds != 86400 || len(r1y.Points) != 365 || r1y.Totals.Queries != 18000 {
		t.Fatal(r1y.ResolutionSeconds, len(r1y.Points), r1y.Totals.Queries)
	}
	for _, rg := range []string{"6h", "30d"} {
		if _, ok := s.Query(rg); !ok {
			t.Fatal(rg)
		}
	}
	if _, ok := s.Query("2h"); ok {
		t.Fatal("unknown range")
	}
	// live counters show up in the open minute
	s.C.Observe(0, 0, querylog.SrcCache, 1, 10)
	r, _ = s.Query("1h")
	if r.Points[len(r.Points)-1].Queries != 1 {
		t.Fatal("live minute")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir, cfg, 4, ck.now)
	if err != nil || len(s2.minutes) != 180 || len(s2.hours) != 3 || s2.hourDone != s.hourDone || len(s2.topMin) != len(s.topMin) {
		t.Fatal(err, len(s2.minutes))
	}
	// pruning by retention
	cfg.MinuteRetentionHours = 1
	s2.Configure(cfg)
	ck.add(time.Minute)
	s2.Tick()
	if len(s2.minutes) > 60 {
		t.Fatal(len(s2.minutes))
	}
}
