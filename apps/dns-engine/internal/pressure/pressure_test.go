package pressure

import (
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/querylog"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func TestHysteresis(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	cfg := config.DefaultPressure() // warning cpu 70, critical 85, emergency 95, exit margin 10, dwell 30
	c := New(cfg, ck.now)
	var trans []string
	step := func(cpu float64, seconds int) {
		for i := 0; i < seconds; i++ {
			if ch := c.Step(Metrics{CPUPercent: cpu}); ch != nil {
				trans = append(trans, fmt.Sprintf("%s>%s", ch.From, ch.To))
			}
			ck.add(time.Second)
		}
	}
	step(50, 5)
	step(72, 1) // one sample is not enough
	if c.Level() != Normal {
		t.Fatal("single sample raised the level")
	}
	step(72, 1)
	if c.Level() != Warning {
		t.Fatal(c.Level())
	}
	step(65, 60) // above exit (60): stays
	if c.Level() != Warning {
		t.Fatal("left warning above exit threshold")
	}
	step(55, 29) // below exit but dwell not reached
	if c.Level() != Warning {
		t.Fatal("dwell")
	}
	step(55, 2)
	if c.Level() != Normal {
		t.Fatal("did not leave warning", c.Level())
	}
	step(99, 2) // straight to emergency
	if c.Level() != Emergency {
		t.Fatal(c.Level())
	}
	v := c.Snapshot()
	if v.Level != "emergency" || len(v.Reasons) != 1 || v.Reasons[0].Metric != MCPU || v.Reasons[0].Threshold != 95 {
		t.Fatalf("%+v", v)
	}
	step(10, 31) // one level per dwell
	if c.Level() != Critical {
		t.Fatal(c.Level())
	}
	step(10, 62)
	if c.Level() != Normal {
		t.Fatal(c.Level())
	}
	want := "[normal>warning warning>normal normal>emergency emergency>critical critical>warning warning>normal]"
	if fmt.Sprint(trans) != want {
		t.Fatal(trans)
	}
	// oscillating around the threshold does not flap
	trans = nil
	for i := 0; i < 60; i++ {
		v := 75.0
		if i%2 == 1 {
			v = 68
		}
		step(v, 1)
	}
	if len(trans) > 1 {
		t.Fatal("flapping", trans)
	}
	cfg.Enabled = false
	c.Configure(cfg)
	if c.Level() != Normal || len(c.Actions().Names) != 0 {
		t.Fatal("disabled")
	}
}

func TestQPSAndHostMetrics(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c := New(config.DefaultPressure(), ck.now)
	if c.SetHost(50, 50, 1, ck.now().Add(-61*time.Second)) {
		t.Fatal("stale host metrics accepted")
	}
	if !c.SetHost(93, 40, 2.5, ck.now()) {
		t.Fatal("fresh rejected")
	}
	c.Step(Metrics{QPSPercent: 20})
	c.Step(Metrics{QPSPercent: 20})
	v := c.Snapshot()
	if c.Level() != Critical || v.Metrics.HostCPUPercent == nil || *v.Metrics.HostCPUPercent != 93 || v.Reasons[0].Metric != MHostCPU {
		t.Fatalf("%v %+v", c.Level(), v)
	}
	ck.add(61 * time.Second) // host metrics expire
	c.Step(Metrics{QPSPercent: 120})
	if v := c.Snapshot(); v.Metrics.HostCPUPercent != nil {
		t.Fatal("expired host metrics still used")
	}
	c.Step(Metrics{QPSPercent: 120})
	if c.Level() != Emergency || c.Snapshot().Reasons[0].Metric != MQPSPercent {
		t.Fatal(c.Level())
	}
}

func TestActions(t *testing.T) {
	all := config.DefaultPressure().Actions
	if a := ActionsFor(Normal, all); len(a.Names) != 0 || a.ClientQPSScale != 1 || a.LogPressure != 0 {
		t.Fatal(a)
	}
	w := ActionsFor(Warning, all)
	if w.LogPressure != querylog.PressureSample25 || !w.DisablePrefetch || w.PreferStale || w.RefuseHeavy || w.ClientQPSScale != 1 {
		t.Fatalf("%+v", w)
	}
	c := ActionsFor(Critical, all)
	if c.LogPressure != querylog.PressureErrorOnly || !c.PreferStale || !c.RefuseHeavy || c.ClientQPSScale != 0.5 || !c.MinimalANY {
		t.Fatalf("%+v", c)
	}
	e := ActionsFor(Emergency, all)
	if e.LogPressure != querylog.PressureOff || e.ClientQPSScale != 0.25 || len(e.Names) != 6 {
		t.Fatalf("%+v", e)
	}
	none := ActionsFor(Emergency, config.Actions{})
	if len(none.Names) != 0 || none.ClientQPSScale != 1 || none.LogPressure != 0 || none.RefuseHeavy {
		t.Fatalf("toggles ignored: %+v", none)
	}
	// actions follow the level (apply and revert)
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	cfg := config.DefaultPressure()
	cfg.DwellSeconds = 1
	ctl := New(cfg, ck.now)
	for i := 0; i < 2; i++ {
		ctl.Step(Metrics{MemoryPercent: 90})
		ck.add(time.Second)
	}
	if !ctl.Actions().RefuseHeavy {
		t.Fatal("not applied")
	}
	for i := 0; i < 6; i++ {
		ctl.Step(Metrics{MemoryPercent: 10})
		ck.add(2 * time.Second)
	}
	if a := ctl.Actions(); a.RefuseHeavy || a.DisablePrefetch || ctl.Level() != Normal {
		t.Fatal("not reverted", a)
	}
}

func TestSampler(t *testing.T) {
	dir := t.TempDir()
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	write := func(name, v string) { os.WriteFile(filepath.Join(dir, name), []byte(v), 0o644) }
	write("cpu.max", "200000 100000\n")
	write("cpu.stat", "usage_usec 1000000\nuser_usec 1\n")
	write("memory.current", "100\n")
	write("memory.max", "400\n")
	lim := int64(math.MaxInt64)
	s := &Sampler{Root: dir, now: ck.now, procCPU: func() (float64, bool) { return 0, false },
		memLimit: func() int64 { return lim }, goMem: func() uint64 { return 50 }}
	if s.CPUs() != 2 {
		t.Fatal(s.CPUs())
	}
	if cpu, mem := s.Sample(); cpu != 0 || mem != 25 {
		t.Fatal(cpu, mem)
	}
	ck.add(time.Second)
	write("cpu.stat", "usage_usec 2500000\n") // 1.5 CPU-seconds in 1 s of 2 CPUs
	lim = 100
	if cpu, mem := s.Sample(); cpu != 75 || mem != 50 {
		t.Fatal(cpu, mem)
	}
	write("cpu.max", "max 100000\n")
	if s.CPUs() < 1 {
		t.Fatal("no quota")
	}
	// fallback to process CPU without cgroup files
	os.Remove(filepath.Join(dir, "cpu.stat"))
	u := 0.0
	s.procCPU = func() (float64, bool) { u += 1e5; return u, true }
	s.Sample()
	ck.add(time.Second)
	if cpu, _ := s.Sample(); cpu <= 0 {
		t.Fatal("process fallback", cpu)
	}
	real := NewSampler()
	real.Sample()
}

func TestHotHeavy(t *testing.T) {
	h := NewHot()
	heavy := netip.MustParseAddr("192.0.2.50")
	lo := netip.MustParseAddr("127.0.0.1")
	v6 := netip.MustParseAddr("2001:db8:1:2::77")
	for s := 0; s < 10; s++ {
		for i := 0; i < 400; i++ {
			h.Observe("flood.example", ClientKeyString(heavy), heavy)
		}
		for i := 0; i < 400; i++ {
			h.Observe("lo.example", ClientKeyString(lo), lo)
		}
		for i := 0; i < 200; i++ {
			h.Observe("v6.example", ClientKeyString(v6), v6)
		}
		for i := 0; i < 100; i++ {
			c := netip.AddrFrom4([4]byte{10, 0, byte(i), 1})
			h.Observe(fmt.Sprintf("n%d.example", i), ClientKeyString(c), c)
		}
		h.Tick(1, 10000)
	}
	hv := h.Heavy()
	if _, ok := hv[heavy]; !ok || len(hv) != 1 {
		t.Fatal("heavy", hv) // loopback excluded, v6 at 18% is below 20%
	}
	v := h.View()
	if v.Clients[0].Client != "127.0.0.1" && v.Clients[0].Client != "192.0.2.50" || v.Domains[0].QPS < 300 {
		t.Fatalf("%+v", v)
	}
	if ClientKeyString(v6) != "2001:db8:1:2::/64" {
		t.Fatal(ClientKeyString(v6))
	}
	// an idle server flags nobody, and a lone normal client (100 qps, 100% of
	// traffic) is not heavy against capacity 50000 (floor 1000 qps)
	h2 := NewHot()
	lone := netip.MustParseAddr("10.0.0.1")
	for s := 0; s < 10; s++ {
		for i := 0; i < 100; i++ {
			h2.Observe("a", "10.0.0.1", lone)
		}
		h2.Tick(1, 50000)
	}
	if len(h2.Heavy()) != 0 {
		t.Fatal("lone client flagged")
	}
}
