package engine

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/events"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/mitigate"
	"mrk/dns-engine/internal/pressure"
	"mrk/dns-engine/internal/querylog"
	"mrk/dns-engine/internal/testutil"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newEngineClock(t testing.TB, upstream string, ck *fakeClock, mut func(s *config.Settings)) *Engine {
	t.Helper()
	e, err := Open(Options{DataDir: t.TempDir(), DefaultListen: "127.0.0.1:5399", Now: ck.now,
		DiskFree: func(string) (float64, error) { return 80, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	s, v := e.Settings()
	s.Upstreams = []config.Upstream{{ID: "test", Address: upstream, Enabled: true}}
	s.Limits.ClientQPS, s.Limits.ClientBurst = 0, 0
	s.Pressure.Enabled = false
	s.DNSSEC.Mode = config.DNSSECOff
	if mut != nil {
		mut(&s)
	}
	if _, _, err := e.PutSettings(s, v); err != nil {
		t.Fatal(err)
	}
	return e
}

func logSearch(t *testing.T, e *Engine, q string) []querylog.Item {
	t.Helper()
	e.FlushMonitor()
	v, _ := url.ParseQuery(q)
	f, err := querylog.ParseFilter(v)
	if err != nil {
		t.Fatal(err)
	}
	res := e.QueryLog().Search(context.Background(), f, 2*time.Second)
	out := make([]querylog.Item, 0, len(res.Rows))
	for i := range res.Rows {
		out = append(out, querylog.View(&res.Rows[i]))
	}
	return out
}

func TestQueryLogAndStatsFromQueries(t *testing.T) {
	ck := &fakeClock{t: time.Now()}
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	e := newEngineClock(t, up.Addr, ck, func(s *config.Settings) { s.Limits.ClientQPS, s.Limits.ClientBurst = 5, 5 })
	other := netip.MustParseAddr("192.168.1.77")
	ask(t, e, lan, UDP, query("WWW.Example.org.", dns.TypeA)) // miss: upstream
	ask(t, e, lan, UDP, query("www.example.org.", dns.TypeA)) // hit: fast path
	ask(t, e, lan, TCP, query("www.example.org.", dns.TypeA))
	ask(t, e, public, UDP, query("www.example.org.", dns.TypeA)) // refused by query_allow
	for i := 0; i < 8; i++ {
		ask(t, e, other, UDP, query("rate.example.org.", dns.TypeA)) // 5 allowed, then rate limited
	}
	items := logSearch(t, e, "name=www.example.org&limit=100")
	if len(items) != 4 {
		t.Fatalf("%d %+v", len(items), items)
	}
	// newest first
	if items[0].Source != "refused" || items[0].Rcode != "REFUSED" || items[0].Client != public.String() {
		t.Fatalf("%+v", items[0])
	}
	if items[1].Source != "cache" || items[1].Proto != "tcp" || !items[1].Flags.Cached {
		t.Fatalf("%+v", items[1])
	}
	if items[3].Source != "upstream" || items[3].Upstream != "test" || items[3].Name != "www.example.org" || items[3].QType != "A" {
		t.Fatalf("%+v", items[3])
	}
	if rl := logSearch(t, e, "source=rate_limited"); len(rl) != 3 {
		t.Fatalf("rate limited %d", len(rl))
	}
	if b := logSearch(t, e, "blocked=true"); len(b) != 4 {
		t.Fatalf("blocked %d", len(b))
	}
	st := e.QueryLog().Status()
	if st.WrittenTotal != 12 || st.ModeEffective != "all" || st.DiskFreePercent == nil {
		t.Fatalf("%+v", st)
	}
	r, ok := e.Stats("1h")
	if !ok || r.Totals.Queries != 12 || r.Totals.ByRcode["REFUSED"] != 4 || r.Totals.BySource["cache"] != 6 {
		t.Fatalf("%+v", r.Totals)
	}
	if len(r.Top.Domains) == 0 || r.Top.Domains[0].Name != "rate.example.org" {
		t.Fatalf("%+v", r.Top)
	}
	// hot apply: logging off stops storage, stats continue
	s, v := e.Settings()
	s.QueryLog.Mode = config.LogOff
	if _, _, err := e.PutSettings(s, v); err != nil {
		t.Fatal(err)
	}
	ask(t, e, lan, UDP, query("www.example.org.", dns.TypeA))
	e.FlushMonitor()
	if e.QueryLog().Status().WrittenTotal != 12 || e.QueryLog().Status().ModeEffective != "off" {
		t.Fatal("still logging")
	}
	if r, _ := e.Stats("1h"); r.Totals.Queries != 13 {
		t.Fatal("stats depend on logging", r.Totals.Queries)
	}
}

func TestMonitorSettingsValidation(t *testing.T) {
	e := newEngine(t, "", nil)
	s, v := e.Settings()
	s.QueryLog.Mode = "loud"
	s.QueryLog.ExcludeNames = []string{"ok.example", "bad name"}
	s.Stats.TopK = 1
	s.Pressure.Thresholds.Critical.CPU = 50 // below warning 70
	s.Pressure.AttackDetection.Mode = "nuke"
	_, _, err := e.PutSettings(s, v)
	fe, ok := err.(*fielderr.Error)
	if !ok || fe.Code != CodeSettingsInvalid {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range fe.Fields {
		got[f.Field] = true
	}
	for _, f := range []string{"querylog.mode", "querylog.exclude_names[1]", "stats.top_k", "pressure.thresholds.critical.cpu",
		"pressure.attack_detection.mode"} {
		if !got[f] {
			t.Errorf("missing %s in %v", f, fe.Fields)
		}
	}
	if _, v2 := e.Settings(); v2 != v {
		t.Fatal("version changed on invalid settings")
	}
}

func TestFastPathAllocationFree(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	e := newEngine(t, up.Addr, nil)
	pkt := query("www.example.org.", dns.TypeA)
	ask(t, e, lan, UDP, pkt)
	sc := NewScratch()
	if _, v := e.Fast(pkt, lan, UDP, sc); v != Reply {
		t.Fatal("not a cache hit")
	}
	n := testing.AllocsPerRun(1000, func() {
		if _, v := e.Fast(pkt, lan, UDP, sc); v != Reply {
			t.Fatal("miss")
		}
	})
	if n != 0 {
		t.Fatalf("fast path allocates %v per query with logging on", n)
	}
}

func BenchmarkFastHitLogging(b *testing.B) {
	up := testutil.StartUpstream(b, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	for _, mode := range []string{config.LogAll, config.LogOff} {
		b.Run(mode, func(b *testing.B) {
			e := newEngine(b, up.Addr, func(s *config.Settings) { s.QueryLog.Mode = mode })
			pkt := query("www.example.org.", dns.TypeA)
			ask(b, e, lan, UDP, pkt)
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				sc := NewScratch()
				for pb.Next() {
					e.Fast(pkt, lan, UDP, sc)
				}
			})
		})
	}
}

func TestMitigationsInQueryPath(t *testing.T) {
	ck := &fakeClock{t: time.Now()}
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	e := newEngineClock(t, up.Addr, ck, nil)
	bad := netip.MustParseAddr("192.168.5.5")
	mk := func(in mitigate.Input) mitigate.Item {
		it, err := e.CreateMitigation(in)
		if err != nil {
			t.Fatal(err)
		}
		return it
	}
	ask(t, e, lan, UDP, query("cached.blocked.example.", dns.TypeA))
	cb := mk(mitigate.Input{Kind: "client", Match: "192.168.5.0/24", Action: "block", Minutes: 5})
	if r := ask(t, e, bad, UDP, query("www.example.org.", dns.TypeA)); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("client block: %v", r)
	}
	mk(mitigate.Input{Kind: "domain", Match: "blocked.example", Action: "block", Minutes: 10})
	r := ask(t, e, lan, UDP, query("cached.blocked.example.", dns.TypeA)) // even cached names
	if r == nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("domain block: %v", r)
	}
	if opt := r.IsEdns0(); opt == nil || len(opt.Option) == 0 {
		t.Fatal("no EDE on blocked answer")
	}
	mk(mitigate.Input{Kind: "domain", Match: "slow.example", Action: "throttle", QPS: 2, Minutes: 10})
	before := up.Queries.Load()
	refused := 0
	for i := 0; i < 10; i++ {
		if r := ask(t, e, lan, UDP, query(fmt.Sprintf("r%d.slow.example.", i), dns.TypeA)); r != nil && r.Rcode == dns.RcodeRefused {
			refused++
		}
	}
	if up.Queries.Load()-before > 3 || refused < 7 {
		t.Fatalf("throttle: upstream %d refused %d", up.Queries.Load()-before, refused)
	}
	// cached names under a throttled domain are always answered
	ask(t, e, lan, UDP, query("r0.slow.example.", dns.TypeA))
	for i := 0; i < 5; i++ {
		if r := ask(t, e, lan, UDP, query("r0.slow.example.", dns.TypeA)); r == nil || r.Rcode != 0 {
			t.Fatal("cached answer throttled")
		}
	}
	items := logSearch(t, e, "source=mitigated&limit=100")
	if len(items) < 9 {
		t.Fatalf("mitigated rows %d", len(items))
	}
	// expiry: events and the query path recovers
	after := e.EventRing().Last()
	ck.add(6 * time.Minute)
	e.MonitorTick()
	evs, _ := e.Events(after, 0)
	if len(evs) != 1 || evs[0].Type != events.MitigationExpired || evs[0].Data["id"] != cb.ID {
		t.Fatalf("%+v", evs)
	}
	if r := ask(t, e, bad, UDP, query("www.example.org.", dns.TypeA)); r == nil || r.Rcode != 0 {
		t.Fatal("still blocked after expiry")
	}
	if err := e.DeleteMitigation("nope"); err == nil {
		t.Fatal("delete unknown")
	}
	if len(e.Mitigations()) != 2 {
		t.Fatal(len(e.Mitigations()))
	}
}

func TestPressureActionsInQueryPath(t *testing.T) {
	ck := &fakeClock{t: time.Now()}
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	e := newEngineClock(t, up.Addr, ck, func(s *config.Settings) {
		s.Pressure.Enabled = true
		s.Pressure.DwellSeconds = 5
		s.Limits.ClientQPS, s.Limits.ClientBurst = 100, 100
	})
	heavy := netip.MustParseAddr("192.168.9.9")
	// heavy client makes up most traffic in the hot window
	for i := 0; i < 600; i++ {
		e.mon.hot.Observe("x.example", pressure.ClientKeyString(heavy), heavy)
	}
	e.mon.hot.Tick(1, 1000)
	for i := 0; i < 2; i++ {
		e.mon.ctl.Step(pressure.Metrics{CPUPercent: 99})
		ck.add(time.Second)
	}
	e.applyActions()
	if e.PressureLevel() != "emergency" {
		t.Fatal(e.PressureLevel())
	}
	a := e.acts()
	if !a.RefuseHeavy || !a.DisablePrefetch || !a.PreferStale || a.ClientQPSScale != 0.25 {
		t.Fatalf("%+v", a)
	}
	if e.pol.Load().clientLim.Scale() != 0.25 || e.QueryLog().ModeEffective() != config.LogOff {
		t.Fatal("limiter scale or log mode not applied")
	}
	if r := ask(t, e, heavy, UDP, query("www.example.org.", dns.TypeA)); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("heavy client answered: %v", r)
	}
	if r := ask(t, e, lan, UDP, query("www.example.org.", dns.TypeA)); r == nil || r.Rcode != 0 {
		t.Fatalf("normal client refused: %v", r)
	}
	if r := ask(t, e, lan, TCP, query("www.example.org.", dns.TypeANY)); r == nil || len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeHINFO {
		t.Fatalf("minimal ANY: %v", r)
	}
	pv := e.Pressure()
	if pv.Level != "emergency" || len(pv.ActiveActions) != 6 || len(pv.Hot.Clients) == 0 {
		t.Fatalf("%+v", pv)
	}
	// drop back to normal (one level per dwell), actions revert
	for i := 0; i < 30; i++ {
		e.mon.ctl.Step(pressure.Metrics{CPUPercent: 5})
		ck.add(time.Second)
	}
	e.applyActions()
	if e.PressureLevel() != "normal" || e.acts().RefuseHeavy || e.pol.Load().clientLim.Scale() != 1 ||
		e.QueryLog().ModeEffective() != config.LogAll {
		t.Fatal("not reverted", e.PressureLevel())
	}
	if r := ask(t, e, heavy, UDP, query("www.example.org.", dns.TypeA)); r == nil || r.Rcode != 0 {
		t.Fatal("heavy client still refused at normal")
	}
	// host metrics
	if !e.HostMetrics(50, 60, 1, ck.now()) || e.HostMetrics(50, 60, 1, ck.now().Add(-2*time.Minute)) {
		t.Fatal("host metrics freshness")
	}
}

// Integration: a random-subdomain flood is detected, an automatic mitigation
// caps upstream work for the victim while normal clients keep getting
// answers, and everything recovers after the flood and the mitigation end.
func TestRandomSubdomainFloodIntegration(t *testing.T) {
	ck := &fakeClock{t: time.Now()}
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg {
		if dns.IsSubDomain("victim.example.", q.Name) && q.Name != "www.victim.example." {
			return testutil.NX(q, 60)
		}
		return testutil.A(q, 300, "93.184.216.34")
	})
	e := newEngineClock(t, up.Addr, ck, func(s *config.Settings) {
		s.Pressure.AttackDetection.Mode = config.AttackAuto
		s.Pressure.AttackDetection.NXDomainUniquePerMinute = 200
		s.Pressure.AttackDetection.MitigationMinutes = 5
	})
	attacker := netip.MustParseAddr("192.168.66.6")
	normal := netip.MustParseAddr("192.168.1.20")
	ask(t, e, normal, UDP, query("www.victim.example.", dns.TypeA)) // cached before the attack
	start := e.EventRing().Last()
	n := 0
	var mitigated bool
	for sec := 0; sec < 40 && !mitigated; sec++ {
		for i := 0; i < 15; i++ {
			ask(t, e, attacker, UDP, query(fmt.Sprintf("x%05d.victim.example.", n), dns.TypeA))
			n++
		}
		e.FlushMonitor()
		ck.add(time.Second)
		e.MonitorTick()
		mitigated = len(e.Mitigations()) > 0
	}
	if !mitigated {
		t.Fatalf("no automatic mitigation after %d unique names", n)
	}
	evs, _ := e.Events(start, 0)
	types := map[string]int{}
	for _, ev := range evs {
		types[ev.Type]++
	}
	if types[events.AttackDetected] != 1 || types[events.MitigationAuto] != 1 {
		t.Fatalf("%v", types)
	}
	m := e.Mitigations()[0]
	if m.Kind != "domain" || m.Match != "victim.example" || m.Source != "auto" || m.Action != "throttle" {
		t.Fatalf("%+v", m)
	}
	pv := e.Pressure()
	if len(pv.Hot.Attacks) != 1 || pv.Hot.Attacks[0].Parent != "victim.example" || pv.Hot.Attacks[0].MitigationID != m.ID ||
		pv.Hot.Attacks[0].TopClients[0] != attacker.String() {
		t.Fatalf("%+v", pv.Hot.Attacks)
	}
	// the flood continues: upstream work for the victim is capped
	before := up.Queries.Load()
	for i := 0; i < 200; i++ {
		ask(t, e, attacker, UDP, query(fmt.Sprintf("y%05d.victim.example.", i), dns.TypeA))
	}
	if d := up.Queries.Load() - before; d > int64(m.QPS)+20 {
		t.Fatalf("upstream got %d queries during mitigation (cap %d qps)", d, m.QPS)
	}
	// normal clients are still answered: cached victim names and other domains
	if r := ask(t, e, normal, UDP, query("www.victim.example.", dns.TypeA)); r == nil || r.Rcode != 0 || len(r.Answer) != 1 {
		t.Fatalf("cached victim name: %v", r)
	}
	if r := ask(t, e, normal, UDP, query("www.other.example.", dns.TypeA)); r == nil || r.Rcode != 0 {
		t.Fatalf("other domain: %v", r)
	}
	// recovery: flood stops, the attack ends, then the mitigation expires
	for sec := 0; sec < 80; sec++ {
		ck.add(time.Second)
		e.MonitorTick()
	}
	if len(e.Pressure().Hot.Attacks) != 0 {
		t.Fatal("attack did not end")
	}
	ck.add(5 * time.Minute)
	e.MonitorTick()
	if len(e.Mitigations()) != 0 {
		t.Fatal("mitigation did not expire")
	}
	evs, _ = e.Events(start, 0)
	if evs[len(evs)-1].Type != events.MitigationExpired {
		t.Fatalf("%+v", evs[len(evs)-1])
	}
	before = up.Queries.Load()
	for i := 0; i < 30; i++ {
		ask(t, e, normal, UDP, query(fmt.Sprintf("z%05d.victim.example.", i), dns.TypeA))
	}
	if up.Queries.Load()-before != 30 {
		t.Fatal("upstream still capped after expiry")
	}
	// the flood is in the query log with its outcome
	if rows := logSearch(t, e, "name=*.victim.example&source=mitigated&limit=1000"); len(rows) < 100 {
		t.Fatalf("mitigated rows %d", len(rows))
	}
}
