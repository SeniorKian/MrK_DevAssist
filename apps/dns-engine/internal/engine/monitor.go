package engine

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/attack"
	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/events"
	"mrk/dns-engine/internal/limits"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/mitigate"
	"mrk/dns-engine/internal/pressure"
	"mrk/dns-engine/internal/querylog"
	"mrk/dns-engine/internal/stats"
	"mrk/dns-engine/internal/wire"
)

// pipelineInterval is how often the pipeline drains the hot-path ring.
const pipelineInterval = 50 * time.Millisecond

// monitor owns the D2 components: query log, statistics, pressure
// controller, hot lists, attack detector, mitigations and events.
type monitor struct {
	now     func() time.Time
	ring    *querylog.Ring
	ql      *querylog.Logger
	st      *stats.Stats
	ctl     *pressure.Controller
	sampler *pressure.Sampler
	hot     *pressure.Hot
	det     *attack.Detector
	mit     *mitigate.Store
	ev      *events.Ring

	actions atomic.Pointer[pressure.Actions]
	heavy   atomic.Pointer[map[netip.Addr]struct{}]

	mu         sync.Mutex // serialises draining/processing/ticks (single ring consumer)
	recs       []querylog.Record
	spare      []querylog.Record
	order      []int32
	names      []string
	clients    []string
	keys       []string
	addrs      []netip.Addr
	nxNames    []string
	nxKeys     []string
	keyCache   map[netip.Addr]string
	observed   uint64
	ringDrops  uint64
	dropWin    [61]uint64
	dropPos    int
	ticks      int
	attackMode string
}

var scratchCtr atomic.Uint32

func ringShards() int {
	n := runtime.GOMAXPROCS(0) * 2
	if n > 64 {
		n = 64
	}
	return n
}

func (e *Engine) openMonitor() error {
	now := e.opts.Now
	m := &monitor{now: now, keyCache: map[netip.Addr]string{}, ev: events.New(now)}
	shards := ringShards()
	per := 65536 / shards
	if per < 4096 {
		per = 4096
	}
	m.ring = querylog.NewRing(shards, per)
	s := e.settings
	ql, warns := querylog.Open(querylog.Options{Dir: filepath.Join(e.opts.DataDir, "querylog"), Now: now,
		DiskFree: e.opts.DiskFree,
		Events: func(typ, sev string, data map[string]any) {
			m.ev.Emit(typ, sev, data)
		}}, s.QueryLog)
	for _, w := range warns {
		e.log.Warn("query log", "err", w)
	}
	if ql == nil {
		return fmt.Errorf("open query log: %v", warns)
	}
	m.ql = ql
	st, err := stats.Open(filepath.Join(e.opts.DataDir, "stats"), s.Stats, m.ring.Shards(), now)
	if err != nil {
		return fmt.Errorf("open stats: %w", err)
	}
	m.st = st
	m.ctl = pressure.New(s.Pressure, now)
	m.sampler = pressure.NewSampler()
	m.hot = pressure.NewHot()
	m.det = attack.New(s.Pressure.AttackDetection.NXDomainUniquePerMinute, now)
	m.attackMode = s.Pressure.AttackDetection.Mode
	mit, err := mitigate.Open(filepath.Join(e.opts.DataDir, "mitigations.json"), now)
	if err != nil {
		return err
	}
	m.mit = mit
	acts := pressure.ActionsFor(pressure.Normal, s.Pressure.Actions)
	m.actions.Store(&acts)
	empty := map[netip.Addr]struct{}{}
	m.heavy.Store(&empty)
	e.mon = m
	return nil
}

// applyMonitorSettings hot-applies the D2 sections (e.mu held).
func (e *Engine) applyMonitorSettings(s config.Settings) {
	m := e.mon
	m.ql.Configure(s.QueryLog)
	m.st.Configure(s.Stats)
	m.ctl.Configure(s.Pressure)
	m.det.SetThreshold(s.Pressure.AttackDetection.NXDomainUniquePerMinute)
	m.mu.Lock()
	if s.Pressure.AttackDetection.Mode == config.AttackOff && m.attackMode != config.AttackOff {
		m.det.Reset()
	}
	m.attackMode = s.Pressure.AttackDetection.Mode
	m.mu.Unlock()
	e.applyActions()
}

// applyActions publishes the controller's actions to the query path.
func (e *Engine) applyActions() {
	m := e.mon
	acts := m.ctl.Actions()
	m.actions.Store(&acts)
	m.ql.SetPressure(acts.LogPressure)
	if p := e.pol.Load(); p != nil {
		p.clientLim.SetScale(acts.ClientQPSScale)
	}
	h := map[netip.Addr]struct{}{}
	if acts.RefuseHeavy {
		h = m.hot.Heavy()
	}
	m.heavy.Store(&h)
}

func (e *Engine) acts() *pressure.Actions { return e.mon.actions.Load() }

// heavyClient reports whether refuse_heavy_clients applies to a.
func (e *Engine) heavyClient(a netip.Addr) bool {
	h := *e.mon.heavy.Load()
	if len(h) == 0 {
		return false
	}
	_, ok := h[limits.ClientKey(a)]
	return ok
}

func protoCode(p Proto) uint8 {
	switch p {
	case TCP:
		return querylog.ProtoTCP
	case DoT:
		return querylog.ProtoDoT
	case DoH:
		return querylog.ProtoDoH
	case DoQ:
		return querylog.ProtoDoQ
	}
	return querylog.ProtoUDP
}

// record feeds the statistics counters and the query-log ring. It never
// blocks or allocates.
func (e *Engine) record(shard uint32, start int64, client netip.Addr, proto Proto, qtype uint16, name []byte,
	rcode int, src uint8, size int, flags uint8, upstream string) {
	now := time.Now().UnixNano()
	d := (now - start) / 1000
	if d < 0 {
		d = 0
	}
	if size > 65535 {
		size = 65535
	}
	h := querylog.Hdr{TS: start, Client: client, Upstream: upstream, DurUS: uint32(d), Size: uint16(size), QType: qtype,
		Rcode: uint8(rcode & 15), Source: src, Proto: protoCode(proto), Flags: flags}
	e.mon.st.C.Observe(shard, h.Rcode, src, qtype, h.DurUS, flags)
	e.mon.st.C.ObserveProto(shard, h.Proto)
	e.mon.ring.Put(shard, &h, name)
}

func slowShard() uint32 { return rand.Uint32() }

// lowerWire packs a presentation name into buf as lower-case wire form.
func lowerWire(name string, buf []byte) []byte {
	n, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		return buf[:0]
	}
	b := buf[:n]
	for off := 0; off < len(b); {
		l := int(b[off])
		if l == 0 {
			break
		}
		for i := off + 1; i <= off+l && i < len(b); i++ {
			if c := b[i]; c >= 'A' && c <= 'Z' {
				b[i] = c + 'a' - 'A'
			}
		}
		off += 1 + l
	}
	return b
}

// fastMitigate applies client and domain mitigations on the fast path.
// done=false means continue.
func (e *Engine) fastMitigate(x *mitigate.Index, pkt []byte, q *wire.Query, name []byte, client netip.Addr, proto Proto,
	sc *Scratch, udpMax int, start int64) ([]byte, Verdict, bool) {
	l := x.Client(client)
	domain := false
	if l == nil {
		if l = x.Domain(name); l == nil || l.Action == mitigate.DoThrottle {
			return nil, 0, false // domain throttles apply to upstream work only (resolveCached)
		}
		domain = true
	}
	if l.Hit(start) && l.Action == mitigate.DoThrottle {
		return nil, 0, false
	}
	e.M.Source(metrics.SrcMitigated)
	if l.Action == mitigate.DoThrottle {
		e.M.Drop(metrics.DropMitigation)
		if proto == UDP {
			e.record(sc.Shard, start, client, proto, q.QType, name, dns.RcodeRefused, querylog.SrcMitigated, 0, 0, "")
			return nil, DropIt, true
		}
	}
	rcode := dns.RcodeRefused
	ede := uint16(dns.ExtendedErrorCodeProhibited)
	if domain && l.Action == mitigate.DoBlock {
		rcode, ede = dns.RcodeNameError, dns.ExtendedErrorCodeBlocked
	}
	e.M.Rcode(rcode)
	out := wire.ErrorResponseEDE(sc.Out, pkt, q, rcode, rcode == dns.RcodeNameError, uint16(udpMax), ede)
	sc.Out = out[:0]
	e.record(sc.Shard, start, client, proto, q.QType, name, rcode, querylog.SrcMitigated, len(out), 0, "")
	return out, Reply, true
}

// slowMitigate is fastMitigate for decoded queries; it returns a response
// (or drop=true) when a mitigation applies.
func (e *Engine) slowMitigate(req *dns.Msg, client netip.Addr, proto Proto) (resp *dns.Msg, drop, applied bool) {
	x := e.mon.mit.Index()
	if x.Empty() || len(req.Question) != 1 {
		return nil, false, false
	}
	var nb [256]byte
	name := lowerWire(req.Question[0].Name, nb[:])
	l := x.Client(client)
	domain := false
	if l == nil {
		if l = x.Domain(name); l == nil || l.Action == mitigate.DoThrottle {
			return nil, false, false
		}
		domain = true
	}
	if l.Hit(time.Now().UnixNano()) && l.Action == mitigate.DoThrottle {
		return nil, false, false
	}
	if l.Action == mitigate.DoThrottle {
		e.M.Drop(metrics.DropMitigation)
		if proto == UDP {
			return nil, true, true
		}
	}
	r := new(dns.Msg)
	r.SetReply(req)
	r.Rcode = dns.RcodeRefused
	if domain && l.Action == mitigate.DoBlock {
		r.Rcode = dns.RcodeNameError
		r.RecursionAvailable = true
	}
	return r, false, true
}

// ---------------------------------------------------------------- pipeline

func (e *Engine) pipeline() {
	defer e.wg.Done()
	t := time.NewTicker(pipelineInterval)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-e.bg.Done():
			e.drainMonitor()
			return
		case <-t.C:
		}
		e.drainMonitor()
		if time.Since(last) >= time.Second {
			last = time.Now()
			e.MonitorTick()
		}
	}
}

// drainMonitor moves ring records into stats, hot lists, the attack
// detector and the query log.
func (e *Engine) drainMonitor() {
	m := e.mon
	m.mu.Lock()
	defer m.mu.Unlock()
	for round := 0; round < 4; round++ {
		m.recs = m.ring.Drain(m.recs[:0], 1<<16)
		if len(m.recs) == 0 {
			return
		}
		m.processLocked()
		if len(m.recs) < 1<<16 {
			return
		}
	}
}

// sortBatch orders a drained batch by arrival time (shards drain one after
// the other), so the log stays newest-first across shards.
func (m *monitor) sortBatch() {
	recs := m.recs
	sorted := true
	for i := 1; i < len(recs); i++ {
		if recs[i].TS < recs[i-1].TS {
			sorted = false
			break
		}
	}
	if sorted {
		return
	}
	m.order = m.order[:0]
	for i := range recs {
		m.order = append(m.order, int32(i))
	}
	sort.Slice(m.order, func(a, b int) bool { return recs[m.order[a]].TS < recs[m.order[b]].TS })
	m.spare = m.spare[:0]
	for _, i := range m.order {
		m.spare = append(m.spare, recs[i])
	}
	m.recs, m.spare = m.spare, m.recs
}

func (m *monitor) processLocked() {
	m.sortBatch()
	recs := m.recs
	m.names, m.clients = m.ql.Prepare(recs, m.names[:0], m.clients[:0])
	if len(m.keyCache) > 100_000 {
		clear(m.keyCache)
	}
	m.keys, m.addrs = m.keys[:0], m.addrs[:0]
	m.nxNames, m.nxKeys = m.nxNames[:0], m.nxKeys[:0]
	attackOn := m.attackMode != config.AttackOff
	for i := range recs {
		a := recs[i].Client
		k, ok := m.keyCache[a]
		if !ok {
			k = pressure.ClientKeyString(a)
			m.keyCache[a] = k
		}
		m.keys = append(m.keys, k)
		m.addrs = append(m.addrs, a)
		if attackOn && recs[i].Rcode == dns.RcodeNameError {
			m.nxNames = append(m.nxNames, m.names[i])
			m.nxKeys = append(m.nxKeys, k)
		}
	}
	m.st.ObserveTopBatch(recs, m.names, m.clients)
	m.hot.ObserveBatch(m.names, m.keys, m.addrs)
	if len(m.nxNames) > 0 {
		m.det.ObserveBatch(m.nxNames, m.nxKeys)
	}
	m.ql.Process(recs, m.names, m.clients)
	m.observed += uint64(len(recs))
}

var levelSeverity = map[pressure.Level]string{pressure.Normal: events.Info, pressure.Warning: events.Warning,
	pressure.Critical: events.Error, pressure.Emergency: events.Critical}

// MonitorTick runs the once-a-second work: log maintenance, statistics,
// hot lists, the pressure controller, attack detection and mitigation
// expiry. The pipeline calls it; tests may call it directly.
func (e *Engine) MonitorTick() {
	m := e.mon
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ticks++
	m.ql.Tick()
	m.st.Tick()
	if d := m.ring.Dropped(); d > m.ringDrops {
		m.ql.AddDropped(d - m.ringDrops)
		m.ringDrops = d
	}
	qps, _ := e.M.QPS()
	scale := 1.0
	if m.observed > 0 && qps > float64(m.observed) {
		scale = qps / float64(m.observed)
	}
	m.observed = 0
	m.hot.Tick(scale, e.pol.Load().s.Pressure.CapacityQPS)

	var drops uint64
	for i := range e.M.Drops {
		drops += e.M.Drops[i].Load()
	}
	drops += m.ring.Dropped()
	m.dropPos = (m.dropPos + 1) % len(m.dropWin)
	m.dropWin[m.dropPos] = drops
	oldest := m.dropWin[(m.dropPos+1)%len(m.dropWin)]
	drops1m := drops
	if oldest <= drops && m.ticks > len(m.dropWin) {
		drops1m = drops - oldest
	}

	p := e.pol.Load()
	cfg := p.s.Pressure
	cpu, mem := m.sampler.Sample()
	met := pressure.Metrics{CPUPercent: cpu, MemoryPercent: mem, QPS: qps, InflightUpstream: e.M.Inflight.Load(), Drops1m: drops1m}
	if cfg.CapacityQPS > 0 {
		met.QPSPercent = float64(int64(qps/float64(cfg.CapacityQPS)*1000+0.5)) / 10
	}
	if ch := m.ctl.Step(met); ch != nil {
		m.ev.Emit(events.PressureLevel, levelSeverity[ch.To], map[string]any{"from": ch.From.String(), "level": ch.To.String(),
			"to": ch.To.String(), "reasons": ch.Reasons, "actions": ch.Actions, "metrics": met})
		e.log.Warn("pressure level", "from", ch.From.String(), "to", ch.To.String())
	}
	e.applyActions()

	if m.attackMode != config.AttackOff {
		for _, c := range m.det.Tick() {
			if !c.Started {
				continue
			}
			e.onAttack(c.Attack, cfg.AttackDetection, m.attackMode)
		}
	}
	for _, it := range m.mit.Sweep() {
		m.ev.Emit(events.MitigationExpired, events.Info, map[string]any{"id": it.ID, "kind": it.Kind, "match": it.Match,
			"action": it.Action, "qps": it.QPS, "source": it.Source, "hits": it.Hits, "expires_at": it.ExpiresAt,
			"minutes": int(it.ExpiresAt.Sub(it.CreatedAt) / time.Minute)})
	}
	if m.ticks%60 == 0 {
		_ = m.mit.Save()
	}
}

// onAttack creates a mitigation (auto mode), then emits attack.detected
// (with mitigation_id when one exists) and mitigation.auto.
func (e *Engine) onAttack(a attack.Attack, cfg config.AttackDetection, mode string) {
	m := e.mon
	data := map[string]any{"kind": a.Kind, "parent": a.Parent, "client": a.Client,
		"unique_nxdomain_per_min": a.UniqueNXDomainPerMin, "nxdomain_per_min": a.NXDomainPerMin, "top_clients": a.TopClients,
		"since": a.Since, "mode": mode}
	var created *mitigate.Item
	if mode == config.AttackAuto {
		if it, existing := e.autoMitigate(a, cfg); it != nil {
			data["mitigation_id"] = it.ID
			if !existing {
				created = it
			}
		}
	}
	m.ev.Emit(events.AttackDetected, events.Warning, data)
	if created != nil {
		it := created
		m.ev.Emit(events.MitigationAuto, events.Warning, map[string]any{"id": it.ID, "kind": it.Kind, "match": it.Match,
			"action": it.Action, "qps": it.QPS, "minutes": cfg.MitigationMinutes, "expires_at": it.ExpiresAt, "reason": it.Reason,
			"source": it.Source, "attack": a.Kind, "parent": a.Parent})
	}
}

// autoMitigate creates the automatic mitigation for an attack. existing is
// true when a user mitigation for the same target is kept instead.
func (e *Engine) autoMitigate(a attack.Attack, cfg config.AttackDetection) (*mitigate.Item, bool) {
	m := e.mon
	in := mitigate.Input{Action: mitigate.ActThrottle, Minutes: cfg.MitigationMinutes}
	switch a.Kind {
	case attack.RandomSubdomain:
		// upstream-bound queries under the parent are capped; cached names keep working
		in.Kind, in.Match = mitigate.KindDomain, a.Parent
		in.QPS = max(20, cfg.NXDomainUniquePerMinute/30)
		in.Reason = fmt.Sprintf("auto: random-subdomain attack (%d unique NXDOMAIN/min)", a.UniqueNXDomainPerMin)
	case attack.NXDomainFlood:
		in.Kind, in.Match = mitigate.KindClient, a.Client
		in.QPS = 20
		in.Reason = fmt.Sprintf("auto: NXDOMAIN flood (%d/min)", a.NXDomainPerMin)
	default:
		return nil, false
	}
	if in.Match == "" || len(mitigate.Validate(&in)) > 0 {
		return nil, false
	}
	if old, ok := m.mit.Find(in.Kind, in.Match); ok && old.Source == mitigate.SourceUser {
		m.det.SetMitigation(a.Key(), old.ID) // never override a user decision
		return &old, true
	}
	it, err := m.mit.Create(in, mitigate.SourceAuto)
	if err != nil {
		e.log.Warn("auto mitigation failed", "err", err)
		return nil, false
	}
	m.det.SetMitigation(a.Key(), it.ID)
	return &it, false
}

func (e *Engine) closeMonitor() {
	m := e.mon
	if m == nil {
		return
	}
	if err := m.ql.Close(); err != nil {
		e.log.Warn("query log close", "err", err)
	}
	if err := m.st.Save(); err != nil {
		e.log.Warn("stats save", "err", err)
	}
	_ = m.mit.Save()
}

// ---------------------------------------------------------------- API

// QueryLog returns the query log.
func (e *Engine) QueryLog() *querylog.Logger { return e.mon.ql }

// FlushMonitor processes pending ring records now (tests, before searches
// that must see the newest queries).
func (e *Engine) FlushMonitor() { e.drainMonitor() }

// Stats returns GET /v1/stats for a range.
func (e *Engine) Stats(rangeName string) (stats.Result, bool) { return e.mon.st.Query(rangeName) }

// HotView is the hot part of GET /v1/pressure.
type HotView struct {
	Domains []pressure.HotName   `json:"domains"`
	Clients []pressure.HotClient `json:"clients"`
	Attacks []attack.Attack      `json:"attacks"`
}

// PressureView is GET /v1/pressure.
type PressureView struct {
	pressure.View
	Hot HotView `json:"hot"`
}

// Pressure returns the controller state, hot lists and attacks.
func (e *Engine) Pressure() PressureView {
	m := e.mon
	hv := m.hot.View()
	att := m.det.Active()
	if att == nil {
		att = []attack.Attack{}
	}
	return PressureView{View: m.ctl.Snapshot(), Hot: HotView{Domains: hv.Domains, Clients: hv.Clients, Attacks: att}}
}

// PressureLevel returns the current level name.
func (e *Engine) PressureLevel() string { return e.mon.ctl.Level().String() }

// HostMetrics stores host metrics from the panel; false means ignored (stale).
func (e *Engine) HostMetrics(cpu, mem, load float64, ts time.Time) bool {
	return e.mon.ctl.SetHost(cpu, mem, load, ts)
}

// Mitigations lists active mitigations.
func (e *Engine) Mitigations() []mitigate.Item { return e.mon.mit.List() }

// CreateMitigation adds a user mitigation.
func (e *Engine) CreateMitigation(in mitigate.Input) (mitigate.Item, error) {
	return e.mon.mit.Create(in, mitigate.SourceUser)
}

// DeleteMitigation removes a mitigation.
func (e *Engine) DeleteMitigation(id string) error { return e.mon.mit.Delete(id) }

// Events returns events after seq.
func (e *Engine) Events(after int64, limit int) ([]events.Event, int64) {
	return e.mon.ev.After(after, limit)
}

// EventRing exposes the event ring (tests).
func (e *Engine) EventRing() *events.Ring { return e.mon.ev }

func (e *Engine) monitorGauges() []metrics.Gauge {
	m := e.mon
	st := m.ql.Status()
	lv := float64(m.ctl.Level())
	return []metrics.Gauge{
		{Name: "mrk_dns_querylog_written_total", Help: "Query log rows stored.", Value: float64(st.WrittenTotal)},
		{Name: "mrk_dns_querylog_dropped_total", Help: "Query log rows lost (ring full or write error).", Value: float64(st.DroppedTotal)},
		{Name: "mrk_dns_querylog_bytes", Help: "Query log size on disk.", Value: float64(st.Bytes)},
		{Name: "mrk_dns_pressure_level", Help: "Pressure level (0 normal, 1 warning, 2 critical, 3 emergency).", Value: lv},
		{Name: "mrk_dns_mitigations", Help: "Active mitigations.", Value: float64(len(m.mit.List()))},
	}
}
