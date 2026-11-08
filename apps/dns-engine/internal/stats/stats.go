// Package stats keeps the engine's aggregated statistics, independent of the
// query log (docs/38 §3 GET /v1/stats): sharded lock-free counters on the hot
// path, closed into per-minute buckets (queries, rcode, source, qtype, a
// log-linear latency histogram) that roll up into hours and days, plus
// Space-Saving top-k lists (domains, clients, NXDOMAIN names, refused
// clients). Everything is persisted atomically under <data_dir>/stats.
package stats

import (
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/querylog"
	"mrk/dns-engine/internal/store"
	"mrk/dns-engine/internal/topk"
)

// Latency histogram: bucket i covers [lower(i), lower(i+1)) microseconds.
// Values below 8 µs have exact buckets; above, four buckets per octave
// (≤ 19% relative width).
const NLat = 8 + 29*4

// LatBucket maps a duration in µs to its bucket.
func LatBucket(us uint32) int {
	if us < 8 {
		return int(us)
	}
	o := bits.Len32(us) - 1
	return 8 + (o-3)*4 + int(us>>(o-2))&3
}

func latLower(i int) float64 {
	if i < 8 {
		return float64(i)
	}
	o := (i-8)/4 + 3
	sub := (i - 8) % 4
	return float64(uint64(4+sub) << (o - 2))
}

// qtype slots kept separately; everything else is "other".
var qtSlots = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS, dns.TypePTR, dns.TypeSOA,
	dns.TypeSRV, dns.TypeTXT, dns.TypeANY, dns.TypeHTTPS, dns.TypeSVCB, dns.TypeCAA, dns.TypeDS, dns.TypeDNSKEY}

// NQType is the number of qtype slots (the last is "other").
var NQType = len(qtSlots) + 1

var qtIndex = func() [256]uint8 {
	var t [256]uint8
	for i := range t {
		t[i] = uint8(len(qtSlots))
	}
	for i, q := range qtSlots {
		if q < 256 {
			t[q] = uint8(i)
		}
	}
	return t
}()

func qtSlot(q uint16) int {
	switch {
	case q < 256:
		return int(qtIndex[q])
	case q == dns.TypeHTTPS:
		return 10
	case q == dns.TypeSVCB:
		return 11
	case q == dns.TypeCAA:
		return 12
	}
	return len(qtSlots)
}

const nQTMax = 16

type cshard struct {
	queries atomic.Uint64
	rcode   [16]atomic.Uint64
	source  [querylog.SrcCount]atomic.Uint64
	qtype   [nQTMax]atomic.Uint64
	lat     [NLat]atomic.Uint64
	_       [64]byte
}

// Counters are the hot-path counters (sharded; shard by worker).
type Counters struct {
	shards []cshard
	mask   uint32
}

// NewCounters creates n shards (rounded up to a power of two).
func NewCounters(n int) *Counters {
	s := 1
	for s < n {
		s <<= 1
	}
	return &Counters{shards: make([]cshard, s), mask: uint32(s - 1)}
}

// Observe counts one answered (or dropped) query. It never allocates.
func (c *Counters) Observe(shard uint32, rcode, src uint8, qtype uint16, durUS uint32) {
	s := &c.shards[shard&c.mask]
	s.queries.Add(1)
	s.rcode[rcode&15].Add(1)
	if src < querylog.SrcCount {
		s.source[src].Add(1)
	}
	s.qtype[qtSlot(qtype)].Add(1)
	s.lat[LatBucket(durUS)].Add(1)
}

// Bucket is one aggregation interval.
type Bucket struct {
	TS      int64                     `json:"t"` // unix seconds, start
	Queries uint64                    `json:"q"`
	Rcode   [16]uint64                `json:"rc"`
	Source  [querylog.SrcCount]uint64 `json:"src"`
	QType   [nQTMax]uint64            `json:"qt"`
	Lat     [NLat]uint64              `json:"lat"`
}

func (b *Bucket) add(o *Bucket) {
	b.Queries += o.Queries
	for i := range b.Rcode {
		b.Rcode[i] += o.Rcode[i]
	}
	for i := range b.Source {
		b.Source[i] += o.Source[i]
	}
	for i := range b.QType {
		b.QType[i] += o.QType[i]
	}
	for i := range b.Lat {
		b.Lat[i] += o.Lat[i]
	}
}

func (b *Bucket) sub(o *Bucket) {
	b.Queries -= o.Queries
	for i := range b.Rcode {
		b.Rcode[i] -= o.Rcode[i]
	}
	for i := range b.Source {
		b.Source[i] -= o.Source[i]
	}
	for i := range b.QType {
		b.QType[i] -= o.QType[i]
	}
	for i := range b.Lat {
		b.Lat[i] -= o.Lat[i]
	}
}

func (c *Counters) snapshot() Bucket {
	var b Bucket
	for i := range c.shards {
		s := &c.shards[i]
		b.Queries += s.queries.Load()
		for j := range b.Rcode {
			b.Rcode[j] += s.rcode[j].Load()
		}
		for j := range b.Source {
			b.Source[j] += s.source[j].Load()
		}
		for j := range b.QType {
			b.QType[j] += s.qtype[j].Load()
		}
		for j := range b.Lat {
			b.Lat[j] += s.lat[j].Load()
		}
	}
	return b
}

// Percentile returns the q-quantile (0..1) of a latency histogram in ms.
func Percentile(lat *[NLat]uint64, q float64) float64 {
	var total uint64
	for _, v := range lat {
		total += v
	}
	if total == 0 {
		return 0
	}
	target := q * float64(total)
	var cum float64
	for i, v := range lat {
		if v == 0 {
			continue
		}
		if cum+float64(v) >= target {
			lo := latLower(i)
			hi := lo + 1
			if i+1 < NLat {
				hi = latLower(i + 1)
			}
			frac := (target - cum) / float64(v)
			return (lo + (hi-lo)*frac) / 1000
		}
		cum += float64(v)
	}
	return latLower(NLat-1) / 1000
}

// TopSet is the top-k lists of one interval.
type TopSet struct {
	TS      int64       `json:"t"`
	Domains []topk.Item `json:"d,omitempty"`
	Clients []topk.Item `json:"c,omitempty"`
	NX      []topk.Item `json:"nx,omitempty"`
	Refused []topk.Item `json:"rf,omitempty"`
}

// Top retention (fixed): minute lists 6 h, hour lists 7 days, day lists as
// day_retention_days.
const (
	minuteTopKeep = 6 * time.Hour
	hourTopKeep   = 7 * 24 * time.Hour
)

// Stats is the aggregator. Observe* run on the hot path / pipeline goroutine;
// Tick runs once a second; Query from API goroutines.
type Stats struct {
	C   *Counters
	dir string
	now func() time.Time

	mu       sync.Mutex
	cfg      config.Stats
	last     Bucket // cumulative counters at the last minute close
	curMin   int64  // start of the open minute (unix s)
	minutes  []Bucket
	hours    []Bucket
	days     []Bucket
	hourDone int64
	dayDone  int64
	topMin   []TopSet
	topHour  []TopSet
	topDay   []TopSet
	hourTop  int64
	dayTop   int64

	// current-minute Space-Saving summaries (pipeline goroutine; guarded by mu)
	dom, cli, nx, ref *topk.Summary

	saveMu  sync.Mutex
	saveErr error
}

type persisted struct {
	Version  int      `json:"v"`
	Minutes  []Bucket `json:"minutes"`
	Hours    []Bucket `json:"hours"`
	Days     []Bucket `json:"days"`
	HourDone int64    `json:"hour_done"`
	DayDone  int64    `json:"day_done"`
	TopMin   []TopSet `json:"top_min"`
	TopHour  []TopSet `json:"top_hour"`
	TopDay   []TopSet `json:"top_day"`
	HourTop  int64    `json:"hour_top"`
	DayTop   int64    `json:"day_top"`
}

const fileName = "stats.json.zst"

var (
	zenc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
	zdec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(512<<20))
)

// Open loads persisted statistics from dir (created if missing).
func Open(dir string, cfg config.Stats, shards int, now func() time.Time) (*Stats, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	s := &Stats{C: NewCounters(shards), dir: dir, now: now, cfg: cfg}
	s.resetTop()
	s.curMin = minuteOf(now())
	raw, err := os.ReadFile(filepath.Join(dir, fileName))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		var p persisted
		if b, derr := zdec.DecodeAll(raw, nil); derr != nil || json.Unmarshal(b, &p) != nil || p.Version != 1 {
			_ = os.Rename(filepath.Join(dir, fileName), filepath.Join(dir, fileName+".bad"))
		} else {
			s.minutes, s.hours, s.days = p.Minutes, p.Hours, p.Days
			s.hourDone, s.dayDone = p.HourDone, p.DayDone
			s.topMin, s.topHour, s.topDay = p.TopMin, p.TopHour, p.TopDay
			s.hourTop, s.dayTop = p.HourTop, p.DayTop
		}
	}
	return s, nil
}

func (s *Stats) resetTop() {
	m := max(4*s.cfg.TopK, 512)
	s.dom, s.cli, s.nx, s.ref = topk.New(m), topk.New(m), topk.New(m), topk.New(m)
}

func minuteOf(t time.Time) int64 { return t.Unix() / 60 * 60 }

// Configure applies new settings.
func (s *Stats) Configure(cfg config.Stats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.TopK != s.cfg.TopK {
		s.cfg = cfg
		s.resetTop()
	}
	s.cfg = cfg
}

// ObserveTop feeds the top-k summaries (pipeline goroutine). client is the
// display form under the query-log privacy mode.
func (s *Stats) ObserveTop(name, client string, rcode, src uint8) {
	s.mu.Lock()
	s.dom.Add(name, 1)
	if client != "" {
		s.cli.Add(client, 1)
	}
	if rcode == dns.RcodeNameError {
		s.nx.Add(name, 1)
	}
	if client != "" && (rcode == dns.RcodeRefused || querylog.Blocked(src)) {
		s.ref.Add(client, 1)
	}
	s.mu.Unlock()
}

// Tick closes finished minutes, rolls up hours and days, prunes and persists.
// It returns true when something was closed.
func (s *Stats) Tick() bool {
	now := s.now()
	m := minuteOf(now)
	s.mu.Lock()
	if m <= s.curMin {
		s.mu.Unlock()
		return false
	}
	cur := s.C.snapshot()
	b := cur
	b.sub(&s.last)
	b.TS = s.curMin
	s.last = cur
	if b.Queries > 0 {
		s.minutes = append(s.minutes, b)
	}
	k := s.cfg.TopK
	if s.dom.Total() > 0 {
		s.topMin = append(s.topMin, TopSet{TS: s.curMin, Domains: s.dom.Top(k), Clients: s.cli.Top(k), NX: s.nx.Top(k),
			Refused: s.ref.Top(k)})
	}
	s.dom.Reset()
	s.cli.Reset()
	s.nx.Reset()
	s.ref.Reset()
	s.curMin = m
	s.rollupLocked(m)
	s.pruneLocked(now)
	p := s.persistLocked()
	s.mu.Unlock()
	s.save(p)
	return true
}

// rollupLocked aggregates closed hours (from minutes) and days (from hours).
func (s *Stats) rollupLocked(openMin int64) {
	openHour := openMin / 3600 * 3600
	agg := func(src []Bucket, done *int64, unit, open int64, dst *[]Bucket) {
		var acc *Bucket
		for i := range src {
			u := src[i].TS / unit * unit
			if u <= *done || u >= open {
				continue
			}
			if acc != nil && acc.TS != u {
				*dst = append(*dst, *acc)
				*done = acc.TS
				acc = nil
			}
			if acc == nil {
				acc = &Bucket{TS: u}
			}
			acc.add(&src[i])
		}
		if acc != nil {
			*dst = append(*dst, *acc)
			*done = acc.TS
		}
	}
	agg(s.minutes, &s.hourDone, 3600, openHour, &s.hours)
	openDay := openMin / 86400 * 86400
	agg(s.hours, &s.dayDone, 86400, openDay, &s.days)
	k := s.cfg.TopK
	aggTop := func(src []TopSet, done *int64, unit, open int64, dst *[]TopSet) {
		groups := map[int64][]TopSet{}
		var keys []int64
		for _, t := range src {
			u := t.TS / unit * unit
			if u <= *done || u >= open {
				continue
			}
			if _, ok := groups[u]; !ok {
				keys = append(keys, u)
			}
			groups[u] = append(groups[u], t)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, u := range keys {
			*dst = append(*dst, mergeTop(u, k, groups[u]))
			*done = u
		}
	}
	aggTop(s.topMin, &s.hourTop, 3600, openHour, &s.topHour)
	aggTop(s.topHour, &s.dayTop, 86400, openDay, &s.topDay)
}

func mergeTop(ts int64, k int, sets []TopSet) TopSet {
	var d, c, n, r [][]topk.Item
	for _, t := range sets {
		d, c, n, r = append(d, t.Domains), append(c, t.Clients), append(n, t.NX), append(r, t.Refused)
	}
	return TopSet{TS: ts, Domains: topk.Merge(k, d...), Clients: topk.Merge(k, c...), NX: topk.Merge(k, n...),
		Refused: topk.Merge(k, r...)}
}

func pruneB(b []Bucket, cut int64) []Bucket {
	i := sort.Search(len(b), func(i int) bool { return b[i].TS >= cut })
	if i == 0 {
		return b
	}
	return append(b[:0:0], b[i:]...)
}

func pruneT(b []TopSet, cut int64) []TopSet {
	i := sort.Search(len(b), func(i int) bool { return b[i].TS >= cut })
	if i == 0 {
		return b
	}
	return append(b[:0:0], b[i:]...)
}

func (s *Stats) pruneLocked(now time.Time) {
	c := s.cfg
	s.minutes = pruneB(s.minutes, now.Add(-time.Duration(c.MinuteRetentionHours)*time.Hour).Unix())
	s.hours = pruneB(s.hours, now.Add(-time.Duration(c.HourRetentionDays)*24*time.Hour).Unix())
	s.days = pruneB(s.days, now.Add(-time.Duration(c.DayRetentionDays)*24*time.Hour).Unix())
	s.topMin = pruneT(s.topMin, now.Add(-min(minuteTopKeep, time.Duration(c.MinuteRetentionHours)*time.Hour)).Unix())
	s.topHour = pruneT(s.topHour, now.Add(-min(hourTopKeep, time.Duration(c.HourRetentionDays)*24*time.Hour)).Unix())
	s.topDay = pruneT(s.topDay, now.Add(-time.Duration(c.DayRetentionDays)*24*time.Hour).Unix())
}

func (s *Stats) persistLocked() persisted {
	return persisted{Version: 1, Minutes: append([]Bucket(nil), s.minutes...), Hours: append([]Bucket(nil), s.hours...),
		Days: append([]Bucket(nil), s.days...), HourDone: s.hourDone, DayDone: s.dayDone,
		TopMin: append([]TopSet(nil), s.topMin...), TopHour: append([]TopSet(nil), s.topHour...),
		TopDay: append([]TopSet(nil), s.topDay...), HourTop: s.hourTop, DayTop: s.dayTop}
}

func (s *Stats) save(p persisted) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	b, err := json.Marshal(p)
	if err == nil {
		err = store.WriteFileAtomic(filepath.Join(s.dir, fileName), zenc.EncodeAll(b, nil), 0o640)
	}
	s.saveErr = err
}

// Save persists now (shutdown).
func (s *Stats) Save() error {
	s.mu.Lock()
	p := s.persistLocked()
	s.mu.Unlock()
	s.save(p)
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	return s.saveErr
}

// ---------------------------------------------------------------- queries

// Ranges and their resolutions.
var Ranges = map[string]struct {
	Span, Res time.Duration
}{
	"1h":  {time.Hour, time.Minute},
	"6h":  {6 * time.Hour, 5 * time.Minute},
	"24h": {24 * time.Hour, 15 * time.Minute},
	"7d":  {7 * 24 * time.Hour, time.Hour},
	"30d": {30 * 24 * time.Hour, 6 * time.Hour},
	"1y":  {365 * 24 * time.Hour, 24 * time.Hour},
}

// Point is one chart point.
type Point struct {
	TS            string            `json:"ts"`
	Queries       uint64            `json:"queries"`
	QPS           float64           `json:"qps"`
	P50           float64           `json:"p50_ms"`
	P95           float64           `json:"p95_ms"`
	P99           float64           `json:"p99_ms"`
	CacheHitRatio float64           `json:"cache_hit_ratio"`
	ByRcode       map[string]uint64 `json:"by_rcode"`
	BySource      map[string]uint64 `json:"by_source"`
}

// Totals over the range.
type Totals struct {
	Queries  uint64            `json:"queries"`
	ByRcode  map[string]uint64 `json:"by_rcode"`
	BySource map[string]uint64 `json:"by_source"`
	ByQType  map[string]uint64 `json:"by_qtype"`
	P50      float64           `json:"p50_ms"`
	P95      float64           `json:"p95_ms"`
	P99      float64           `json:"p99_ms"`
	CacheHit float64           `json:"cache_hit_ratio"`
}

// NameCount and ClientCount are top list items.
type NameCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// ClientCount is a top client.
type ClientCount struct {
	Client string `json:"client"`
	Count  uint64 `json:"count"`
}

// Top lists.
type Top struct {
	Domains        []NameCount   `json:"domains"`
	Clients        []ClientCount `json:"clients"`
	NXDomain       []NameCount   `json:"nxdomain"`
	RefusedClients []ClientCount `json:"refused_clients"`
}

// Result is GET /v1/stats.
type Result struct {
	Range             string  `json:"range"`
	ResolutionSeconds int64   `json:"resolution_seconds"`
	From              string  `json:"from"`
	To                string  `json:"to"`
	Points            []Point `json:"points"`
	Totals            Totals  `json:"totals"`
	Top               Top     `json:"top"`
}

func rcodeMap(rc *[16]uint64) map[string]uint64 {
	m := map[string]uint64{"NOERROR": rc[0], "NXDOMAIN": rc[3], "SERVFAIL": rc[2], "REFUSED": rc[5]}
	for i, v := range rc {
		if v > 0 {
			m[querylog.RcodeName(uint8(i))] = v
		}
	}
	return m
}

func sourceMap(src *[querylog.SrcCount]uint64) map[string]uint64 {
	m := make(map[string]uint64, len(src))
	for i, v := range src {
		m[querylog.SourceNames[i]] = v
	}
	return m
}

func hitRatio(src *[querylog.SrcCount]uint64) float64 {
	d := src[querylog.SrcCache] + src[querylog.SrcUpstream] + src[querylog.SrcForwarder]
	if d == 0 {
		return 0
	}
	return math.Round(float64(src[querylog.SrcCache])/float64(d)*10000) / 10000
}

func r3(v float64) float64 { return math.Round(v*1000) / 1000 }

// Query builds the response for a range name.
func (s *Stats) Query(rangeName string) (Result, bool) {
	rg, ok := Ranges[rangeName]
	if !ok {
		return Result{}, false
	}
	now := s.now()
	s.mu.Lock()
	res := int64(rg.Res / time.Second)
	end := now.Unix()/res*res + res // exclusive, includes the open interval
	start := end - int64(rg.Span/time.Second)
	// the open minute from the live counters
	live := s.C.snapshot()
	live.sub(&s.last)
	live.TS = s.curMin
	var src []Bucket
	switch {
	case res < 3600 && int64(s.cfg.MinuteRetentionHours)*3600 >= end-start:
		src = append(append(src, s.minutes...), live)
	case res < 86400 && int64(s.cfg.HourRetentionDays)*86400 >= end-start:
		src = append(src, s.hours...)
		src = append(src, s.openHourLocked(live)...)
		if res < 3600 {
			res = 3600
			end = now.Unix()/res*res + res
			start = end - int64(rg.Span/time.Second)
		}
	default:
		src = append(src, s.days...)
		src = append(src, s.openDayLocked(live)...)
		if res < 86400 {
			res = 86400
			end = now.Unix()/res*res + res
			start = end - int64(rg.Span/time.Second)
		}
	}
	top := s.topLocked(start, now)
	s.mu.Unlock()

	n := int((end - start) / res)
	pts := make([]Bucket, n)
	var tot Bucket
	for i := range src {
		b := &src[i]
		if b.TS < start || b.TS >= end {
			continue
		}
		pts[(b.TS-start)/res].add(b)
		tot.add(b)
	}
	out := Result{Range: rangeName, ResolutionSeconds: res, From: time.Unix(start, 0).UTC().Format(time.RFC3339),
		To: time.Unix(end, 0).UTC().Format(time.RFC3339), Points: make([]Point, n), Top: top}
	for i := range pts {
		b := &pts[i]
		out.Points[i] = Point{TS: time.Unix(start+int64(i)*res, 0).UTC().Format(time.RFC3339), Queries: b.Queries,
			QPS: r3(float64(b.Queries) / float64(res)), P50: r3(Percentile(&b.Lat, 0.5)), P95: r3(Percentile(&b.Lat, 0.95)),
			P99: r3(Percentile(&b.Lat, 0.99)), CacheHitRatio: hitRatio(&b.Source), ByRcode: rcodeMap(&b.Rcode),
			BySource: sourceMap(&b.Source)}
	}
	out.Totals = Totals{Queries: tot.Queries, ByRcode: rcodeMap(&tot.Rcode), BySource: sourceMap(&tot.Source),
		ByQType: map[string]uint64{}, P50: r3(Percentile(&tot.Lat, 0.5)), P95: r3(Percentile(&tot.Lat, 0.95)),
		P99: r3(Percentile(&tot.Lat, 0.99)), CacheHit: hitRatio(&tot.Source)}
	for i, v := range tot.QType {
		if v == 0 || i >= NQType {
			continue
		}
		name := "OTHER"
		if i < len(qtSlots) {
			name = dns.TypeToString[qtSlots[i]]
		}
		out.Totals.ByQType[name] = v
	}
	return out, true
}

// openHourLocked aggregates the minutes not yet rolled into an hour.
func (s *Stats) openHourLocked(live Bucket) []Bucket {
	var out []Bucket
	for _, m := range append(append([]Bucket(nil), s.minutes...), live) {
		h := m.TS / 3600 * 3600
		if h <= s.hourDone {
			continue
		}
		if len(out) == 0 || out[len(out)-1].TS != h {
			out = append(out, Bucket{TS: h})
		}
		out[len(out)-1].add(&m)
	}
	return out
}

func (s *Stats) openDayLocked(live Bucket) []Bucket {
	var out []Bucket
	for _, h := range append(s.hours[:len(s.hours):len(s.hours)], s.openHourLocked(live)...) {
		d := h.TS / 86400 * 86400
		if d <= s.dayDone {
			continue
		}
		if len(out) == 0 || out[len(out)-1].TS != d {
			out = append(out, Bucket{TS: d})
		}
		out[len(out)-1].add(&h)
	}
	return out
}

// topLocked merges the finest top lists covering [start, now] without
// overlap: the open minute, then minute lists, then hour and day lists for
// what the finer levels do not cover.
func (s *Stats) topLocked(start int64, now time.Time) Top {
	k := s.cfg.TopK
	sets := []TopSet{{Domains: s.dom.Top(k), Clients: s.cli.Top(k), NX: s.nx.Top(k), Refused: s.ref.Top(k)}}
	covered := s.curMin // everything at or after covered is already included
	take := func(list []TopSet, unit int64) {
		oldest := covered
		for i := len(list) - 1; i >= 0; i-- {
			t := list[i]
			if t.TS < start {
				break
			}
			if t.TS+unit > covered {
				continue
			}
			sets = append(sets, t)
			oldest = t.TS
		}
		covered = oldest
	}
	take(s.topMin, 60)
	take(s.topHour, 3600)
	take(s.topDay, 86400)
	_ = now
	m := mergeTop(0, k, sets)
	top := Top{Domains: []NameCount{}, Clients: []ClientCount{}, NXDomain: []NameCount{}, RefusedClients: []ClientCount{}}
	for _, it := range m.Domains {
		top.Domains = append(top.Domains, NameCount{it.Key, it.Count})
	}
	for _, it := range m.Clients {
		top.Clients = append(top.Clients, ClientCount{it.Key, it.Count})
	}
	for _, it := range m.NX {
		top.NXDomain = append(top.NXDomain, NameCount{it.Key, it.Count})
	}
	for _, it := range m.Refused {
		top.RefusedClients = append(top.RefusedClients, ClientCount{it.Key, it.Count})
	}
	return top
}

// ObserveTopBatch is ObserveTop for a batch under one lock.
func (s *Stats) ObserveTopBatch(recs []querylog.Record, names, clients []string) {
	s.mu.Lock()
	for i := range recs {
		r := &recs[i]
		name, client := names[i], clients[i]
		s.dom.Add(name, 1)
		if client != "" {
			s.cli.Add(client, 1)
		}
		if r.Rcode == dns.RcodeNameError {
			s.nx.Add(name, 1)
		}
		if client != "" && (r.Rcode == dns.RcodeRefused || querylog.Blocked(r.Source)) {
			s.ref.Add(client, 1)
		}
	}
	s.mu.Unlock()
}
