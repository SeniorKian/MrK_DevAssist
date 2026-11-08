package querylog

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	crand "crypto/rand"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/store"
)

// Effective-mode restrictions, ordered from least to most restrictive.
const (
	levelAll = iota
	levelSample
	levelErrors
	levelOff
)

var modeLevel = map[string]int{config.LogAll: levelAll, config.LogSample: levelSample,
	config.LogErrorsOnly: levelErrors, config.LogOff: levelOff}

var levelMode = [...]string{config.LogAll, config.LogSample, config.LogErrorsOnly, config.LogOff}

// Pressure overrides (set by the pressure controller's log_sampling action).
const (
	PressureNone      = 0
	PressureSample25  = 1
	PressureErrorOnly = 2
	PressureOff       = 3
)

// Degradation reasons.
const (
	ReasonDiskLow      = "disk_low"      // free space below min_free_disk_percent: errors only
	ReasonDiskCritical = "disk_critical" // below half of it: off
	ReasonPressure     = "pressure"
	ReasonWriteError   = "write_error"
)

// DiskFreeFunc returns the free-space percentage of the filesystem holding path.
type DiskFreeFunc func(path string) (float64, error)

// EventFunc receives querylog.degraded / querylog.recovered events.
type EventFunc func(typ, severity string, data map[string]any)

type compiled struct {
	s          config.QueryLog
	exclNames  map[string]struct{}
	exclClient *acl.List
}

// Logger turns hot-path records into stored rows.
type Logger struct {
	st     *Store
	key    []byte
	now    func() time.Time
	free   DiskFreeFunc
	events EventFunc

	cfg      atomic.Pointer[compiled]
	pressure atomic.Int32

	// guarded by mu (pipeline goroutine and status readers)
	mu           sync.Mutex
	diskLevel    int // levelAll / levelErrors / levelOff
	diskFree     float64
	diskChecked  time.Time
	writeErr     bool
	lastReason   string
	lastRetain   time.Time
	internNames  map[string]string
	internClient map[netip.Addr]string
	internMode   string
	nameBuf      []byte
	rows         []Row

	written atomic.Uint64
	dropped atomic.Uint64
	rng     *rand.Rand

	streamMu sync.Mutex
	streams  map[*Stream]struct{}
}

// Options configure a Logger.
type Options struct {
	Dir      string
	Now      func() time.Time
	DiskFree DiskFreeFunc
	Events   EventFunc
}

// MaxStreams bounds concurrent live streams.
const MaxStreams = 20 // the panel allows 3 per user and 20 in total (docs/38 §0.1)

// Open opens the log store in o.Dir.
func Open(o Options, s config.QueryLog) (*Logger, []error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.DiskFree == nil {
		o.DiskFree = DiskFree
	}
	if o.Events == nil {
		o.Events = func(string, string, map[string]any) {}
	}
	st, warns := OpenStore(o.Dir, o.Now)
	if st == nil {
		return nil, warns
	}
	key, err := loadKey(filepath.Join(o.Dir, "hash.key"))
	if err != nil {
		return nil, append(warns, err)
	}
	l := &Logger{st: st, key: key, now: o.Now, free: o.DiskFree, events: o.Events, diskFree: -1,
		internNames: map[string]string{}, internClient: map[netip.Addr]string{}, streams: map[*Stream]struct{}{},
		rng: rand.New(rand.NewPCG(uint64(o.Now().UnixNano()), 0x9e3779b97f4a7c15))}
	l.Configure(s)
	l.mu.Lock()
	l.diskChecked = o.Now()
	l.checkDiskLocked(l.cfg.Load())
	l.mu.Unlock()
	return l, warns
}

// loadKey reads or creates the 32-byte hashing key (mode 0600).
func loadKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := crand.Read(k); err != nil {
		return nil, err
	}
	if err := store.WriteFileAtomic(path, k, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// Store returns the underlying store.
func (l *Logger) Store() *Store { return l.st }

// Configure applies new settings (hot).
func (l *Logger) Configure(s config.QueryLog) {
	c := &compiled{s: s, exclNames: map[string]struct{}{}}
	c.s.ExcludeNames = append([]string(nil), s.ExcludeNames...)
	c.s.ExcludeClients = append([]string(nil), s.ExcludeClients...)
	for _, n := range s.ExcludeNames {
		if v, ok := config.NormalizeSuffix(n); ok {
			c.exclNames[v] = struct{}{}
		}
	}
	if a, err := acl.Compile(s.ExcludeClients); err == nil {
		c.exclClient = a
	} else {
		c.exclClient, _ = acl.Compile(nil)
	}
	l.cfg.Store(c)
}

// SetPressure sets the pressure override (PressureNone ... PressureOff).
func (l *Logger) SetPressure(p int) { l.pressure.Store(int32(p)) }

// effective returns the effective restriction level, sample percent and reason.
func (l *Logger) effective(c *compiled, disk int) (int, int, string) {
	if !c.s.Enabled {
		return levelOff, 0, ""
	}
	lv := modeLevel[c.s.Mode]
	pct := 100
	if lv == levelSample {
		pct = c.s.SamplePercent
	}
	reason := ""
	switch l.pressure.Load() {
	case PressureSample25:
		if lv <= levelSample {
			if lv < levelSample || pct > 25 {
				reason = ReasonPressure
			}
			lv = levelSample
			pct = min(pct, 25)
		}
	case PressureErrorOnly:
		if lv < levelErrors {
			lv, reason = levelErrors, ReasonPressure
		}
	case PressureOff:
		if lv < levelOff {
			lv, reason = levelOff, ReasonPressure
		}
	}
	if disk > lv {
		lv = disk
		reason = ReasonDiskLow
		if disk == levelOff {
			reason = ReasonDiskCritical
		}
	}
	if l.writeErr && reason == "" {
		reason = ReasonWriteError
	}
	return lv, pct, reason
}

// isError reports whether a record is kept in errors_only mode: anything that
// is not NOERROR/NXDOMAIN, and every refused, rate-limited or mitigated query.
func isError(rcode, src uint8) bool {
	return (rcode != 0 && rcode != 3) || Blocked(src)
}

// HealthProbeName is the reserved name `mrk-dns health` asks for (the .invalid
// TLD never exists, RFC 6761). Probes from loopback are never logged, so the
// container healthcheck does not fill the query log every 15 seconds.
const HealthProbeName = "mrk-health.invalid"

// IsHealthProbe reports whether a query is the engine's own healthcheck.
func IsHealthProbe(name string, client netip.Addr) bool {
	return name == HealthProbeName && client.Unmap().IsLoopback()
}

func (c *compiled) excluded(name string, client netip.Addr) bool {
	if len(c.exclNames) > 0 {
		if _, ok := c.exclNames[name]; ok {
			return true
		}
		for i := 0; i < len(name); i++ {
			if name[i] == '.' {
				if _, ok := c.exclNames[name[i+1:]]; ok {
					return true
				}
			}
		}
	}
	return c.exclClient.Len() > 0 && c.exclClient.Allowed(client)
}

// ClientDisplay renders a client address under the privacy mode.
func (l *Logger) ClientDisplay(mode string, a netip.Addr) string {
	switch mode {
	case config.IPNone:
		return ""
	case config.IPMask:
		bits := 24
		if a.Is6() {
			bits = 48
		}
		p, _ := a.Prefix(bits)
		return p.Addr().String()
	case config.IPHash:
		return l.hashClient(a)
	}
	return a.String()
}

func (l *Logger) hashClient(a netip.Addr) string {
	m := hmac.New(sha256.New, l.key)
	b := a.Unmap().As16()
	m.Write(b[:])
	return "h:" + hex.EncodeToString(m.Sum(nil)[:8])
}

// Prepare converts the names (presentation form) and clients (display form
// under the privacy mode) of a batch, using intern caches so steady-state
// traffic does not allocate (pipeline goroutine only).
func (l *Logger) Prepare(recs []Record, names, clients []string) ([]string, []string) {
	c := l.cfg.Load()
	if len(l.internNames) > 200_000 {
		clear(l.internNames)
	}
	if len(l.internClient) > 100_000 || l.internMode != c.s.ClientIP {
		l.internMode = c.s.ClientIP
		clear(l.internClient)
	}
	for i := range recs {
		r := &recs[i]
		l.nameBuf = PresentName(r.WireName(), l.nameBuf)
		name, ok := l.internNames[string(l.nameBuf)]
		if !ok {
			name = string(l.nameBuf)
			l.internNames[name] = name
		}
		cl, ok := l.internClient[r.Client]
		if !ok {
			cl = l.ClientDisplay(c.s.ClientIP, r.Client)
			l.internClient[r.Client] = cl
		}
		names = append(names, name)
		clients = append(clients, cl)
	}
	return names, clients
}

// Process stores a batch of records (pipeline goroutine only). names and
// clients come from Prepare (nil: computed here).
func (l *Logger) Process(recs []Record, names, clients []string) {
	c := l.cfg.Load()
	l.mu.Lock()
	lv, pct, _ := l.effective(c, l.diskLevel)
	l.mu.Unlock()
	streaming := l.streamCount() > 0 && c.s.Enabled && c.s.Mode != config.LogOff
	if lv == levelOff && !streaming {
		return
	}
	if names == nil {
		names, clients = l.Prepare(recs, nil, nil)
	}
	rows := l.rows[:0]
	for i := range recs {
		r := &recs[i]
		store := false
		switch lv {
		case levelAll:
			store = true
		case levelSample:
			store = pct >= 100 || l.rng.IntN(100) < pct
		case levelErrors:
			store = isError(r.Rcode, r.Source)
		}
		if !store && !streaming {
			continue
		}
		name, cl := names[i], clients[i]
		if c.excluded(name, r.Client) || IsHealthProbe(name, r.Client) {
			continue
		}
		row := Row{TS: r.TS / 1000, Client: cl, Name: name, Upstream: r.Upstream, DurUS: r.DurUS, Size: r.Size,
			QType: r.QType, Rcode: r.Rcode, Source: r.Source, Proto: r.Proto, Flags: r.Flags}
		if streaming {
			l.broadcast(&row)
		}
		if store {
			rows = append(rows, row)
		}
	}
	l.rows = rows[:0]
	if len(rows) == 0 {
		return
	}
	err := l.st.Append(rows)
	l.mu.Lock()
	if err != nil {
		l.dropped.Add(uint64(len(rows)))
		l.writeErr = true
	} else {
		l.written.Add(uint64(len(rows)))
		l.writeErr = false
	}
	l.mu.Unlock()
}

// AddDropped counts records lost before reaching the logger (ring full).
func (l *Logger) AddDropped(n uint64) { l.dropped.Add(n) }

// Tick runs periodic work (pipeline goroutine, about once a second): WAL
// fsync, age-based finalisation, the disk guard every 10 s and retention
// every minute. It emits degraded/recovered events on changes.
func (l *Logger) Tick() {
	now := l.now()
	if err := l.st.Sync(); err != nil {
		l.mu.Lock()
		l.writeErr = true
		l.mu.Unlock()
	}
	c := l.cfg.Load()
	l.mu.Lock()
	if now.Sub(l.diskChecked) >= 10*time.Second {
		l.diskChecked = now
		l.checkDiskLocked(c)
	}
	retain := now.Sub(l.lastRetain) >= time.Minute
	if retain {
		l.lastRetain = now
	}
	_, _, reason := l.effective(c, l.diskLevel)
	prev := l.lastReason
	l.lastReason = reason
	free := l.diskFree
	l.mu.Unlock()
	if retain {
		l.st.Retention(time.Duration(c.s.MaxAgeDays)*24*time.Hour, c.s.MaxBytes)
	}
	if reason != prev {
		mode := l.ModeEffective()
		switch {
		case reason != "" && reason != ReasonPressure:
			sev := "warning"
			if reason == ReasonDiskCritical || reason == ReasonWriteError {
				sev = "error"
			}
			l.events("querylog.degraded", sev, map[string]any{"reason": reason, "mode_effective": mode,
				"disk_free_percent": round1(free)})
		case prev != "" && prev != ReasonPressure:
			l.events("querylog.recovered", "info", map[string]any{"mode_effective": mode, "disk_free_percent": round1(free),
				"previous_reason": prev})
		}
	}
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// checkDiskLocked applies the disk-free guard with 2-point hysteresis.
func (l *Logger) checkDiskLocked(c *compiled) {
	free, err := l.free(l.st.Dir())
	if err != nil {
		return
	}
	l.diskFree = free
	min := float64(c.s.MinFreeDiskPercent)
	switch {
	case free < min/2:
		l.diskLevel = levelOff
	case free < min:
		if l.diskLevel != levelOff || free >= min/2+2 {
			l.diskLevel = levelErrors
		}
	case free >= min+2:
		l.diskLevel = levelAll
	default: // between min and min+2: keep the current state
		if l.diskLevel == levelOff {
			l.diskLevel = levelErrors
		}
	}
}

// ModeEffective returns the effective mode name.
func (l *Logger) ModeEffective() string {
	c := l.cfg.Load()
	l.mu.Lock()
	lv, _, _ := l.effective(c, l.diskLevel)
	l.mu.Unlock()
	return levelMode[lv]
}

// Status is GET /v1/querylog/status.
type Status struct {
	Enabled         bool     `json:"enabled"`
	Mode            string   `json:"mode"`
	ModeEffective   string   `json:"mode_effective"`
	SamplePercent   int      `json:"sample_percent_effective"`
	DegradedReason  *string  `json:"degraded_reason,omitempty"`
	Bytes           int64    `json:"bytes"`
	Segments        int      `json:"segments"`
	Rows            int      `json:"rows"`
	OldestTS        *string  `json:"oldest_ts"`
	WrittenTotal    uint64   `json:"written_total"`
	DroppedTotal    uint64   `json:"dropped_total"`
	DiskFreePercent *float64 `json:"disk_free_percent"`
	Streams         int      `json:"streams"`
}

// Status reports the log state.
func (l *Logger) Status() Status {
	c := l.cfg.Load()
	u := l.st.Usage()
	l.mu.Lock()
	lv, pct, reason := l.effective(c, l.diskLevel)
	free := l.diskFree
	l.mu.Unlock()
	st := Status{Enabled: c.s.Enabled, Mode: c.s.Mode, ModeEffective: levelMode[lv], Bytes: u.Bytes, Segments: u.Segments,
		Rows: u.Rows, WrittenTotal: l.written.Load(), DroppedTotal: l.dropped.Load(), Streams: l.streamCount()}
	if lv == levelSample {
		st.SamplePercent = pct
	} else if lv == levelAll {
		st.SamplePercent = 100
	}
	if reason != "" {
		st.DegradedReason = &reason
	}
	if u.OldestTS > 0 {
		s := TSString(u.OldestTS)
		st.OldestTS = &s
	}
	if free >= 0 {
		f := round1(free)
		st.DiskFreePercent = &f
	}
	return st
}

// PrepareFilter adapts a client filter to the privacy mode the rows were
// written with (mask the queried address, hash it, or match nothing).
func (l *Logger) PrepareFilter(f *Filter) {
	c := l.cfg.Load()
	p := f.ClientPrefix
	if !p.IsValid() {
		if f.ClientExact != "" && c.s.ClientIP == config.IPNone {
			f.ClientNone = true
		}
		return
	}
	host := p.Bits() == p.Addr().BitLen()
	switch c.s.ClientIP {
	case config.IPNone:
		f.ClientNone = true
	case config.IPHash:
		if host {
			f.ClientExact = l.hashClient(p.Addr())
		} else {
			f.ClientNone = true
		}
		f.ClientPrefix = netip.Prefix{}
	case config.IPMask:
		bits := 24
		if p.Addr().Is6() {
			bits = 48
		}
		if p.Bits() > bits {
			f.ClientPrefix, _ = p.Addr().Prefix(bits)
		}
	}
}

// Search runs a filtered newest-first search with the docs/38 2 s budget.
func (l *Logger) Search(ctx context.Context, f Filter, budget time.Duration) SearchResult {
	l.PrepareFilter(&f)
	return l.st.Search(ctx, &f, budget)
}

// Delete removes rows (client: IP or CIDR string, before: unix µs).
func (l *Logger) Delete(client string, before int64) (DeleteResult, error) {
	var cf *Filter
	if client != "" {
		f, err := ParseFilter(map[string][]string{"client": {client}})
		if err != nil {
			return DeleteResult{}, err
		}
		l.PrepareFilter(&f)
		cf = &Filter{ClientPrefix: f.ClientPrefix, ClientExact: f.ClientExact, ClientNone: f.ClientNone, Rcode: -1, Source: -1}
	}
	return l.st.Delete(cf, before)
}

// Close finalizes the active segment.
func (l *Logger) Close() error { return l.st.Close() }

// ---------------------------------------------------------------- streams

// Stream is one live subscriber.
type Stream struct {
	C       chan Row
	Filter  Filter
	skipped atomic.Uint64
	l       *Logger
}

// ErrTooManyStreams is returned when MaxStreams are open.
var ErrTooManyStreams = fmt.Errorf("too many live streams (max %d)", MaxStreams)

// Subscribe opens a live stream.
func (l *Logger) Subscribe(f Filter) (*Stream, error) {
	l.PrepareFilter(&f)
	l.streamMu.Lock()
	defer l.streamMu.Unlock()
	if len(l.streams) >= MaxStreams {
		return nil, ErrTooManyStreams
	}
	s := &Stream{C: make(chan Row, 4096), Filter: f, l: l}
	l.streams[s] = struct{}{}
	return s, nil
}

// Close unsubscribes.
func (s *Stream) Close() {
	s.l.streamMu.Lock()
	delete(s.l.streams, s)
	s.l.streamMu.Unlock()
}

// TakeSkipped returns and resets the count of rows lost because the
// subscriber was slow.
func (s *Stream) TakeSkipped() uint64 { return s.skipped.Swap(0) }

func (l *Logger) streamCount() int {
	l.streamMu.Lock()
	defer l.streamMu.Unlock()
	return len(l.streams)
}

func (l *Logger) broadcast(r *Row) {
	l.streamMu.Lock()
	for s := range l.streams {
		if !s.Filter.MatchRow(r) {
			continue
		}
		select {
		case s.C <- *r:
		default:
			s.skipped.Add(1)
		}
	}
	l.streamMu.Unlock()
}

// StreamMaxEPS returns the configured per-stream rate cap.
func (l *Logger) StreamMaxEPS() int { return l.cfg.Load().s.StreamMaxEPS }

// ---------------------------------------------------------------- views

// Item is the API view of a row (docs/38 §3).
type Item struct {
	TS       string  `json:"ts"`
	Client   string  `json:"client"`
	Proto    string  `json:"proto"`
	Name     string  `json:"name"`
	QType    string  `json:"qtype"`
	Rcode    string  `json:"rcode"`
	Source   string  `json:"source"`
	Upstream string  `json:"upstream,omitempty"`
	MS       float64 `json:"ms"`
	Size     int     `json:"size"`
	Flags    Flags   `json:"flags"`
}

// Flags of an item.
type Flags struct {
	TC     bool `json:"tc"`
	Stale  bool `json:"stale"`
	Cached bool `json:"cached"`
}

// View converts a row.
func View(r *Row) Item {
	return Item{TS: TSString(r.TS), Client: r.Client, Proto: ProtoNames[r.Proto%ProtoCount], Name: r.Name,
		QType: QTypeName(r.QType), Rcode: RcodeName(r.Rcode), Source: SourceNames[r.Source%SrcCount], Upstream: r.Upstream,
		MS: float64(r.DurUS) / 1000, Size: int(r.Size),
		Flags: Flags{TC: r.Flags&FlagTC != 0, Stale: r.Flags&FlagStale != 0, Cached: r.Flags&FlagCached != 0}}
}

// CSVHeader is the export header.
var CSVHeader = []string{"ts", "client", "proto", "name", "qtype", "rcode", "source", "upstream", "ms", "size", "tc", "stale", "cached"}

// CSV renders an item as CSV fields.
func (it Item) CSV() []string {
	b := func(v bool) string {
		if v {
			return "true"
		}
		return "false"
	}
	return []string{it.TS, it.Client, it.Proto, it.Name, it.QType, it.Rcode, it.Source, it.Upstream,
		strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", it.MS), "0"), "."), itoa(it.Size),
		b(it.Flags.TC), b(it.Flags.Stale), b(it.Flags.Cached)}
}
