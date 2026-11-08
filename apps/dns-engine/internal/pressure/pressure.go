// Package pressure is the critical-monitoring controller (docs/38 §1, §3):
// it samples the engine's resource use once a second, derives a level
// (normal → warning → critical → emergency) with enter thresholds, exit at
// threshold minus exit_margin_percent and a minimum dwell time, and maps the
// level to reversible load-shedding actions.
package pressure

import (
	"math"
	"sort"
	"sync"
	"time"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/querylog"
)

// Level is a pressure level.
type Level int

// Levels.
const (
	Normal Level = iota
	Warning
	Critical
	Emergency
)

var levelNames = [...]string{"normal", "warning", "critical", "emergency"}

func (l Level) String() string { return levelNames[l] }

// Metric names (docs/38 §3 reasons[].metric).
const (
	MCPU        = "cpu"
	MMemory     = "memory"
	MQPSPercent = "qps_percent"
	MHostCPU    = "host_cpu"
	MHostMemory = "host_memory"
)

var metricOrder = []string{MCPU, MMemory, MQPSPercent, MHostCPU, MHostMemory}

// Metrics is one sample.
type Metrics struct {
	CPUPercent        float64    `json:"cpu_percent"`
	MemoryPercent     float64    `json:"memory_percent"`
	QPS               float64    `json:"qps"`
	QPSPercent        float64    `json:"qps_percent"`
	InflightUpstream  int64      `json:"inflight_upstream"`
	Drops1m           uint64     `json:"drops_1m"`
	HostCPUPercent    *float64   `json:"host_cpu_percent,omitempty"`
	HostMemoryPercent *float64   `json:"host_memory_percent,omitempty"`
	HostLoad1         *float64   `json:"host_load1,omitempty"`
	HostMetricsAt     *time.Time `json:"host_metrics_at,omitempty"`
}

func (m *Metrics) value(name string) (float64, bool) {
	switch name {
	case MCPU:
		return m.CPUPercent, true
	case MMemory:
		return m.MemoryPercent, true
	case MQPSPercent:
		return m.QPSPercent, true
	case MHostCPU:
		if m.HostCPUPercent != nil {
			return *m.HostCPUPercent, true
		}
	case MHostMemory:
		if m.HostMemoryPercent != nil {
			return *m.HostMemoryPercent, true
		}
	}
	return 0, false
}

func threshold(t config.Threshold, name string) float64 {
	switch name {
	case MCPU:
		return t.CPU
	case MMemory:
		return t.Memory
	case MQPSPercent:
		return t.QPSPercent
	case MHostCPU:
		return t.HostCPU
	}
	return t.HostMemory
}

func levelThreshold(c *config.Pressure, l Level) config.Threshold {
	switch l {
	case Warning:
		return c.Thresholds.Warning
	case Critical:
		return c.Thresholds.Critical
	}
	return c.Thresholds.Emergency
}

// Reason is one metric over its threshold.
type Reason struct {
	Metric    string  `json:"metric"`
	Value     float64 `json:"value"`
	Threshold float64 `json:"threshold"`
}

// Actions are what the engine applies at the current level.
type Actions struct {
	LogPressure     int     // querylog.Pressure*
	DisablePrefetch bool    // no prefetch, no background refresh
	PreferStale     bool    // serve stale at once, refresh in the background
	ClientQPSScale  float64 // multiplier on client_qps / client_burst
	RefuseHeavy     bool    // REFUSE recursion for heavy clients
	MinimalANY      bool    // RFC 8482 answers for ANY on every transport
	Names           []string
}

// ActionsFor maps a level and toggles to actions.
func ActionsFor(l Level, a config.Actions) Actions {
	out := Actions{ClientQPSScale: 1, Names: []string{}}
	if l == Normal {
		return out
	}
	add := func(on bool, name string) bool {
		if on {
			out.Names = append(out.Names, name)
		}
		return on
	}
	if add(a.LogSampling, "log_sampling") {
		out.LogPressure = map[Level]int{Warning: querylog.PressureSample25, Critical: querylog.PressureErrorOnly,
			Emergency: querylog.PressureOff}[l]
	}
	out.DisablePrefetch = add(a.DisablePrefetch, "disable_prefetch")
	out.MinimalANY = add(a.MinimalANY, "minimal_any")
	if l >= Critical {
		out.PreferStale = add(a.PreferStale, "prefer_stale")
		if add(a.TightenClientQPS, "tighten_client_qps") {
			out.ClientQPSScale = 0.5
			if l == Emergency {
				out.ClientQPSScale = 0.25
			}
		}
		out.RefuseHeavy = add(a.RefuseHeavyClients, "refuse_heavy_clients")
	}
	return out
}

// hostMaxAge is how long host metrics stay valid.
const hostMaxAge = 60 * time.Second

// upSamples is how many consecutive samples must breach before going up.
const upSamples = 2

// Controller holds the level state machine.
type Controller struct {
	now func() time.Time

	mu        sync.Mutex
	cfg       config.Pressure
	level     Level
	since     time.Time
	lastAbove time.Time
	up        int
	upTarget  Level
	reasons   []Reason
	metrics   Metrics
	actions   Actions

	hostCPU, hostMem, hostLoad float64
	hostAt                     time.Time
	hostValid                  bool
}

// New creates a controller at level normal.
func New(cfg config.Pressure, now func() time.Time) *Controller {
	if now == nil {
		now = time.Now
	}
	c := &Controller{now: now, cfg: cfg, since: now()}
	c.actions = ActionsFor(Normal, cfg.Actions)
	return c
}

// Configure applies new settings; actions are recomputed at once.
func (c *Controller) Configure(cfg config.Pressure) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg
	if !cfg.Enabled {
		c.level = Normal
		c.reasons = nil
	}
	c.actions = ActionsFor(c.level, cfg.Actions)
}

// SetHost stores host metrics; it returns false (ignored) when ts is more
// than 60 s old or in the future by more than 60 s.
func (c *Controller) SetHost(cpu, mem, load float64, ts time.Time) bool {
	now := c.now()
	if ts.IsZero() {
		ts = now
	}
	if now.Sub(ts) > hostMaxAge || ts.Sub(now) > hostMaxAge || math.IsNaN(cpu) || math.IsNaN(mem) {
		return false
	}
	c.mu.Lock()
	c.hostCPU, c.hostMem, c.hostLoad, c.hostAt, c.hostValid = clamp(cpu), clamp(mem), load, ts, true
	c.mu.Unlock()
	return true
}

func clamp(v float64) float64 { return math.Max(0, math.Min(100, v)) }

// Change describes a level transition.
type Change struct {
	From, To Level
	Reasons  []Reason
	Actions  []string
}

// Step evaluates one sample. It returns a non-nil Change on a transition.
func (c *Controller) Step(m Metrics) *Change {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hostValid && now.Sub(c.hostAt) <= hostMaxAge {
		hc, hm, hl, at := c.hostCPU, c.hostMem, c.hostLoad, c.hostAt.UTC()
		m.HostCPUPercent, m.HostMemoryPercent, m.HostLoad1, m.HostMetricsAt = &hc, &hm, &hl, &at
	}
	c.metrics = m
	cfg := &c.cfg
	if !cfg.Enabled {
		return nil
	}
	breach := func(l Level, margin float64) []Reason {
		var out []Reason
		t := levelThreshold(cfg, l)
		for _, name := range metricOrder {
			thr := threshold(t, name)
			v, ok := m.value(name)
			if thr <= 0 || !ok {
				continue
			}
			if v >= thr-margin {
				out = append(out, Reason{Metric: name, Value: round1(v), Threshold: thr})
			}
		}
		return out
	}
	target := Normal
	for l := Emergency; l >= Warning; l-- {
		if len(breach(l, 0)) > 0 {
			target = l
			break
		}
	}
	prev := c.level
	if target > c.level {
		if c.upTarget != target {
			c.up = 0
			c.upTarget = target
		}
		c.up++
		if c.up >= upSamples {
			c.level, c.since, c.lastAbove, c.up = target, now, now, 0
		}
	} else {
		c.up, c.upTarget = 0, Normal
	}
	if c.level > Normal && c.level == prev {
		if len(breach(c.level, cfg.ExitMarginPercent)) > 0 {
			c.lastAbove = now
		} else {
			dwell := time.Duration(cfg.DwellSeconds) * time.Second
			ref := c.since
			if c.lastAbove.After(ref) {
				ref = c.lastAbove
			}
			if now.Sub(ref) >= dwell {
				c.level--
				c.since, c.lastAbove = now, now
			}
		}
	}
	if c.level > Normal {
		c.reasons = breach(c.level, cfg.ExitMarginPercent)
	} else {
		c.reasons = nil
	}
	if c.level == prev {
		return nil
	}
	c.actions = ActionsFor(c.level, cfg.Actions)
	return &Change{From: prev, To: c.level, Reasons: append([]Reason{}, c.reasons...), Actions: append([]string{}, c.actions.Names...)}
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// Level returns the current level.
func (c *Controller) Level() Level {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.level
}

// Actions returns the active actions.
func (c *Controller) Actions() Actions {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.actions
}

// View is the controller part of GET /v1/pressure.
type View struct {
	Level         string   `json:"level"`
	Since         string   `json:"since"`
	Reasons       []Reason `json:"reasons"`
	Metrics       Metrics  `json:"metrics"`
	ActiveActions []string `json:"active_actions"`
	Enabled       bool     `json:"enabled"`
}

// Snapshot returns the current state.
func (c *Controller) Snapshot() View {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := View{Level: c.level.String(), Since: c.since.UTC().Format(time.RFC3339), Reasons: append([]Reason{}, c.reasons...),
		Metrics: c.metrics, ActiveActions: append([]string{}, c.actions.Names...), Enabled: c.cfg.Enabled}
	sort.SliceStable(v.Reasons, func(i, j int) bool {
		return v.Reasons[i].Value/v.Reasons[i].Threshold > v.Reasons[j].Value/v.Reasons[j].Threshold
	})
	return v
}
