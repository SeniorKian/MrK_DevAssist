package config

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/fielderr"
)

// Query log modes.
const (
	LogAll        = "all"
	LogSample     = "sample"
	LogErrorsOnly = "errors_only"
	LogOff        = "off"
)

// Client IP privacy modes.
const (
	IPFull = "full"
	IPMask = "mask"
	IPHash = "hash"
	IPNone = "none"
)

// Attack detection modes.
const (
	AttackOff     = "off"
	AttackSuggest = "suggest"
	AttackAuto    = "auto"
)

// QueryLog configures the query log (docs/38 §2).
type QueryLog struct {
	Enabled            bool     `json:"enabled"`
	Mode               string   `json:"mode"`
	SamplePercent      int      `json:"sample_percent"`
	MaxAgeDays         int      `json:"max_age_days"`
	MaxBytes           int64    `json:"max_bytes"`
	MinFreeDiskPercent int      `json:"min_free_disk_percent"`
	ClientIP           string   `json:"client_ip"`
	ExcludeNames       []string `json:"exclude_names"`
	ExcludeClients     []string `json:"exclude_clients"`
	StreamMaxEPS       int      `json:"stream_max_eps"`
}

// Stats configures the aggregated statistics.
type Stats struct {
	MinuteRetentionHours int `json:"minute_retention_hours"`
	HourRetentionDays    int `json:"hour_retention_days"`
	DayRetentionDays     int `json:"day_retention_days"`
	TopK                 int `json:"top_k"`
}

// Threshold is one pressure level's enter thresholds (0 disables a metric).
type Threshold struct {
	CPU        float64 `json:"cpu"`
	Memory     float64 `json:"memory"`
	QPSPercent float64 `json:"qps_percent"`
	HostCPU    float64 `json:"host_cpu"`
	HostMemory float64 `json:"host_memory"`
}

// Thresholds per level.
type Thresholds struct {
	Warning   Threshold `json:"warning"`
	Critical  Threshold `json:"critical"`
	Emergency Threshold `json:"emergency"`
}

// Actions toggles the automatic pressure actions.
type Actions struct {
	LogSampling        bool `json:"log_sampling"`
	DisablePrefetch    bool `json:"disable_prefetch"`
	PreferStale        bool `json:"prefer_stale"`
	TightenClientQPS   bool `json:"tighten_client_qps"`
	RefuseHeavyClients bool `json:"refuse_heavy_clients"`
	MinimalANY         bool `json:"minimal_any"`
}

// AttackDetection configures random-subdomain / NXDOMAIN flood detection.
type AttackDetection struct {
	Mode                    string `json:"mode"`
	NXDomainUniquePerMinute int    `json:"nxdomain_unique_per_minute"`
	MitigationMinutes       int    `json:"mitigation_minutes"`
}

// Pressure configures the pressure controller.
type Pressure struct {
	Enabled           bool            `json:"enabled"`
	CapacityQPS       int             `json:"capacity_qps"`
	DwellSeconds      int             `json:"dwell_seconds"`
	Thresholds        Thresholds      `json:"thresholds"`
	ExitMarginPercent float64         `json:"exit_margin_percent"`
	Actions           Actions         `json:"actions"`
	AttackDetection   AttackDetection `json:"attack_detection"`
}

// DefaultQueryLog returns the factory query log settings.
func DefaultQueryLog() QueryLog {
	return QueryLog{Enabled: true, Mode: LogAll, SamplePercent: 100, MaxAgeDays: 7, MaxBytes: 2 << 30,
		MinFreeDiskPercent: 10, ClientIP: IPFull, ExcludeNames: []string{}, ExcludeClients: []string{}, StreamMaxEPS: 200}
}

// DefaultStats returns the factory statistics settings.
func DefaultStats() Stats {
	return Stats{MinuteRetentionHours: 48, HourRetentionDays: 90, DayRetentionDays: 400, TopK: 100}
}

// DefaultPressure returns the factory pressure settings.
func DefaultPressure() Pressure {
	return Pressure{Enabled: true, CapacityQPS: 50000, DwellSeconds: 30,
		Thresholds: Thresholds{
			Warning:   Threshold{CPU: 70, Memory: 75, QPSPercent: 70, HostCPU: 85, HostMemory: 90},
			Critical:  Threshold{CPU: 85, Memory: 85, QPSPercent: 90, HostCPU: 92, HostMemory: 95},
			Emergency: Threshold{CPU: 95, Memory: 95, QPSPercent: 110, HostCPU: 97, HostMemory: 98},
		},
		ExitMarginPercent: 10,
		Actions: Actions{LogSampling: true, DisablePrefetch: true, PreferStale: true, TightenClientQPS: true,
			RefuseHeavyClients: true, MinimalANY: true},
		AttackDetection: AttackDetection{Mode: AttackSuggest, NXDomainUniquePerMinute: 500, MitigationMinutes: 30},
	}
}

// NormalizeSuffix canonicalises a domain suffix ("*.Example.COM." -> "example.com").
// "." / "" mean the root. ok is false for invalid names.
func NormalizeSuffix(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", false
	}
	if _, ok := dns.IsDomainName(s + "."); !ok || len(s) > 253 || strings.ContainsAny(s, " *\\") {
		return "", false
	}
	for _, lab := range strings.Split(s, ".") {
		if lab == "" || len(lab) > 63 {
			return "", false
		}
	}
	return s, true
}

func validateMonitor(s *Settings, l *fielderr.List) {
	q := &s.QueryLog
	switch q.Mode {
	case LogAll, LogSample, LogErrorsOnly, LogOff:
	default:
		l.Add("querylog.mode", "invalid_choice", "choices", []string{LogAll, LogSample, LogErrorsOnly, LogOff})
	}
	rng(l, "querylog.sample_percent", q.SamplePercent, 1, 100)
	rng(l, "querylog.max_age_days", q.MaxAgeDays, 1, 3650)
	if q.MaxBytes < 16<<20 || q.MaxBytes > 1<<42 {
		l.Add("querylog.max_bytes", "out_of_range", "min", int64(16<<20), "max", int64(1<<42))
	}
	rng(l, "querylog.min_free_disk_percent", q.MinFreeDiskPercent, 1, 50)
	switch q.ClientIP {
	case IPFull, IPMask, IPHash, IPNone:
	default:
		l.Add("querylog.client_ip", "invalid_choice", "choices", []string{IPFull, IPMask, IPHash, IPNone})
	}
	if q.ExcludeNames == nil {
		q.ExcludeNames = []string{}
	}
	if q.ExcludeClients == nil {
		q.ExcludeClients = []string{}
	}
	if len(q.ExcludeNames) > 1000 {
		l.Add("querylog.exclude_names", "too_many", "max", 1000)
	} else {
		for i, n := range q.ExcludeNames {
			v, ok := NormalizeSuffix(n)
			if !ok {
				l.Add(fmt.Sprintf("querylog.exclude_names[%d]", i), "invalid_name")
				continue
			}
			q.ExcludeNames[i] = v
		}
	}
	if len(q.ExcludeClients) > 1000 {
		l.Add("querylog.exclude_clients", "too_many", "max", 1000)
	} else {
		for i, c := range q.ExcludeClients {
			p, deny, err := acl.ParseEntry(c)
			if err != nil || deny {
				l.Add(fmt.Sprintf("querylog.exclude_clients[%d]", i), "invalid_network")
				continue
			}
			q.ExcludeClients[i] = p.String()
		}
	}
	rng(l, "querylog.stream_max_eps", q.StreamMaxEPS, 1, 10000)

	st := s.Stats
	rng(l, "stats.minute_retention_hours", st.MinuteRetentionHours, 1, 168)
	rng(l, "stats.hour_retention_days", st.HourRetentionDays, 1, 730)
	rng(l, "stats.day_retention_days", st.DayRetentionDays, 1, 3650)
	rng(l, "stats.top_k", st.TopK, 10, 1000)

	p := s.Pressure
	rng(l, "pressure.capacity_qps", p.CapacityQPS, 100, 10_000_000)
	rng(l, "pressure.dwell_seconds", p.DwellSeconds, 1, 3600)
	if p.ExitMarginPercent < 0 || p.ExitMarginPercent > 50 {
		l.Add("pressure.exit_margin_percent", "out_of_range", "min", 0, "max", 50)
	}
	levels := []struct {
		name string
		t    Threshold
	}{{"warning", p.Thresholds.Warning}, {"critical", p.Thresholds.Critical}, {"emergency", p.Thresholds.Emergency}}
	metric := func(t Threshold, m string) float64 {
		switch m {
		case "cpu":
			return t.CPU
		case "memory":
			return t.Memory
		case "qps_percent":
			return t.QPSPercent
		case "host_cpu":
			return t.HostCPU
		}
		return t.HostMemory
	}
	for _, m := range []string{"cpu", "memory", "qps_percent", "host_cpu", "host_memory"} {
		hi := 100.0
		if m == "qps_percent" {
			hi = 1000
		}
		prev := 0.0
		for _, lv := range levels {
			v := metric(lv.t, m)
			f := "pressure.thresholds." + lv.name + "." + m
			if v < 0 || v > hi {
				l.Add(f, "out_of_range", "min", 0, "max", hi)
				continue
			}
			if v == 0 {
				continue // metric disabled for this level
			}
			if v < prev {
				l.Add(f, "below_lower_level")
			}
			prev = v
		}
	}
	a := p.AttackDetection
	switch a.Mode {
	case AttackOff, AttackSuggest, AttackAuto:
	default:
		l.Add("pressure.attack_detection.mode", "invalid_choice", "choices", []string{AttackOff, AttackSuggest, AttackAuto})
	}
	rng(l, "pressure.attack_detection.nxdomain_unique_per_minute", a.NXDomainUniquePerMinute, 10, 10_000_000)
	rng(l, "pressure.attack_detection.mitigation_minutes", a.MitigationMinutes, 1, 10080)
}
