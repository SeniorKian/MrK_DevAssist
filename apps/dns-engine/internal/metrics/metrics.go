// Package metrics holds the engine's lock-free counters, the 1s/1m QPS
// windows and the Prometheus text exposition.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Sources of answers (docs/37 §2 resolve.source plus drop reasons).
const (
	SrcAuthoritative = iota
	SrcOverride
	SrcCache
	SrcStale
	SrcUpstream
	SrcRefused
	SrcLocal
	SrcError
	SrcMitigated
	SrcRateLimited
	SrcRecursive // resolved from the root (D4)
	SrcBlocked   // filtering (docs/41 §3)
	srcCount
)

var srcNames = [srcCount]string{"authoritative", "override", "cache", "stale", "upstream", "refused", "local", "error",
	"mitigated", "rate_limited", "recursive", "blocked"}

// Drop reasons.
const (
	DropMalformed = iota
	DropClientLimit
	DropRRL
	DropOverload
	DropTCPLimit
	DropMitigation
	dropCount
)

var dropNames = [dropCount]string{"malformed", "client_rate_limit", "rrl", "overload", "tcp_connection_limit", "mitigation"}

// Metrics is safe for concurrent use; the zero value is not usable, use New.
type Metrics struct {
	QueriesUDP atomic.Uint64
	QueriesTCP atomic.Uint64
	Rcodes     [24]atomic.Uint64
	Sources    [srcCount]atomic.Uint64
	Drops      [dropCount]atomic.Uint64
	RRLSlips   atomic.Uint64
	Truncated  atomic.Uint64
	TCPConns   atomic.Int64
	Prefetches atomic.Uint64
	Rebinding  atomic.Uint64
	Inflight   atomic.Int64

	mu       sync.Mutex
	window   [61]uint64 // per-second totals ring
	pos      int
	lastTot  uint64
	qps1s    atomic.Uint64
	qps1m    atomic.Uint64 // x100 fixed point
	upstream map[string]*Upstream
}

// Upstream counters for one forwarder.
type Upstream struct {
	Queries  atomic.Uint64
	Errors   atomic.Uint64
	Timeouts atomic.Uint64
}

// New returns ready metrics.
func New() *Metrics { return &Metrics{upstream: map[string]*Upstream{}} }

// Source counts an answer source.
func (m *Metrics) Source(s int) { m.Sources[s].Add(1) }

// Rcode counts a response code.
func (m *Metrics) Rcode(rc int) {
	if rc >= 0 && rc < len(m.Rcodes) {
		m.Rcodes[rc].Add(1)
	}
}

// Drop counts a dropped query.
func (m *Metrics) Drop(reason int) { m.Drops[reason].Add(1) }

// Upstream returns (creating) the counters for id.
func (m *Metrics) Upstream(id string) *Upstream {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.upstream[id]
	if u == nil {
		u = &Upstream{}
		m.upstream[id] = u
	}
	return u
}

// Total returns all received queries.
func (m *Metrics) Total() uint64 { return m.QueriesUDP.Load() + m.QueriesTCP.Load() }

// Tick must be called once per second; it updates QPS windows.
func (m *Metrics) Tick() {
	tot := m.Total()
	m.mu.Lock()
	d := tot - m.lastTot
	m.lastTot = tot
	m.pos = (m.pos + 1) % len(m.window)
	m.window[m.pos] = tot
	oldest := m.window[(m.pos+1)%len(m.window)]
	m.mu.Unlock()
	m.qps1s.Store(d)
	if oldest <= tot && oldest > 0 {
		m.qps1m.Store((tot - oldest) * 100 / 60)
	} else {
		m.qps1m.Store(tot * 100 / 60)
	}
}

// Run ticks until stop is closed.
func (m *Metrics) Run(stop <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m.Tick()
		}
	}
}

// QPS returns the last-second and last-minute average rates.
func (m *Metrics) QPS() (float64, float64) {
	return float64(m.qps1s.Load()), float64(m.qps1m.Load()) / 100
}

// Gauge is an extra value rendered by WritePrometheus.
type Gauge struct {
	Name, Help string
	Labels     string
	Value      float64
}

// WritePrometheus renders counters in the text exposition format.
func (m *Metrics) WritePrometheus(w io.Writer, gauges []Gauge) {
	p := func(name, typ, help string) { fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ) }
	p("mrk_dns_queries_total", "counter", "Queries received by transport.")
	fmt.Fprintf(w, "mrk_dns_queries_total{proto=\"udp\"} %d\n", m.QueriesUDP.Load())
	fmt.Fprintf(w, "mrk_dns_queries_total{proto=\"tcp\"} %d\n", m.QueriesTCP.Load())
	p("mrk_dns_responses_total", "counter", "Responses by rcode.")
	for i := range m.Rcodes {
		if v := m.Rcodes[i].Load(); v > 0 {
			fmt.Fprintf(w, "mrk_dns_responses_total{rcode=\"%d\"} %d\n", i, v)
		}
	}
	p("mrk_dns_answers_total", "counter", "Answers by source.")
	for i, n := range srcNames {
		fmt.Fprintf(w, "mrk_dns_answers_total{source=%q} %d\n", n, m.Sources[i].Load())
	}
	p("mrk_dns_dropped_total", "counter", "Queries dropped by reason.")
	for i, n := range dropNames {
		fmt.Fprintf(w, "mrk_dns_dropped_total{reason=%q} %d\n", n, m.Drops[i].Load())
	}
	p("mrk_dns_rrl_slipped_total", "counter", "Truncated responses sent by RRL slip.")
	fmt.Fprintf(w, "mrk_dns_rrl_slipped_total %d\n", m.RRLSlips.Load())
	p("mrk_dns_truncated_total", "counter", "UDP responses sent with TC=1.")
	fmt.Fprintf(w, "mrk_dns_truncated_total %d\n", m.Truncated.Load())
	p("mrk_dns_prefetch_total", "counter", "Background cache refreshes.")
	fmt.Fprintf(w, "mrk_dns_prefetch_total %d\n", m.Prefetches.Load())
	p("mrk_dns_rebinding_filtered_total", "counter", "Upstream answers with private addresses removed.")
	fmt.Fprintf(w, "mrk_dns_rebinding_filtered_total %d\n", m.Rebinding.Load())
	p("mrk_dns_tcp_connections", "gauge", "Open inbound TCP connections.")
	fmt.Fprintf(w, "mrk_dns_tcp_connections %d\n", m.TCPConns.Load())
	p("mrk_dns_upstream_inflight", "gauge", "Upstream exchanges in flight.")
	fmt.Fprintf(w, "mrk_dns_upstream_inflight %d\n", m.Inflight.Load())
	q1, q60 := m.QPS()
	p("mrk_dns_qps", "gauge", "Queries per second.")
	fmt.Fprintf(w, "mrk_dns_qps{window=\"1s\"} %g\nmrk_dns_qps{window=\"1m\"} %g\n", q1, q60)
	m.mu.Lock()
	ids := make([]string, 0, len(m.upstream))
	for id := range m.upstream {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	sort.Strings(ids)
	p("mrk_dns_upstream_queries_total", "counter", "Queries sent per upstream.")
	for _, id := range ids {
		u := m.Upstream(id)
		fmt.Fprintf(w, "mrk_dns_upstream_queries_total{upstream=%q} %d\n", id, u.Queries.Load())
	}
	p("mrk_dns_upstream_errors_total", "counter", "Failed upstream exchanges.")
	for _, id := range ids {
		u := m.Upstream(id)
		fmt.Fprintf(w, "mrk_dns_upstream_errors_total{upstream=%q} %d\n", id, u.Errors.Load())
	}
	seen := map[string]bool{}
	for _, g := range gauges {
		if !seen[g.Name] {
			p(g.Name, "gauge", g.Help)
			seen[g.Name] = true
		}
		if g.Labels != "" {
			fmt.Fprintf(w, "%s{%s} %g\n", g.Name, g.Labels, g.Value)
		} else {
			fmt.Fprintf(w, "%s %g\n", g.Name, g.Value)
		}
	}
}
