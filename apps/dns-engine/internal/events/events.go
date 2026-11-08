// Package events is the engine's in-memory event ring (docs/38 §3
// GET /v1/events): the last 1000 notable events with a monotonically
// increasing sequence number that the panel polls with ?after=<seq>.
//
// Sequence numbers start at unix-milliseconds*1000 when the engine starts, so
// they keep increasing across restarts and a panel cursor from before a
// restart never hides new events.
package events

import (
	"sync"
	"time"
)

// Types (docs/38 §3).
const (
	PressureLevel     = "pressure.level"
	AttackDetected    = "attack.detected"
	MitigationAuto    = "mitigation.auto"
	MitigationExpired = "mitigation.expired"
	QueryLogDegraded  = "querylog.degraded"
	QueryLogRecovered = "querylog.recovered"
)

// Severities.
const (
	Info     = "info"
	Warning  = "warning"
	Error    = "error"
	Critical = "critical"
)

// Capacity of the ring.
const Capacity = 1000

// Event is one item.
type Event struct {
	Seq      int64          `json:"seq"`
	TS       time.Time      `json:"ts"`
	Type     string         `json:"type"`
	Severity string         `json:"severity"`
	Data     map[string]any `json:"data"`
}

// Ring stores the last Capacity events. Safe for concurrent use.
type Ring struct {
	mu   sync.Mutex
	buf  []Event
	head int // index of oldest
	n    int
	seq  int64
	now  func() time.Time
	subs []func(Event)
}

// New creates a ring; now may be nil (time.Now).
func New(now func() time.Time) *Ring {
	if now == nil {
		now = time.Now
	}
	return &Ring{buf: make([]Event, Capacity), now: now, seq: now().UnixMilli() * 1000}
}

// Subscribe registers f, called synchronously (keep it cheap) for every event.
func (r *Ring) Subscribe(f func(Event)) {
	r.mu.Lock()
	r.subs = append(r.subs, f)
	r.mu.Unlock()
}

// Emit appends an event and returns it.
func (r *Ring) Emit(typ, severity string, data map[string]any) Event {
	if data == nil {
		data = map[string]any{}
	}
	r.mu.Lock()
	r.seq++
	ev := Event{Seq: r.seq, TS: r.now().UTC(), Type: typ, Severity: severity, Data: data}
	if r.n < len(r.buf) {
		r.buf[(r.head+r.n)%len(r.buf)] = ev
		r.n++
	} else {
		r.buf[r.head] = ev
		r.head = (r.head + 1) % len(r.buf)
	}
	subs := r.subs
	r.mu.Unlock()
	for _, f := range subs {
		f(ev)
	}
	return ev
}

// After returns events with seq > after (oldest first, at most limit) and the
// cursor to use next. A cursor larger than the newest sequence (clock moved
// back across a restart) returns everything held.
func (r *Ring) After(after int64, limit int) ([]Event, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit <= 0 || limit > Capacity {
		limit = Capacity
	}
	if after > r.seq {
		after = 0
	}
	out := []Event{}
	next := after
	for i := 0; i < r.n && len(out) < limit; i++ {
		ev := r.buf[(r.head+i)%len(r.buf)]
		if ev.Seq > after {
			out = append(out, ev)
			next = ev.Seq
		}
	}
	if len(out) == 0 && next < r.seq && after == 0 {
		next = r.seq
	}
	return out, next
}

// Last returns the newest sequence number.
func (r *Ring) Last() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seq
}
