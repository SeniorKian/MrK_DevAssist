// Package limits implements per-client query rate limiting (token bucket) and
// Response Rate Limiting (RRL) keyed by client prefix and response class, both
// with bounded memory.
package limits

import (
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const shards = 64

// DefaultMaxClients bounds the per-client table (memory ~100 B per client).
const DefaultMaxClients = 1 << 20

type bucket struct {
	tokens float64
	last   int64
}

func (b *bucket) take(now int64, rate, burst float64) bool {
	if b.last == 0 {
		b.tokens = burst
	} else if now > b.last {
		b.tokens += float64(now-b.last) / float64(time.Second) * rate
		if b.tokens > burst {
			b.tokens = burst
		}
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

type cshard struct {
	mu sync.Mutex
	m  map[netip.Addr]*bucket
	_  [40]byte
}

// ClientLimiter limits queries per client address (IPv4 /32, IPv6 /64).
type ClientLimiter struct {
	rate, burst float64
	perShard    int
	shards      [shards]cshard
	overflowMu  sync.Mutex
	overflow    bucket        // shared by new clients when the table is full
	scale       atomic.Uint64 // float64 bits; pressure action tighten_client_qps
	// pressureOnly: client_qps is 0 (unlimited); the limiter only acts while
	// tighten_client_qps scales it down (docs/41 §4).
	pressureOnly bool
}

// PressureFallbackQPS is the per-client rate that tighten_client_qps scales
// when client_qps is 0 (unlimited): ×0.5 at critical = 1000 qps, ×0.25 at
// emergency = 500 qps per client.
const PressureFallbackQPS = 2000

// NewClientLimiterFor returns NewClientLimiter, or for qps <= 0 a limiter
// that allows everything until the pressure controller tightens it, so
// tighten_client_qps also bounds an unlimited configuration.
func NewClientLimiterFor(qps, burst, maxClients int) *ClientLimiter {
	if qps > 0 {
		return NewClientLimiter(qps, burst, maxClients)
	}
	l := NewClientLimiter(PressureFallbackQPS, 2*PressureFallbackQPS, maxClients)
	l.pressureOnly = true
	return l
}

// Unlimited reports whether the limiter only acts under pressure.
func (l *ClientLimiter) Unlimited() bool { return l == nil || l.pressureOnly }

// SetScale multiplies the configured rate and burst (1 = as configured).
func (l *ClientLimiter) SetScale(f float64) {
	if l == nil || f <= 0 || f > 1 {
		return
	}
	l.scale.Store(math.Float64bits(f))
}

// Scale returns the current multiplier.
func (l *ClientLimiter) Scale() float64 {
	if l == nil {
		return 1
	}
	return math.Float64frombits(l.scale.Load())
}

// NewClientLimiter returns nil when qps <= 0 (unlimited).
func NewClientLimiter(qps, burst, maxClients int) *ClientLimiter {
	if qps <= 0 {
		return nil
	}
	if burst < qps {
		burst = qps
	}
	if maxClients <= 0 {
		maxClients = DefaultMaxClients
	}
	l := &ClientLimiter{rate: float64(qps), burst: float64(burst), perShard: maxClients/shards + 1}
	l.scale.Store(math.Float64bits(1))
	for i := range l.shards {
		l.shards[i].m = make(map[netip.Addr]*bucket)
	}
	return l
}

// ClientKey returns the identity used for limiting.
func ClientKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

func addrShard(a netip.Addr) int {
	b := a.As16()
	h := uint32(2166136261)
	for _, x := range b {
		h ^= uint32(x)
		h *= 16777619
	}
	return int(h % shards)
}

// Allow reports whether a query from addr may proceed.
func (l *ClientLimiter) Allow(addr netip.Addr, now int64) bool {
	if l == nil {
		return true
	}
	sc := math.Float64frombits(l.scale.Load())
	if l.pressureOnly && sc >= 1 {
		return true
	}
	k := ClientKey(addr)
	rate, burst := l.rate*sc, math.Max(1, l.burst*sc)
	s := &l.shards[addrShard(k)]
	s.mu.Lock()
	b := s.m[k]
	if b == nil {
		if len(s.m) >= l.perShard {
			l.sweepLocked(s, now)
		}
		if len(s.m) >= l.perShard {
			s.mu.Unlock()
			l.overflowMu.Lock()
			ok := l.overflow.take(now, rate, burst)
			l.overflowMu.Unlock()
			return ok
		}
		b = &bucket{}
		s.m[k] = b
	}
	if b.tokens > burst {
		b.tokens = burst // the burst shrank (tightened)
	}
	ok := b.take(now, rate, burst)
	s.mu.Unlock()
	return ok
}

func (l *ClientLimiter) sweepLocked(s *cshard, now int64) {
	for k, b := range s.m {
		// a bucket that has refilled completely is equivalent to a new one
		if b.tokens+float64(now-b.last)/float64(time.Second)*l.rate >= l.burst {
			delete(s.m, k)
		}
	}
}

// Sweep drops idle clients; call periodically.
func (l *ClientLimiter) Sweep(now int64) {
	if l == nil {
		return
	}
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		l.sweepLocked(s, now)
		s.mu.Unlock()
	}
}

// Len returns the tracked client count.
func (l *ClientLimiter) Len() int {
	if l == nil {
		return 0
	}
	n := 0
	for i := range l.shards {
		l.shards[i].mu.Lock()
		n += len(l.shards[i].m)
		l.shards[i].mu.Unlock()
	}
	return n
}

// Action is the RRL decision for one response.
type Action int

// RRL actions.
const (
	Send Action = iota
	Drop
	Slip // send a truncated (TC=1) empty response so real clients retry over TCP
)

type rrlKey struct {
	prefix netip.Addr
	class  uint64
}

type rrlState struct {
	bucket
	slip uint32
}

type rshard struct {
	mu sync.Mutex
	m  map[rrlKey]*rrlState
	_  [40]byte
}

// RRL limits identical responses towards one client prefix (BIND-style RRL).
type RRL struct {
	rate     float64
	slip     uint32
	v4, v6   int
	perShard int
	shards   [shards]rshard
}

// NewRRL returns nil when rps <= 0 (disabled).
func NewRRL(rps, slip, v4bits, v6bits, maxEntries int) *RRL {
	if rps <= 0 {
		return nil
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxClients
	}
	r := &RRL{rate: float64(rps), slip: uint32(slip), v4: v4bits, v6: v6bits, perShard: maxEntries/shards + 1}
	for i := range r.shards {
		r.shards[i].m = make(map[rrlKey]*rrlState)
	}
	return r
}

// Prefix returns the aggregation prefix address of a client.
func (r *RRL) Prefix(a netip.Addr) netip.Addr {
	a = a.Unmap()
	bits := r.v4
	if a.Is6() {
		bits = r.v6
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return a
	}
	return p.Addr()
}

// Check accounts one response of class (a hash of the response identity).
func (r *RRL) Check(client netip.Addr, class uint64, now int64) Action {
	if r == nil {
		return Send
	}
	k := rrlKey{prefix: r.Prefix(client), class: class}
	s := &r.shards[(addrShard(k.prefix)+int(class%shards))%shards]
	s.mu.Lock()
	st := s.m[k]
	if st == nil {
		if len(s.m) >= r.perShard {
			for kk, v := range s.m {
				if v.tokens+float64(now-v.last)/float64(time.Second)*r.rate >= r.rate {
					delete(s.m, kk)
				}
			}
		}
		if len(s.m) >= r.perShard {
			s.mu.Unlock()
			return Drop // table full under attack: fail closed for new response classes
		}
		st = &rrlState{}
		s.m[k] = st
	}
	if st.take(now, r.rate, r.rate) {
		s.mu.Unlock()
		return Send
	}
	act := Drop
	if r.slip > 0 {
		st.slip++
		if st.slip%r.slip == 0 {
			act = Slip
		}
	}
	s.mu.Unlock()
	return act
}

// Sweep drops idle entries.
func (r *RRL) Sweep(now int64) {
	if r == nil {
		return
	}
	for i := range r.shards {
		s := &r.shards[i]
		s.mu.Lock()
		for k, v := range s.m {
			if v.tokens+float64(now-v.last)/float64(time.Second)*r.rate >= r.rate {
				delete(s.m, k)
			}
		}
		s.mu.Unlock()
	}
}

// ClassHash hashes response identity parts (FNV-1a 64).
func ClassHash(parts ...string) uint64 {
	h := uint64(14695981039346656037)
	for _, p := range parts {
		for i := 0; i < len(p); i++ {
			h ^= uint64(p[i])
			h *= 1099511628211
		}
		h ^= 0xff
		h *= 1099511628211
	}
	return h
}
