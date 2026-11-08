package resolver

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
)

// Limiter bounds concurrent upstream exchanges across all groups.
type Limiter struct{ ch chan struct{} }

// NewLimiter returns a limiter with n slots.
func NewLimiter(n int) *Limiter { return &Limiter{ch: make(chan struct{}, n)} }

// TryAcquire takes a slot without waiting.
func (l *Limiter) TryAcquire() bool {
	select {
	case l.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release returns a slot.
func (l *Limiter) Release() { <-l.ch }

// InUse returns occupied slots.
func (l *Limiter) InUse() int { return len(l.ch) }

// Group is an ordered set of upstreams with a selection strategy.
type Group struct {
	Upstreams []*Upstream
	Strategy  string
	limiter   *Limiter
	// AttemptTimeout bounds one exchange; MaxAttempts bounds retries.
	AttemptTimeout time.Duration
	MaxAttempts    int
}

// NewGroup builds a group of enabled upstreams.
func NewGroup(ups []*Upstream, strategy string, lim *Limiter) *Group {
	var en []*Upstream
	for _, u := range ups {
		if u.Enabled {
			en = append(en, u)
		}
	}
	return &Group{Upstreams: en, Strategy: strategy, limiter: lim, AttemptTimeout: 1500 * time.Millisecond, MaxAttempts: 3}
}

// order returns the candidate order for one query.
func (g *Group) order() []*Upstream {
	c := make([]*Upstream, 0, len(g.Upstreams))
	var sick []*Upstream
	for _, u := range g.Upstreams {
		if u.Healthy() {
			c = append(c, u)
		} else {
			sick = append(sick, u)
		}
	}
	if g.Strategy == config.StrategyFastest {
		sort.SliceStable(c, func(i, j int) bool { return c[i].RTT() < c[j].RTT() })
	}
	// unhealthy ones are a last resort (fail open, never fail closed)
	return append(c, sick...)
}

// Exchange resolves q (its Id may be rewritten) and returns the response and
// the upstream that answered.
func (g *Group) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, *Upstream, error) {
	if g == nil || len(g.Upstreams) == 0 {
		return nil, nil, ErrNoUpstream
	}
	cands := g.order()
	if g.Strategy == config.StrategyParallel {
		return g.parallel(ctx, q, cands)
	}
	var lastErr error
	attempts := g.MaxAttempts
	if attempts > len(cands) {
		attempts = len(cands)
	}
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			break
		}
		r, err := g.one(ctx, q.Copy(), cands[i])
		if err == nil && r.Rcode != dns.RcodeServerFailure && r.Rcode != dns.RcodeRefused {
			return r, cands[i], nil
		}
		if err == nil {
			lastErr = errors.New("resolver: upstream returned " + dns.RcodeToString[r.Rcode])
			if i == attempts-1 {
				return r, cands[i], nil // pass the upstream's own error rcode through
			}
			continue
		}
		lastErr = err
		if errors.Is(err, ErrOverloaded) {
			break
		}
	}
	if lastErr == nil {
		lastErr = context.DeadlineExceeded
	}
	return nil, nil, lastErr
}

func (g *Group) one(ctx context.Context, q *dns.Msg, u *Upstream) (*dns.Msg, error) {
	if g.limiter != nil {
		if !g.limiter.TryAcquire() {
			return nil, ErrOverloaded
		}
		defer g.limiter.Release()
	}
	to := g.AttemptTimeout
	if rtt := u.RTT(); u.Healthy() && 4*rtt+200*time.Millisecond < to {
		to = 4*rtt + 200*time.Millisecond
	}
	actx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	q.Id = dns.Id()
	r, _, err := u.Exchange(actx, q)
	return r, err
}

func (g *Group) parallel(ctx context.Context, q *dns.Msg, cands []*Upstream) (*dns.Msg, *Upstream, error) {
	n := len(cands)
	if n > 3 {
		n = 3
	}
	type res struct {
		r   *dns.Msg
		u   *Upstream
		err error
	}
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan res, n)
	for i := 0; i < n; i++ {
		go func(u *Upstream) {
			r, err := g.one(pctx, q.Copy(), u)
			ch <- res{r, u, err}
		}(cands[i])
	}
	var fallback *res
	var lastErr error
	for i := 0; i < n; i++ {
		x := <-ch
		if x.err == nil && x.r.Rcode != dns.RcodeServerFailure && x.r.Rcode != dns.RcodeRefused {
			return x.r, x.u, nil
		}
		if x.err == nil && fallback == nil {
			fallback = &x
		}
		if x.err != nil {
			lastErr = x.err
		}
	}
	if fallback != nil {
		return fallback.r, fallback.u, nil
	}
	return nil, nil, lastErr
}

// HealthCheck probes upstreams that are unhealthy or idle (". NS" query).
func (g *Group) HealthCheck(ctx context.Context, idle time.Duration) {
	var wg sync.WaitGroup
	now := time.Now().UnixNano()
	for _, u := range g.Upstreams {
		if u.Healthy() && now-u.lastUsed.Load() < int64(idle) {
			continue
		}
		wg.Add(1)
		go func(u *Upstream) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			_, _, _ = u.Exchange(cctx, NewQuery(".", dns.TypeNS))
		}(u)
	}
	wg.Wait()
}

// Flight coalesces concurrent identical work (single-flight).
type Flight struct {
	mu sync.Mutex
	m  map[string]*call
}

type call struct {
	done chan struct{}
	val  any
	err  error
	dups int
}

// Do runs fn once per key among concurrent callers. shared reports whether
// the result came from another caller's execution.
func (f *Flight) Do(key string, fn func() (any, error)) (v any, err error, shared bool) {
	f.mu.Lock()
	if f.m == nil {
		f.m = map[string]*call{}
	}
	if c, ok := f.m[key]; ok {
		c.dups++
		f.mu.Unlock()
		<-c.done
		return c.val, c.err, true
	}
	c := &call{done: make(chan struct{})}
	f.m[key] = c
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.m, key)
		f.mu.Unlock()
		close(c.done)
	}()
	c.val, c.err = fn()
	return c.val, c.err, false
}

// DoChan is like Do but returns a channel so callers can stop waiting.
func (f *Flight) DoChan(key string, fn func() (any, error)) <-chan Result {
	ch := make(chan Result, 1)
	go func() {
		v, err, shared := f.Do(key, fn)
		ch <- Result{Val: v, Err: err, Shared: shared}
	}()
	return ch
}

// Result of DoChan.
type Result struct {
	Val    any
	Err    error
	Shared bool
}

// Pending returns the number of keys in flight.
func (f *Flight) Pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.m)
}
