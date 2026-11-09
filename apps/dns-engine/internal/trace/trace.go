// Package trace collects the step-by-step path of one test resolution
// (POST /v1/resolve trace:true, docs/40 §3) and carries the "bypass caches"
// flag through the resolver and validator.
package trace

import (
	"context"
	"sync"
)

// MaxSteps bounds a trace.
const MaxSteps = 200

// Step is one exchange or validation decision.
type Step struct {
	Step       int      `json:"step"`
	Zone       string   `json:"zone"`
	Server     string   `json:"server"`
	ServerName string   `json:"server_name,omitempty"`
	QName      string   `json:"qname"`
	QType      string   `json:"qtype"`
	Rcode      string   `json:"rcode"`
	RTTMS      float64  `json:"rtt_ms"`
	Referral   []string `json:"referral,omitempty"`
	DNSSEC     string   `json:"dnssec,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// Trace is safe for concurrent use.
type Trace struct {
	mu        sync.Mutex
	steps     []Step
	truncated bool
}

// Add appends a step (numbered from 1); beyond MaxSteps it is dropped.
func (t *Trace) Add(s Step) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.steps) >= MaxSteps {
		t.truncated = true
		return
	}
	s.Step = len(t.steps) + 1
	t.steps = append(t.steps, s)
}

// Steps returns a copy of the steps.
func (t *Trace) Steps() []Step {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Step{}, t.steps...)
}

type ctxKey struct{}

type ctxVal struct {
	t       *Trace
	noCache bool
}

// With returns ctx carrying t (may be nil) and the no-cache flag.
func With(ctx context.Context, t *Trace, noCache bool) context.Context {
	return context.WithValue(ctx, ctxKey{}, &ctxVal{t: t, noCache: noCache || t != nil})
}

// From returns the trace of ctx (nil when not tracing).
func From(ctx context.Context) *Trace {
	if v, ok := ctx.Value(ctxKey{}).(*ctxVal); ok {
		return v.t
	}
	return nil
}

// NoCache reports whether caches must be bypassed (a trace always does).
func NoCache(ctx context.Context) bool {
	if v, ok := ctx.Value(ctxKey{}).(*ctxVal); ok {
		return v.noCache
	}
	return false
}
