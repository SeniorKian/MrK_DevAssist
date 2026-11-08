// Package attack detects random-subdomain ("water torture") attacks and
// NXDOMAIN floods from the stream of answered queries (docs/38 §3).
//
// Random subdomain: for each parent (the NXDOMAIN name without its first
// label, at least two labels deep) a HyperLogLog per 10-second sub-window
// estimates the distinct names; the six sub-windows of the last minute are
// merged and compared with nxdomain_unique_per_minute. Parents are tracked
// in a bounded Space-Saving summary (256), so memory is fixed even when the
// attacker sprays parents.
//
// NXDOMAIN flood: per client NXDOMAIN answers in the last minute (six
// Space-Saving sub-windows) at or above twice the threshold.
//
// An attack ends when its rate falls below half the threshold.
package attack

import (
	"sort"
	"strings"
	"sync"
	"time"

	"mrk/dns-engine/internal/hll"
	"mrk/dns-engine/internal/topk"
)

// Kinds.
const (
	RandomSubdomain = "random_subdomain"
	NXDomainFlood   = "nxdomain_flood"
)

const (
	subWindows   = 6
	subWindow    = 10 * time.Second
	maxParents   = 256
	hllPrecision = 10
	clientCap    = 512
)

// Attack is one detected attack.
type Attack struct {
	Kind                 string    `json:"kind"`
	Parent               string    `json:"parent,omitempty"`
	Client               string    `json:"client,omitempty"`
	UniqueNXDomainPerMin uint64    `json:"unique_nxdomain_per_min"`
	NXDomainPerMin       uint64    `json:"nxdomain_per_min"`
	TopClients           []string  `json:"top_clients"`
	Since                time.Time `json:"since"`
	MitigationID         string    `json:"mitigation_id,omitempty"`
}

// Key identifies an attack.
func (a *Attack) Key() string { return a.Kind + "|" + a.Parent + "|" + a.Client }

type parent struct {
	subs    [subWindows]*hll.Sketch
	counts  [subWindows]uint64
	clients *topk.Summary
}

// Detector is fed by one goroutine (Observe) and evaluated by Tick; reads
// (Active) may come from any goroutine.
type Detector struct {
	now func() time.Time

	mu        sync.Mutex
	threshold uint64
	sub       int // current sub-window index
	subStart  time.Time
	cycle     int
	parents   map[string]*parent
	pcount    *topk.Summary
	clients   [subWindows]*topk.Summary
	active    map[string]*Attack
	merged    *hll.Sketch
}

// New creates a detector.
func New(threshold int, now func() time.Time) *Detector {
	if now == nil {
		now = time.Now
	}
	d := &Detector{now: now, threshold: uint64(threshold), parents: map[string]*parent{}, pcount: topk.New(maxParents),
		active: map[string]*Attack{}, merged: hll.New(hllPrecision), subStart: now()}
	for i := range d.clients {
		d.clients[i] = topk.New(clientCap)
	}
	return d
}

// SetThreshold updates nxdomain_unique_per_minute.
func (d *Detector) SetThreshold(n int) {
	d.mu.Lock()
	d.threshold = uint64(n)
	d.mu.Unlock()
}

// ParentOf returns the parent of a presentation name ("" when it has fewer
// than three labels: TLD-level floods are covered by the client detector).
func ParentOf(name string) string {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return ""
	}
	p := name[i+1:]
	if strings.IndexByte(p, '.') < 0 {
		return ""
	}
	return p
}

// Observe records one NXDOMAIN answer for name (presentation form) by client.
func (d *Detector) Observe(name, client string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if client != "" {
		d.clients[d.sub].Add(client, 1)
	}
	p := ParentOf(name)
	if p == "" {
		return
	}
	st := d.parents[p]
	if st == nil {
		if ev, did := d.pcount.AddReport(p, 1); did {
			delete(d.parents, ev)
		}
		st = &parent{clients: topk.New(8)}
		d.parents[p] = st
	} else {
		d.pcount.Add(p, 1)
	}
	sk := st.subs[d.sub]
	if sk == nil {
		sk = hll.New(hllPrecision)
		st.subs[d.sub] = sk
	}
	sk.Add([]byte(name))
	st.counts[d.sub]++
	if client != "" {
		st.clients.Add(client, 1)
	}
}

// Change is a start or end of an attack reported by Tick.
type Change struct {
	Attack  Attack
	Started bool // false: ended
}

// Tick rotates sub-windows every 10 s and evaluates; it returns changes.
func (d *Detector) Tick() []Change {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Sub(d.subStart) < subWindow {
		return nil
	}
	changes := d.evaluateLocked(now)
	// rotate: advance one sub-window and clear it
	steps := int(now.Sub(d.subStart) / subWindow)
	if steps > subWindows {
		steps = subWindows
	}
	for i := 0; i < steps; i++ {
		d.sub = (d.sub + 1) % subWindows
		if d.sub == 0 {
			d.cycle++
		}
		d.clients[d.sub].Reset()
		for _, st := range d.parents {
			if st.subs[d.sub] != nil {
				st.subs[d.sub].Reset()
			}
			st.counts[d.sub] = 0
			if d.sub == 0 {
				st.clients.Reset()
			}
		}
	}
	d.subStart = d.subStart.Add(time.Duration(steps) * subWindow)
	// rebuild the parent summary from windowed counts so old parents decay
	np := topk.New(maxParents)
	for p, st := range d.parents {
		var c uint64
		for _, v := range st.counts {
			c += v
		}
		if c == 0 {
			delete(d.parents, p)
			continue
		}
		np.Add(p, c)
	}
	d.pcount = np
	return changes
}

func (d *Detector) evaluateLocked(now time.Time) []Change {
	var out []Change
	seen := map[string]bool{}
	thr := d.threshold
	for p, st := range d.parents {
		d.merged.Reset()
		var total uint64
		for i, sk := range st.subs {
			d.merged.Merge(sk)
			total += st.counts[i]
		}
		u := d.merged.Estimate()
		if u > total {
			u = total
		}
		a := &Attack{Kind: RandomSubdomain, Parent: p}
		k := a.Key()
		if cur := d.active[k]; cur != nil {
			if u*2 >= thr {
				cur.UniqueNXDomainPerMin, cur.NXDomainPerMin = u, total
				cur.TopClients = keys(st.clients.Top(5))
				seen[k] = true
			}
			continue
		}
		if u >= thr {
			a.UniqueNXDomainPerMin, a.NXDomainPerMin, a.Since = u, total, now.UTC()
			a.TopClients = keys(st.clients.Top(5))
			d.active[k] = a
			seen[k] = true
			out = append(out, Change{Attack: *a, Started: true})
		}
	}
	merged := topk.Merge(-1, func() [][]topk.Item {
		var l [][]topk.Item
		for _, c := range d.clients {
			l = append(l, c.Top(-1))
		}
		return l
	}()...)
	for _, it := range merged {
		a := &Attack{Kind: NXDomainFlood, Client: it.Key}
		k := a.Key()
		if cur := d.active[k]; cur != nil {
			if it.Count >= thr {
				cur.NXDomainPerMin = it.Count
				seen[k] = true
			}
			continue
		}
		if it.Count >= 2*thr {
			a.NXDomainPerMin, a.Since, a.TopClients = it.Count, now.UTC(), []string{it.Key}
			d.active[k] = a
			seen[k] = true
			out = append(out, Change{Attack: *a, Started: true})
		}
	}
	for k, a := range d.active {
		if !seen[k] {
			out = append(out, Change{Attack: *a, Started: false})
			delete(d.active, k)
		}
	}
	return out
}

func keys(items []topk.Item) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Key)
	}
	return out
}

// SetMitigation records the mitigation created for an attack.
func (d *Detector) SetMitigation(key, id string) {
	d.mu.Lock()
	if a := d.active[key]; a != nil {
		a.MitigationID = id
	}
	d.mu.Unlock()
}

// Active returns current attacks, strongest first.
func (d *Detector) Active() []Attack {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Attack, 0, len(d.active))
	for _, a := range d.active {
		c := *a
		c.TopClients = append([]string{}, a.TopClients...)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UniqueNXDomainPerMin != out[j].UniqueNXDomainPerMin {
			return out[i].UniqueNXDomainPerMin > out[j].UniqueNXDomainPerMin
		}
		return out[i].Key() < out[j].Key()
	})
	return out
}

// Reset forgets everything (mode switched off).
func (d *Detector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.parents = map[string]*parent{}
	d.pcount = topk.New(maxParents)
	d.active = map[string]*Attack{}
	for i := range d.clients {
		d.clients[i].Reset()
	}
}

// ObserveBatch records NXDOMAIN answers (names and clients in parallel).
func (d *Detector) ObserveBatch(names, clients []string) {
	for i := range names {
		d.Observe(names[i], clients[i])
	}
}
