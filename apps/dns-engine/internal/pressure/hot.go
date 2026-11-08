package pressure

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"mrk/dns-engine/internal/limits"
	"mrk/dns-engine/internal/topk"
)

const (
	hotSlots = 10  // seconds in the sliding window
	hotCap   = 256 // Space-Saving counters per second and dimension
	// HeavyShare is the share of all queries above which a client is heavy.
	HeavyShare = 0.20
	// HeavyMinQPS is the absolute floor for a heavy client.
	HeavyMinQPS = 50
	// HeavyCapacityShare: a heavy client must also send at least this share
	// of capacity_qps, so a lone normal client is never refused.
	HeavyCapacityShare = 0.02
)

// Hot tracks the heaviest domains and clients over the last 10 seconds
// (ten per-second Space-Saving summaries). Observe runs on the pipeline
// goroutine; Tick once a second.
type Hot struct {
	mu      sync.Mutex
	pos     int
	doms    [hotSlots]*topk.Summary
	clis    [hotSlots]*topk.Summary
	totals  [hotSlots]uint64
	keyAddr map[string]netip.Addr

	heavy atomic.Pointer[map[netip.Addr]struct{}]
	view  atomic.Pointer[HotView]
}

// NewHot creates a tracker.
func NewHot() *Hot {
	h := &Hot{keyAddr: map[string]netip.Addr{}}
	for i := range h.doms {
		h.doms[i], h.clis[i] = topk.New(hotCap), topk.New(hotCap)
	}
	empty := map[netip.Addr]struct{}{}
	h.heavy.Store(&empty)
	h.view.Store(&HotView{Domains: []HotName{}, Clients: []HotClient{}})
	return h
}

// ClientKeyString renders the rate-limit identity of a client (IPv4
// address, IPv6 /64) as used in hot lists and mitigations.
func ClientKeyString(a netip.Addr) string {
	k := limits.ClientKey(a)
	if k.Is6() {
		return netip.PrefixFrom(k, 64).String()
	}
	return k.String()
}

// Observe counts one query. clientKey must come from ClientKeyString.
func (h *Hot) Observe(name, clientKey string, addr netip.Addr) {
	h.mu.Lock()
	h.doms[h.pos].Add(name, 1)
	if clientKey != "" {
		if _, ok := h.keyAddr[clientKey]; !ok && len(h.keyAddr) < 1<<16 {
			h.keyAddr[clientKey] = limits.ClientKey(addr)
		}
		h.clis[h.pos].Add(clientKey, 1)
	}
	h.totals[h.pos]++
	h.mu.Unlock()
}

// HotName is a hot domain.
type HotName struct {
	Name string  `json:"name"`
	QPS  float64 `json:"qps"`
}

// HotClient is a hot client.
type HotClient struct {
	Client string  `json:"client"`
	QPS    float64 `json:"qps"`
	Share  float64 `json:"share"`
}

// HotView is the published top lists.
type HotView struct {
	Domains []HotName   `json:"domains"`
	Clients []HotClient `json:"clients"`
	Total   uint64      `json:"-"`
}

// Tick publishes the window, computes heavy clients and rotates. scale
// corrects for records lost before the tracker (total qps / observed qps).
// A heavy client sends at least HeavyShare of all queries and at least
// max(HeavyMinQPS, HeavyCapacityShare*capacityQPS) queries per second.
func (h *Hot) Tick(scale float64, capacityQPS int) {
	if scale < 1 {
		scale = 1
	}
	h.mu.Lock()
	var dl, cl [][]topk.Item
	var total uint64
	for i := 0; i < hotSlots; i++ {
		dl = append(dl, h.doms[i].Top(64))
		cl = append(cl, h.clis[i].Top(64))
		total += h.totals[i]
	}
	keyAddr := h.keyAddr
	h.pos = (h.pos + 1) % hotSlots
	h.doms[h.pos].Reset()
	h.clis[h.pos].Reset()
	h.totals[h.pos] = 0
	if len(h.keyAddr) > 1<<15 {
		h.keyAddr = map[string]netip.Addr{}
	}
	h.mu.Unlock()

	doms := topk.Merge(20, dl...)
	clis := topk.Merge(20, cl...)
	v := &HotView{Domains: make([]HotName, 0, len(doms)), Clients: make([]HotClient, 0, len(clis)), Total: total}
	for _, it := range doms {
		v.Domains = append(v.Domains, HotName{Name: it.Key, QPS: round1(float64(it.Count) * scale / hotSlots)})
	}
	heavy := map[netip.Addr]struct{}{}
	minQPS := max(HeavyMinQPS, HeavyCapacityShare*float64(capacityQPS))
	for _, it := range clis {
		share := 0.0
		if total > 0 {
			share = float64(it.Count) / float64(total)
		}
		qps := float64(it.Count) * scale / hotSlots
		v.Clients = append(v.Clients, HotClient{Client: it.Key, QPS: round1(qps), Share: round1(share * 100)})
		if share >= HeavyShare && qps >= minQPS {
			if a, ok := keyAddr[it.Key]; ok && !a.IsLoopback() {
				heavy[a] = struct{}{}
			}
		}
	}
	h.view.Store(v)
	h.heavy.Store(&heavy)
}

// View returns the last published lists.
func (h *Hot) View() HotView { return *h.view.Load() }

// Heavy returns the heavy-client set (keys from limits.ClientKey). Never nil.
func (h *Hot) Heavy() map[netip.Addr]struct{} { return *h.heavy.Load() }

// ObserveBatch is Observe for a batch under one lock.
func (h *Hot) ObserveBatch(names, keys []string, addrs []netip.Addr) {
	h.mu.Lock()
	for i, name := range names {
		h.doms[h.pos].Add(name, 1)
		if k := keys[i]; k != "" {
			if _, ok := h.keyAddr[k]; !ok && len(h.keyAddr) < 1<<16 {
				h.keyAddr[k] = limits.ClientKey(addrs[i])
			}
			h.clis[h.pos].Add(k, 1)
		}
	}
	h.totals[h.pos] += uint64(len(names))
	h.mu.Unlock()
}
