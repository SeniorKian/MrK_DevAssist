// Package topk implements the Space-Saving heavy-hitter algorithm
// (Metwally, Agrawal, El Abbadi 2005): with m counters, every key whose true
// count exceeds N/m is guaranteed to be tracked, and each reported count
// overestimates the truth by at most its Err. Memory is O(m).
package topk

import (
	"container/heap"
	"sort"
)

type counter struct {
	key   string
	count uint64
	err   uint64
	idx   int
}

type minHeap []*counter

func (h minHeap) Len() int           { return len(h) }
func (h minHeap) Less(i, j int) bool { return h[i].count < h[j].count }
func (h minHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].idx = i; h[j].idx = j }
func (h *minHeap) Push(x any)        { c := x.(*counter); c.idx = len(*h); *h = append(*h, c) }
func (h *minHeap) Pop() any {
	old := *h
	c := old[len(old)-1]
	*h = old[:len(old)-1]
	return c
}

// Summary is a Space-Saving summary. Not safe for concurrent use.
type Summary struct {
	cap   int
	m     map[string]*counter
	h     minHeap
	total uint64
}

// New returns a summary with capacity m (minimum 1).
func New(m int) *Summary {
	if m < 1 {
		m = 1
	}
	return &Summary{cap: m, m: make(map[string]*counter, m)}
}

// Cap returns the counter capacity.
func (s *Summary) Cap() int { return s.cap }

// Total returns the sum of all weights added.
func (s *Summary) Total() uint64 { return s.total }

// Len returns the number of tracked keys.
func (s *Summary) Len() int { return len(s.m) }

// AddBytes is Add for a byte-slice key; it does not allocate when the key is
// already tracked.
func (s *Summary) AddBytes(key []byte, w uint64) {
	if c, ok := s.m[string(key)]; ok {
		s.total += w
		c.count += w
		heap.Fix(&s.h, c.idx)
		return
	}
	s.Add(string(key), w)
}

// Add counts w occurrences of key.
func (s *Summary) Add(key string, w uint64) {
	s.total += w
	if c, ok := s.m[key]; ok {
		c.count += w
		heap.Fix(&s.h, c.idx)
		return
	}
	if len(s.m) < s.cap {
		c := &counter{key: key, count: w}
		s.m[key] = c
		heap.Push(&s.h, c)
		return
	}
	// replace the minimum: the newcomer inherits its count as error bound
	c := s.h[0]
	delete(s.m, c.key)
	c.key, c.err, c.count = key, c.count, c.count+w
	s.m[key] = c
	heap.Fix(&s.h, 0)
}

// Item is one reported heavy hitter.
type Item struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
	Err   uint64 `json:"err,omitempty"`
}

// Top returns up to n items with the highest counts, descending (ties by key).
func (s *Summary) Top(n int) []Item {
	out := make([]Item, 0, len(s.m))
	for _, c := range s.m {
		out = append(out, Item{Key: c.key, Count: c.count, Err: c.err})
	}
	sortItems(out)
	if n >= 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func sortItems(out []Item) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
}

// Reset clears the summary keeping its capacity.
func (s *Summary) Reset() {
	clear(s.m)
	s.h = s.h[:0]
	s.total = 0
}

// Merge combines item lists (e.g. per-minute summaries) into the n heaviest:
// counts of the same key are summed. Merging Space-Saving summaries this way
// keeps the overestimation guarantee (errors add up).
func Merge(n int, lists ...[]Item) []Item {
	agg := map[string]*Item{}
	for _, l := range lists {
		for _, it := range l {
			if a := agg[it.Key]; a != nil {
				a.Count += it.Count
				a.Err += it.Err
			} else {
				c := it
				agg[it.Key] = &c
			}
		}
	}
	out := make([]Item, 0, len(agg))
	for _, a := range agg {
		out = append(out, *a)
	}
	sortItems(out)
	if n >= 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// AddReport is Add that also reports which key (if any) was evicted to make
// room for key, so callers can drop per-key state.
func (s *Summary) AddReport(key string, w uint64) (evicted string, did bool) {
	if _, ok := s.m[key]; ok || len(s.m) < s.cap {
		s.Add(key, w)
		return "", false
	}
	evicted = s.h[0].key
	s.Add(key, w)
	return evicted, true
}

// Count returns the tracked count of key (0 if untracked).
func (s *Summary) Count(key string) uint64 {
	if c, ok := s.m[key]; ok {
		return c.count
	}
	return 0
}
