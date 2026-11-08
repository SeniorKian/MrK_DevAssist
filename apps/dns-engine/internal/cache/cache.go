// Package cache is a sharded, byte-capped LRU cache of packed DNS responses
// with RFC 2308 negative entries and an RFC 8767 serve-stale window.
package cache

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mrk/dns-engine/internal/wire"
)

const shardCount = 64

// Entry is an immutable cached response plus a few atomic hints.
type Entry struct {
	key        string
	Name       string // lower-case FQDN, for subtree flushes
	T          *wire.Template
	Stored     int64 // unix nanoseconds
	Expire     int64 // fresh until
	StaleUntil int64 // may be served stale until
	OrigTTL    uint32
	Negative   bool

	Hits       atomic.Uint32
	Refreshing atomic.Bool  // a prefetch/refresh is in flight
	RetryAfter atomic.Int64 // after a failed refresh: serve stale without retrying until
	size       int64
	prev, next *Entry
}

// Fresh reports whether e is within its TTL at now.
func (e *Entry) Fresh(now int64) bool { return now < e.Expire }

// Elapsed returns whole seconds since insertion.
func (e *Entry) Elapsed(now int64) uint32 {
	d := (now - e.Stored) / int64(time.Second)
	if d < 0 {
		return 0
	}
	return uint32(d)
}

// Remaining returns the remaining fresh seconds (0 if expired).
func (e *Entry) Remaining(now int64) uint32 {
	if now >= e.Expire {
		return 0
	}
	return uint32((e.Expire - now) / int64(time.Second))
}

type shard struct {
	mu    sync.Mutex
	m     map[string]*Entry
	head  *Entry // most recent
	tail  *Entry
	bytes int64
	_     [40]byte // keep shards on separate cache lines
}

// Cache is safe for concurrent use.
type Cache struct {
	shards   [shardCount]shard
	maxShard atomic.Int64
	hits     atomic.Uint64
	misses   atomic.Uint64
	evicted  atomic.Uint64
}

// New returns a cache bounded to roughly maxBytes.
func New(maxBytes int64) *Cache {
	c := &Cache{}
	for i := range c.shards {
		c.shards[i].m = make(map[string]*Entry)
	}
	c.SetMaxBytes(maxBytes)
	return c
}

// SetMaxBytes changes the bound; shrinking evicts lazily on the next insert
// and eagerly here.
func (c *Cache) SetMaxBytes(n int64) {
	per := n / shardCount
	if per < 4096 {
		per = 4096
	}
	c.maxShard.Store(per)
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		c.evictLocked(s, per)
		s.mu.Unlock()
	}
}

// MaxBytes returns the configured bound.
func (c *Cache) MaxBytes() int64 { return c.maxShard.Load() * shardCount }

func hash(b []byte) uint32 {
	h := uint32(2166136261)
	for _, x := range b {
		h ^= uint32(x)
		h *= 16777619
	}
	return h
}

func (c *Cache) shardFor(key []byte) *shard { return &c.shards[hash(key)%shardCount] }

func (s *shard) unlink(e *Entry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		s.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		s.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

func (s *shard) pushFront(e *Entry) {
	e.next = s.head
	e.prev = nil
	if s.head != nil {
		s.head.prev = e
	}
	s.head = e
	if s.tail == nil {
		s.tail = e
	}
}

func (s *shard) remove(e *Entry) {
	s.unlink(e)
	delete(s.m, e.key)
	s.bytes -= e.size
}

func (c *Cache) evictLocked(s *shard, limit int64) {
	for s.bytes > limit && s.tail != nil {
		s.remove(s.tail)
		c.evicted.Add(1)
	}
}

// Get returns the entry for key (fresh or within the stale window), or nil.
// Entries beyond the stale window are removed.
func (c *Cache) Get(key []byte, now int64) *Entry {
	s := c.shardFor(key)
	s.mu.Lock()
	e := s.m[string(key)]
	if e == nil {
		s.mu.Unlock()
		c.misses.Add(1)
		return nil
	}
	if now >= e.StaleUntil && now >= e.Expire {
		s.remove(e)
		s.mu.Unlock()
		c.misses.Add(1)
		return nil
	}
	if s.head != e {
		s.unlink(e)
		s.pushFront(e)
	}
	s.mu.Unlock()
	c.hits.Add(1)
	e.Hits.Add(1)
	return e
}

// Put inserts a response. ttl is the fresh lifetime, stale the extra window.
func (c *Cache) Put(key []byte, name string, t *wire.Template, ttl, stale uint32, negative bool, now int64) *Entry {
	e := &Entry{key: string(key), Name: name, T: t, Stored: now, OrigTTL: ttl, Negative: negative}
	e.Expire = now + int64(ttl)*int64(time.Second)
	e.StaleUntil = e.Expire + int64(stale)*int64(time.Second)
	e.size = int64(t.Size() + len(e.key) + len(name) + 160)
	s := c.shardFor(key)
	limit := c.maxShard.Load()
	if e.size > limit {
		return nil
	}
	s.mu.Lock()
	if old := s.m[e.key]; old != nil {
		s.remove(old)
	}
	s.m[e.key] = e
	s.pushFront(e)
	s.bytes += e.size
	c.evictLocked(s, limit)
	s.mu.Unlock()
	return e
}

// Delete removes a single key.
func (c *Cache) Delete(key []byte) {
	s := c.shardFor(key)
	s.mu.Lock()
	if e := s.m[string(key)]; e != nil {
		s.remove(e)
	}
	s.mu.Unlock()
}

// Flush removes name and everything below it ("" or "." flushes all).
// It returns the number of removed entries.
func (c *Cache) Flush(name string) int {
	name = strings.ToLower(name)
	if name != "" && !strings.HasSuffix(name, ".") {
		name += "."
	}
	all := name == "" || name == "."
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		if all {
			n += len(s.m)
			s.m = make(map[string]*Entry)
			s.head, s.tail, s.bytes = nil, nil, 0
		} else {
			for _, e := range s.m {
				if e.Name == name || strings.HasSuffix(e.Name, "."+name) {
					s.remove(e)
					n++
				}
			}
		}
		s.mu.Unlock()
	}
	return n
}

// Stats is a snapshot of cache counters.
type Stats struct {
	Entries  int     `json:"entries"`
	Bytes    int64   `json:"bytes"`
	MaxBytes int64   `json:"max_bytes"`
	HitRatio float64 `json:"hit_ratio"`
	Hits     uint64  `json:"-"`
	Misses   uint64  `json:"-"`
	Evicted  uint64  `json:"-"`
}

// Stats returns current counters.
func (c *Cache) Stats() Stats {
	var st Stats
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		st.Entries += len(s.m)
		st.Bytes += s.bytes
		s.mu.Unlock()
	}
	st.MaxBytes = c.MaxBytes()
	st.Hits, st.Misses, st.Evicted = c.hits.Load(), c.misses.Load(), c.evicted.Load()
	if t := st.Hits + st.Misses; t > 0 {
		st.HitRatio = float64(st.Hits) / float64(t)
	}
	return st
}
