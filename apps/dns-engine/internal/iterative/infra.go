package iterative

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// unknownRTT is the prior for servers never queried (tried before slow ones,
// after fast ones).
const unknownRTT = 200 * time.Millisecond

// infraTTL is how long knowledge about a server is kept.
const infraTTL = 15 * time.Minute

// ServerInfo is what the infra cache knows about one authoritative server.
type ServerInfo struct {
	RTT       time.Duration // smoothed
	Timeouts  int           // consecutive
	LastFail  time.Time
	NoEDNS    bool // answers only without EDNS (FORMERR/timeouts with it)
	No0x20    bool // does not preserve the query name case
	Updated   time.Time
	Successes uint64
}

type infraEntry struct {
	addr netip.Addr
	info ServerInfo
}

// Infra is a bounded LRU of per-server state (RTT, EDNS and 0x20 support).
type Infra struct {
	mu  sync.Mutex
	max int
	m   map[netip.Addr]*list.Element
	l   *list.List
	now func() time.Time
}

// NewInfra returns an infra cache with max entries.
func NewInfra(max int, now func() time.Time) *Infra {
	if now == nil {
		now = time.Now
	}
	return &Infra{max: max, m: map[netip.Addr]*list.Element{}, l: list.New(), now: now}
}

// SetMax changes the bound.
func (c *Infra) SetMax(n int) {
	c.mu.Lock()
	c.max = n
	c.evictLocked()
	c.mu.Unlock()
}

// Len returns the number of entries.
func (c *Infra) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.l.Len()
}

func (c *Infra) evictLocked() {
	for c.l.Len() > c.max && c.max > 0 {
		e := c.l.Back()
		c.l.Remove(e)
		delete(c.m, e.Value.(*infraEntry).addr)
	}
}

// Get returns the info for a (zero value with RTT unknownRTT if absent).
func (c *Infra) Get(a netip.Addr) ServerInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[a]; ok {
		ie := e.Value.(*infraEntry)
		if c.now().Sub(ie.info.Updated) < infraTTL {
			return ie.info
		}
		c.l.Remove(e)
		delete(c.m, a)
	}
	return ServerInfo{RTT: unknownRTT}
}

func (c *Infra) update(a netip.Addr, f func(*ServerInfo)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ie *infraEntry
	if e, ok := c.m[a]; ok {
		ie = e.Value.(*infraEntry)
		c.l.MoveToFront(e)
		if c.now().Sub(ie.info.Updated) >= infraTTL {
			ie.info = ServerInfo{RTT: unknownRTT}
		}
	} else {
		ie = &infraEntry{addr: a, info: ServerInfo{RTT: unknownRTT}}
		c.m[a] = c.l.PushFront(ie)
		c.evictLocked()
	}
	f(&ie.info)
	ie.info.Updated = c.now()
}

// Success records an answer after rtt.
func (c *Infra) Success(a netip.Addr, rtt time.Duration) {
	c.update(a, func(s *ServerInfo) {
		if s.Successes == 0 {
			s.RTT = rtt
		} else {
			s.RTT = (7*s.RTT + 3*rtt) / 10
		}
		s.Successes++
		s.Timeouts = 0
	})
}

// Failure records a timeout or network error.
func (c *Infra) Failure(a netip.Addr, timeout time.Duration) {
	c.update(a, func(s *ServerInfo) {
		s.Timeouts++
		s.LastFail = c.now()
		r := s.RTT * 2
		if r < timeout {
			r = timeout
		}
		if r > 10*time.Second {
			r = 10 * time.Second
		}
		s.RTT = r
	})
}

// SetNoEDNS remembers that a server needs plain DNS.
func (c *Infra) SetNoEDNS(a netip.Addr) { c.update(a, func(s *ServerInfo) { s.NoEDNS = true }) }

// SetNo0x20 remembers that a server does not echo the query case.
func (c *Infra) SetNo0x20(a netip.Addr) { c.update(a, func(s *ServerInfo) { s.No0x20 = true }) }

// score orders servers: smoothed RTT, heavily penalised while failing.
func (s ServerInfo) score(now time.Time) time.Duration {
	r := s.RTT
	if s.Timeouts >= 3 && now.Sub(s.LastFail) < time.Minute {
		r += 30 * time.Second // practically last resort
	}
	return r
}
