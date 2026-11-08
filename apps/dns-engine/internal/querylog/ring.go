// Package querylog is the DNS query log (docs/38 §3): an allocation-free,
// lock-free sharded ring on the hot path, a writer that batches rows into
// compressed, indexed on-disk segments, search/stream/export/delete, retention
// and the disk-free guard.
package querylog

import (
	"net/netip"
	"sync/atomic"
)

// Sources (docs/38 §3 querylog source).
const (
	SrcAuthoritative uint8 = iota
	SrcOverride
	SrcCache
	SrcUpstream
	SrcRefused
	SrcRateLimited
	SrcMitigated
	SrcForwarder
	SrcCount
)

// SourceNames are the API names of the sources.
var SourceNames = [SrcCount]string{"authoritative", "override", "cache", "upstream", "refused", "rate_limited", "mitigated", "forwarder"}

// Transports.
const (
	ProtoUDP uint8 = iota
	ProtoTCP
	ProtoDoT
	ProtoDoH
	ProtoCount
)

// ProtoNames are the API names of the transports.
var ProtoNames = [ProtoCount]string{"udp", "tcp", "dot", "doh"}

// Flags.
const (
	FlagTC     uint8 = 1
	FlagStale  uint8 = 2
	FlagCached uint8 = 4
)

// Hdr is the fixed part of one query record.
type Hdr struct {
	TS       int64 // unix nanoseconds when the query arrived
	Client   netip.Addr
	Upstream string // upstream id (an existing string: no allocation)
	DurUS    uint32
	Size     uint16 // response bytes
	QType    uint16
	Rcode    uint8
	Source   uint8
	Proto    uint8
	Flags    uint8
}

// Record is a Hdr plus the query name in lower-case wire form.
type Record struct {
	Hdr
	NameLen uint8
	Name    [255]byte
}

// WireName returns the stored wire-form name.
func (r *Record) WireName() []byte { return r.Name[:r.NameLen] }

type slot struct {
	seq atomic.Uint64
	rec Record
}

type ringShard struct {
	enq     atomic.Uint64
	_       [56]byte
	dropped atomic.Uint64
	_       [56]byte
	deq     uint64 // consumer only
	mask    uint64
	slots   []slot
}

// Ring is a set of bounded multi-producer / single-consumer queues
// (Vyukov's bounded queue). Producers never block or allocate: when a shard
// is full the record is dropped and counted.
type Ring struct {
	shards []ringShard
	mask   uint32
}

// NewRing creates a ring with nshards shards (rounded up to a power of two)
// of perShard slots each (rounded up to a power of two).
func NewRing(nshards, perShard int) *Ring {
	ns := 1
	for ns < nshards {
		ns <<= 1
	}
	ps := 1
	for ps < perShard {
		ps <<= 1
	}
	r := &Ring{shards: make([]ringShard, ns), mask: uint32(ns - 1)}
	for i := range r.shards {
		s := &r.shards[i]
		s.slots = make([]slot, ps)
		s.mask = uint64(ps - 1)
		for j := range s.slots {
			s.slots[j].seq.Store(uint64(j))
		}
	}
	return r
}

// Shards returns the shard count.
func (r *Ring) Shards() int { return len(r.shards) }

// Put enqueues one record on shard (any value; it is masked). name is the
// lower-case wire-form query name (at most 255 bytes, longer is cut).
// It reports false when the shard was full.
func (r *Ring) Put(shard uint32, h *Hdr, name []byte) bool {
	s := &r.shards[shard&r.mask]
	for {
		pos := s.enq.Load()
		sl := &s.slots[pos&s.mask]
		seq := sl.seq.Load()
		switch dif := int64(seq) - int64(pos); {
		case dif == 0:
			if !s.enq.CompareAndSwap(pos, pos+1) {
				continue
			}
			sl.rec.Hdr = *h
			n := copy(sl.rec.Name[:], name)
			sl.rec.NameLen = uint8(n)
			sl.seq.Store(pos + 1)
			return true
		case dif < 0:
			s.dropped.Add(1)
			return false
		}
		// another producer advanced enq: retry
	}
}

// Drain appends every available record to dst (single consumer only) and
// returns it.
func (r *Ring) Drain(dst []Record, max int) []Record {
	for i := range r.shards {
		s := &r.shards[i]
		for max <= 0 || len(dst) < max {
			sl := &s.slots[s.deq&s.mask]
			if sl.seq.Load() != s.deq+1 {
				break
			}
			dst = append(dst, sl.rec)
			sl.seq.Store(s.deq + s.mask + 1)
			s.deq++
		}
	}
	return dst
}

// Dropped returns the number of records dropped because a shard was full.
func (r *Ring) Dropped() uint64 {
	var n uint64
	for i := range r.shards {
		n += r.shards[i].dropped.Load()
	}
	return n
}
