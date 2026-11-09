// Package filter implements the DNS block lists of docs/41 §3.1: parsing of
// hosts, domains, adblock and RPZ lists, a compact immutable matcher read
// lock-free by the query path, and the download/refresh service.
//
// Storage: every rule is a 64-bit hash of the wire-form name (maphash; the
// lowest bit tells an exact rule from a "name and subdomains" rule) in one
// sorted array with a parallel 32-bit mask of the lists that contain it, plus
// a 64K-bucket index on the top 16 bits. That is 12 bytes per unique name
// (about 12 MB for one million names) and a lookup is a handful of
// comparisons per label. Hash collisions (2^-63 per pair) are accepted: the
// worst case is one wrongly blocked name, which the allow list fixes.
package filter

import (
	"hash/maphash"
	"math/bits"
	"slices"
)

var seed = maphash.MakeSeed()

// CustomBit is the mask bit of the custom allow/block lists of the settings;
// bits 0..30 are the downloaded lists.
const CustomBit = uint32(1) << 31

// key hashes a wire-form name (lower case, ending with the root label).
func key(wire []byte, sub bool) uint64 {
	h := maphash.Bytes(seed, wire) &^ 1
	if sub {
		h |= 1
	}
	return h
}

// AppendWire appends the wire form of a validated presentation name (no
// trailing dot, ASCII, lower case).
func AppendWire(dst []byte, name string) []byte {
	for len(name) > 0 {
		i := 0
		for i < len(name) && name[i] != '.' {
			i++
		}
		dst = append(dst, byte(i))
		dst = append(dst, name[:i]...)
		if i == len(name) {
			break
		}
		name = name[i+1:]
	}
	return append(dst, 0)
}

// nameKey is the key of a presentation name.
func nameKey(name string, sub bool) uint64 {
	var buf [256]byte
	return key(AppendWire(buf[:0], name), sub)
}

// indexMin is the size above which the bucket index is built (below it a
// plain binary search is as fast and the 256 KiB index is not worth it).
const indexMin = 4096

// set is an immutable sorted key array with per-key list masks.
type set struct {
	keys  []uint64
	masks []uint32
	idx   []uint32 // len 65537 when len(keys) >= indexMin
}

func (s *set) len() int {
	if s == nil {
		return 0
	}
	return len(s.keys)
}

func newSet(keys []uint64, masks []uint32) *set {
	s := &set{keys: keys, masks: masks}
	if len(keys) >= indexMin {
		s.idx = make([]uint32, 65537)
		j := 0
		for b := 0; b <= 65536; b++ {
			for j < len(keys) && int(keys[j]>>48) < b {
				j++
			}
			s.idx[b] = uint32(j)
		}
	}
	return s
}

// get returns the mask of k (0 when absent).
func (s *set) get(k uint64) uint32 {
	if s == nil || len(s.keys) == 0 {
		return 0
	}
	lo, hi := 0, len(s.keys)
	if s.idx != nil {
		b := k >> 48
		lo, hi = int(s.idx[b]), int(s.idx[b+1])
	}
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if s.keys[m] < k {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if lo < len(s.keys) && s.keys[lo] == k {
		return s.masks[lo]
	}
	return 0
}

// bytes is the memory held by the set.
func (s *set) bytes() int64 {
	if s == nil {
		return 0
	}
	return int64(cap(s.keys))*8 + int64(cap(s.masks))*4 + int64(cap(s.idx))*4
}

// counts returns, per mask bit, the number of keys carrying it.
func (s *set) counts() [32]int {
	var c [32]int
	if s == nil {
		return c
	}
	for _, m := range s.masks {
		for m != 0 {
			b := 31 - bits.LeadingZeros32(m)
			c[b]++
			m &^= 1 << b
		}
	}
	return c
}

// source is a sorted, de-duplicated key list contributing one mask bit.
type source struct {
	keys []uint64
	bit  uint32
}

// sortUnique sorts and de-duplicates keys in place.
func sortUnique(keys []uint64) []uint64 {
	slices.Sort(keys)
	return slices.Compact(keys)
}

// merge builds a new set from the entries of base whose mask intersects
// keep (masks reduced to keep) and the given sources. The output is sized
// exactly by a counting pass, so the peak memory is the old set plus the new
// one.
func merge(base *set, keep uint32, adds []source) *set {
	var drop uint32
	for _, a := range adds {
		drop |= a.bit // a replaced list: its old entries go
	}
	keep &^= drop
	run := func(emit func(k uint64, m uint32)) {
		bi := 0
		heads := make([]int, len(adds))
		for {
			// next base entry still carrying a kept bit
			for base != nil && bi < len(base.keys) && base.masks[bi]&keep == 0 {
				bi++
			}
			var k uint64
			have := false
			if base != nil && bi < len(base.keys) {
				k, have = base.keys[bi], true
			}
			for i, a := range adds {
				if heads[i] < len(a.keys) && (!have || a.keys[heads[i]] < k) {
					k, have = a.keys[heads[i]], true
				}
			}
			if !have {
				return
			}
			var m uint32
			if base != nil && bi < len(base.keys) && base.keys[bi] == k {
				m |= base.masks[bi] & keep
				bi++
			}
			for i, a := range adds {
				if heads[i] < len(a.keys) && a.keys[heads[i]] == k {
					m |= a.bit
					heads[i]++
				}
			}
			emit(k, m)
		}
	}
	n := 0
	run(func(uint64, uint32) { n++ })
	keys := make([]uint64, 0, n)
	masks := make([]uint32, 0, n)
	run(func(k uint64, m uint32) {
		keys = append(keys, k)
		masks = append(masks, m)
	})
	return newSet(keys, masks)
}
