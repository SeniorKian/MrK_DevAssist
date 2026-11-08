// Package hll is a small HyperLogLog distinct counter (Flajolet et al. 2007)
// with the small-range linear-counting correction. Precision p uses 2^p
// one-byte registers; the standard error is about 1.04/sqrt(2^p).
package hll

import (
	"math"
	"math/bits"
)

// Sketch is a HyperLogLog sketch. Not safe for concurrent use.
type Sketch struct {
	p   uint8
	reg []uint8
}

// New returns a sketch with precision p (4..16).
func New(p uint8) *Sketch {
	if p < 4 {
		p = 4
	}
	if p > 16 {
		p = 16
	}
	return &Sketch{p: p, reg: make([]uint8, 1<<p)}
}

// Hash64 is FNV-1a 64 followed by a murmur3 finaliser (good avalanche).
func Hash64(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// AddHash adds a pre-hashed item.
func (s *Sketch) AddHash(h uint64) {
	idx := h >> (64 - s.p)
	w := h<<s.p | 1<<(s.p-1) // guard bit bounds the rank
	r := uint8(bits.LeadingZeros64(w)) + 1
	if r > s.reg[idx] {
		s.reg[idx] = r
	}
}

// Add adds an item.
func (s *Sketch) Add(b []byte) { s.AddHash(Hash64(b)) }

// Merge folds o (same precision) into s.
func (s *Sketch) Merge(o *Sketch) {
	if o == nil || o.p != s.p {
		return
	}
	for i, v := range o.reg {
		if v > s.reg[i] {
			s.reg[i] = v
		}
	}
}

// Reset clears all registers.
func (s *Sketch) Reset() { clear(s.reg) }

// Estimate returns the approximate distinct count.
func (s *Sketch) Estimate() uint64 {
	m := float64(len(s.reg))
	var sum float64
	zeros := 0
	for _, v := range s.reg {
		sum += 1 / float64(uint64(1)<<v)
		if v == 0 {
			zeros++
		}
	}
	var alpha float64
	switch len(s.reg) {
	case 16:
		alpha = 0.673
	case 32:
		alpha = 0.697
	case 64:
		alpha = 0.709
	default:
		alpha = 0.7213 / (1 + 1.079/m)
	}
	e := alpha * m * m / sum
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros))
	}
	return uint64(e + 0.5)
}
