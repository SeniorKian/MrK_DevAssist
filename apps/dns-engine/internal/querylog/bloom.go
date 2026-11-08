package querylog

import (
	"encoding/binary"
	"math"
)

// bloom is a split-free Bloom filter with Kirsch–Mitzenmacher double hashing.
type bloom struct {
	k    uint8
	bits []uint64
}

func hash64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// newBloom sizes a filter for n items at about 1% false positives.
func newBloom(n int) *bloom {
	if n < 16 {
		n = 16
	}
	m := int(math.Ceil(float64(n) * 9.6))
	words := (m + 63) / 64
	return &bloom{k: 7, bits: make([]uint64, words)}
}

func (b *bloom) add(s string) {
	h := hash64(s)
	h1, h2 := uint32(h), uint32(h>>32)|1
	m := uint32(len(b.bits) * 64)
	for i := uint32(0); i < uint32(b.k); i++ {
		p := (h1 + i*h2) % m
		b.bits[p/64] |= 1 << (p % 64)
	}
}

// has reports whether s may be in the set (nil filter: always true).
func (b *bloom) has(s string) bool {
	if b == nil || len(b.bits) == 0 {
		return true
	}
	h := hash64(s)
	h1, h2 := uint32(h), uint32(h>>32)|1
	m := uint32(len(b.bits) * 64)
	for i := uint32(0); i < uint32(b.k); i++ {
		p := (h1 + i*h2) % m
		if b.bits[p/64]&(1<<(p%64)) == 0 {
			return false
		}
	}
	return true
}

func (b *bloom) marshal(dst []byte) []byte {
	dst = append(dst, b.k)
	dst = binary.AppendUvarint(dst, uint64(len(b.bits)))
	for _, w := range b.bits {
		dst = binary.LittleEndian.AppendUint64(dst, w)
	}
	return dst
}

func readBloom(r *reader) *bloom {
	k := r.bytes(1)
	n := r.uvarint()
	if r.err != nil || n > uint64(len(r.b)-r.off)/8 || k[0] == 0 || k[0] > 16 {
		r.err = errCorrupt
		return nil
	}
	b := &bloom{k: k[0], bits: make([]uint64, n)}
	for i := range b.bits {
		b.bits[i] = binary.LittleEndian.Uint64(r.bytes(8))
	}
	if n == 0 {
		return nil
	}
	return b
}

// nameKeys returns the bloom keys of a presentation name: every suffix
// ("a.b.c", "b.c", "c") and every label prefixed with '|'.
func nameKeys(name string, f func(string)) {
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || (name[i] == '.' && (i == 0 || name[i-1] != '\\')) {
			f("|" + name[start:i])
			start = i + 1
		}
	}
	f(name)
	for i := 0; i < len(name); i++ {
		if name[i] == '.' && (i == 0 || name[i-1] != '\\') {
			f(name[i+1:])
		}
	}
}
