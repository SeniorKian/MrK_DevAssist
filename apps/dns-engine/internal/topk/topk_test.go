package topk

import (
	"fmt"
	"math/rand/v2"
	"testing"
)

func TestExactWhenUnderCapacity(t *testing.T) {
	s := New(10)
	for i := 0; i < 5; i++ {
		for j := 0; j <= i; j++ {
			s.Add(fmt.Sprint(i), 1)
		}
	}
	top := s.Top(3)
	if len(top) != 3 || top[0].Key != "4" || top[0].Count != 5 || top[2].Key != "2" || top[0].Err != 0 {
		t.Fatalf("%v", top)
	}
	if s.Total() != 15 || s.Len() != 5 {
		t.Fatal(s.Total(), s.Len())
	}
	s.Reset()
	if s.Len() != 0 || s.Total() != 0 {
		t.Fatal("reset")
	}
}

// Zipf-like stream with a large tail: the heavy hitters must be found and
// counts must be within the Space-Saving bound N/m.
func TestAccuracyZipf(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	z := rand.NewZipf(r, 1.2, 1, 100000)
	const n = 500000
	const m = 256
	s := New(m)
	truth := map[string]uint64{}
	for i := 0; i < n; i++ {
		k := fmt.Sprintf("d%d.example", z.Uint64())
		truth[k]++
		s.AddBytes([]byte(k), 1)
	}
	bound := uint64(n / m)
	top := s.Top(20)
	for _, it := range top {
		tr := truth[it.Key]
		if it.Count < tr || it.Count-tr > bound || it.Count-it.Err > tr {
			t.Fatalf("%s: est %d err %d true %d bound %d", it.Key, it.Count, it.Err, tr, bound)
		}
	}
	// every key with true count > N/m must be present
	present := map[string]bool{}
	for _, it := range s.Top(-1) {
		present[it.Key] = true
	}
	for k, c := range truth {
		if c > bound && !present[k] {
			t.Fatalf("heavy hitter %s (%d) missing", k, c)
		}
	}
	if top[0].Key != "d0.example" {
		t.Fatalf("top %v", top[:3])
	}
}

func TestMerge(t *testing.T) {
	a := []Item{{Key: "x", Count: 5}, {Key: "y", Count: 1, Err: 1}}
	b := []Item{{Key: "y", Count: 7}, {Key: "z", Count: 2}}
	m := Merge(2, a, b)
	if len(m) != 2 || m[0].Key != "y" || m[0].Count != 8 || m[0].Err != 1 || m[1].Key != "x" {
		t.Fatalf("%v", m)
	}
}

func BenchmarkAddExisting(b *testing.B) {
	s := New(1024)
	keys := make([][]byte, 1024)
	for i := range keys {
		keys[i] = []byte(fmt.Sprintf("k%d", i))
		s.AddBytes(keys[i], 1)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.AddBytes(keys[i&1023], 1)
	}
}
