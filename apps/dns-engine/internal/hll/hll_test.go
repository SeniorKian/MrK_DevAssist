package hll

import (
	"fmt"
	"math"
	"testing"
)

func TestEstimate(t *testing.T) {
	for _, n := range []int{0, 10, 100, 1000, 20000, 200000} {
		s := New(10)
		for i := 0; i < n; i++ {
			s.Add([]byte(fmt.Sprintf("r%08x.victim.example", i*2654435761)))
			s.Add([]byte(fmt.Sprintf("r%08x.victim.example", i*2654435761))) // duplicates do not count
		}
		got := float64(s.Estimate())
		if n == 0 {
			if got != 0 {
				t.Fatal(got)
			}
			continue
		}
		if math.Abs(got-float64(n))/float64(n) > 0.1 {
			t.Fatalf("n=%d estimate %v", n, got)
		}
	}
}

func TestMerge(t *testing.T) {
	a, b := New(10), New(10)
	for i := 0; i < 1000; i++ {
		a.Add([]byte(fmt.Sprint("a", i)))
		b.Add([]byte(fmt.Sprint("b", i)))
	}
	a.Merge(b)
	a.Merge(New(9)) // ignored: different precision
	if e := float64(a.Estimate()); math.Abs(e-2000)/2000 > 0.1 {
		t.Fatal(e)
	}
	a.Reset()
	if a.Estimate() != 0 {
		t.Fatal("reset")
	}
}
