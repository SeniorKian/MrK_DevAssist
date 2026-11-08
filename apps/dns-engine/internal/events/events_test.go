package events

import (
	"testing"
	"time"
)

func TestRing(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	r := New(func() time.Time { return now })
	base := r.Last()
	if base != now.UnixMilli()*1000 {
		t.Fatal(base)
	}
	got := 0
	r.Subscribe(func(Event) { got++ })
	for i := 0; i < Capacity+5; i++ {
		r.Emit(PressureLevel, Info, map[string]any{"i": i})
	}
	if got != Capacity+5 {
		t.Fatal(got)
	}
	items, next := r.After(0, 0)
	if len(items) != Capacity || items[0].Data["i"] != 5 || next != r.Last() {
		t.Fatalf("%d %v %d", len(items), items[0].Data, next)
	}
	items, next2 := r.After(next-2, 10)
	if len(items) != 2 || next2 != next {
		t.Fatal(len(items), next2)
	}
	items, n3 := r.After(next, 10)
	if len(items) != 0 || n3 != next {
		t.Fatal("empty after newest")
	}
	// cursor from the future (clock went back): everything
	items, _ = r.After(next+1000, 3)
	if len(items) != 3 {
		t.Fatal(len(items))
	}
	ev := r.Emit(AttackDetected, Warning, nil)
	if ev.Data == nil || ev.Seq != next+1 {
		t.Fatal(ev)
	}
}
