package attack

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func TestParentOf(t *testing.T) {
	for in, want := range map[string]string{"a.b.example.com": "b.example.com", "x.example.com": "example.com", "example.com": "", "com": ""} {
		if got := ParentOf(in); got != want {
			t.Errorf("%s: %q", in, got)
		}
	}
}

func TestRandomSubdomainLifecycle(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	d := New(500, ck.now)
	var started, ended []Change
	run := func(seconds int, perSec int, unique bool, client string) {
		for s := 0; s < seconds; s++ {
			for i := 0; i < perSec; i++ {
				name := "www.victim.example"
				if unique {
					name = fmt.Sprintf("r%d-%d.victim.example", ck.now().Unix(), i)
				}
				d.Observe(name, client)
				d.Observe("typo.normal.example", "10.0.0.50") // background noise, same name
			}
			ck.add(time.Second)
			for _, c := range d.Tick() {
				if c.Attack.Kind != RandomSubdomain {
					continue
				}
				if c.Started {
					started = append(started, c)
				} else {
					ended = append(ended, c)
				}
			}
		}
	}
	run(30, 5, true, "10.0.0.66") // 150 unique in 30 s: below 500/min
	if len(started) != 0 {
		t.Fatal("false positive", started)
	}
	run(40, 30, true, "10.0.0.66") // 1800 unique/min
	if len(started) != 1 || started[0].Attack.Kind != RandomSubdomain || started[0].Attack.Parent != "victim.example" ||
		started[0].Attack.TopClients[0] != "10.0.0.66" || started[0].Attack.UniqueNXDomainPerMin < 500 {
		t.Fatalf("%+v", started)
	}
	act := d.Active()
	if len(act) < 1 || act[0].Kind != RandomSubdomain {
		t.Fatal(act)
	}
	d.SetMitigation(act[0].Key(), "m_1")
	if d.Active()[0].MitigationID != "m_1" {
		t.Fatal("mitigation id")
	}
	// the same name repeated is not an attack, and the flood stops
	run(90, 30, false, "10.0.0.66")
	if len(ended) != 1 || ended[0].Attack.Parent != "victim.example" {
		t.Fatalf("ended %+v active %+v", ended, d.Active())
	}
}

func TestNXDomainFloodAndBounds(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	d := New(100, ck.now)
	var changes []Change
	for s := 0; s < 30; s++ {
		for i := 0; i < 20; i++ {
			d.Observe("nonexistent.tld", "192.0.2.7") // TLD-level: no parent, client flood only
		}
		// attacker sprays thousands of parents: memory stays bounded
		for i := 0; i < 300; i++ {
			d.Observe(fmt.Sprintf("a.p%d-%d.example", s, i), "")
		}
		ck.add(time.Second)
		changes = append(changes, d.Tick()...)
	}
	found := false
	for _, c := range changes {
		if c.Started && c.Attack.Kind == NXDomainFlood && c.Attack.Client == "192.0.2.7" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", changes)
	}
	d.mu.Lock()
	n := len(d.parents)
	d.mu.Unlock()
	if n > maxParents {
		t.Fatal("parents", n)
	}
	d.SetThreshold(1_000_000)
	ck.add(10 * time.Second)
	d.Tick()
	if len(d.Active()) != 0 {
		t.Fatal("raised threshold ends attacks")
	}
	d.Reset()
}
