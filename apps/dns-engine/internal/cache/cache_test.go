package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/wire"
)

func tmpl(t testing.TB, name string, ttl uint32) *wire.Template {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Response = true
	rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN A 192.0.2.1", name, ttl))
	m.Answer = []dns.RR{rr}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	tp, err := wire.NewTemplate(b)
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

func key(name string) []byte {
	buf := make([]byte, 256)
	n, _ := dns.PackDomainName(name, buf, 0, nil, false)
	return wire.AppendKey(nil, buf[:n], dns.TypeA)
}

func TestTTLAndStale(t *testing.T) {
	c := New(1 << 20)
	now := time.Now().UnixNano()
	c.Put(key("a.example."), "a.example.", tmpl(t, "a.example.", 60), 60, 100, false, now)
	e := c.Get(key("a.example."), now+int64(30*time.Second))
	if e == nil || !e.Fresh(now+int64(30*time.Second)) || e.Remaining(now+int64(30*time.Second)) != 30 || e.Elapsed(now+int64(30*time.Second)) != 30 {
		t.Fatal("fresh entry")
	}
	stale := now + int64(90*time.Second)
	if e := c.Get(key("a.example."), stale); e == nil || e.Fresh(stale) {
		t.Fatal("stale window must keep the entry, not fresh")
	}
	if e := c.Get(key("a.example."), now+int64(161*time.Second)); e != nil {
		t.Fatal("entry beyond stale window must be gone")
	}
	if c.Stats().Entries != 0 {
		t.Fatal("expired entry not removed")
	}
	// no stale window: removed right after expiry
	c.Put(key("b.example."), "b.example.", tmpl(t, "b.example.", 5), 5, 0, false, now)
	if c.Get(key("b.example."), now+int64(6*time.Second)) != nil {
		t.Fatal("no-stale entry served after expiry")
	}
}

func TestByteCapLRU(t *testing.T) {
	c := New(64 * 4096) // 4 KiB per shard minimum
	now := time.Now().UnixNano()
	for i := 0; i < 20000; i++ {
		n := fmt.Sprintf("h%d.example.", i)
		c.Put(key(n), n, tmpl(t, n, 300), 300, 0, false, now)
	}
	st := c.Stats()
	if st.Bytes > c.MaxBytes() || st.Evicted == 0 || st.Entries == 0 {
		t.Fatalf("cap not enforced: %+v", st)
	}
	// recently used entries survive: touch one, add more to its shard
	c.Flush("")
	k := key("keep.example.")
	c.Put(k, "keep.example.", tmpl(t, "keep.example.", 300), 300, 0, false, now)
	for i := 0; i < 20000; i++ {
		c.Get(k, now)
		n := fmt.Sprintf("x%d.example.", i)
		c.Put(key(n), n, tmpl(t, n, 300), 300, 0, false, now)
	}
	if c.Get(k, now) == nil {
		t.Fatal("hot entry evicted")
	}
	c.SetMaxBytes(1 << 20)
	if c.MaxBytes() != 1<<20 {
		t.Fatal("resize")
	}
}

func TestFlushSubtree(t *testing.T) {
	c := New(1 << 20)
	now := time.Now().UnixNano()
	for _, n := range []string{"example.com.", "a.example.com.", "b.a.example.com.", "notexample.com.", "other.org."} {
		c.Put(key(n), n, tmpl(t, n, 300), 300, 0, false, now)
	}
	if n := c.Flush("example.com"); n != 3 {
		t.Fatalf("flushed %d", n)
	}
	if c.Get(key("notexample.com."), now) == nil || c.Get(key("other.org."), now) == nil {
		t.Fatal("unrelated names flushed")
	}
	if n := c.Flush(""); n != 2 {
		t.Fatalf("flush all %d", n)
	}
}

func TestConcurrent(t *testing.T) {
	c := New(1 << 20)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			now := time.Now().UnixNano()
			for i := 0; i < 2000; i++ {
				n := fmt.Sprintf("c%d.example.", i%50)
				if i%3 == 0 {
					c.Put(key(n), n, tmpl(t, n, 300), 300, 10, false, now)
				} else if e := c.Get(key(n), now); e != nil {
					e.Hits.Add(1)
				}
				if i%500 == 0 {
					c.Flush("example.")
				}
			}
		}(g)
	}
	wg.Wait()
	st := c.Stats()
	if st.Hits+st.Misses == 0 {
		t.Fatal("no activity")
	}
}
