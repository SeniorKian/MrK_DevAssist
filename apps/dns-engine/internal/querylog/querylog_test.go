package querylog

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
)

func wire(name string) []byte {
	buf := make([]byte, 256)
	n, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		panic(err)
	}
	return buf[:n]
}

func rec(ts time.Time, client, name string, qtype uint16, rcode, src uint8) Record {
	var r Record
	r.Hdr = Hdr{TS: ts.UnixNano(), Client: netip.MustParseAddr(client), QType: qtype, Rcode: rcode, Source: src,
		DurUS: 1500, Size: 80, Proto: ProtoUDP, Flags: FlagCached}
	w := wire(name)
	r.NameLen = uint8(copy(r.Name[:], w))
	return r
}

func TestRingPutDrain(t *testing.T) {
	r := NewRing(3, 5) // 4 shards x 8 slots
	if r.Shards() != 4 {
		t.Fatal(r.Shards())
	}
	h := Hdr{QType: 1}
	n := wire("example.com")
	for i := 0; i < 10; i++ {
		h.Size = uint16(i)
		r.Put(0, &h, n)
	}
	if r.Dropped() != 2 {
		t.Fatal("dropped", r.Dropped())
	}
	out := r.Drain(nil, 0)
	if len(out) != 8 || out[7].Size != 7 || string(out[0].WireName()) != string(n) {
		t.Fatalf("%d", len(out))
	}
	// concurrent producers, single consumer: nothing lost when not full
	r = NewRing(4, 1<<16)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			hh := Hdr{QType: uint16(g)}
			for i := 0; i < 10000; i++ {
				r.Put(uint32(g), &hh, n)
			}
		}(g)
	}
	var got atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buf []Record
		for got.Load() < 80000 {
			buf = r.Drain(buf[:0], 0)
			got.Add(int64(len(buf)))
		}
	}()
	wg.Wait()
	<-done
	if got.Load() != 80000 || r.Dropped() != 0 {
		t.Fatal(got.Load(), r.Dropped())
	}
}

func TestRingPutNoAlloc(t *testing.T) {
	r := NewRing(1, 1024)
	h := Hdr{QType: 1, Client: netip.MustParseAddr("10.0.0.1"), Upstream: "x"}
	n := wire("www.example.com")
	var buf []Record
	allocs := testing.AllocsPerRun(1000, func() {
		r.Put(0, &h, n)
		buf = r.Drain(buf[:0], 0)
	})
	if allocs != 0 {
		t.Fatal(allocs)
	}
}

func BenchmarkRingPut(b *testing.B) {
	r := NewRing(64, 4096)
	n := wire("www.example.com")
	var ctr atomic.Uint32
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		h := Hdr{QType: 1}
		sh := ctr.Add(1)
		for pb.Next() {
			if !r.Put(sh, &h, n) {
				r.Drain(nil, 0) // racy drain is fine for the benchmark only from one goroutine
			}
		}
	})
}

func TestPresentName(t *testing.T) {
	cases := map[string]string{"example.com.": "example.com", ".": ".", "a\\.b.c.": "a\\.b.c", "x\\000y.z.": "x\\000y.z"}
	for in, want := range cases {
		buf := make([]byte, 256)
		n, err := dns.PackDomainName(in, buf, 0, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(PresentName(buf[:n], nil)); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

func sampleBlock(n int, base time.Time) *block {
	b := newBuilder()
	for i := 0; i < n; i++ {
		r := Row{TS: base.Add(time.Duration(i) * time.Millisecond).UnixMicro(), Client: fmt.Sprintf("10.0.%d.%d", i%3, i%7),
			Name: fmt.Sprintf("h%d.example%d.com", i%50, i%4), QType: uint16(1 + i%2), Rcode: uint8(i % 4),
			Source: uint8(i % int(SrcCount)), Proto: uint8(i % 2), Flags: uint8(i % 8), DurUS: uint32(i * 10), Size: uint16(i)}
		if i%3 == 0 {
			r.Upstream = "quad9"
		}
		b.add(&r)
	}
	return b
}

func TestBlockRoundTrip(t *testing.T) {
	b := sampleBlock(5000, time.Unix(1_800_000_000, 0))
	for _, rng := range [][2]int{{0, 5000}, {100, 3000}, {4999, 5000}, {0, 0}} {
		enc := b.encode(nil, rng[0], rng[1])
		d, err := decodeBlock(enc)
		if err != nil {
			t.Fatal(err)
		}
		if d.len() != rng[1]-rng[0] {
			t.Fatal(d.len())
		}
		for i := 0; i < d.len(); i++ {
			if d.row(i) != b.row(rng[0]+i) {
				t.Fatalf("row %d: %+v != %+v", i, d.row(i), b.row(rng[0]+i))
			}
		}
	}
	data, m := marshalSegment(7, b)
	m2, d, err := parseSegment(data)
	if err != nil || m2.Seq != 7 || m2.Rows != 5000 || d.len() != 5000 || m2.MinTS != b.minTS || m2.MaxTS != b.maxTS {
		t.Fatal(err, m2)
	}
	if m.Rcodes != m2.Rcodes || m.Sources != m2.Sources {
		t.Fatal("counts")
	}
	if bpr := float64(len(data)) / 5000; bpr > 8 {
		t.Fatalf("%.1f bytes/row", bpr)
	}
	// every corruption is detected
	for _, off := range []int{0, 9, 20, len(data) / 2, len(data) - 20, len(data) - 1} {
		bad := append([]byte(nil), data...)
		bad[off] ^= 0x55
		if _, _, err := parseSegment(bad); err == nil {
			t.Fatalf("corruption at %d undetected", off)
		}
	}
	if _, _, err := parseSegment(data[:len(data)-3]); err == nil {
		t.Fatal("truncation undetected")
	}
}

func TestBloom(t *testing.T) {
	b := newBloom(1000)
	for i := 0; i < 1000; i++ {
		b.add(fmt.Sprint("key", i))
	}
	for i := 0; i < 1000; i++ {
		if !b.has(fmt.Sprint("key", i)) {
			t.Fatal("false negative")
		}
	}
	fp := 0
	for i := 0; i < 10000; i++ {
		if b.has(fmt.Sprint("other", i)) {
			fp++
		}
	}
	if fp > 300 {
		t.Fatalf("false positive rate %d/10000", fp)
	}
	var keys []string
	nameKeys("a.b.example.com", func(s string) { keys = append(keys, s) })
	want := map[string]bool{"a.b.example.com": true, "b.example.com": true, "example.com": true, "com": true, "|a": true, "|example": true}
	got := map[string]bool{}
	for _, k := range keys {
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("missing key %q in %v", k, keys)
		}
	}
	var nilB *bloom
	if !nilB.has("x") {
		t.Fatal("nil bloom must not skip")
	}
}

type fakeDisk struct {
	mu   sync.Mutex
	free float64
}

func (f *fakeDisk) get(string) (float64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.free, nil
}

func (f *fakeDisk) set(v float64) { f.mu.Lock(); f.free = v; f.mu.Unlock() }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type evRec struct {
	mu  sync.Mutex
	evs []string
}

func (e *evRec) add(typ, sev string, data map[string]any) {
	e.mu.Lock()
	e.evs = append(e.evs, typ+":"+fmt.Sprint(data["reason"]))
	e.mu.Unlock()
}

func newLogger(t *testing.T, mut func(*config.QueryLog)) (*Logger, *clock, *fakeDisk, *evRec) {
	t.Helper()
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	fd := &fakeDisk{free: 50}
	ev := &evRec{}
	s := config.DefaultQueryLog()
	if mut != nil {
		mut(&s)
	}
	l, warns := Open(Options{Dir: filepath.Join(t.TempDir(), "querylog"), Now: ck.now, DiskFree: fd.get, Events: ev.add}, s)
	if l == nil {
		t.Fatal(warns)
	}
	t.Cleanup(func() { l.Close() })
	return l, ck, fd, ev
}

func search(t *testing.T, l *Logger, q string) SearchResult {
	t.Helper()
	v, _ := url.ParseQuery(q)
	f, err := ParseFilter(v)
	if err != nil {
		t.Fatal(err)
	}
	return l.Search(context.Background(), f, 2*time.Second)
}

func TestSearchFiltersAndCursor(t *testing.T) {
	l, ck, _, _ := newLogger(t, nil)
	l.st.SegmentRows = 1000
	base := ck.now()
	var recs []Record
	for i := 0; i < 3500; i++ {
		client := fmt.Sprintf("192.168.1.%d", i%10)
		name := fmt.Sprintf("host%d.example.com", i%20)
		rc := uint8(0)
		if i%5 == 0 {
			rc = 3
		}
		if i%100 == 0 {
			name = "x.other.org"
		}
		recs = append(recs, rec(base.Add(time.Duration(i)*time.Millisecond), client, name, dns.TypeA, rc, SrcCache))
	}
	for i := 0; i < len(recs); i += 250 {
		l.Process(recs[i:i+250], nil, nil)
	}
	if len(l.st.segs) != 3 || l.st.active.len() != 500 {
		t.Fatalf("segs %d active %d", len(l.st.segs), l.st.active.len())
	}
	r := search(t, l, "limit=5")
	if len(r.Rows) != 5 || r.Rows[0].TS != base.Add(3499*time.Millisecond).UnixMicro() || r.Next == nil {
		t.Fatalf("%+v", r.Rows)
	}
	// page through everything with the cursor: newest first, no duplicates
	seen := map[int64]bool{}
	cur := ""
	last := int64(1 << 62)
	pages := 0
	for {
		q := "limit=1000"
		if cur != "" {
			q += "&cursor=" + cur
		}
		r := search(t, l, q)
		pages++
		for _, row := range r.Rows {
			if seen[row.TS] || row.TS > last {
				t.Fatal("order/dup", row.TS)
			}
			seen[row.TS] = true
			last = row.TS
		}
		if r.Next == nil {
			break
		}
		cur = r.Next.String()
	}
	if len(seen) != 3500 || pages != 4 {
		t.Fatal(len(seen), pages)
	}
	if r := search(t, l, "rcode=NXDOMAIN&limit=1000"); len(r.Rows) != 700 {
		t.Fatal("rcode", len(r.Rows))
	}
	if r := search(t, l, "name=*.other.org&limit=1000"); len(r.Rows) != 35 {
		t.Fatal("suffix", len(r.Rows))
	}
	if r := search(t, l, "name=host1&limit=1000"); len(r.Rows) == 0 {
		t.Fatal("substring")
	}
	if r := search(t, l, "client=192.168.1.3&limit=1000"); len(r.Rows) != 350 {
		t.Fatal("client", len(r.Rows))
	}
	if r := search(t, l, "client=192.168.1.0/30&limit=1000"); len(r.Rows) != 1000 {
		t.Fatal("cidr", len(r.Rows))
	}
	from := base.Add(1000 * time.Millisecond).UnixMilli()
	to := base.Add(1099 * time.Millisecond).UnixMilli()
	if r := search(t, l, fmt.Sprintf("from=%d&to=%d&limit=1000", from, to)); len(r.Rows) != 100 {
		t.Fatal("range", len(r.Rows))
	}
	if r := search(t, l, "name=*.nowhere.net"); len(r.Rows) != 0 || r.Scanned != 1 {
		t.Fatal("bloom skip", r.Scanned) // only the active block is scanned
	}
	if r := search(t, l, "qtype=AAAA"); len(r.Rows) != 0 {
		t.Fatal("qtype")
	}
	if r := search(t, l, "blocked=true"); len(r.Rows) != 0 {
		t.Fatal("blocked")
	}
	if r := search(t, l, "min_ms=2"); len(r.Rows) != 0 {
		t.Fatal("min_ms")
	}
	// the budget truncates and the cursor resumes
	v, _ := url.ParseQuery("name=zzz")
	f, _ := ParseFilter(v)
	r = l.st.Search(context.Background(), &f, time.Nanosecond)
	if !r.Truncated || r.Next == nil {
		t.Fatalf("%+v", r)
	}
}

func TestParseFilterErrors(t *testing.T) {
	bad := []string{"from=yesterday", "client=999.1.1.1", "name=a*b", "qtype=BOGUS", "rcode=WHAT", "source=x",
		"blocked=maybe", "min_ms=-1", "limit=0", "limit=1001", "cursor=@@", "from=2000&to=1000"}
	for _, q := range bad {
		v, _ := url.ParseQuery(q)
		if _, err := ParseFilter(v); err == nil {
			t.Errorf("%s accepted", q)
		}
	}
	v, _ := url.ParseQuery("from=2026-11-08T10:00:00Z&client=::ffff:10.0.0.1&qtype=28&rcode=2&source=upstream&blocked=false")
	f, err := ParseFilter(v)
	if err != nil || f.QType != 28 || f.Rcode != 2 || f.Source != int(SrcUpstream) || f.Blocked != 2 ||
		f.ClientPrefix.String() != "10.0.0.1/32" || f.From == 0 {
		t.Fatal(err, f)
	}
}

func TestPrivacyAndExclusions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, mode := range []string{config.IPFull, config.IPMask, config.IPHash, config.IPNone} {
		l, _, _, _ := newLogger(t, func(q *config.QueryLog) {
			q.ClientIP = mode
			q.ExcludeNames = []string{"ignored.example"}
			q.ExcludeClients = []string{"10.9.0.0/16"}
		})
		l.Process([]Record{
			rec(now, "192.168.7.42", "a.example.com", 1, 0, SrcCache),
			rec(now, "2001:db8:1:2::5", "b.example.com", 1, 0, SrcCache),
			rec(now, "192.168.7.42", "x.ignored.example", 1, 0, SrcCache),
			rec(now, "10.9.3.3", "c.example.com", 1, 0, SrcCache),
		}, nil, nil)
		r := search(t, l, "")
		if len(r.Rows) != 2 {
			t.Fatalf("%s: %d rows", mode, len(r.Rows))
		}
		c4, c6 := r.Rows[1].Client, r.Rows[0].Client
		switch mode {
		case config.IPFull:
			if c4 != "192.168.7.42" || c6 != "2001:db8:1:2::5" {
				t.Fatal(c4, c6)
			}
		case config.IPMask:
			if c4 != "192.168.7.0" || c6 != "2001:db8:1::" {
				t.Fatal(c4, c6)
			}
		case config.IPHash:
			if len(c4) != 18 || c4[:2] != "h:" || c4 == c6 || c4 != l.hashClient(netip.MustParseAddr("192.168.7.42")) {
				t.Fatal(c4, c6)
			}
		case config.IPNone:
			if c4 != "" || c6 != "" {
				t.Fatal(c4, c6)
			}
		}
		// a client search by the real IP finds the row under every mode but "none"
		got := search(t, l, "client=192.168.7.42")
		if (mode == config.IPNone) != (len(got.Rows) == 0) {
			t.Fatalf("%s: client search %d", mode, len(got.Rows))
		}
	}
	// the hash key persists 0600
	l, _, _, _ := newLogger(t, nil)
	st, err := os.Stat(filepath.Join(l.st.Dir(), "hash.key"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal(err, st.Mode())
	}
}

func TestModesAndSampling(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	batch := func() []Record {
		var out []Record
		for i := 0; i < 1000; i++ {
			rc := uint8(0)
			if i%10 == 0 {
				rc = 2
			}
			out = append(out, rec(now, "10.0.0.1", "a.example", 1, rc, SrcUpstream))
		}
		return out
	}
	l, _, _, _ := newLogger(t, func(q *config.QueryLog) { q.Mode = config.LogSample; q.SamplePercent = 20 })
	l.Process(batch(), nil, nil)
	if n := l.written.Load(); n < 120 || n > 280 {
		t.Fatal("sample", n)
	}
	l.Configure(func() config.QueryLog { q := config.DefaultQueryLog(); q.Mode = config.LogErrorsOnly; return q }())
	l.written.Store(0)
	l.Process(batch(), nil, nil)
	if l.written.Load() != 100 {
		t.Fatal("errors_only", l.written.Load())
	}
	l.Configure(config.DefaultQueryLog())
	l.SetPressure(PressureOff)
	l.written.Store(0)
	l.Process(batch(), nil, nil)
	if l.written.Load() != 0 || l.ModeEffective() != config.LogOff || l.Status().DegradedReason == nil {
		t.Fatal("pressure off")
	}
	l.SetPressure(PressureSample25)
	if st := l.Status(); st.ModeEffective != config.LogSample || st.SamplePercent != 25 {
		t.Fatal(st)
	}
	l.SetPressure(PressureNone)
	l.Configure(func() config.QueryLog { q := config.DefaultQueryLog(); q.Enabled = false; return q }())
	l.Process(batch(), nil, nil)
	if l.written.Load() != 0 {
		t.Fatal("disabled")
	}
}

func TestDiskGuard(t *testing.T) {
	l, ck, fd, ev := newLogger(t, nil) // min_free 10
	step := func(free float64) string {
		fd.set(free)
		ck.add(11 * time.Second)
		l.Tick()
		return l.ModeEffective()
	}
	if m := step(50); m != config.LogAll {
		t.Fatal(m)
	}
	if m := step(8); m != config.LogErrorsOnly {
		t.Fatal(m)
	}
	if m := step(4); m != config.LogOff {
		t.Fatal(m)
	}
	if m := step(6); m != config.LogOff { // hysteresis: needs >= 7
		t.Fatal(m)
	}
	if m := step(7.5); m != config.LogErrorsOnly {
		t.Fatal(m)
	}
	if m := step(11); m != config.LogErrorsOnly { // needs >= 12
		t.Fatal(m)
	}
	if m := step(12.5); m != config.LogAll {
		t.Fatal(m)
	}
	ev.mu.Lock()
	defer ev.mu.Unlock()
	want := []string{"querylog.degraded:disk_low", "querylog.degraded:disk_critical", "querylog.degraded:disk_low", "querylog.recovered:<nil>"}
	if fmt.Sprint(ev.evs) != fmt.Sprint(want) {
		t.Fatalf("%v", ev.evs)
	}
	if st := l.Status(); st.DiskFreePercent == nil || *st.DiskFreePercent != 12.5 {
		t.Fatal(st)
	}
}

func TestRetention(t *testing.T) {
	l, ck, _, _ := newLogger(t, func(q *config.QueryLog) { q.MaxAgeDays = 1 })
	l.st.SegmentRows = 100
	for d := 0; d < 3; d++ {
		var recs []Record
		for i := 0; i < 100; i++ {
			recs = append(recs, rec(ck.now(), "10.0.0.1", fmt.Sprintf("n%d.example", i), 1, 0, SrcCache))
		}
		l.Process(recs, nil, nil)
		ck.add(20 * time.Hour)
	}
	if len(l.st.segs) != 3 {
		t.Fatal(len(l.st.segs))
	}
	if n := l.st.Retention(24*time.Hour, 1<<40); n != 2 {
		t.Fatal("age", n)
	}
	for i := 0; i < 5; i++ {
		var recs []Record
		for j := 0; j < 100; j++ {
			recs = append(recs, rec(ck.now(), "10.0.0.1", fmt.Sprintf("n%d-%d.example", i, j), 1, 0, SrcCache))
		}
		l.Process(recs, nil, nil)
	}
	u := l.st.Usage()
	limit := u.Bytes / 2
	l.st.Retention(24*time.Hour, limit)
	if u2 := l.st.Usage(); u2.Bytes > limit || u2.Segments == 0 {
		t.Fatal(u2, limit)
	}
}

func TestDeleteRewrite(t *testing.T) {
	l, ck, _, _ := newLogger(t, nil)
	l.st.SegmentRows = 400
	base := ck.now()
	var recs []Record
	for i := 0; i < 1000; i++ {
		recs = append(recs, rec(base.Add(time.Duration(i)*time.Second), fmt.Sprintf("10.0.0.%d", i%4), "a.example", 1, 0, SrcCache))
	}
	l.Process(recs, nil, nil) // 2 segments of 400 (finalized as rows arrive) ... the rest active
	l.Process(nil, nil, nil)
	res, err := l.Delete("10.0.0.1", 0)
	if err != nil || res.DeletedRows != 250 {
		t.Fatal(err, res)
	}
	if r := search(t, l, "client=10.0.0.1"); len(r.Rows) != 0 {
		t.Fatal("still there")
	}
	before := base.Add(500 * time.Second).UnixMicro()
	res, err = l.Delete("", before)
	if err != nil || res.DeletedRows != 375 {
		t.Fatal(err, res)
	}
	if r := search(t, l, "limit=1000"); len(r.Rows) != 375 {
		t.Fatal(len(r.Rows))
	}
	// survives a restart (rewritten segments are on disk, the active WAL is current)
	dir := l.st.Dir()
	l.st.mu.Lock()
	l.st.closeWALLocked(false)
	l.st.mu.Unlock()
	st, warns := OpenStore(dir, ck.now)
	if len(warns) > 0 {
		t.Fatal(warns)
	}
	f := Filter{Rcode: -1, Source: -1, Limit: 1000}
	if r := st.Search(context.Background(), &f, 0); len(r.Rows) != 375 {
		t.Fatal("after restart", len(r.Rows))
	}
	res, _ = st.Delete(nil, 0)
	if res.DeletedRows != 375 {
		t.Fatal(res)
	}
	st.Close()
}

func TestCrashRecovery(t *testing.T) {
	l, ck, _, _ := newLogger(t, nil)
	var recs []Record
	for i := 0; i < 300; i++ {
		recs = append(recs, rec(ck.now(), "10.0.0.1", fmt.Sprintf("n%d.example", i), 1, 0, SrcCache))
	}
	l.Process(recs[:100], nil, nil)
	l.Process(recs[100:], nil, nil)
	dir := l.st.Dir()
	walp := l.st.walPath(l.st.activeSeq)
	l.st.mu.Lock()
	l.st.closeWALLocked(false) // simulate a crash: WAL left behind
	l.st.mu.Unlock()
	// torn tail: garbage appended after the valid records
	f, _ := os.OpenFile(walp, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Close()
	os.WriteFile(filepath.Join(dir, ".tmp-123"), []byte("partial"), 0o640)
	st, warns := OpenStore(dir, ck.now)
	if len(warns) != 0 || len(st.segs) != 1 || st.segs[0].Rows != 300 {
		t.Fatal(warns, st.segs)
	}
	if _, err := os.Stat(walp); !os.IsNotExist(err) {
		t.Fatal("wal not removed")
	}
	if _, err := os.Stat(filepath.Join(dir, ".tmp-123")); !os.IsNotExist(err) {
		t.Fatal("tmp not removed")
	}
	// a WAL whose segment exists is discarded (crash between rename and WAL removal)
	os.WriteFile(st.walPath(st.segs[0].Seq), append(append([]byte(nil), walMagic...), 0, 0), 0o640)
	st.Close()
	st2, _ := OpenStore(dir, ck.now)
	if len(st2.segs) != 1 || st2.segs[0].Rows != 300 {
		t.Fatal(st2.segs)
	}
	// a corrupt segment is set aside, not fatal
	os.WriteFile(segPath(dir, 99), []byte("garbage-garbage-garbage"), 0o640)
	st2.Close()
	st3, warns := OpenStore(dir, ck.now)
	if len(warns) != 1 || len(st3.segs) != 1 {
		t.Fatal(warns)
	}
	st3.Close()
}

func TestStreams(t *testing.T) {
	l, ck, _, _ := newLogger(t, func(q *config.QueryLog) { q.ClientIP = config.IPMask })
	v, _ := url.ParseQuery("rcode=NXDOMAIN")
	f, _ := ParseFilter(v)
	var subs []*Stream
	for i := 0; i < MaxStreams; i++ {
		s, err := l.Subscribe(f)
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, s)
	}
	if _, err := l.Subscribe(f); err != ErrTooManyStreams {
		t.Fatal(err)
	}
	l.SetPressure(PressureOff) // streams still see rows while storage is off
	l.Process([]Record{rec(ck.now(), "10.1.2.3", "a.example", 1, 3, SrcUpstream), rec(ck.now(), "10.1.2.3", "b.example", 1, 0, SrcUpstream)}, nil, nil)
	select {
	case r := <-subs[0].C:
		if r.Name != "a.example" || r.Client != "10.1.2.0" {
			t.Fatal(r)
		}
	default:
		t.Fatal("no row")
	}
	if len(subs[0].C) != 0 || l.written.Load() != 0 {
		t.Fatal("filter or storage")
	}
	for i := 0; i < 5000; i++ {
		l.Process([]Record{rec(ck.now(), "10.1.2.3", "a.example", 1, 3, SrcUpstream)}, nil, nil)
	}
	if s := subs[1].TakeSkipped(); s == 0 {
		t.Fatal("slow subscriber must skip")
	}
	for _, s := range subs {
		s.Close()
	}
	if l.streamCount() != 0 {
		t.Fatal("close")
	}
}

func TestItemView(t *testing.T) {
	r := Row{TS: 1_800_000_000_123_000, Client: "10.0.0.1", Name: "a.example", QType: 28, Rcode: 3, Source: SrcUpstream,
		Proto: ProtoTCP, Flags: FlagStale | FlagTC, DurUS: 1250, Size: 99, Upstream: "q9"}
	it := View(&r)
	if it.TS != "2027-01-15T08:00:00.123Z" || it.QType != "AAAA" || it.Rcode != "NXDOMAIN" || it.Source != "upstream" ||
		it.Proto != "tcp" || !it.Flags.Stale || !it.Flags.TC || it.Flags.Cached || it.MS != 1.25 {
		t.Fatalf("%+v", it)
	}
	if c := it.CSV(); len(c) != len(CSVHeader) || c[8] != "1.25" {
		t.Fatal(c)
	}
}

func FuzzSegment(f *testing.F) {
	data, _ := marshalSegment(1, sampleBlock(50, time.Unix(1_800_000_000, 0)))
	f.Add(data)
	f.Add(sampleBlock(10, time.Unix(0, 0)).encode(nil, 0, 10))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = parseSegment(b)
		if blk, err := decodeBlock(b); err == nil {
			for i := 0; i < blk.len(); i++ {
				_ = blk.row(i)
			}
		}
		_, _ = ReadWAL(b)
	})
}

func FuzzParseFilter(f *testing.F) {
	f.Add("from=1&to=2&client=10.0.0.0/8&name=*.example.com&qtype=A&rcode=NXDOMAIN&source=cache&blocked=true&min_ms=1.5&limit=10")
	f.Add("cursor=" + Cursor{Seq: 5, Row: 9}.String())
	f.Fuzz(func(t *testing.T, q string) {
		v, err := url.ParseQuery(q)
		if err != nil {
			return
		}
		flt, err := ParseFilter(v)
		if err != nil {
			return
		}
		r := Row{Name: "a.example.com", Client: "10.0.0.1"}
		_ = flt.MatchRow(&r)
		b := sampleBlock(20, time.Unix(1_800_000_000, 0))
		var mt matcher
		flt.compile(b, &mt)
		for i := 0; i < b.len(); i++ {
			_ = mt.match(b, i)
		}
	})
}

func TestHealthProbeIsRecognisedOnlyFromLoopback(t *testing.T) {
	if !IsHealthProbe(HealthProbeName, netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback probe must be skipped")
	}
	if !IsHealthProbe(HealthProbeName, netip.MustParseAddr("::ffff:127.0.0.1")) {
		t.Fatal("mapped loopback probe must be skipped")
	}
	if IsHealthProbe(HealthProbeName, netip.MustParseAddr("10.0.0.5")) {
		t.Fatal("a probe name from the network is logged like any query")
	}
	if IsHealthProbe("example.com", netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("other loopback queries are logged")
	}
}
