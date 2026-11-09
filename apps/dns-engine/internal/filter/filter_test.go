package filter

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mrk/dns-engine/internal/config"
)

func wire(n string) []byte { return AppendWire(nil, strings.TrimSuffix(n, ".")) }

func TestParseFormats(t *testing.T) {
	cases := []struct {
		format, text string
		want         []Rule
	}{
		{config.FormatHosts, "# c\n0.0.0.0 ads.example.com tracker.example.net # x\n127.0.0.1 localhost\n" +
			"::1 ip6-localhost\n0.0.0.0 0.0.0.0\n1.2.3.4 Bad_Host.Example.ORG.\nnot-an-ip x.com\n",
			[]Rule{{Name: "ads.example.com"}, {Name: "tracker.example.net"}, {Name: "bad_host.example.org"}}},
		{config.FormatDomains, "! comment\n# c\nads.example.com\n*.wild.example.com\n0.0.0.0 h.example.com\ncom\nbad..name\n",
			[]Rule{{Name: "ads.example.com"}, {Name: "wild.example.com", Sub: true}, {Name: "h.example.com"}}},
		{config.FormatAdblock, "[Adblock Plus 2.0]\n! c\n||ads.example.com^\n||imp.example.com^$important\n" +
			"@@||ok.ads.example.com^\n|exact.example.com^\n||x.example.com^$third-party\nexample.com##.banner\n" +
			"/regex/\n||path.example.com/ads\nplain.example.com\n0.0.0.0 hosts.example.com\n",
			[]Rule{{Name: "ads.example.com", Sub: true}, {Name: "imp.example.com", Sub: true},
				{Name: "ok.ads.example.com", Sub: true, Allow: true}, {Name: "exact.example.com"},
				{Name: "plain.example.com"}, {Name: "hosts.example.com"}}},
		{config.FormatRPZ, "$TTL 300\n$ORIGIN rpz.local.\n@ SOA ns. h. 1 1 1 1 1\n NS ns.\n" +
			"ads.example.com CNAME .\n*.ads.example.com 300 IN CNAME .\nok.example.com CNAME rpz-passthru.\n" +
			"nodata.example.com CNAME *.\nabs.example.org.rpz.local. CNAME .\nother.example. CNAME .\n" +
			"32.1.2.0.192.rpz-ip CNAME .\nlocal.example.com A 10.0.0.1 ; walled garden\n",
			[]Rule{{Name: "ads.example.com"}, {Name: "ads.example.com", Sub: true}, {Name: "ok.example.com", Allow: true},
				{Name: "nodata.example.com"}, {Name: "abs.example.org"}, {Name: "local.example.com"}}},
	}
	for _, c := range cases {
		got := ParseRules(c.format, []byte(c.text))
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s:\n got %v\nwant %v", c.format, got, c.want)
		}
	}
}

func parse(t testing.TB, format, text string) *Parsed {
	t.Helper()
	p, err := Parse(strings.NewReader(text), format, 0)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMatcherRules(t *testing.T) {
	ads := parse(t, config.FormatAdblock, "||ads.example.com^\n@@||ok.ads.example.com^\n|exact.example.org^\n")
	hosts := parse(t, config.FormatHosts, "0.0.0.0 track.example.net\n")
	m := Rebuild(nil, 0, []Update{{Bit: 1, Parsed: ads}, {Bit: 2, Parsed: hosts},
		{Bit: CustomBit, Parsed: &Parsed{Block: CustomKeys([]string{"custom.test"}), Allow: CustomKeys([]string{"track.example.net"})}}})
	all := uint32(1 | 2 | CustomBit)
	for _, c := range []struct {
		name string
		mask uint32
		want Verdict
	}{
		{"ads.example.com", all, Blocked}, {"x.y.ads.example.com", all, Blocked}, {"example.com", all, NotListed},
		{"ok.ads.example.com", all, Allowed}, {"a.ok.ads.example.com", all, Allowed},
		{"exact.example.org", all, Blocked}, {"sub.exact.example.org", all, NotListed},
		{"track.example.net", all, Allowed}, // custom allow wins
		{"track.example.net", 2, Blocked},   // without the custom bit
		{"custom.test", all, Blocked}, {"a.custom.test", all, Blocked},
		{"ads.example.com", 2 | CustomBit, NotListed}, // list 1 not active
	} {
		if v, _ := m.Match(wire(c.name), c.mask); v != c.want {
			t.Errorf("%s mask %x: %v want %v", c.name, c.mask, v, c.want)
		}
	}
	if c := m.Counts(); c[0] != 3 || c[1] != 1 || c[31] != 2 {
		t.Fatalf("counts %v", c[:3])
	}
	// remove list 1: its entries go, the others stay
	m2 := Rebuild(m, 2|CustomBit, []Update{{Bit: 1}})
	if v, _ := m2.Match(wire("ads.example.com"), all); v != NotListed {
		t.Fatal("removed list still matches")
	}
	if v, _ := m2.Match(wire("track.example.net"), 2); v != Blocked {
		t.Fatal("kept list lost")
	}
	// the old matcher is untouched (readers keep using it)
	if v, _ := m.Match(wire("ads.example.com"), all); v != Blocked {
		t.Fatal("old matcher changed")
	}
	// malformed wire input never panics
	for _, w := range [][]byte{nil, {5, 'a'}, {0}, {63}} {
		m.Match(w, all)
	}
}

func TestNamesAndSafeSearch(t *testing.T) {
	n := NewNames(map[string][]string{"youtube": config.BlockedServices["youtube"]})
	if id, ok := n.Match(wire("r3.googlevideo.com")); !ok || id != "youtube" {
		t.Fatal(id, ok)
	}
	if _, ok := n.Match(wire("google.com")); ok {
		t.Fatal("unrelated name matched")
	}
	for name, want := range map[string]string{"www.google.com": SafeGoogle, "google.co.uk": SafeGoogle,
		"www.youtube.com": SafeYouTube, "www.bing.com": SafeBing, "duckduckgo.com": SafeDDG,
		"forcesafesearch.google.com": "", "mail.google.com": "", "www.google.example.test": ""} {
		got, _ := SafeSearch(wire(name))
		if got != want {
			t.Errorf("%s: %q want %q", name, got, want)
		}
	}
}

func TestParseLimits(t *testing.T) {
	if _, err := Parse(strings.NewReader("a.com\nb.com\nc.com\n"), config.FormatDomains, 2); err != ErrTooMany {
		t.Fatal(err)
	}
	if _, err := Parse(strings.NewReader("<html>not a list</html>\n"), config.FormatDomains, 0); err != ErrEmpty {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 100<<10) + "\nok.example.com\n"
	p, err := Parse(strings.NewReader(long), config.FormatDomains, 0)
	if err != nil || len(p.Block) != 1 {
		t.Fatalf("overlong line: %v %v", p, err)
	}
}

type listServer struct {
	srv    *httptest.Server
	mu     sync.Mutex
	body   string
	status int
	hits   atomic.Int32
}

func newListServer(t *testing.T, body string) *listServer {
	ls := &listServer{body: body, status: 200}
	ls.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ls.hits.Add(1)
		ls.mu.Lock()
		b, st := ls.body, ls.status
		ls.mu.Unlock()
		if st != 200 {
			w.WriteHeader(st)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, len(b)))
		if r.Header.Get("If-None-Match") == fmt.Sprintf(`"%d"`, len(b)) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(b))
	}))
	t.Cleanup(ls.srv.Close)
	return ls
}

func (ls *listServer) set(body string, status int) {
	ls.mu.Lock()
	ls.body, ls.status = body, status
	ls.mu.Unlock()
}

func wait(t *testing.T, s *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.WaitIdle(ctx)
}

func statusOf(s *Service, id string) ListStatus {
	for _, st := range s.Status() {
		if st.ID == id {
			return st
		}
	}
	return ListStatus{}
}

func TestServiceDownloadFailureAndCache(t *testing.T) {
	ls := newListServer(t, "0.0.0.0 ads.example.com\n0.0.0.0 track.example.com\n")
	dir := t.TempDir()
	var failed atomic.Value
	opts := Options{Dir: dir, Client: ls.srv.Client(), OnFail: func(id, code, detail string) { failed.Store(code) },
		MaxListBytes: 1 << 10}
	s := New(opts)
	defer s.Close()
	f := config.Filtering{Enabled: true, Action: config.BlockNXDomain, Allow: []string{}, Block: []string{"custom.test"},
		Lists: []config.FilterList{{ID: "ads", URL: ls.srv.URL + "/ads.txt", Format: config.FormatHosts, Enabled: true, UpdateHours: 24}}}
	s.Configure(f)
	// custom names apply synchronously
	if v, _ := s.Matcher().Match(wire("custom.test"), CustomBit); v != Blocked {
		t.Fatal("custom block not applied at once")
	}
	wait(t, s)
	bit := s.BitOf("ads")
	if v, _ := s.Matcher().Match(wire("ads.example.com"), bit); v != Blocked || bit == 0 {
		t.Fatal("list not loaded")
	}
	if st := statusOf(s, "ads"); st.Entries != 2 || st.UpdatedAt == nil || st.Error != "" {
		t.Fatalf("%+v", st)
	}
	// conditional refresh: 304 keeps the entries
	s.mu.Lock()
	s.lists["ads"].nextAt = time.Time{}
	s.mu.Unlock()
	s.poke()
	wait(t, s)
	if st := statusOf(s, "ads"); st.Entries != 2 || st.Error != "" {
		t.Fatalf("after 304: %+v", st)
	}
	// failures keep the previous version
	for _, c := range []struct {
		body   string
		status int
		code   string
	}{{"", 500, ErrCodeHTTP}, {strings.Repeat("0.0.0.0 x.example.com\n", 100), 200, ErrCodeTooLarge},
		{"<html>oops</html>", 200, ErrCodeEmpty}} {
		ls.set(c.body, c.status)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		s.Refresh(ctx)
		cancel()
		st := statusOf(s, "ads")
		if st.Error != c.code || st.Entries != 2 {
			t.Fatalf("%s: %+v", c.code, st)
		}
		if v, _ := s.Matcher().Match(wire("ads.example.com"), bit); v != Blocked {
			t.Fatalf("%s: previous version lost", c.code)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if failed.Load() == nil {
		t.Fatal("OnFail not called")
	}
	// a new service loads the cached copy without the network
	ls.srv.Close()
	s2 := New(Options{Dir: dir, Client: &http.Client{Timeout: time.Second}})
	defer s2.Close()
	s2.Configure(f)
	wait(t, s2)
	if v, _ := s2.Matcher().Match(wire("track.example.com"), s2.BitOf("ads")); v != Blocked {
		t.Fatal("cached copy not loaded")
	}
	// disabling filtering unloads the lists (status falls back to the cache)
	f.Enabled = false
	s2.Configure(f)
	if s2.Matcher().Len() != 0 {
		t.Fatal("lists kept while filtering is off")
	}
	// deleting a list from the settings removes its cache
	f.Lists = nil
	s2.Configure(f)
	if _, err := os.Stat(filepath.Join(dir, "ads.list")); !os.IsNotExist(err) {
		t.Fatal("cache of a deleted list kept", err)
	}
}

func TestServiceRejectsPlainHTTPAndBudget(t *testing.T) {
	ls := newListServer(t, "a.example.com\nb.example.com\nc.example.com\n")
	s := New(Options{Dir: t.TempDir(), Client: ls.srv.Client(), MaxTotal: 2})
	defer s.Close()
	s.Configure(config.Filtering{Enabled: true, Lists: []config.FilterList{
		{ID: "big", URL: ls.srv.URL, Format: config.FormatDomains, Enabled: true, UpdateHours: 1}}})
	wait(t, s)
	if st := statusOf(s, "big"); st.Error != ErrCodeTooMany {
		t.Fatalf("%+v", st)
	}
	// the memory guard refuses a build
	s3 := New(Options{Dir: t.TempDir(), Client: ls.srv.Client(), MemCheck: func(int64) error { return fmt.Errorf("no room") }})
	defer s3.Close()
	s3.Configure(config.Filtering{Enabled: true, Lists: []config.FilterList{
		{ID: "x", URL: ls.srv.URL, Format: config.FormatDomains, Enabled: true, UpdateHours: 1}}})
	wait(t, s3)
	if st := statusOf(s3, "x"); st.Error != ErrCodeMemory || s3.Matcher().Len() != 0 {
		t.Fatalf("%+v", st)
	}
	// pressure defers work
	s4 := New(Options{Dir: t.TempDir(), Client: ls.srv.Client(), Busy: func() bool { return true }})
	defer s4.Close()
	s4.Configure(config.Filtering{Enabled: true, Lists: []config.FilterList{
		{ID: "x", URL: ls.srv.URL, Format: config.FormatDomains, Enabled: true, UpdateHours: 1}}})
	wait(t, s4)
	if st := statusOf(s4, "x"); st.Error != ErrCodePressure {
		t.Fatalf("%+v", st)
	}
}

func genNames(n int) []byte {
	var b bytes.Buffer
	b.Grow(n * 24)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "0.0.0.0 host%d.ads%d.example.com\n", i, i%977)
	}
	return b.Bytes()
}

func heap() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// TestMemoryOneMillion measures the resident cost of a one-million-name list
// (docs/41 §3.1: memory-efficient storage).
func TestMemoryOneMillion(t *testing.T) {
	if testing.Short() {
		t.Skip("large")
	}
	const n = 1_000_000
	data := genNames(n)
	before := heap()
	start := time.Now()
	p, err := Parse(bytes.NewReader(data), config.FormatHosts, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := Rebuild(nil, 0, []Update{{Bit: 1, Parsed: p}})
	build := time.Since(start)
	p = nil
	after := heap()
	runtime.KeepAlive(data)
	delta := int64(after) - int64(before)
	perName := float64(delta) / n
	t.Logf("1M names: %.1f MiB resident (%.1f B/name), matcher %.1f MiB, parse+build %v",
		float64(delta)/(1<<20), perName, float64(m.Bytes())/(1<<20), build)
	if m.Len() != n {
		t.Fatalf("entries %d", m.Len())
	}
	if perName > 16 {
		t.Fatalf("%.1f bytes per name (budget 16)", perName)
	}
	if v, _ := m.Match(wire(fmt.Sprintf("host123456.ads%d.example.com", 123456%977)), 1); v != Blocked {
		t.Fatal("lookup failed")
	}
	runtime.KeepAlive(m)
}

func BenchmarkMatchOneMillion(b *testing.B) {
	p, err := Parse(bytes.NewReader(genNames(1_000_000)), config.FormatHosts, 0)
	if err != nil {
		b.Fatal(err)
	}
	m := Rebuild(nil, 0, []Update{{Bit: 1, Parsed: p}})
	names := [][]byte{wire("host42.ads42.example.com"), wire("www.not-listed.example.org"), wire("a.b.c.d.e.example.net")}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match(names[i%len(names)], 1|CustomBit)
	}
}

func FuzzParseList(f *testing.F) {
	for _, s := range []string{"0.0.0.0 a.example.com\n", "||ads.example.com^$important\n@@||ok.example.com^\n",
		"$ORIGIN rpz.\n*.x.example CNAME .\n", "*.w.example.com\n", "\xff\xfe\x00||^\n"} {
		f.Add(uint8(0), []byte(s))
	}
	formats := []string{config.FormatHosts, config.FormatDomains, config.FormatAdblock, config.FormatRPZ}
	f.Fuzz(func(t *testing.T, fi uint8, data []byte) {
		format := formats[int(fi)%len(formats)]
		for _, r := range ParseRules(format, data) {
			if _, ok := listName([]byte(r.Name)); !ok || r.Name != strings.ToLower(r.Name) {
				t.Fatalf("invalid rule name %q", r.Name)
			}
		}
		p, err := Parse(bytes.NewReader(data), format, 1000)
		if err != nil {
			return
		}
		m := Rebuild(nil, 0, []Update{{Bit: 1, Parsed: p}})
		m.Match(data, 1)
		if m.Len() != len(p.Block) {
			t.Fatal("matcher size")
		}
	})
}
