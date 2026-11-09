package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/testutil"
	"mrk/dns-engine/internal/zone"
)

var (
	lan    = netip.MustParseAddr("192.168.1.10")
	public = netip.MustParseAddr("203.0.113.9")
)

func newEngine(t testing.TB, upstream string, mut func(s *config.Settings)) *Engine {
	t.Helper()
	e, err := Open(Options{DataDir: t.TempDir(), DefaultListen: "127.0.0.1:5399"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	s, v := e.Settings()
	s.Upstreams = []config.Upstream{{ID: "test", Address: upstream, Enabled: true}}
	if upstream == "" {
		s.Upstreams = nil
	}
	s.Pressure.Enabled = false // keep D1 tests independent of the test machine's CPU load
	s.Limits.ClientQPS, s.Limits.ClientBurst = 0, 0
	s.DNSSEC.Mode = config.DNSSECOff // D1/D2 tests count upstream queries; D4 tests enable validation
	if mut != nil {
		mut(&s)
	}
	if _, _, err := e.PutSettings(s, v); err != nil {
		t.Fatal(err)
	}
	return e
}

func query(name string, qtype uint16, mut ...func(*dns.Msg)) []byte {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(1232, false)
	for _, f := range mut {
		f(m)
	}
	b, _ := m.Pack()
	return b
}

// ask runs the same path the UDP server runs: Fast, then Slow if needed.
func ask(t testing.TB, e *Engine, client netip.Addr, proto Proto, pkt []byte) *dns.Msg {
	t.Helper()
	sc := NewScratch()
	out, v := e.Fast(pkt, client, proto, sc)
	switch v {
	case DropIt:
		return nil
	case Slow, SlowUnchecked:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out = e.Slow(ctx, pkt, client, proto, v == Slow)
	default:
		out = append([]byte(nil), out...)
	}
	if out == nil {
		return nil
	}
	r := new(dns.Msg)
	if err := r.Unpack(out); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return r
}

func s(v string) *string { return &v }
func i(v int) *int       { return &v }

func addRecord(t testing.TB, e *Engine, z, name, typ, data string) zone.Record {
	t.Helper()
	r, err := e.CreateRecord(z, zone.RecordInput{Name: s(name), Type: s(typ), TTL: i(300), Data: json.RawMessage(data)})
	if err != nil {
		t.Fatalf("add %s %s: %v", name, typ, err)
	}
	return r
}

func TestOpenResolverRefusal(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	e := newEngine(t, up.Addr, func(s *config.Settings) {
		s.QueryAllow = []string{"0.0.0.0/0", "::/0"} // public authoritative service
	})
	if _, err := e.CreateZone("example.com", "primary", nil); err != nil {
		t.Fatal(err)
	}
	addRecord(t, e, "example.com", "www", "A", `{"address":"192.0.2.80"}`)
	// public client: authoritative data yes, recursion never
	r := ask(t, e, public, UDP, query("www.example.com.", dns.TypeA))
	if r.Rcode != 0 || !r.Authoritative || len(r.Answer) != 1 || r.RecursionAvailable {
		t.Fatalf("auth for public: %v", r)
	}
	for _, name := range []string{"google.com.", "x.example.net."} {
		r = ask(t, e, public, UDP, query(name, dns.TypeA))
		if r.Rcode != dns.RcodeRefused || len(r.Answer) != 0 {
			t.Fatalf("open resolver! %s -> %v", name, r)
		}
	}
	if up.Queries.Load() != 0 {
		t.Fatal("upstream contacted for a refused client")
	}
	// LAN client recurses
	r = ask(t, e, lan, UDP, query("google.com.", dns.TypeA))
	if r.Rcode != 0 || len(r.Answer) != 1 || !r.RecursionAvailable {
		t.Fatalf("lan recursion: %v", r)
	}
	// default query_allow: public clients get REFUSED for everything
	e2 := newEngine(t, up.Addr, nil)
	if r := ask(t, e2, public, UDP, query("www.example.com.", dns.TypeA)); r.Rcode != dns.RcodeRefused {
		t.Fatalf("query_allow: %v", r)
	}
	// recursion disabled globally
	e3 := newEngine(t, up.Addr, func(s *config.Settings) { s.Recursion.Enabled = false })
	if r := ask(t, e3, lan, UDP, query("google.com.", dns.TypeA)); r.Rcode != dns.RcodeRefused {
		t.Fatalf("recursion disabled: %v", r)
	}
}

func TestCacheFastPathAndNegative(t *testing.T) {
	var nx atomic.Bool
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg {
		if strings.HasPrefix(q.Name, "missing.") {
			return testutil.NX(q, 120)
		}
		if strings.HasPrefix(q.Name, "nodata.") && q.Qtype == dns.TypeAAAA {
			m := testutil.NX(q, 60)
			m.Rcode = 0
			return m
		}
		if nx.Load() {
			return testutil.NX(q, 120)
		}
		m := testutil.A(q, 300, "93.184.216.34")
		extra, _ := dns.NewRR("evil.example. 300 IN A 6.6.6.6")
		m.Extra = append(m.Extra, extra) // must be scrubbed
		bogus, _ := dns.NewRR("other.example. 300 IN A 6.6.6.6")
		m.Answer = append(m.Answer, bogus) // out-of-chain: scrubbed
		return m
	})
	e := newEngine(t, up.Addr, func(s *config.Settings) { s.Cache.MaxTTL = 200 })
	pkt := query("WWW.Example.", dns.TypeA)
	r := ask(t, e, lan, UDP, pkt)
	if len(r.Answer) != 1 || len(r.Extra) != 1 /* OPT only */ || r.Answer[0].Header().Ttl != 200 {
		t.Fatalf("first: %v", r)
	}
	// second time: fast path (no upstream query), question case preserved, ID echoed
	sc := NewScratch()
	m := new(dns.Msg)
	_ = m.Unpack(pkt)
	out, v := e.Fast(pkt, lan, UDP, sc)
	if v != Reply {
		t.Fatalf("expected fast-path cache hit, got %v", v)
	}
	r2 := new(dns.Msg)
	_ = r2.Unpack(out)
	if r2.Id != m.Id || r2.Question[0].Name != "WWW.Example." || !r2.RecursionAvailable || r2.Authoritative {
		t.Fatalf("fast hit: %v", r2)
	}
	if up.Queries.Load() != 1 {
		t.Fatalf("upstream queried %d times", up.Queries.Load())
	}
	// NXDOMAIN is cached for the name across types (RFC 2308 §5)
	r = ask(t, e, lan, UDP, query("missing.example.", dns.TypeA))
	if r.Rcode != dns.RcodeNameError || len(r.Ns) != 1 {
		t.Fatalf("nx: %v", r)
	}
	n := up.Queries.Load()
	r = ask(t, e, lan, UDP, query("missing.example.", dns.TypeMX))
	if r.Rcode != dns.RcodeNameError || up.Queries.Load() != n || r.Question[0].Qtype != dns.TypeMX {
		t.Fatalf("nx for other type not from cache: %v", r)
	}
	if ttl := r.Ns[0].Header().Ttl; ttl > 120 || ttl < 118 {
		t.Fatalf("negative ttl %d", ttl)
	}
	// NODATA cached per type
	r = ask(t, e, lan, UDP, query("nodata.example.", dns.TypeAAAA))
	n = up.Queries.Load()
	r = ask(t, e, lan, UDP, query("nodata.example.", dns.TypeAAAA))
	if r.Rcode != 0 || len(r.Answer) != 0 || up.Queries.Load() != n {
		t.Fatalf("nodata: %v", r)
	}
	// RD=0: cache only
	r = ask(t, e, lan, UDP, query("never.example.", dns.TypeA, func(m *dns.Msg) { m.RecursionDesired = false }))
	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("rd=0 miss: %v", r)
	}
	if n, _ := e.FlushCache("example."); n == 0 {
		t.Fatal("flush")
	}
}

func TestServeStale(t *testing.T) {
	var down atomic.Bool
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg {
		if down.Load() {
			return nil // timeout
		}
		return testutil.A(q, 1, "93.184.216.34")
	})
	e := newEngine(t, up.Addr, nil)
	if r := ask(t, e, lan, UDP, query("stale.example.", dns.TypeA)); len(r.Answer) != 1 {
		t.Fatal(r)
	}
	down.Store(true)
	time.Sleep(1100 * time.Millisecond)
	start := time.Now()
	r := ask(t, e, lan, UDP, query("stale.example.", dns.TypeA))
	if r == nil || len(r.Answer) != 1 || r.Answer[0].Header().Ttl != staleAnswerTTL {
		t.Fatalf("stale: %v", r)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("stale answer too slow")
	}
	if opt := r.IsEdns0(); opt == nil || len(opt.Option) == 0 {
		t.Fatalf("missing EDE stale: %v", r)
	}
	// after a failed refresh, stale is served immediately (no wait) during the retry window
	start = time.Now()
	r = ask(t, e, lan, UDP, query("stale.example.", dns.TypeA))
	if len(r.Answer) != 1 || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("second stale: %v %v", r, time.Since(start))
	}
	// no stale entry and dead upstream: SERVFAIL
	if r := ask(t, e, lan, UDP, query("unknown.example.", dns.TypeA)); r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("servfail: %v", r)
	}
}

func TestSingleFlight(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	up.SetDelay(150 * time.Millisecond)
	e := newEngine(t, up.Addr, nil)
	var wg sync.WaitGroup
	for k := 0; k < 30; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := ask(t, e, lan, UDP, query("sf.example.", dns.TypeA)); r == nil || len(r.Answer) != 1 {
				t.Error("answer")
			}
		}()
	}
	wg.Wait()
	if q := up.Queries.Load(); q != 1 {
		t.Fatalf("upstream got %d queries, want 1", q)
	}
}

func TestRebindingProtection(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "10.0.0.5", "93.184.216.34") })
	e := newEngine(t, up.Addr, nil)
	r := ask(t, e, lan, UDP, query("rebind.example.", dns.TypeA))
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "93.184.216.34" {
		t.Fatalf("private address not filtered: %v", r)
	}
	e2 := newEngine(t, up.Addr, func(s *config.Settings) { s.RebindingProtection = false })
	if r := ask(t, e2, lan, UDP, query("rebind.example.", dns.TypeA)); len(r.Answer) != 2 {
		t.Fatalf("disabled: %v", r)
	}
	// forwarder zones are internal: private answers allowed
	if _, err := e.CreateZone("corp.internal", "forwarder", []string{up.Addr}); err != nil {
		t.Fatal(err)
	}
	if r := ask(t, e, lan, UDP, query("db.corp.internal.", dns.TypeA)); len(r.Answer) != 2 {
		t.Fatalf("forwarder zone filtered: %v", r)
	}
	if r := ask(t, e, public, UDP, query("db.corp.internal.", dns.TypeA)); r.Rcode != dns.RcodeRefused {
		t.Fatalf("forwarder zone for outsider: %v", r)
	}
}

func TestOverrides(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	e := newEngine(t, up.Addr, nil)
	if _, err := e.CreateOverride(OverrideInput{Name: s("panel.mrk.internal"), Type: s("A"), Value: s("172.17.0.1"), Source: "services"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CreateOverride(OverrideInput{Name: s("*.apps.example"), Type: s("CNAME"), Value: s("panel.mrk.internal")}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CreateOverride(OverrideInput{Name: s("ext.example"), Type: s("CNAME"), Value: s("www.upstream.example")}); err != nil {
		t.Fatal(err)
	}
	r := ask(t, e, lan, UDP, query("panel.mrk.internal.", dns.TypeA))
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "172.17.0.1" {
		t.Fatalf("override: %v", r)
	}
	if r := ask(t, e, lan, UDP, query("panel.mrk.internal.", dns.TypeAAAA)); r.Rcode != 0 || len(r.Answer) != 0 {
		t.Fatalf("override NODATA: %v", r)
	}
	r = ask(t, e, lan, UDP, query("x.apps.example.", dns.TypeA))
	if len(r.Answer) != 2 || r.Answer[0].Header().Name != "x.apps.example." {
		t.Fatalf("wildcard override chain: %v", r)
	}
	r = ask(t, e, lan, UDP, query("ext.example.", dns.TypeA))
	if len(r.Answer) != 2 || r.Answer[1].(*dns.A).A.String() != "93.184.216.34" {
		t.Fatalf("override CNAME to upstream: %v", r)
	}
	if up.Queries.Load() != 1 {
		t.Fatalf("upstream queries %d", up.Queries.Load())
	}
	if r := ask(t, e, public, UDP, query("panel.mrk.internal.", dns.TypeA)); r.Rcode != dns.RcodeRefused {
		t.Fatal("override leaked to outsider")
	}
	// validation
	if _, err := e.CreateOverride(OverrideInput{Name: s("panel.mrk.internal"), Type: s("CNAME"), Value: s("x.example")}); !isCode(err, CodeCNAMEConflict) {
		t.Fatalf("cname conflict: %v", err)
	}
	if _, err := e.CreateOverride(OverrideInput{Name: s("bad name"), Type: s("A"), Value: s("1.2.3.4")}); !isCode(err, CodeRecordInvalid) {
		t.Fatal(err)
	}
	if _, err := e.CreateOverride(OverrideInput{Name: s("v6.example"), Type: s("A"), Value: s("::1")}); !isCode(err, CodeRecordInvalid) {
		t.Fatal(err)
	}
	items := e.Overrides()
	if err := e.DeleteOverride(items[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteOverride("nope"); !isCode(err, CodeOverrideNotFound) {
		t.Fatal(err)
	}
	// globally disabled
	st, v := e.Settings()
	st.Overrides.Enabled = false
	if _, _, err := e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
	if r := ask(t, e, lan, UDP, query("x.apps.example.", dns.TypeA)); len(r.Answer) == 2 && r.Answer[0].Header().Rrtype == dns.TypeCNAME {
		t.Fatal("disabled overrides still answered")
	}
}

func isCode(err error, code string) bool {
	var fe *fielderr.Error
	return errors.As(err, &fe) && fe.Code == code
}

func TestAuthoritativeAndChase(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	e := newEngine(t, up.Addr, nil)
	if _, err := e.CreateZone("Example.COM.", "primary", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CreateZone("example.com", "primary", nil); !isCode(err, CodeZoneExists) {
		t.Fatal(err)
	}
	addRecord(t, e, "example.com", "cdn", "CNAME", `{"target":"edge.cdn.example"}`)
	big := strings.Repeat("y", 250)
	for k := 0; k < 8; k++ {
		addRecord(t, e, "example.com", "big", "TXT", `{"text":"`+big+string(rune('a'+k))+`"}`)
	}
	r := ask(t, e, lan, UDP, query("cdn.example.com.", dns.TypeA))
	if !r.Authoritative || len(r.Answer) != 2 {
		t.Fatalf("chase: %v", r)
	}
	// UDP truncation then full answer over TCP
	r = ask(t, e, lan, UDP, query("big.example.com.", dns.TypeTXT))
	if !r.Truncated {
		t.Fatalf("expected TC: %d answers", len(r.Answer))
	}
	r = ask(t, e, lan, TCP, query("big.example.com.", dns.TypeTXT))
	if r.Truncated || len(r.Answer) != 8 {
		t.Fatalf("tcp: %v", r.Truncated)
	}
	// no EDNS: 512 limit
	r = ask(t, e, lan, UDP, query("big.example.com.", dns.TypeTXT, func(m *dns.Msg) { m.Extra = nil }))
	if !r.Truncated {
		t.Fatal("512 limit")
	}
	// minimal ANY over UDP (RFC 8482)
	addRecord(t, e, "example.com", "multi", "A", `{"address":"192.0.2.1"}`)
	addRecord(t, e, "example.com", "multi", "TXT", `{"text":"t"}`)
	r = ask(t, e, lan, UDP, query("multi.example.com.", dns.TypeANY))
	if len(r.Answer) != 1 {
		t.Fatalf("minimal ANY: %v", r)
	}
	if r := ask(t, e, lan, TCP, query("multi.example.com.", dns.TypeANY)); len(r.Answer) != 2 {
		t.Fatalf("ANY over TCP: %v", r)
	}
	r = ask(t, e, lan, UDP, query("anything.example.net.", dns.TypeANY))
	if len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeHINFO {
		t.Fatalf("recursive ANY: %v", r)
	}
	// disabling the zone falls back to recursion
	if _, err := e.PatchZone("example.com", ZonePatch{Disabled: boolp(true)}); err != nil {
		t.Fatal(err)
	}
	if r := ask(t, e, lan, UDP, query("multi.example.com.", dns.TypeA)); r.Authoritative {
		t.Fatal("disabled zone still authoritative")
	}
}

func boolp(b bool) *bool { return &b }

func TestProtocolSanity(t *testing.T) {
	e := newEngine(t, "", nil)
	sc := NewScratch()
	// responses and short packets are dropped silently
	resp := query("x.", dns.TypeA, func(m *dns.Msg) { m.Response = true })
	if out := e.Slow(context.Background(), resp, lan, UDP, false); out != nil {
		t.Fatal("answered a response")
	}
	if out := e.Slow(context.Background(), []byte{1, 2, 3}, lan, UDP, false); out != nil {
		t.Fatal("answered garbage")
	}
	if _, v := e.Fast([]byte{1, 2, 3}, lan, UDP, sc); v != SlowUnchecked {
		t.Fatal("fast")
	}
	// garbage with a valid header: FORMERR (for allowed clients), nothing for others
	garbage := append(query("x.", dns.TypeA)[:12], 0xff, 0xff, 0xff)
	if out := e.Slow(context.Background(), garbage, lan, UDP, false); out == nil || out[3]&0xf != dns.RcodeFormatError {
		t.Fatal("formerr")
	}
	if out := e.Slow(context.Background(), garbage, public, UDP, false); out != nil {
		t.Fatal("formerr to outsider")
	}
	cases := []struct {
		pkt   []byte
		rcode int
	}{
		{query("version.bind.", dns.TypeTXT, func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS }), dns.RcodeRefused},
		{query("example.", dns.TypeAXFR), dns.RcodeRefused},
		// NOTIFY is handled now: a zone we are not secondary for is NOTAUTH
		{query("example.", dns.TypeSOA, func(m *dns.Msg) { m.Opcode = dns.OpcodeNotify }), dns.RcodeNotAuth},
		{query("example.", dns.TypeA, func(m *dns.Msg) { m.Opcode = dns.OpcodeStatus }), dns.RcodeNotImplemented},
		{query("example.", dns.TypeA, func(m *dns.Msg) { m.Question = append(m.Question, m.Question[0]) }), dns.RcodeFormatError},
		{query("example.", dns.TypeA, func(m *dns.Msg) { m.IsEdns0().SetVersion(1) }), dns.RcodeBadVers},
		{query("localhost.", dns.TypeA), dns.RcodeSuccess},
		{query("5.0.17.172.in-addr.arpa.", dns.TypePTR), dns.RcodeNameError},
		{query("foo.invalid.", dns.TypeA), dns.RcodeNameError},
		{query("example.", dns.TypeA), dns.RcodeServerFailure}, // no upstreams
	}
	for n, c := range cases {
		r := ask(t, e, lan, UDP, c.pkt)
		if r == nil || r.Rcode != c.rcode {
			t.Errorf("case %d: want %s got %v", n, dns.RcodeToString[c.rcode], r)
		}
	}
	if r := ask(t, e, lan, UDP, query("localhost.", dns.TypeA)); len(r.Answer) != 1 {
		t.Fatal("localhost")
	}
}

func TestRateLimits(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	e := newEngine(t, up.Addr, func(s *config.Settings) {
		s.Limits.ClientQPS, s.Limits.ClientBurst = 10, 10
		s.Limits.RRLResponsesPerSecond, s.Limits.RRLSlip = 5, 2
		s.QueryAllow = []string{"0.0.0.0/0", "::/0"}
	})
	if _, err := e.CreateZone("example.com", "primary", nil); err != nil {
		t.Fatal(err)
	}
	addRecord(t, e, "example.com", "www", "A", `{"address":"192.0.2.80"}`)
	ok, dropped := 0, 0
	for k := 0; k < 50; k++ {
		if r := ask(t, e, lan, UDP, query("www.example.com.", dns.TypeA)); r != nil {
			ok++
		} else {
			dropped++
		}
	}
	if ok != 10 || dropped != 40 {
		t.Fatalf("client limit: ok %d dropped %d", ok, dropped)
	}
	if r := ask(t, e, netip.MustParseAddr("192.168.1.11"), UDP, query("www.example.com.", dns.TypeA)); r == nil {
		t.Fatal("other client starved")
	}
	// TCP over the limit gets REFUSED rather than silence
	if r := ask(t, e, lan, TCP, query("www.example.com.", dns.TypeA)); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("tcp over limit: %v", r)
	}
	// RRL: spoofed-looking outsiders (many IPs in one /24) asking the same name
	sent, slip, drop := 0, 0, 0
	for k := 0; k < 9; k++ {
		r := ask(t, e, netip.AddrFrom4([4]byte{198, 51, 100, byte(k)}), UDP, query("www.example.com.", dns.TypeA))
		switch {
		case r == nil:
			drop++
		case r.Truncated:
			slip++
		default:
			sent++
		}
	}
	if sent != 5 || slip != 2 || drop != 2 {
		t.Fatalf("rrl: sent %d slip %d drop %d", sent, slip, drop)
	}
}

func TestZoneLifecycleAndPersistence(t *testing.T) {
	dir := t.TempDir()
	e, err := Open(Options{DataDir: dir, DefaultListen: "127.0.0.1:5399"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.CreateZone("bad zone", "primary", nil); !isCode(err, CodeInvalidZoneName) {
		t.Fatal(err)
	}
	if _, err := e.CreateZone("x.example", "weird", nil); !isCode(err, CodeZoneInvalid) {
		t.Fatal(err)
	}
	if _, err := e.CreateZone("fw.example", "forwarder", []string{"not an ip"}); !isCode(err, CodeZoneInvalid) {
		t.Fatal(err)
	}
	d, err := e.CreateZone("example.com", "primary", nil)
	if err != nil {
		t.Fatal(err)
	}
	serial0 := d.Serial
	w := addRecord(t, e, "example.com", "www", "A", `{"address":"192.0.2.1"}`)
	_, err = e.CreateRecord("example.com", zone.RecordInput{Name: s("www"), Type: s("CNAME"), Data: json.RawMessage(`{"target":"x.example.net"}`)})
	if !isCode(err, CodeCNAMEConflict) {
		t.Fatalf("cname conflict: %v", err)
	}
	var fe *fielderr.Error
	if errors.As(err, &fe); len(fe.Fields) == 0 {
		t.Fatal("fields missing")
	}
	if _, err := e.CreateRecord("example.com", zone.RecordInput{Name: s("www"), Type: s("A"), Data: json.RawMessage(`{"address":"192.0.2.1"}`)}); !isCode(err, CodeRecordInvalid) {
		t.Fatalf("duplicate: %v", err)
	}
	// RRset TTL uniformity: adding with another TTL updates the set
	r2, _ := e.CreateRecord("example.com", zone.RecordInput{Name: s("www"), Type: s("A"), TTL: i(60), Data: json.RawMessage(`{"address":"192.0.2.2"}`)})
	recs, _ := e.Records("example.com")
	for _, r := range recs {
		if r.Name == "www" && r.TTL != 60 {
			t.Fatalf("rrset ttl not synced: %+v", r)
		}
	}
	if recs[0].ID != zone.SOAID {
		t.Fatal("SOA first")
	}
	if _, err := e.UpdateRecord("example.com", w.ID, zone.RecordInput{Name: s("www"), Type: s("A"), TTL: i(60), Data: json.RawMessage(`{"address":"192.0.2.3"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.UpdateRecord("example.com", "soa", zone.RecordInput{TTL: i(600), Data: json.RawMessage(
		`{"mname":"ns1.example.com","rname":"admin@example.com","refresh":3600,"retry":600,"expire":604800,"minimum":60}`)}); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteRecord("example.com", "soa"); err == nil {
		t.Fatal("SOA deleted")
	}
	if err := e.DeleteRecord("example.com", r2.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteRecord("example.com", "missing"); !isCode(err, CodeRecordNotFound) {
		t.Fatal(err)
	}
	det, _ := e.Zone("example.com")
	if det.Serial <= serial0 || det.Version != 6 {
		t.Fatalf("serial %d->%d version %d", serial0, det.Serial, det.Version)
	}
	// export / import(replace) round trip
	text, err := e.Export("example.com")
	if err != nil || !strings.Contains(text, "192.0.2.3") || !strings.Contains(text, "admin.example.com.") {
		t.Fatalf("export: %v\n%s", err, text)
	}
	res, err := e.Import("example.com", "new 300 IN A 192.0.2.9\n", true)
	if err != nil || res.Added != 1 {
		t.Fatal(res, err)
	}
	if r := ask(t, e, lan, UDP, query("www.example.com.", dns.TypeA)); r.Rcode != dns.RcodeNameError {
		t.Fatalf("replace import kept old data: %v", r)
	}
	res, err = e.Import("example.com", text, false)
	if err != nil || res.Added == 0 {
		t.Fatal(res, err)
	}
	if _, err := e.Import("example.com", "garbage here\n", false); !isCode(err, CodeImportInvalid) {
		t.Fatal(err)
	}
	// history + rollback to version 3 (www=192.0.2.1 + .2)
	h, _ := e.History("example.com")
	if len(h) != 8 || h[0].Version <= h[1].Version {
		t.Fatalf("history %v", h)
	}
	before, _ := e.Zone("example.com")
	if _, err := e.Rollback("example.com", 3); err != nil {
		t.Fatal(err)
	}
	after, _ := e.Zone("example.com")
	if after.Serial <= before.Serial || after.Version != before.Version+1 {
		t.Fatal("rollback must create a new version with a higher serial")
	}
	if r := ask(t, e, lan, UDP, query("www.example.com.", dns.TypeA)); len(r.Answer) != 2 {
		t.Fatalf("rollback content: %v", r)
	}
	if _, err := e.Rollback("example.com", 999); !isCode(err, CodeVersionNotFound) {
		t.Fatal(err)
	}
	if _, err := e.CreateOverride(OverrideInput{Name: s("o.example"), Type: s("A"), Value: s("10.1.1.1")}); err != nil {
		t.Fatal(err)
	}
	st, v := e.Settings()
	st.Cache.MaxBytes = 2 << 20
	if _, _, err := e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
	e.Close()

	// restart: everything is back
	e2, err := Open(Options{DataDir: dir, DefaultListen: "127.0.0.1:9999"})
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	st2, v2 := e2.Settings()
	if v2 != v+1 || st2.Cache.MaxBytes != 2<<20 || st2.Listen[0].Address != "127.0.0.1:5399" {
		t.Fatalf("settings not persisted: v=%d %+v", v2, st2.Listen)
	}
	if r := ask(t, e2, lan, UDP, query("www.example.com.", dns.TypeA)); len(r.Answer) != 2 {
		t.Fatal("zone not persisted")
	}
	if len(e2.Overrides()) != 1 {
		t.Fatal("overrides not persisted")
	}
	if err := e2.DeleteZone("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.Zone("example.com"); !isCode(err, CodeZoneNotFound) {
		t.Fatal(err)
	}
}

func TestSettingsConflictAndValidation(t *testing.T) {
	e := newEngine(t, "", nil)
	st, v := e.Settings()
	if _, _, err := e.PutSettings(st, v-1); !isCode(err, CodeConfigConflict) {
		t.Fatal(err)
	}
	bad := st.Clone()
	bad.Limits.UDPMaxSize = 10
	if _, _, err := e.PutSettings(bad, v); !isCode(err, CodeSettingsInvalid) {
		t.Fatal(err)
	}
	// concurrent writers with the same version: exactly one wins
	var wins atomic.Int32
	var wg sync.WaitGroup
	for k := 0; k < 10; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := e.PutSettings(st, v); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("wins %d", wins.Load())
	}
	hooked := make(chan config.Settings, 1)
	e.SetListenerHook(func(s config.Settings) { hooked <- s })
	_, v = e.Settings()
	if _, _, err := e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hooked:
	case <-time.After(time.Second):
		t.Fatal("listener hook not called")
	}
}

func TestResolveAndStatus(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	e := newEngine(t, up.Addr, nil)
	r, err := e.Resolve(context.Background(), "example.org", "A", "")
	if err != nil || r.Rcode != "NOERROR" || r.Source != "upstream" || r.Upstream != "test" || len(r.Answers) != 1 || r.Answers[0].Data != "93.184.216.34" {
		t.Fatalf("%+v %v", r, err)
	}
	r, _ = e.Resolve(context.Background(), "example.org", "A", "")
	if r.Source != "cache" {
		t.Fatalf("second resolve source %s", r.Source)
	}
	r, _ = e.Resolve(context.Background(), "example.org", "A", "8.8.8.8")
	if r.Source != "refused" || r.Rcode != "REFUSED" {
		t.Fatalf("outsider: %+v", r)
	}
	if _, err := e.Resolve(context.Background(), "", "BOGUS", "x"); !isCode(err, CodeRecordInvalid) {
		t.Fatal(err)
	}
	st := e.Status(nil)
	if st.ConfigVersion < 2 || st.Version == "" || len(st.Upstreams) != 1 || st.Pressure != "normal" {
		t.Fatalf("%+v", st)
	}
	var b strings.Builder
	e.WritePrometheus(&b)
	if !strings.Contains(b.String(), "mrk_dns_cache_entries") {
		t.Fatal("metrics")
	}
}

func FuzzHandle(f *testing.F) {
	for _, p := range [][]byte{
		query("example.com.", dns.TypeA), query("localhost.", dns.TypeAAAA),
		query("x.", dns.TypeANY, func(m *dns.Msg) { m.Opcode = dns.OpcodeUpdate }),
		query("a.zone.test.", dns.TypeMX),
	} {
		f.Add(p)
	}
	e, err := Open(Options{DataDir: f.TempDir(), DefaultListen: "127.0.0.1:5399"})
	if err != nil {
		f.Fatal(err)
	}
	st, v := e.Settings()
	st.Upstreams = nil
	st.Limits.ClientQPS, st.Limits.ClientBurst = 0, 0
	if _, _, err := e.PutSettings(st, v); err != nil {
		f.Fatal(err)
	}
	if _, err := e.CreateZone("zone.test", "primary", nil); err != nil {
		f.Fatal(err)
	}
	if _, err := e.CreateRecord("zone.test", zone.RecordInput{Name: s("*"), Type: s("A"), Data: json.RawMessage(`{"address":"192.0.2.1"}`)}); err != nil {
		f.Fatal(err)
	}
	sc := NewScratch()
	f.Fuzz(func(t *testing.T, pkt []byte) {
		for _, proto := range []Proto{UDP, TCP} {
			out, v := e.Fast(pkt, lan, proto, sc)
			if v == Slow || v == SlowUnchecked {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				out = e.Slow(ctx, pkt, lan, proto, v == Slow)
				cancel()
			}
			if out == nil {
				continue
			}
			if proto == UDP && len(out) > 1232 {
				t.Fatalf("UDP response %d bytes exceeds limit", len(out))
			}
			if len(pkt) >= 2 && (out[0] != pkt[0] || out[1] != pkt[1]) {
				t.Fatal("response ID differs from query")
			}
			if out[2]&0x80 == 0 {
				t.Fatal("response without QR")
			}
		}
	})
}
