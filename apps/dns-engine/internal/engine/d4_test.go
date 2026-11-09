package engine

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/iterative"
	"mrk/dns-engine/internal/resolver"
	"mrk/dns-engine/internal/store"
	"mrk/dns-engine/internal/testutil"
)

// simNet is an in-memory Internet of authoritative servers.
type simNet struct {
	mu      sync.Mutex
	servers map[netip.Addr]*testutil.Zone
	dead    map[netip.Addr]bool
	queries atomic.Int64
}

func (n *simNet) Exchange(ctx context.Context, ap netip.AddrPort, m *dns.Msg, tcp bool) (*dns.Msg, error) {
	n.queries.Add(1)
	n.mu.Lock()
	z, dead := n.servers[ap.Addr()], n.dead[ap.Addr()]
	n.mu.Unlock()
	if z == nil || dead {
		<-ctx.Done()
		return nil, iterative.ErrTimeout
	}
	do := m.IsEdns0() != nil && m.IsEdns0().Do()
	r := z.Answer(m.Question[0], do).Copy()
	r.Id, r.Response = m.Id, true
	r.Question = []dns.Question{m.Question[0]}
	return r, nil
}

type d4world struct {
	net  *simNet
	root *testutil.Zone
	h    *testutil.Hierarchy
}

// newD4World: . (192.0.2.1) -> com (192.0.2.2) -> example.com (192.0.2.3,
// signed), bad.com (192.0.2.4, forged answers), plain.com (192.0.2.5, unsigned).
func newD4World() *d4world {
	root := testutil.NewZone(".", false)
	com := testutil.NewZone("com.", false)
	root.Delegate(com, "ns.com.", "192.0.2.2")
	root.Add("ns.com. 3600 IN A 192.0.2.2", ". 3600 IN NS a.root.test.", "a.root.test. 3600 IN A 192.0.2.1")
	mk := func(origin, ip string, unsigned bool) *testutil.Zone {
		z := testutil.NewZone(origin, unsigned)
		z.Add(origin+" 3600 IN NS ns1."+origin, "ns1."+origin+" 3600 IN A "+ip)
		com.Delegate(z, "ns1."+origin, ip)
		return z
	}
	ex := mk("example.com.", "192.0.2.3", false)
	ex.Add("www.example.com. 300 IN A 203.0.113.10", "*.wild.example.com. 300 IN A 203.0.113.11")
	bad := mk("bad.com.", "192.0.2.4", false)
	bad.Add("www.bad.com. 300 IN A 203.0.113.20")
	bad.Tamper = func(q dns.Question, m *dns.Msg) {
		for _, rr := range m.Answer {
			if a, ok := rr.(*dns.A); ok {
				a.A = []byte{198, 51, 100, 99}
			}
		}
	}
	plain := mk("plain.com.", "192.0.2.5", true)
	plain.Add("www.plain.com. 300 IN A 203.0.113.30")
	n := &simNet{servers: map[netip.Addr]*testutil.Zone{
		netip.MustParseAddr("192.0.2.1"): root, netip.MustParseAddr("192.0.2.2"): com,
		netip.MustParseAddr("192.0.2.3"): ex, netip.MustParseAddr("192.0.2.4"): bad, netip.MustParseAddr("192.0.2.5"): plain,
	}, dead: map[netip.Addr]bool{}}
	return &d4world{net: n, root: root, h: &testutil.Hierarchy{Zones: []*testutil.Zone{root, com, ex, bad, plain}}}
}

func (w *d4world) engine(t *testing.T, upstream string, mut func(s *config.Settings)) *Engine {
	t.Helper()
	e, err := Open(Options{DataDir: t.TempDir(), DefaultListen: "127.0.0.1:5399", IterTransport: w.net,
		TrustAnchors: []*dns.DS{w.root.DS()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	s, v := e.Settings()
	s.Upstreams = nil
	if upstream != "" {
		s.Upstreams = []config.Upstream{{ID: "test", Address: upstream, Enabled: true}}
	}
	s.Pressure.Enabled = false
	s.Limits.ClientQPS, s.Limits.ClientBurst = 0, 0
	s.Resolution.Mode = config.ModeRecursive
	s.Resolution.RootHints = []config.RootHint{{Name: "a.root.test", IPv4: "192.0.2.1"}}
	s.Resolution.QueryTimeoutMS = 300
	if mut != nil {
		mut(&s)
	}
	if _, _, err := e.PutSettings(s, v); err != nil {
		t.Fatal(err)
	}
	return e
}

func withDO(m *dns.Msg) {
	if o := m.IsEdns0(); o != nil {
		o.SetDo()
		return
	}
	m.SetEdns0(1232, true)
}
func withCD(m *dns.Msg) { m.CheckingDisabled = true }
func withAD(m *dns.Msg) { m.AuthenticatedData = true }

func hasType(rrs []dns.RR, t uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}

func edeCode(m *dns.Msg) int {
	if o := m.IsEdns0(); o != nil {
		for _, x := range o.Option {
			if e, ok := x.(*dns.EDNS0_EDE); ok {
				return int(e.InfoCode)
			}
		}
	}
	return -1
}

func TestRecursiveSecureAnswer(t *testing.T) {
	w := newD4World()
	e := w.engine(t, "", nil)
	r := ask(t, e, lan, UDP, query("www.example.com.", dns.TypeA, withDO))
	if r.Rcode != dns.RcodeSuccess || !r.AuthenticatedData || !hasType(r.Answer, dns.TypeRRSIG) || !hasType(r.Answer, dns.TypeA) {
		t.Fatalf("secure answer with DO: %v", r)
	}
	// from cache (fast path): same flags, RRSIG only for DO clients
	r = ask(t, e, lan, UDP, query("www.example.com.", dns.TypeA, withDO))
	if !r.AuthenticatedData || !hasType(r.Answer, dns.TypeRRSIG) {
		t.Fatalf("cached secure answer with DO: %v", r)
	}
	r = ask(t, e, lan, UDP, query("www.example.com.", dns.TypeA))
	if r.AuthenticatedData || hasType(r.Answer, dns.TypeRRSIG) || !hasType(r.Answer, dns.TypeA) {
		t.Fatalf("DO=0 client: %v", r)
	}
	r = ask(t, e, lan, UDP, query("www.example.com.", dns.TypeA, withAD))
	if !r.AuthenticatedData || hasType(r.Answer, dns.TypeRRSIG) {
		t.Fatalf("AD=1 client: %v", r)
	}
	// negative and wildcard answers are validated too
	r = ask(t, e, lan, UDP, query("nope.example.com.", dns.TypeA, withDO))
	if r.Rcode != dns.RcodeNameError || !r.AuthenticatedData || !hasType(r.Ns, dns.TypeNSEC) {
		t.Fatalf("secure NXDOMAIN: %v", r)
	}
	r = ask(t, e, lan, UDP, query("x.wild.example.com.", dns.TypeA, withDO))
	if !r.AuthenticatedData || !hasType(r.Ns, dns.TypeNSEC) {
		t.Fatalf("secure wildcard: %v", r)
	}
	// unsigned zone: insecure, no AD, served
	r = ask(t, e, lan, UDP, query("www.plain.com.", dns.TypeA, withDO))
	if r.Rcode != dns.RcodeSuccess || r.AuthenticatedData || len(r.Answer) != 1 {
		t.Fatalf("insecure answer: %v", r)
	}
	items := logSearch(t, e, "name=www.example.com")
	if len(items) == 0 || items[len(items)-1].Source != "recursive" || items[len(items)-1].DNSSEC != "secure" {
		t.Fatalf("query log %+v", items)
	}
	if got := logSearch(t, e, "dnssec=insecure&source=recursive"); len(got) != 1 || got[0].Name != "www.plain.com" {
		t.Fatalf("dnssec filter %+v", got)
	}
	st := e.Status(nil)
	if st.Resolution.Mode != "recursive" || st.DNSSEC.Counters.Secure == 0 || len(st.DNSSEC.TrustAnchors) != 1 {
		t.Fatalf("status %+v %+v", st.Resolution, st.DNSSEC)
	}
}

func TestRecursiveBogus(t *testing.T) {
	w := newD4World()
	e := w.engine(t, "", nil)
	for i := 0; i < 2; i++ { // miss, then the cached bogus entry
		r := ask(t, e, lan, UDP, query("www.bad.com.", dns.TypeA, withDO))
		if r.Rcode != dns.RcodeServerFailure || len(r.Answer) != 0 || edeCode(r) != int(dns.ExtendedErrorCodeDNSBogus) {
			t.Fatalf("bogus #%d: %v", i, r)
		}
	}
	r := ask(t, e, lan, UDP, query("www.bad.com.", dns.TypeA, withDO, withCD))
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 || r.AuthenticatedData {
		t.Fatalf("CD=1 must return the raw data: %v", r)
	}
	if got := logSearch(t, e, "dnssec=bogus"); len(got) < 2 {
		t.Fatalf("bogus not logged: %+v", got)
	}
	res, err := e.ResolveWith(context.Background(), ResolveRequest{Name: "www.bad.com", Type: "A"})
	if err != nil || res.Rcode != "SERVFAIL" || res.DNSSEC.Status != "bogus" || len(res.EDE) == 0 || res.EDE[0].Code != 6 {
		t.Fatalf("resolve view %+v %v", res, err)
	}
	// log_only: delivered like insecure
	lo := w.engine(t, "", func(s *config.Settings) { s.DNSSEC.Mode = config.DNSSECLogOnly })
	r = ask(t, lo, lan, UDP, query("www.bad.com.", dns.TypeA, withDO))
	if r.Rcode != dns.RcodeSuccess || r.AuthenticatedData || len(r.Answer) == 0 {
		t.Fatalf("log_only: %v", r)
	}
	// negative trust anchor
	nta := w.engine(t, "", func(s *config.Settings) {
		s.DNSSEC.NegativeTrustAnchors = []config.NTA{{Domain: "bad.com", Reason: "broken"}}
	})
	r = ask(t, nta, lan, UDP, query("www.bad.com.", dns.TypeA, withDO))
	if r.Rcode != dns.RcodeSuccess || r.AuthenticatedData {
		t.Fatalf("NTA: %v", r)
	}
}

func TestResolveTraceAndUnreachable(t *testing.T) {
	w := newD4World()
	e := w.engine(t, "", nil)
	res, err := e.ResolveWith(context.Background(), ResolveRequest{Name: "www.example.com", Type: "A", Trace: true})
	if err != nil || res.Rcode != "NOERROR" || res.Source != "recursive" || res.DNSSEC.Status != "secure" {
		t.Fatalf("%+v %v", res, err)
	}
	zones := map[string]bool{}
	for _, s := range res.Trace {
		zones[s.Zone] = true
	}
	if !zones["."] || !zones["com"] || !zones["example.com"] {
		t.Fatalf("trace does not walk root -> TLD -> domain: %+v", res.Trace)
	}
	// a second trace still walks from the root (no cache)
	before := w.net.queries.Load()
	if _, err := e.ResolveWith(context.Background(), ResolveRequest{Name: "www.example.com", Type: "A", Trace: true}); err != nil {
		t.Fatal(err)
	}
	if w.net.queries.Load()-before < 3 {
		t.Fatal("trace was answered from cache")
	}
	w.net.mu.Lock()
	w.net.dead[netip.MustParseAddr("192.0.2.5")] = true
	w.net.mu.Unlock()
	r := ask(t, e, lan, UDP, query("www.plain.com.", dns.TypeA, withDO))
	if r.Rcode != dns.RcodeServerFailure || edeCode(r) != int(dns.ExtendedErrorCodeNoReachableAuthority) {
		t.Fatalf("unreachable authority: %v", r)
	}
}

func TestForwardModeValidation(t *testing.T) {
	w := newD4World()
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return w.h.Resolve(q, true) })
	e := w.engine(t, up.Addr, func(s *config.Settings) { s.Resolution.Mode = config.ModeForward })
	r := ask(t, e, lan, UDP, query("www.example.com.", dns.TypeA, withDO))
	if r.Rcode != dns.RcodeSuccess || !r.AuthenticatedData {
		t.Fatalf("forward secure: %v", r)
	}
	r = ask(t, e, lan, UDP, query("www.bad.com.", dns.TypeA))
	if r.Rcode != dns.RcodeServerFailure || edeCode(r) != int(dns.ExtendedErrorCodeDNSBogus) {
		t.Fatalf("forward bogus: %v", r)
	}
	if w.net.queries.Load() != 0 {
		t.Fatal("forward mode used the root path")
	}
}

func TestForwardThenRecursive(t *testing.T) {
	w := newD4World()
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg {
		m := new(dns.Msg)
		m.Rcode = dns.RcodeServerFailure
		return m
	})
	e := w.engine(t, up.Addr, func(s *config.Settings) { s.Resolution.Mode = config.ModeForwardThenRecursive })
	res, err := e.Resolve(context.Background(), "www.example.com", "A", "")
	if err != nil || res.Rcode != "NOERROR" || res.Source != "recursive" || len(res.Answers) == 0 {
		t.Fatalf("fallback to the root: %+v %v", res, err)
	}
	// a valid NXDOMAIN from the forwarder is final
	up2 := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return w.h.Resolve(q, true) })
	e2 := w.engine(t, up2.Addr, func(s *config.Settings) { s.Resolution.Mode = config.ModeForwardThenRecursive })
	before := w.net.queries.Load()
	res, _ = e2.Resolve(context.Background(), "nope.example.com", "A", "")
	if res.Rcode != "NXDOMAIN" || res.Source != "upstream" || w.net.queries.Load() != before {
		t.Fatalf("NXDOMAIN must not fall back: %+v", res)
	}
}

func TestAutoInsecureLocal(t *testing.T) {
	w := newD4World()
	corp := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 60, "10.1.2.3") })
	e := w.engine(t, "", nil)
	if _, err := e.CreateZone("corp.lan", "forwarder", []string{corp.Addr}); err != nil {
		t.Fatal(err)
	}
	r := ask(t, e, lan, UDP, query("intranet.corp.lan.", dns.TypeA, withDO))
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.AuthenticatedData {
		t.Fatalf("forwarder zone must be insecure-but-allowed: %v", r)
	}
	res, _ := e.ResolveWith(context.Background(), ResolveRequest{Name: "intranet.corp.lan", Type: "A"})
	if res.DNSSEC.Status != "insecure" || res.DNSSEC.Reason != "local_zone" {
		t.Fatalf("resolve view %+v", res.DNSSEC)
	}
	// without auto_insecure_local the zone is validated through its forwarder,
	// which carries no DNSSEC: the trust anchor cannot be applied
	s, v := e.Settings()
	s.DNSSEC.AutoInsecureLocal = false
	if _, _, err := e.PutSettings(s, v); err != nil {
		t.Fatal(err)
	}
	res, _ = e.ResolveWith(context.Background(), ResolveRequest{Name: "intranet.corp.lan", Type: "A"})
	if res.DNSSEC.Status != "indeterminate" || res.Rcode != "NOERROR" {
		t.Fatalf("validated forwarder zone: %+v", res)
	}
}

func TestPrimingAtStart(t *testing.T) {
	w := newD4World()
	e := w.engine(t, "", nil)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ps := e.Status(nil).Resolution.RootPriming; ps.At != nil {
			if !ps.OK || ps.ServersReachable != 1 {
				t.Fatalf("priming %+v", ps)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no priming after switching to recursive mode")
}

func TestD4SettingsDefaultsAndValidation(t *testing.T) {
	dir := t.TempDir()
	// a D2-era settings file without the resolution/dnssec sections
	old := config.Defaults("127.0.0.1:5399")
	raw, _ := json.Marshal(old)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	delete(m, "resolution")
	delete(m, "dnssec")
	doc := map[string]any{"schema": store.Schema, "config_version": 7, "settings": m}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := Open(Options{DataDir: dir, DefaultListen: "127.0.0.1:5399"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s, v := e.Settings()
	if v != 7 || s.Resolution.Mode != config.ModeForward || s.DNSSEC.Mode != config.DNSSECValidate ||
		s.Resolution.MaxReferrals != 30 || s.DNSSEC.NegativeTrustAnchors == nil || s.Resolution.RootHints == nil {
		t.Fatalf("defaults not filled: %+v %+v", s.Resolution, s.DNSSEC)
	}
	bad := s.Clone()
	bad.Resolution.Mode = "magic"
	bad.Resolution.MaxReferrals = 0
	bad.Resolution.RootHints = []config.RootHint{{Name: "x.root.", IPv4: "2001:db8::1"}}
	bad.DNSSEC.NSEC3MaxIterations = 9999
	bad.DNSSEC.NegativeTrustAnchors = []config.NTA{{Domain: "bad..name"}, {Domain: "ok.example", ExpiresAt: "tomorrow"}}
	_, _, err = e.PutSettings(bad, v)
	want := []string{"resolution.mode", "resolution.max_referrals", "resolution.root_hints[0].ipv4",
		"dnssec.nsec3_max_iterations", "dnssec.negative_trust_anchors[0].domain", "dnssec.negative_trust_anchors[1].expires_at"}
	msg := ""
	if err != nil {
		b, _ := json.Marshal(err)
		msg = string(b)
	}
	for _, f := range want {
		if !strings.Contains(msg, `"`+f+`"`) {
			t.Errorf("missing field error %s in %s", f, msg)
		}
	}
	good := s.Clone()
	good.DNSSEC.NegativeTrustAnchors = []config.NTA{{Domain: "Broken.Example.", ExpiresAt: "2030-01-02T03:04:05+03:30"}}
	out, _, err := e.PutSettings(good, v)
	if err != nil {
		t.Fatal(err)
	}
	if n := out.DNSSEC.NegativeTrustAnchors[0]; n.Domain != "broken.example" || n.ExpiresAt != "2030-01-01T23:34:05Z" {
		t.Fatalf("normalised NTA %+v", n)
	}
	if dv := e.DNSSEC(); dv.Mode != "validate" || len(dv.NegativeTrustAnchors) != 1 || len(dv.TrustAnchors) != 2 {
		t.Fatalf("dnssec view %+v", dv)
	}
}

func TestTrustAnchorRefreshAndBogusSpike(t *testing.T) {
	w := newD4World()
	e := w.engine(t, "", nil)
	v := e.RefreshTrustAnchors()
	if v.Error != "" || v.UpdatedAt == nil || len(v.TrustAnchors) != 1 || v.TrustAnchors[0].State != "valid" {
		t.Fatalf("refresh %+v", v)
	}
	// a second KSK appears: pending (RFC 5011 hold-down), and an event is raised
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	if _, err := k.Generate(256); err != nil {
		t.Fatal(err)
	}
	w.root.AddRR(k)
	v = e.RefreshTrustAnchors()
	states := map[string]int{}
	for _, a := range v.TrustAnchors {
		states[a.State]++
	}
	if states["valid"] != 1 || states["pending"] != 1 {
		t.Fatalf("after a new KSK: %+v", v.TrustAnchors)
	}
	evs, _ := e.Events(0, 100)
	found := false
	for _, ev := range evs {
		if ev.Type == "dnssec.trust_anchor_updated" {
			found = true
		}
	}
	if !found {
		t.Fatal("no trust anchor event")
	}
	if fi, err := os.Stat(filepath.Join(e.opts.DataDir, "trust-anchors.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("trust-anchors.json %v %v", fi, err)
	}
	for i := 0; i < 120; i++ {
		e.observeSpike("x"+string(rune('a'+i%20))+".bad.com.", 3 /* bogus */)
	}
	evs, _ = e.Events(0, 100)
	for _, ev := range evs {
		if ev.Type == "dnssec.bogus_spike" {
			if names := ev.Data["names"].([]string); len(names) != 10 {
				t.Fatalf("spike names %v", names)
			}
			return
		}
	}
	t.Fatal("no bogus spike event")
}

func TestDNSSECQueryHasOneOPT(t *testing.T) {
	q := resolver.NewQuery("example.com.", dns.TypeA)
	dnssecQuery(q)
	n := 0
	for _, rr := range q.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			n++
		}
	}
	if n != 1 || !q.IsEdns0().Do() || !q.CheckingDisabled {
		t.Fatalf("OPT records %d, DO %v", n, q.IsEdns0().Do())
	}
}
