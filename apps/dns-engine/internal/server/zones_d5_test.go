package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/dnssec"
	"mrk/dns-engine/internal/engine"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/signer"
	"mrk/dns-engine/internal/testutil"
	"mrk/dns-engine/internal/xfr"
	"mrk/dns-engine/internal/zone"
)

// docs/41 §7.1: two engines talking to each other (primary ↔ secondary),
// TSIG, NOTIFY, dynamic update and DNSSEC signing checked with the D4
// validator.

type zh struct {
	e    *engine.Engine
	srv  *Server
	addr string
	stop sync.Once
}

func (h *zh) shutdown() {
	h.stop.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		h.srv.Shutdown(ctx)
		cancel()
	})
}

func startZones(t *testing.T) *zh {
	t.Helper()
	addr := freePort(t)
	e, err := engine.Open(engine.Options{DataDir: t.TempDir(), DefaultListen: addr})
	if err != nil {
		t.Fatal(err)
	}
	st, v := e.Settings()
	st.Upstreams = nil
	st.Limits.ClientQPS, st.Limits.ClientBurst = 0, 0
	st.DNSSEC.Mode = config.DNSSECOff
	st.Pressure.Enabled = false
	if _, _, err := e.PutSettings(st, v); err != nil {
		t.Fatal(err)
	}
	srv := New(e, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetListenerHook(srv.Apply)
	st, _ = e.Settings()
	srv.Apply(st)
	h := &zh{e: e, srv: srv, addr: addr}
	t.Cleanup(func() {
		h.shutdown()
		e.Close()
	})
	return h
}

func sp(s string) *string { return &s }
func bp(b bool) *bool     { return &b }
func ssp(s ...string) *[]string {
	if s == nil {
		s = []string{}
	}
	return &s
}

func addA(t *testing.T, e *engine.Engine, zn, name, ip string) zone.Record {
	t.Helper()
	r, err := e.CreateRecord(zn, zone.RecordInput{Name: sp(name), Type: sp("A"), Data: json.RawMessage(`{"address":"` + ip + `"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ask(t *testing.T, netw, addr, name string, qt uint16, do bool) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: netw, Timeout: 2 * time.Second, UDPSize: 4096}
	m := new(dns.Msg)
	m.SetQuestion(name, qt)
	m.RecursionDesired = false
	m.SetEdns0(4096, do)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s %s: %v", netw, name, err)
	}
	return r
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func hasA(r *dns.Msg, ip string) bool {
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == ip {
			return true
		}
	}
	return false
}

func code(err error) string {
	if fe, ok := err.(*fielderr.Error); ok {
		return fe.Code
	}
	return ""
}

const secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA=="

func TestSecondaryTransferNotify(t *testing.T) {
	p, s := startZones(t), startZones(t)
	clock := &fakeClock{t: time.Now()}
	s.e.SetZoneTiming(engine.ZoneTiming{Now: clock.Now, Tick: 20 * time.Millisecond, MinRefresh: time.Hour})
	p.e.SetZoneTiming(engine.ZoneTiming{Tick: 20 * time.Millisecond, NotifyRetry: 50 * time.Millisecond})
	for _, h := range []*zh{p, s} {
		if _, err := h.e.CreateTSIG(engine.TSIGInput{Name: "xfr.key", Secret: secret}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.e.CreateZone("example.test", "primary", nil); err != nil {
		t.Fatal(err)
	}
	addA(t, p.e, "example.test", "www", "192.0.2.1")
	old := addA(t, p.e, "example.test", "old", "192.0.2.9")
	_, err := p.e.PatchZone("example.test", engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{
		Transfer: &engine.TransferInput{Allow: ssp("127.0.0.0/8"), TSIGKey: sp("xfr.key")},
		Notify:   &engine.NotifyInput{Targets: ssp(s.addr), Enabled: bp(true)}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.e.CreateSecondary("example.test", engine.ZoneCreateD5{Primaries: []string{p.addr}, TSIGKey: "xfr.key"}); err != nil {
		t.Fatal(err)
	}
	// initial AXFR
	eventually(t, "AXFR", func() bool { return hasA(ask(t, "udp", s.addr, "www.example.test.", dns.TypeA, false), "192.0.2.1") })
	r := ask(t, "udp", s.addr, "www.example.test.", dns.TypeA, false)
	if !r.Authoritative {
		t.Fatal("secondary answer is not authoritative")
	}
	d, _ := s.e.Zone("example.test")
	pd, _ := p.e.Zone("example.test")
	if d.Secondary == nil || d.Secondary.Serial != pd.Serial || d.Secondary.LastTransfer != "axfr" || !d.Secondary.Loaded {
		t.Fatalf("secondary status %+v (primary serial %d)", d.Secondary, pd.Serial)
	}
	// change on the primary → NOTIFY → IXFR (addition and deletion)
	addA(t, p.e, "example.test", "api", "192.0.2.2")
	if err := p.e.DeleteRecord("example.test", old.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "IXFR after NOTIFY", func() bool {
		return hasA(ask(t, "udp", s.addr, "api.example.test.", dns.TypeA, false), "192.0.2.2") &&
			ask(t, "udp", s.addr, "old.example.test.", dns.TypeA, false).Rcode == dns.RcodeNameError
	})
	pd, _ = p.e.Zone("example.test")
	eventually(t, "same serial", func() bool { d, _ = s.e.Zone("example.test"); return d.Secondary.Serial == pd.Serial })
	if d.Secondary.LastTransfer != "ixfr" {
		t.Fatalf("expected IXFR, got %+v", d.Secondary)
	}
	// secondary records are read-only
	_, err = s.e.CreateRecord("example.test", zone.RecordInput{Name: sp("x"), Type: sp("A"), Data: json.RawMessage(`{"address":"192.0.2.3"}`)})
	if code(err) != engine.CodeZoneReadOnly {
		t.Fatalf("record on secondary: %v", err)
	}
	if recs, err := s.e.Records("example.test"); err != nil || len(recs) < 3 || recs[0].Type != "SOA" {
		t.Fatalf("secondary records %v %v", recs, err)
	}
	// manual refresh: up to date
	st, err := s.e.RefreshZone(context.Background(), "example.test")
	if err != nil || st.Error != "" || st.Serial != d.Secondary.Serial {
		t.Fatalf("refresh %+v %v", st, err)
	}
	// primary gone: refresh fails, data kept until expire, then SERVFAIL
	p.shutdown()
	st, _ = s.e.RefreshZone(context.Background(), "example.test")
	if st.Error == "" {
		t.Fatal("refresh against a stopped primary succeeded")
	}
	if r := ask(t, "udp", s.addr, "www.example.test.", dns.TypeA, false); !hasA(r, "192.0.2.1") {
		t.Fatal("data dropped before expire")
	}
	clock.Add(8 * 24 * time.Hour) // SOA expire is 7 days
	eventually(t, "SERVFAIL after expire", func() bool {
		return ask(t, "udp", s.addr, "www.example.test.", dns.TypeA, false).Rcode == dns.RcodeServerFailure
	})
	d, _ = s.e.Zone("example.test")
	if !d.Secondary.Expired {
		t.Fatalf("status %+v", d.Secondary)
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func axfr(addr, zn, key, sec string) ([]dns.RR, int, error) {
	m := new(dns.Msg)
	m.SetAxfr(zn)
	tr := &dns.Transfer{}
	if key != "" {
		m.SetTsig(key, dns.HmacSHA256, 300, time.Now().Unix())
		tr.TsigSecret = map[string]string{key: sec}
	}
	ch, err := tr.In(m, addr)
	if err != nil {
		return nil, 0, err
	}
	var out []dns.RR
	for env := range ch {
		if env.Error != nil {
			return out, 0, env.Error
		}
		out = append(out, env.RR...)
	}
	return out, 0, nil
}

func rawQuery(t *testing.T, netw, addr string, m *dns.Msg, secrets map[string]string) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: netw, Timeout: 2 * time.Second, TsigSecret: secrets}
	r, _, err := c.Exchange(m, addr)
	if err != nil && r == nil {
		t.Fatalf("exchange: %v", err)
	}
	return r
}

func TestTransferACLAndTSIG(t *testing.T) {
	p := startZones(t)
	if _, err := p.e.CreateTSIG(engine.TSIGInput{Name: "xfr.key", Secret: secret}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.e.CreateZone("example.test", "primary", nil); err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	for i := 0; i < 600; i++ { // several messages
		text.WriteString("host-" + itoa(i) + " 300 IN A 192.0.2.1\n")
	}
	if _, err := p.e.Import("example.test", text.String(), false); err != nil {
		t.Fatal(err)
	}
	// closed by default
	if _, _, err := axfr(p.addr, "example.test.", "", ""); err == nil {
		t.Fatal("transfer allowed while closed")
	}
	_, err := p.e.PatchZone("example.test", engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{
		Transfer: &engine.TransferInput{Allow: ssp("127.0.0.0/8"), TSIGKey: sp("xfr.key")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := axfr(p.addr, "example.test.", "", ""); err == nil {
		t.Fatal("unsigned transfer accepted with tsig_key set")
	}
	if _, _, err := axfr(p.addr, "example.test.", "xfr.key.", "d3Jvbmctd3Jvbmctd3Jvbmctd3Jvbmc="); err == nil {
		t.Fatal("transfer with a wrong secret accepted")
	}
	rrs, _, err := axfr(p.addr, "example.test.", "xfr.key.", secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 600+1+2 { // records + NS + SOA twice
		t.Fatalf("AXFR returned %d RRs", len(rrs))
	}
	// TSIG on a plain query to an unknown key: NOTAUTH/BADKEY
	m := new(dns.Msg)
	m.SetIxfr("example.test.", 1, "ns1.example.test.", "hostmaster.example.test.")
	m.SetTsig("nope.key.", dns.HmacSHA256, 300, time.Now().Unix())
	r := rawQuery(t, "udp", p.addr, m, map[string]string{"nope.key.": secret})
	if r.Rcode != dns.RcodeNotAuth {
		t.Fatalf("unknown key: %s", dns.RcodeToString[r.Rcode])
	}
	// UDP IXFR with the right key: SOA only
	m = new(dns.Msg)
	m.SetIxfr("example.test.", 1, "ns1.example.test.", "hostmaster.example.test.")
	m.SetTsig("xfr.key.", dns.HmacSHA256, 300, time.Now().Unix())
	r = rawQuery(t, "udp", p.addr, m, map[string]string{"xfr.key.": secret})
	if r.Rcode != 0 || len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("udp ixfr %v", r)
	}
	// address not allowed
	_, err = p.e.PatchZone("example.test", engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{
		Transfer: &engine.TransferInput{Allow: ssp("10.0.0.0/8")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := axfr(p.addr, "example.test.", "xfr.key.", secret); err == nil {
		t.Fatal("transfer from a disallowed address accepted")
	}
	// the key is in use and cannot be deleted
	if err := p.e.DeleteTSIG("xfr.key"); code(err) != engine.CodeTSIGInUse {
		t.Fatalf("delete in-use key: %v", err)
	}
}

func itoa(i int) string {
	const d = "0123456789"
	if i < 10 {
		return d[i : i+1]
	}
	return itoa(i/10) + d[i%10:i%10+1]
}

func TestNotifyRules(t *testing.T) {
	s := startZones(t)
	s.e.SetZoneTiming(engine.ZoneTiming{Tick: time.Hour})
	if _, err := s.e.CreateTSIG(engine.TSIGInput{Name: "xfr.key", Secret: secret}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.e.CreateSecondary("example.test", engine.ZoneCreateD5{Primaries: []string{"192.0.2.53"}, TSIGKey: "xfr.key"}); err != nil {
		t.Fatal(err)
	}
	notify := func(zn, key, sec string) *dns.Msg {
		m := new(dns.Msg)
		m.SetNotify(zn)
		secrets := map[string]string(nil)
		if key != "" {
			m.SetTsig(key, dns.HmacSHA256, 300, time.Now().Unix())
			secrets = map[string]string{key: sec}
		}
		return rawQuery(t, "udp", s.addr, m, secrets)
	}
	if r := notify("example.test.", "", ""); r.Rcode != dns.RcodeRefused {
		t.Fatalf("unsigned notify from a non-primary: %s", dns.RcodeToString[r.Rcode])
	}
	if r := notify("other.test.", "", ""); r.Rcode != dns.RcodeNotAuth {
		t.Fatalf("notify for unknown zone: %s", dns.RcodeToString[r.Rcode])
	}
	if r := notify("example.test.", "xfr.key.", "d3Jvbmctd3Jvbmctd3Jvbmctd3Jvbmc="); r.Rcode != dns.RcodeNotAuth {
		t.Fatalf("bad signature: %s", dns.RcodeToString[r.Rcode])
	}
	// signed but 127.0.0.1 is neither a primary nor in notify_allow
	if r := notify("example.test.", "xfr.key.", secret); r.Rcode != dns.RcodeRefused {
		t.Fatalf("signed notify from outside: %s", dns.RcodeToString[r.Rcode])
	}
	_, err := s.e.PatchZone("example.test", engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{NotifyAllow: ssp("127.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	if r := notify("example.test.", "xfr.key.", secret); r.Rcode != dns.RcodeSuccess || !r.Authoritative {
		t.Fatalf("allowed notify: %v", r)
	}
}

func update(zn string, f func(m *dns.Msg)) *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate(zn)
	f(m)
	return m
}

func mustRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

func TestDynamicUpdate(t *testing.T) {
	p := startZones(t)
	if _, err := p.e.CreateTSIG(engine.TSIGInput{Name: "upd.key", Secret: secret}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.e.CreateZone("example.test", "primary", nil); err != nil {
		t.Fatal(err)
	}
	addA(t, p.e, "example.test", "www", "192.0.2.1")
	keys := map[string]string{"upd.key.": secret}
	signed := func(m *dns.Msg) *dns.Msg {
		m.SetTsig("upd.key.", dns.HmacSHA256, 300, time.Now().Unix())
		return m
	}
	add := update("example.test.", func(m *dns.Msg) { m.Insert([]dns.RR{mustRR("dyn.example.test. 300 IN A 192.0.2.7")}) })
	// disabled by default
	if r := rawQuery(t, "udp", p.addr, signed(add.Copy()), keys); r.Rcode != dns.RcodeRefused {
		t.Fatalf("update while disabled: %s", dns.RcodeToString[r.Rcode])
	}
	_, err := p.e.PatchZone("example.test", engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{
		Update: &engine.UpdateInput{Enabled: bp(true), Allow: ssp("127.0.0.0/8"), TSIGKey: sp("upd.key")}}})
	if err != nil {
		t.Fatal(err)
	}
	if r := rawQuery(t, "udp", p.addr, add.Copy(), nil); r.Rcode != dns.RcodeRefused {
		t.Fatalf("unsigned update with require_tsig: %s", dns.RcodeToString[r.Rcode])
	}
	before, _ := p.e.Zone("example.test")
	r := rawQuery(t, "udp", p.addr, signed(add.Copy()), keys)
	if r.Rcode != dns.RcodeSuccess || r.IsTsig() == nil {
		t.Fatalf("signed update: %v", r)
	}
	if !hasA(ask(t, "udp", p.addr, "dyn.example.test.", dns.TypeA, false), "192.0.2.7") {
		t.Fatal("update not served")
	}
	after, _ := p.e.Zone("example.test")
	if !xfr.SerialLess(before.Serial, after.Serial) {
		t.Fatalf("serial %d -> %d", before.Serial, after.Serial)
	}
	h, _ := p.e.History("example.test")
	if h[0].Actor != "update:upd.key" || h[0].Reason != "update" {
		t.Fatalf("history %+v", h[0])
	}
	// prerequisites
	nx := update("example.test.", func(m *dns.Msg) {
		m.NameNotUsed([]dns.RR{mustRR("www.example.test. 0 IN A 0.0.0.0")})
		m.Insert([]dns.RR{mustRR("x.example.test. 300 IN A 192.0.2.8")})
	})
	if r := rawQuery(t, "udp", p.addr, signed(nx), keys); r.Rcode != dns.RcodeYXDomain {
		t.Fatalf("name-not-in-use prerequisite: %s", dns.RcodeToString[r.Rcode])
	}
	rr := update("example.test.", func(m *dns.Msg) {
		m.Used([]dns.RR{mustRR("www.example.test. 0 IN A 192.0.2.99")}) // value-dependent, wrong value
		m.Insert([]dns.RR{mustRR("x.example.test. 300 IN A 192.0.2.8")})
	})
	if r := rawQuery(t, "tcp", p.addr, signed(rr), keys); r.Rcode != dns.RcodeNXRrset {
		t.Fatalf("value prerequisite: %s", dns.RcodeToString[r.Rcode])
	}
	ok := update("example.test.", func(m *dns.Msg) {
		m.RRsetUsed([]dns.RR{mustRR("www.example.test. 0 IN A 0.0.0.0")})
		m.RemoveRRset([]dns.RR{mustRR("dyn.example.test. 0 IN A 0.0.0.0")})
		m.Insert([]dns.RR{mustRR("txt.example.test. 300 IN TXT \"hello\"")})
	})
	if r := rawQuery(t, "tcp", p.addr, signed(ok), keys); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("delete rrset + add: %s", dns.RcodeToString[r.Rcode])
	}
	if ask(t, "udp", p.addr, "dyn.example.test.", dns.TypeA, false).Rcode != dns.RcodeNameError {
		t.Fatal("rrset not deleted")
	}
	if r := ask(t, "udp", p.addr, "txt.example.test.", dns.TypeTXT, false); len(r.Answer) != 1 {
		t.Fatal("txt not added")
	}
	// the last apex NS survives a delete
	ns := update("example.test.", func(m *dns.Msg) { m.Remove([]dns.RR{mustRR("example.test. 0 IN NS ns1.example.test.")}) })
	if r := rawQuery(t, "udp", p.addr, signed(ns), keys); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("ns delete: %s", dns.RcodeToString[r.Rcode])
	}
	if r := ask(t, "udp", p.addr, "example.test.", dns.TypeNS, false); len(r.Answer) != 1 {
		t.Fatal("last apex NS removed")
	}
	// out of zone
	oz := update("example.test.", func(m *dns.Msg) { m.Insert([]dns.RR{mustRR("a.other.test. 300 IN A 192.0.2.1")}) })
	if r := rawQuery(t, "udp", p.addr, signed(oz), keys); r.Rcode != dns.RcodeNotZone {
		t.Fatalf("notzone: %s", dns.RcodeToString[r.Rcode])
	}
	// address-based update without TSIG
	_, err = p.e.PatchZone("example.test", engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{
		Update: &engine.UpdateInput{RequireTSIG: bp(false), TSIGKey: sp("")}}})
	if err != nil {
		t.Fatal(err)
	}
	plain := update("example.test.", func(m *dns.Msg) { m.Insert([]dns.RR{mustRR("ip.example.test. 300 IN A 192.0.2.5")}) })
	if r := rawQuery(t, "udp", p.addr, plain, nil); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("address update: %s", dns.RcodeToString[r.Rcode])
	}
	h, _ = p.e.History("example.test")
	if h[0].Actor != "update:127.0.0.1" {
		t.Fatalf("actor %q", h[0].Actor)
	}
	// open update (no TSIG, no address list) is rejected
	_, err = p.e.PatchZone("example.test", engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{
		Update: &engine.UpdateInput{Allow: ssp()}}})
	if code(err) != engine.CodeZoneInvalid {
		t.Fatalf("open update accepted: %v", err)
	}
}

// ---------------------------------------------------------------- DNSSEC

type dnssecWorld struct {
	root  *testutil.Zone
	addr  string
	zone  string
	tamp  func(m *dns.Msg)
	clock *fakeClock
}

func (w *dnssecWorld) fetch(t *testing.T) dnssec.Fetcher {
	return func(_ context.Context, name string, qt uint16) (*dns.Msg, error) {
		name = strings.ToLower(name)
		if !dns.IsSubDomain(w.zone, name) || qt == dns.TypeDS && name == w.zone {
			return w.root.Answer(dns.Question{Name: name, Qtype: qt, Qclass: dns.ClassINET}, true), nil
		}
		c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
		m := new(dns.Msg)
		m.SetQuestion(name, qt)
		m.SetEdns0(4096, true)
		r, _, err := c.Exchange(m, w.addr)
		if err == nil && w.tamp != nil {
			w.tamp(r)
		}
		return r, err
	}
}

func newDNSSECWorld(t *testing.T, h *zh, zn string, dsTexts []string) *dnssecWorld {
	t.Helper()
	root := testutil.NewZone(".", false)
	root.Add(zn + " 3600 IN NS ns1." + zn)
	for _, s := range dsTexts {
		root.AddRR(mustRR(s))
	}
	return &dnssecWorld{root: root, addr: h.addr, zone: zn}
}

func (w *dnssecWorld) check(t *testing.T, name string, qt uint16, want dnssec.State) {
	t.Helper()
	var now func() time.Time
	if w.clock != nil {
		now = w.clock.Now
	}
	v := dnssec.New(dnssec.OpenAnchorsWith("", []*dns.DS{w.root.DS()}, now), now)
	f := w.fetch(t)
	msg, err := f(context.Background(), name, qt)
	if err != nil {
		t.Fatal(err)
	}
	res := v.Validate(context.Background(), f, name, qt, msg)
	if res.State != want {
		t.Fatalf("%s %s: %v (%s %s), want %v\n%v", name, dns.TypeToString[qt], res.State, res.Reason, res.Detail, want, msg)
	}
}

func signZone(t *testing.T, h *zh, zn string, in engine.SigningInput) engine.ZoneDNSSECView {
	t.Helper()
	if _, err := h.e.CreateZone(zn, "primary", nil); err != nil {
		t.Fatal(err)
	}
	addA(t, h.e, zn, "www", "192.0.2.1")
	addA(t, h.e, zn, "*.wild", "192.0.2.7")
	addA(t, h.e, zn, "deep.ent", "192.0.2.9")
	addA(t, h.e, zn, "ns1.sub", "192.0.2.53")
	if _, err := h.e.CreateRecord(zn, zone.RecordInput{Name: sp("sub"), Type: sp("NS"), Data: json.RawMessage(`{"nameserver":"ns1.sub.` + zn + `"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.e.CreateRecord(zn, zone.RecordInput{Name: sp("alias"), Type: sp("CNAME"), Data: json.RawMessage(`{"target":"www.` + zn + `"}`)}); err != nil {
		t.Fatal(err)
	}
	in.Enabled = bp(true)
	if _, err := h.e.PatchZone(zn, engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{DNSSEC: &in}}); err != nil {
		t.Fatal(err)
	}
	v, err := h.e.ZoneDNSSEC(zn)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func dsTexts(v engine.ZoneDNSSECView) []string {
	var out []string
	for _, d := range v.DS {
		out = append(out, d.Text)
	}
	return out
}

func TestSignedZoneValidates(t *testing.T) {
	for _, denial := range []string{"nsec", "nsec3"} {
		for _, alg := range []string{signer.AlgECDSAP256, signer.AlgED25519} {
			t.Run(denial+"/"+alg, func(t *testing.T) {
				h := startZones(t)
				zn := "signed.test."
				in := engine.SigningInput{Algorithm: sp(alg), Denial: sp(denial)}
				v := signZone(t, h, "signed.test", in)
				if !v.Enabled || len(v.Keys) != 2 || len(v.DS) != 1 || v.NextResign == nil {
					t.Fatalf("dnssec view %+v", v)
				}
				w := newDNSSECWorld(t, h, zn, dsTexts(v))
				for _, c := range []struct {
					name string
					qt   uint16
				}{
					{"www." + zn, dns.TypeA},       // positive
					{"nope." + zn, dns.TypeA},      // NXDOMAIN
					{"www." + zn, dns.TypeAAAA},    // NODATA
					{"ent." + zn, dns.TypeA},       // empty non-terminal
					{"x.wild." + zn, dns.TypeA},    // wildcard expansion
					{"x.wild." + zn, dns.TypeAAAA}, // wildcard NODATA
					{"alias." + zn, dns.TypeA},     // CNAME
					{zn, dns.TypeDNSKEY},
					{zn, dns.TypeSOA},
					{zn, dns.TypeCDS},
					{"sub." + zn, dns.TypeDS}, // insecure delegation: proof of no DS
				} {
					w.check(t, c.name, c.qt, dnssec.Secure)
				}
				// tampering is detected
				w.tamp = func(m *dns.Msg) {
					for _, rr := range m.Answer {
						if a, ok := rr.(*dns.A); ok {
							a.A = []byte{198, 51, 100, 66}
						}
					}
				}
				w.check(t, "www."+zn, dns.TypeA, dnssec.Bogus)
				// the signed zone is transferred with its signatures
				_, err := h.e.PatchZone("signed.test", engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{
					Transfer: &engine.TransferInput{Allow: ssp("127.0.0.1/32")}}})
				if err != nil {
					t.Fatal(err)
				}
				rrs, _, err := axfr(h.addr, zn, "", "")
				if err != nil {
					t.Fatal(err)
				}
				sigs := 0
				for _, rr := range rrs {
					if rr.Header().Rrtype == dns.TypeRRSIG {
						sigs++
					}
				}
				if sigs < 8 {
					t.Fatalf("AXFR of the signed zone has %d RRSIGs", sigs)
				}
			})
		}
	}
}

func TestSignedSecondary(t *testing.T) {
	p, s := startZones(t), startZones(t)
	s.e.SetZoneTiming(engine.ZoneTiming{Tick: 20 * time.Millisecond, MinRefresh: time.Hour})
	v := signZone(t, p, "signed.test", engine.SigningInput{Denial: sp("nsec3")})
	_, err := p.e.PatchZone("signed.test", engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{
		Transfer: &engine.TransferInput{Allow: ssp("127.0.0.0/8")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.e.CreateSecondary("signed.test", engine.ZoneCreateD5{Primaries: []string{p.addr}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "AXFR", func() bool { return hasA(ask(t, "udp", s.addr, "www.signed.test.", dns.TypeA, false), "192.0.2.1") })
	w := newDNSSECWorld(t, s, "signed.test.", dsTexts(v)) // validated against the secondary
	w.check(t, "www.signed.test.", dns.TypeA, dnssec.Secure)
	w.check(t, "nope.signed.test.", dns.TypeA, dnssec.Secure)
	w.check(t, "x.wild.signed.test.", dns.TypeA, dnssec.Secure)
}

func TestResignAndRollover(t *testing.T) {
	h := startZones(t)
	clock := &fakeClock{t: time.Now()}
	h.e.SetZoneTiming(engine.ZoneTiming{Now: clock.Now, Tick: 20 * time.Millisecond,
		Keys: signer.Timing{ZSKPublish: 2 * time.Hour, ZSKRetire: 26 * time.Hour, KSKRetire: 48 * time.Hour}})
	v := signZone(t, h, "signed.test", engine.SigningInput{})
	zn := "signed.test."
	w := newDNSSECWorld(t, h, zn, dsTexts(v))
	w.clock = clock
	w.check(t, "www."+zn, dns.TypeA, dnssec.Secure)
	exp0 := *v.Expiration
	d0, _ := h.e.Zone("signed.test")

	// re-sign before expiry: 14 days validity, refresh 3 days before
	clock.Add(12 * 24 * time.Hour)
	eventually(t, "re-sign", func() bool {
		v, _ := h.e.ZoneDNSSEC("signed.test")
		return v.Expiration != nil && v.Expiration.After(exp0)
	})
	d1, _ := h.e.Zone("signed.test")
	if !xfr.SerialLess(d0.Serial, d1.Serial) {
		t.Fatalf("serial not bumped by re-sign: %d -> %d", d0.Serial, d1.Serial)
	}
	hist, _ := h.e.History("signed.test")
	if hist[0].Reason != "dnssec.resign" || hist[0].Actor != "dnssec" {
		t.Fatalf("history %+v", hist[0])
	}
	w.check(t, "www."+zn, dns.TypeA, dnssec.Secure)

	// ZSK rollover: pre-publish, switch, retire
	v, err := h.e.RolloverDNSSEC("signed.test", "zsk")
	if err != nil {
		t.Fatal(err)
	}
	if states(v, "zsk") != "active,published" {
		t.Fatalf("after rollover: %s", states(v, "zsk"))
	}
	if _, err := h.e.RolloverDNSSEC("signed.test", "zsk"); code(err) != engine.CodeRolloverInProgress {
		t.Fatalf("second rollover: %v", err)
	}
	w.check(t, "www."+zn, dns.TypeA, dnssec.Secure)
	clock.Add(3 * time.Hour)
	eventually(t, "zsk active", func() bool {
		v, _ := h.e.ZoneDNSSEC("signed.test")
		return states(v, "zsk") == "active,retired"
	})
	w.check(t, "www."+zn, dns.TypeA, dnssec.Secure)
	clock.Add(27 * time.Hour)
	eventually(t, "old zsk removed", func() bool {
		v, _ := h.e.ZoneDNSSEC("signed.test")
		return states(v, "zsk") == "active"
	})
	w.check(t, "www."+zn, dns.TypeA, dnssec.Secure)

	// KSK rollover: both DS valid during the double signature
	v, err = h.e.RolloverDNSSEC("signed.test", "ksk")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.DS) != 2 || states(v, "ksk") != "active,retired" {
		t.Fatalf("ksk rollover %+v", v)
	}
	for _, ds := range v.DS {
		w2 := newDNSSECWorld(t, h, zn, []string{ds.Text})
		w2.clock = clock
		w2.check(t, "www."+zn, dns.TypeA, dnssec.Secure)
	}
	clock.Add(49 * time.Hour)
	eventually(t, "old ksk removed", func() bool {
		v, _ := h.e.ZoneDNSSEC("signed.test")
		return len(v.DS) == 1
	})
	v, _ = h.e.ZoneDNSSEC("signed.test")
	w3 := newDNSSECWorld(t, h, zn, dsTexts(v))
	w3.clock = clock
	w3.check(t, "www."+zn, dns.TypeA, dnssec.Secure)

	// disabling stops signing; the keys are kept for re-enabling
	if _, err := h.e.PatchZone("signed.test", engine.ZonePatch{ZonePatchD5: engine.ZonePatchD5{
		DNSSEC: &engine.SigningInput{Enabled: bp(false)}}}); err != nil {
		t.Fatal(err)
	}
	if r := ask(t, "udp", h.addr, "www."+zn, dns.TypeA, true); len(r.Answer) != 1 {
		t.Fatalf("unsigned answer %v", r)
	}
}

func states(v engine.ZoneDNSSECView, role string) string {
	var s []string
	for _, k := range v.Keys {
		if k.Role == role {
			s = append(s, k.State)
		}
	}
	sortStrings(s)
	return strings.Join(s, ",")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
