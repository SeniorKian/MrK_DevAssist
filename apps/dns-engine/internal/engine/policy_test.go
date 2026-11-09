package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/filter"
	"mrk/dns-engine/internal/pressure"
	"mrk/dns-engine/internal/testutil"
	"mrk/dns-engine/internal/zone"
)

func policyEngine(t *testing.T, upstream string, client *http.Client, mut func(s *config.Settings)) *Engine {
	t.Helper()
	e, err := Open(Options{DataDir: t.TempDir(), DefaultListen: "127.0.0.1:5399", FilterClient: client,
		DiskFree: func(string) (float64, error) { return 80, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	put(t, e, func(s *config.Settings) {
		s.Upstreams = []config.Upstream{{ID: "test", Address: upstream, Enabled: true}}
		s.Pressure.Enabled = false
		s.Limits.ClientQPS, s.Limits.ClientBurst = 0, 0
		s.DNSSEC.Mode = config.DNSSECOff
		if mut != nil {
			mut(s)
		}
	})
	return e
}

func put(t *testing.T, e *Engine, mut func(s *config.Settings)) {
	t.Helper()
	s, v := e.Settings()
	mut(&s)
	if _, _, err := e.PutSettings(s, v); err != nil {
		t.Fatal(err)
	}
}

func waitLists(t *testing.T, e *Engine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e.WaitFiltering(ctx)
}

func aOf(r *dns.Msg) string {
	for _, rr := range r.Answer {
		switch v := rr.(type) {
		case *dns.A:
			return v.A.String()
		case *dns.AAAA:
			return v.AAAA.String()
		}
	}
	return ""
}

func TestFilteringInQueryPath(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "93.184.216.34") })
	lists := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("! test list\n||ads.example.com^\n@@||ok.ads.example.com^\n"))
	}))
	defer lists.Close()
	e := policyEngine(t, up.Addr, lists.Client(), func(s *config.Settings) {
		s.Filtering = config.Filtering{Enabled: true, Action: config.BlockNXDomain,
			Lists: []config.FilterList{{ID: "ads", Name: "Ads", URL: lists.URL + "/list.txt", Format: config.FormatAdblock, Enabled: true}},
			Allow: []string{"allowed.ads.example.com"}, Block: []string{"*.custom.test"}}
	})
	waitLists(t, e)

	r := ask(t, e, lan, UDP, query("x.ads.example.com.", dns.TypeA))
	if r == nil || r.Rcode != dns.RcodeNameError || edeCode(r) != int(dns.ExtendedErrorCodeBlocked) {
		t.Fatalf("list block: %v", r)
	}
	for _, n := range []string{"ok.ads.example.com.", "allowed.ads.example.com.", "www.example.org."} {
		if r := ask(t, e, lan, UDP, query(n, dns.TypeA)); r == nil || r.Rcode != 0 || aOf(r) != "93.184.216.34" {
			t.Fatalf("%s not answered: %v", n, r)
		}
	}
	if r := ask(t, e, lan, TCP, query("a.custom.test.", dns.TypeAAAA)); r == nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("custom block: %v", r)
	}
	// a cached name blocked later is blocked on the fast path too
	ask(t, e, lan, UDP, query("cached.example.net.", dns.TypeA))
	put(t, e, func(s *config.Settings) { s.Filtering.Block = append(s.Filtering.Block, "cached.example.net") })
	if r := ask(t, e, lan, UDP, query("cached.example.net.", dns.TypeA)); r == nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("cached answer served for a blocked name: %v", r)
	}
	// non-recursion clients are refused, not "blocked"
	if r := ask(t, e, public, UDP, query("x.ads.example.com.", dns.TypeA)); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("public: %v", r)
	}
	// null_ip and refuse actions
	put(t, e, func(s *config.Settings) { s.Filtering.Action = config.BlockNullIP })
	if r := ask(t, e, lan, UDP, query("x.ads.example.com.", dns.TypeA)); r == nil || r.Rcode != 0 || aOf(r) != "0.0.0.0" {
		t.Fatalf("null_ip A: %v", r)
	}
	if r := ask(t, e, lan, UDP, query("x.ads.example.com.", dns.TypeAAAA)); r == nil || aOf(r) != "::" {
		t.Fatalf("null_ip AAAA: %v", r)
	}
	if r := ask(t, e, lan, UDP, query("x.ads.example.com.", dns.TypeMX)); r == nil || r.Rcode != 0 || len(r.Answer) != 0 {
		t.Fatalf("null_ip MX: %v", r)
	}
	put(t, e, func(s *config.Settings) { s.Filtering.Action = config.BlockRefuse })
	if r := ask(t, e, lan, UDP, query("x.ads.example.com.", dns.TypeA)); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("refuse: %v", r)
	}
	// log source "blocked", blocked=true filter and statistics
	if got := logSearch(t, e, "source=blocked"); len(got) != 7 {
		t.Fatalf("blocked log rows %d", len(got))
	}
	if got := logSearch(t, e, "blocked=true&name=x.ads.example.com"); len(got) != 6 {
		t.Fatalf("blocked=true rows %d", len(got))
	}
	st := e.FilteringStatus()
	if st.Blocked1h != 7 || st.TotalEntries != 3 || len(st.Lists) != 1 || st.Lists[0].Entries != 2 || st.Lists[0].UpdatedAt == nil {
		t.Fatalf("%+v", st)
	}
	// "why was this blocked?"
	for name, want := range map[string]FilterCheck{
		"x.ads.example.com":       {Blocked: true, Reason: "list", ListID: "ads", Rule: "||ads.example.com^"},
		"ok.ads.example.com":      {Reason: "allow_list", ListID: "ads", Rule: "@@||ok.ads.example.com^"},
		"allowed.ads.example.com": {Reason: "allow_list", Rule: "allowed.ads.example.com"},
		"b.custom.test":           {Blocked: true, Reason: "custom_block", Rule: "custom.test"},
		"example.org":             {Reason: "not_listed"},
	} {
		got, err := e.CheckFilter(name, "")
		if err != nil || got.Blocked != want.Blocked || got.Reason != want.Reason || got.ListID != want.ListID || got.Rule != want.Rule {
			t.Errorf("check %s: %+v %v", name, got, err)
		}
	}
	if _, err := e.CheckFilter("bad name!", ""); !isCode(err, CodeInvalidRequest) {
		t.Fatal(err)
	}
}

func TestFilteringSettingsValidation(t *testing.T) {
	e := newEngine(t, "", nil)
	s, v := e.Settings()
	s.Filtering = config.Filtering{Enabled: true, Action: "drop", Allow: []string{"ok.example", "bad name"},
		Lists: []config.FilterList{{ID: "A!", URL: "http://x.example/list", Format: "csv"}, {ID: "dup", URL: "https://x.example/"},
			{ID: "dup", URL: "https://x.example/", Format: config.FormatHosts, UpdateHours: 99999}}}
	s.ClientGroups = []config.ClientGroup{{ID: "kids", Networks: []string{"nope"}, Filtering: "maybe", Lists: []string{"missing"},
		Upstreams: []string{"nope"}, BlockedServices: []string{"myspace"}}, {ID: "kids"}}
	_, _, err := e.PutSettings(s, v)
	want := map[string]string{"filtering.action": "invalid_choice", "filtering.allow[1]": "invalid_name",
		"filtering.lists[0].id": "invalid_id", "filtering.lists[0].url": "https_required", "filtering.lists[0].format": "invalid_choice",
		"filtering.lists[2].id": "duplicate", "filtering.lists[2].update_hours": "out_of_range",
		"client_groups[0].networks[0]": "invalid_network", "client_groups[0].filtering": "invalid_choice",
		"client_groups[0].lists[0]": "unknown_list", "client_groups[0].upstreams[0]": "unknown_upstream",
		"client_groups[0].blocked_services[0]": "invalid_choice", "client_groups[1].id": "duplicate",
		"client_groups[1].networks": "required"}
	got := reasons(err)
	for f, r := range want {
		if got[f] != r {
			t.Errorf("%s: %q want %q (all %v)", f, got[f], r, got)
		}
	}
	// defaults: a D4 settings file without the sections loads with them
	s, _ = e.Settings()
	if s.Filtering.Action != config.BlockNXDomain || s.Filtering.Lists == nil || s.ClientGroups == nil {
		t.Fatalf("%+v", s.Filtering)
	}
}

func TestClientGroupsAndViews(t *testing.T) {
	def := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "192.0.2.1") })
	kidsUp := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "192.0.2.99") })
	kids := netip.MustParseAddr("192.168.50.7")
	guest := netip.MustParseAddr("10.9.1.1")
	e := policyEngine(t, def.Addr, nil, func(s *config.Settings) {
		s.Upstreams = append(s.Upstreams, config.Upstream{ID: "kidsup", Address: kidsUp.Addr, Enabled: true})
		s.UpstreamStrategy = config.StrategyInOrder
		s.Filtering = config.Filtering{Enabled: true, Block: []string{"blocked.test"}, SafeSearch: true}
		s.ClientGroups = []config.ClientGroup{
			{ID: "kids", Name: "Kids", Networks: []string{"192.168.50.0/24"}, Filtering: config.GroupOn,
				Upstreams: []string{"kidsup"}, BlockedServices: []string{"youtube"}},
			{ID: "guests", Networks: []string{"10.9.0.0/16"}, Filtering: config.GroupOff},
		}
	})
	// group upstreams, with a cache of their own
	for n := 0; n < 2; n++ {
		if r := ask(t, e, kids, UDP, query("www.example.org.", dns.TypeA)); r == nil || aOf(r) != "192.0.2.99" {
			t.Fatalf("kids round %d: %v", n, r)
		}
		if r := ask(t, e, lan, UDP, query("www.example.org.", dns.TypeA)); r == nil || aOf(r) != "192.0.2.1" {
			t.Fatalf("default round %d: %v", n, r)
		}
	}
	if kidsUp.Queries.Load() != 1 {
		t.Fatalf("group cache not used: %d upstream queries", kidsUp.Queries.Load())
	}
	// blocked services (group), custom block (inherited), filtering off (guests)
	if r := ask(t, e, kids, UDP, query("r1.googlevideo.com.", dns.TypeA)); r == nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("service: %v", r)
	}
	if r := ask(t, e, lan, UDP, query("r1.googlevideo.com.", dns.TypeA)); r == nil || r.Rcode != 0 {
		t.Fatalf("service blocked for the default group: %v", r)
	}
	if r := ask(t, e, lan, UDP, query("blocked.test.", dns.TypeA)); r == nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("custom: %v", r)
	}
	if r := ask(t, e, guest, UDP, query("blocked.test.", dns.TypeA)); r == nil || r.Rcode != 0 {
		t.Fatalf("guests (filtering off): %v", r)
	}
	if c, _ := e.CheckFilter("r1.googlevideo.com", kids.String()); !c.Blocked || c.Reason != "service" || c.Group != "kids" {
		t.Fatalf("%+v", c)
	}
	// safe search: CNAME to the enforcement name, then chased
	r := ask(t, e, lan, UDP, query("www.google.com.", dns.TypeA))
	if r == nil || len(r.Answer) < 2 || r.Answer[0].(*dns.CNAME).Target != filter.SafeGoogle {
		t.Fatalf("safe search: %v", r)
	}
	if r := ask(t, e, guest, UDP, query("www.google.com.", dns.TypeA)); r == nil || r.Answer[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("safe search for guests: %v", r)
	}

	// split horizon: kids see the view record
	if _, err := e.CreateZone("corp.test", "primary", nil); err != nil {
		t.Fatal(err)
	}
	addRecord(t, e, "corp.test", "app", "A", `{"address":"203.0.113.10"}`)
	if _, err := e.CreateRecord("corp.test", zone.RecordInput{Name: s("app"), Type: s("A"), TTL: i(60),
		Data: json.RawMessage(`{"address":"10.0.0.10"}`), View: "kids"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CreateRecord("corp.test", zone.RecordInput{Name: s("app"), Type: s("A"),
		Data: json.RawMessage(`{"address":"10.0.0.10"}`), View: "Bad View"}); err == nil {
		t.Fatal("invalid view accepted")
	}
	if r := ask(t, e, kids, UDP, query("app.corp.test.", dns.TypeA)); r == nil || len(r.Answer) != 1 || aOf(r) != "10.0.0.10" {
		t.Fatalf("view: %v", r)
	}
	if r := ask(t, e, lan, UDP, query("app.corp.test.", dns.TypeA)); r == nil || len(r.Answer) != 1 || aOf(r) != "203.0.113.10" {
		t.Fatalf("general: %v", r)
	}
	// records_override=false: the view adds to the general records
	f := false
	d, err := e.PatchZone("corp.test", ZonePatch{ZonePatchViews: ZonePatchViews{Views: &[]ZoneView{{GroupID: "kids", RecordsOverride: &f}}}})
	if err != nil || len(d.Views) != 1 || *d.Views[0].RecordsOverride || len(d.RecordViews) != 1 {
		t.Fatalf("%+v %v", d.ZoneViewsView, err)
	}
	if r := ask(t, e, kids, UDP, query("app.corp.test.", dns.TypeA)); r == nil || len(r.Answer) != 2 {
		t.Fatalf("union view: %v", r)
	}
	if _, err := e.PatchZone("corp.test", ZonePatch{ZonePatchViews: ZonePatchViews{Views: &[]ZoneView{{GroupID: "x"}, {GroupID: "x"}}}}); !isCode(err, CodeZoneInvalid) {
		t.Fatal(err)
	}
	// the views are stored with the zone
	zs, _ := e.st.LoadZones()
	for _, z := range zs {
		if z.Name == "corp.test." && (len(z.Views) != 1 || z.Views[0].Override() || len(zone.ViewIDs(z)) != 1) {
			t.Fatalf("stored views %+v", z.Views)
		}
	}
}

// tighten_client_qps also bounds an unlimited client_qps under pressure.
func TestTightenUnlimitedClientQPS(t *testing.T) {
	ck := &fakeClock{t: time.Now()}
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "192.0.2.1") })
	e := newEngineClock(t, up.Addr, ck, func(s *config.Settings) { s.Pressure.Enabled = true; s.Pressure.DwellSeconds = 5 })
	pkt := query("www.example.org.", dns.TypeA)
	burst := func() (answered int) {
		for n := 0; n < 2500; n++ {
			if r := ask(t, e, lan, UDP, pkt); r != nil {
				answered++
			}
		}
		return answered
	}
	if a := burst(); a != 2500 {
		t.Fatalf("normal: %d of 2500 answered", a)
	}
	for n := 0; n < 2; n++ {
		e.mon.ctl.Step(pressure.Metrics{CPUPercent: 90})
		ck.add(time.Second)
	}
	e.applyActions()
	if e.PressureLevel() != "critical" || e.pol.Load().clientLim.Scale() != 0.5 {
		t.Fatal(e.PressureLevel())
	}
	if a := burst(); a >= 2500 || a < 1500 {
		t.Fatalf("critical: %d of 2500 answered (cap 1000 qps, burst 2000)", a)
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	up := testutil.StartUpstream(t, func(q dns.Question) *dns.Msg { return testutil.A(q, 300, "192.0.2.1") })
	a := policyEngine(t, up.Addr, nil, func(s *config.Settings) {
		s.Filtering.Block = []string{"blocked.test"}
		s.Filtering.Enabled = true
	})
	if _, err := a.CreateZone("backup.test", "primary", nil); err != nil {
		t.Fatal(err)
	}
	addRecord(t, a, "backup.test", "www", "A", `{"address":"198.51.100.7"}`)
	if _, err := a.CreateOverride(OverrideInput{Name: s("nas.lan"), Type: s("A"), Value: s("192.168.1.5")}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SelfSignedTLS([]string{"dns.backup.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateToken("phone", nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := a.Backup(&buf); err != nil {
		t.Fatal(err)
	}
	archive := buf.Bytes()

	b := policyEngine(t, up.Addr, nil, nil)
	_, before := b.Settings()
	if _, err := b.CreateZone("gone.test", "primary", nil); err != nil {
		t.Fatal(err)
	}
	res, err := b.Restore(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	s, v := b.Settings()
	if !res.Restored || v <= before || res.ConfigVersion != v || len(s.Filtering.Block) != 1 || res.RestartRequired {
		t.Fatalf("%+v version %d→%d %+v", res, before, v, s.Filtering)
	}
	if r := ask(t, b, lan, UDP, query("www.backup.test.", dns.TypeA)); r == nil || aOf(r) != "198.51.100.7" {
		t.Fatalf("restored zone: %v", r)
	}
	if _, err := b.Zone("gone.test"); !isCode(err, CodeZoneNotFound) {
		t.Fatal("zone created after the backup survived the restore", err)
	}
	if r := ask(t, b, lan, UDP, query("nas.lan.", dns.TypeA)); r == nil || aOf(r) != "192.168.1.5" {
		t.Fatalf("restored override: %v", r)
	}
	if r := ask(t, b, lan, UDP, query("blocked.test.", dns.TypeA)); r == nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("restored filtering: %v", r)
	}
	if !b.TLS().Present || len(b.Tokens()) != 1 {
		t.Fatal("certificate or tokens not restored")
	}

	// invalid archives change nothing
	for name, arc := range map[string][]byte{
		"garbage":   []byte("not a tar.gz"),
		"truncated": archive[:len(archive)/2],
		"checksum":  tamper(t, archive, "zones/backup.test.json", []byte(`{"name":"backup.test.","type":"primary","records":[]}`), false),
		"zone":      tamper(t, archive, "zones/backup.test.json", []byte(`{"name":"backup.test.","type":"primary","version":999,"records":[{"id":"x","name":"@","type":"CNAME","ttl":60,"data":{"target":"a.example."}}]}`), true),
		"settings":  tamper(t, archive, "settings.json", []byte(`{"schema":1,"config_version":3,"settings":{"listen":[{"address":"bad"}]}}`), true),
		"path":      tamper(t, archive, "../evil.json", []byte(`{}`), true),
	} {
		_, err := b.Restore(bytes.NewReader(arc))
		if !isCode(err, CodeRestoreInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
		if r := ask(t, b, lan, UDP, query("www.backup.test.", dns.TypeA)); r == nil || aOf(r) != "198.51.100.7" {
			t.Fatalf("%s: state changed by a rejected restore", name)
		}
	}
}

func TestRestoreJournalRecovery(t *testing.T) {
	dir := t.TempDir()
	e, err := Open(Options{DataDir: dir, DefaultListen: "127.0.0.1:5399"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.CreateZone("keep.test", "primary", nil); err != nil {
		t.Fatal(err)
	}
	e.Close()
	// simulate a crash in the middle of a swap: originals moved to old/,
	// one archive file already in place
	stage := dir + "/.restore-abc"
	cur, _ := listBackupFiles(dir)
	if err := swapIn(dir, stage, cur, nil); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(dir, journal{Stage: ".restore-abc", Phase: "moving_new"}); err != nil {
		t.Fatal(err)
	}
	e2, err := Open(Options{DataDir: dir, DefaultListen: "127.0.0.1:5399"})
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	if _, err := e2.Zone("keep.test"); err != nil {
		t.Fatal("interrupted restore not rolled back:", err)
	}
}

func reasons(err error) map[string]string {
	out := map[string]string{}
	var fe *fielderr.Error
	if errors.As(err, &fe) {
		for _, f := range fe.Fields {
			out[f.Field] = f.ReasonCode
		}
	}
	return out
}

// tamper rewrites one archive member (adding it when missing); fix updates
// the manifest so only the content check can reject it.
func tamper(t *testing.T, archive []byte, name string, content []byte, fix bool) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var order []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = b
		order = append(order, h.Name)
	}
	if _, ok := files[name]; !ok {
		order = append(order, name)
	}
	files[name] = content
	if fix {
		var m BackupManifest
		if err := json.Unmarshal(files[manifestName], &m); err != nil {
			t.Fatal(err)
		}
		found := false
		for i := range m.Files {
			if m.Files[i].Path == name {
				sum := sha256.Sum256(content)
				m.Files[i].Size, m.Files[i].SHA256, found = int64(len(content)), hex.EncodeToString(sum[:]), true
			}
		}
		if !found {
			sum := sha256.Sum256(content)
			m.Files = append(m.Files, BackupFile{Path: name, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])})
		}
		files[manifestName], _ = json.Marshal(m)
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for _, n := range order {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
		_, _ = tw.Write(files[n])
	}
	_ = tw.Close()
	_ = zw.Close()
	return out.Bytes()
}
