package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mrk/dns-engine/internal/engine"
)

const tok = "0123456789abcdef0123456789abcdef0123456789abcdef"

func setup(t *testing.T) (*httptest.Server, *engine.Engine) {
	t.Helper()
	e, err := engine.Open(engine.Options{DataDir: t.TempDir(), DefaultListen: "127.0.0.1:5399"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	api := New(e, func() []engine.ListenerStatus {
		return []engine.ListenerStatus{{Address: "127.0.0.1:5399", Proto: "udp", OK: true}}
	}, tok, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	return srv, e
}

type resp struct {
	status int
	body   map[string]any
	raw    string
}

func call(t *testing.T, srv *httptest.Server, method, path, body string, auth ...string) resp {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	a := "Bearer " + tok
	if len(auth) > 0 {
		a = auth[0]
	}
	if a != "" {
		req.Header.Set("Authorization", a)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	out := resp{status: r.StatusCode, raw: string(b)}
	_ = json.Unmarshal(b, &out.body)
	return out
}

func errCode(r resp) string {
	if e, ok := r.body["error"].(map[string]any); ok {
		return e["code"].(string)
	}
	return ""
}

func TestAuthAndLimits(t *testing.T) {
	srv, _ := setup(t)
	if r := call(t, srv, "GET", "/v1/status", "", ""); r.status != 401 || errCode(r) != "unauthorized" {
		t.Fatalf("%+v", r)
	}
	if r := call(t, srv, "GET", "/v1/status", "", "Bearer wrong"); r.status != 401 {
		t.Fatal(r.status)
	}
	if r := call(t, srv, "GET", "/v1/health", "", ""); r.status != 200 || r.body["ok"] != true {
		t.Fatalf("health %+v", r)
	}
	big := `{"text":"` + strings.Repeat("a", MaxBody) + `"}`
	if r := call(t, srv, "POST", "/v1/zones/x/import", big); r.status != 413 {
		t.Fatalf("body cap: %d", r.status)
	}
	if r := call(t, srv, "GET", "/v1/nope", ""); r.status != 404 {
		t.Fatal(r.status)
	}
	if r := call(t, srv, "POST", "/v1/zones", `{"name":"a.example","bogus":1}`); r.status != 400 || errCode(r) != "invalid_request" {
		t.Fatalf("unknown field: %+v", r)
	}
	if r := call(t, srv, "POST", "/v1/zones", `{"name":5}`); r.status != 400 {
		t.Fatalf("type error: %+v", r)
	}
	st := call(t, srv, "GET", "/v1/status", "")
	for _, k := range []string{"version", "started_at", "uptime_s", "listeners", "qps_1s", "qps_1m", "queries_total", "cache",
		"upstreams", "pressure", "memory_bytes", "goroutines", "config_version"} {
		if _, ok := st.body[k]; !ok {
			t.Errorf("status missing %s", k)
		}
	}
	m := call(t, srv, "GET", "/v1/metrics", "")
	if m.status != 200 || !strings.Contains(m.raw, "mrk_dns_queries_total") {
		t.Fatal("metrics")
	}
}

func TestSettingsAPI(t *testing.T) {
	srv, _ := setup(t)
	g := call(t, srv, "GET", "/v1/settings", "")
	ver := g.body["config_version"].(float64)
	if g.body["upstream_strategy"] != "fastest" || g.body["limits"] == nil {
		t.Fatalf("%+v", g.body)
	}
	if r := call(t, srv, "PUT", "/v1/settings", `{"upstream_strategy":"parallel"}`); r.status != 422 {
		t.Fatalf("missing config_version: %+v", r)
	}
	body := `{"config_version":` + itoa(ver) + `,"upstream_strategy":"parallel","limits":{"client_qps":50,"client_burst":100}}`
	// concurrent PUTs with the same version: one 200, the rest 409
	var wg sync.WaitGroup
	codes := make(chan int, 5)
	for k := 0; k < 5; k++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- call(t, srv, "PUT", "/v1/settings", body).status }()
	}
	wg.Wait()
	close(codes)
	n200, n409 := 0, 0
	for c := range codes {
		switch c {
		case 200:
			n200++
		case 409:
			n409++
		}
	}
	if n200 != 1 || n409 != 4 {
		t.Fatalf("200=%d 409=%d", n200, n409)
	}
	g = call(t, srv, "GET", "/v1/settings", "")
	lim := g.body["limits"].(map[string]any)
	if g.body["upstream_strategy"] != "parallel" || lim["client_qps"].(float64) != 50 || lim["udp_max_size"].(float64) != 1232 {
		t.Fatalf("partial update semantics: %+v", g.body)
	}
	r := call(t, srv, "PUT", "/v1/settings", `{"config_version":`+itoa(g.body["config_version"].(float64))+`,"limits":{"udp_max_size":99},"listen":[{"address":"x","udp":true}]}`)
	if r.status != 422 || errCode(r) != "settings_invalid" {
		t.Fatalf("%+v", r)
	}
	fields := r.body["error"].(map[string]any)["fields"].([]any)
	got := map[string]bool{}
	for _, f := range fields {
		got[f.(map[string]any)["field"].(string)] = true
	}
	if !got["limits.udp_max_size"] || !got["listen[0].address"] {
		t.Fatalf("fields %v", fields)
	}
}

func itoa(f float64) string    { return strings.TrimSuffix(strings.TrimSuffix(jsonNum(f), ".0"), ".") }
func jsonNum(f float64) string { b, _ := json.Marshal(f); return string(b) }

func TestZonesRecordsOverridesAPI(t *testing.T) {
	srv, _ := setup(t)
	if r := call(t, srv, "POST", "/v1/zones", `{"name":"example.com","type":"primary"}`); r.status != 201 || r.body["name"] != "example.com" {
		t.Fatalf("%+v", r)
	}
	if r := call(t, srv, "POST", "/v1/zones", `{"name":"example.com"}`); r.status != 409 || errCode(r) != "zone_exists" {
		t.Fatal(r)
	}
	if r := call(t, srv, "POST", "/v1/zones", `{"name":"-bad-"}`); r.status != 422 || errCode(r) != "invalid_zone_name" {
		t.Fatal(r)
	}
	if r := call(t, srv, "POST", "/v1/zones", `{"name":"corp.lan","type":"forwarder","forwarders":["10.0.0.1"]}`); r.status != 201 {
		t.Fatal(r)
	}
	l := call(t, srv, "GET", "/v1/zones", "")
	if len(l.body["items"].([]any)) != 2 {
		t.Fatal(l.raw)
	}
	rec := call(t, srv, "POST", "/v1/zones/example.com/records", `{"name":"www","type":"A","ttl":300,"data":{"address":"192.0.2.1"},"comment":"web"}`)
	if rec.status != 201 || rec.body["id"] == "" {
		t.Fatal(rec)
	}
	id := rec.body["id"].(string)
	bad := call(t, srv, "POST", "/v1/zones/example.com/records", `{"name":"www","type":"CNAME","data":{"target":"x.example.net"}}`)
	if bad.status != 409 || errCode(bad) != "cname_conflict" {
		t.Fatal(bad)
	}
	bad = call(t, srv, "POST", "/v1/zones/example.com/records", `{"name":"x","type":"MX","data":{"exchange":"m"}}`)
	if bad.status != 422 || errCode(bad) != "record_invalid" || !strings.Contains(bad.raw, "data.preference") {
		t.Fatal(bad)
	}
	if r := call(t, srv, "PUT", "/v1/zones/example.com/records/"+id, `{"name":"www","type":"A","ttl":60,"data":{"address":"192.0.2.2"}}`); r.status != 200 {
		t.Fatal(r)
	}
	if r := call(t, srv, "PUT", "/v1/zones/example.com/records/nope", `{"name":"www","type":"A","data":{"address":"192.0.2.2"}}`); r.status != 404 {
		t.Fatal(r)
	}
	rs := call(t, srv, "GET", "/v1/zones/example.com/records", "")
	items := rs.body["items"].([]any)
	if len(items) != 3 || items[0].(map[string]any)["type"] != "SOA" {
		t.Fatal(rs.raw)
	}
	ex := call(t, srv, "GET", "/v1/zones/example.com/export", "")
	if ex.status != 200 || !strings.Contains(ex.raw, "192.0.2.2") {
		t.Fatal(ex.raw)
	}
	imp := call(t, srv, "POST", "/v1/zones/example.com/import", `{"text":"mail 300 IN A 192.0.2.25\n","replace":false}`)
	if imp.status != 200 || imp.body["added"].(float64) != 1 {
		t.Fatal(imp)
	}
	h := call(t, srv, "GET", "/v1/zones/example.com/history", "")
	hi := h.body["items"].([]any)
	if len(hi) != 4 || hi[0].(map[string]any)["actor"] != "api" || hi[0].(map[string]any)["created_at"] == "" || hi[0].(map[string]any)["version"].(float64) != 4 {
		t.Fatal(h.raw)
	}
	if r := call(t, srv, "POST", "/v1/zones/example.com/rollback", `{"version":"x"}`); r.status != 400 {
		t.Fatal(r)
	}
	if r := call(t, srv, "POST", "/v1/zones/example.com/rollback", `{"version":"1"}`); r.status != 200 {
		t.Fatal(r)
	}
	if r := call(t, srv, "PATCH", "/v1/zones/example.com", `{"disabled":true}`); r.status != 200 || r.body["disabled"] != true {
		t.Fatal(r)
	}
	if r := call(t, srv, "PATCH", "/v1/zones/example.com", `{"forwarders":["1.1.1.1"]}`); r.status != 409 {
		t.Fatal(r)
	}
	if r := call(t, srv, "GET", "/v1/zones/corp.lan/records", ""); r.status != 409 || errCode(r) != "zone_type_mismatch" {
		t.Fatal(r)
	}
	if r := call(t, srv, "DELETE", "/v1/zones/example.com/records/"+id, ""); r.status != 404 { // rolled back to v1: gone
		t.Fatal(r.status)
	}
	if r := call(t, srv, "DELETE", "/v1/zones/corp.lan", ""); r.status != 204 {
		t.Fatal(r.status)
	}
	if r := call(t, srv, "GET", "/v1/zones/corp.lan", ""); r.status != 404 || errCode(r) != "zone_not_found" {
		t.Fatal(r)
	}

	o := call(t, srv, "POST", "/v1/overrides", `{"name":"panel.mrk.internal","type":"A","value":"172.17.0.1","ttl":30,"source":"services"}`)
	if o.status != 201 || o.body["source"] != "services" {
		t.Fatal(o)
	}
	oid := o.body["id"].(string)
	if r := call(t, srv, "PUT", "/v1/overrides/"+oid, `{"name":"panel.mrk.internal","type":"A","value":"172.17.0.2"}`); r.status != 200 || r.body["source"] != "user" {
		t.Fatal(r)
	}
	if r := call(t, srv, "POST", "/v1/overrides", `{"name":"x","type":"MX","value":"y"}`); r.status != 422 {
		t.Fatal(r)
	}
	ol := call(t, srv, "GET", "/v1/overrides", "")
	if len(ol.body["items"].([]any)) != 1 {
		t.Fatal(ol.raw)
	}
	rv := call(t, srv, "POST", "/v1/resolve", `{"name":"panel.mrk.internal","type":"A"}`)
	if rv.status != 200 || rv.body["source"] != "override" || rv.body["rcode"] != "NOERROR" {
		t.Fatal(rv.raw)
	}
	if r := call(t, srv, "POST", "/v1/resolve", `{"name":"panel.mrk.internal","client_ip":"8.8.8.8"}`); r.body["source"] != "refused" {
		t.Fatal(r.raw)
	}
	if r := call(t, srv, "DELETE", "/v1/overrides/"+oid, ""); r.status != 204 {
		t.Fatal(r.status)
	}
	if r := call(t, srv, "POST", "/v1/cache/flush", `{}`); r.status != 200 {
		t.Fatal(r)
	}
	if r := call(t, srv, "POST", "/v1/cache/flush", `{"name":"example.com"}`); r.status != 200 {
		t.Fatal(r)
	}
}

func TestUnixSocketAndToken(t *testing.T) {
	dir, err := os.MkdirTemp("", "mrkdns") // short path: unix socket paths are limited to ~108 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tp := filepath.Join(dir, "admin.token")
	t1, err := EnsureToken(tp)
	if err != nil || len(t1) != 64 {
		t.Fatal(t1, err)
	}
	fi, _ := os.Stat(tp)
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("token perm %v", fi.Mode().Perm())
	}
	if t2, _ := EnsureToken(tp); t2 != t1 {
		t.Fatal("token must be stable across restarts")
	}
	sock := filepath.Join(dir, "admin.sock")
	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ = os.Lstat(sock)
	if fi.Mode().Perm() != 0o660 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode %v", fi.Mode())
	}
	if _, err := ListenUnix(sock); err == nil {
		t.Fatal("second listener on a live socket")
	}
	e, err := engine.Open(engine.Options{DataDir: filepath.Join(dir, "data"), DefaultListen: "127.0.0.1:5399"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	api := New(e, func() []engine.ListenerStatus { return nil }, t1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- api.Serve(ctx, ln) }()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}, Timeout: 3 * time.Second}
	req, _ := http.NewRequest("POST", "http://mrk-dns/v1/zones", bytes.NewBufferString(`{"name":"sock.example"}`))
	req.Header.Set("Authorization", "Bearer "+t1)
	r, err := c.Do(req)
	if err != nil || r.StatusCode != 201 {
		t.Fatalf("%v %v", r, err)
	}
	r.Body.Close()
	h, err := c.Get("http://mrk-dns/v1/health")
	if err != nil || h.StatusCode != 503 { // no listeners reported
		t.Fatalf("health %v %v", h, err)
	}
	h.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// stale socket file (no listener) is replaced on restart
	ln2, err := ListenUnix(sock)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	ln2.Close()
	_ = os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o600)
	if _, err := ListenUnix(filepath.Join(dir, "file")); err == nil {
		t.Fatal("regular file replaced")
	}
}
