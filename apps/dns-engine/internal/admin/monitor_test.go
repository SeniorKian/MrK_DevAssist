package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/engine"
)

func pkt(name string) []byte {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.SetEdns0(1232, false)
	b, _ := m.Pack()
	return b
}

// send runs queries through the engine as the UDP server would (no upstream:
// a public client is refused, which is enough to produce log rows).
func send(e *engine.Engine, client string, names ...string) {
	a := netip.MustParseAddr(client)
	sc := engine.NewScratch()
	for _, n := range names {
		p := pkt(n)
		if _, v := e.Fast(p, a, engine.UDP, sc); v == engine.Slow || v == engine.SlowUnchecked {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			e.Slow(ctx, p, a, engine.UDP, v == engine.Slow)
			cancel()
		}
	}
}

func TestQueryLogEndpoints(t *testing.T) {
	srv, e := setup(t)
	send(e, "203.0.113.1", "a.example.com.", "b.example.com.", "c.other.org.")
	send(e, "203.0.113.2", "d.example.com.")
	r := call(t, srv, "GET", "/v1/querylog?limit=2", "")
	if r.status != 200 {
		t.Fatal(r.raw)
	}
	its := r.body["items"].([]any)
	if len(its) != 2 || r.body["next_cursor"] == nil || r.body["truncated"] != false {
		t.Fatal(r.raw)
	}
	first := its[0].(map[string]any)
	for _, k := range []string{"ts", "client", "proto", "name", "qtype", "rcode", "source", "ms", "size", "flags"} {
		if _, ok := first[k]; !ok {
			t.Fatalf("item lacks %s: %v", k, first)
		}
	}
	if first["name"] != "d.example.com" || first["source"] != "refused" {
		t.Fatal(first)
	}
	r = call(t, srv, "GET", "/v1/querylog?limit=10&cursor="+r.body["next_cursor"].(string), "")
	if len(r.body["items"].([]any)) != 2 || r.body["next_cursor"] != nil {
		t.Fatal(r.raw)
	}
	if r := call(t, srv, "GET", "/v1/querylog?name=*.example.com&client=203.0.113.1", ""); len(r.body["items"].([]any)) != 2 {
		t.Fatal(r.raw)
	}
	if r := call(t, srv, "GET", "/v1/querylog?limit=5000", ""); r.status != 422 || errCode(r) != "query_invalid" {
		t.Fatal(r.raw)
	}
	st := call(t, srv, "GET", "/v1/querylog/status", "")
	for _, k := range []string{"enabled", "mode", "mode_effective", "bytes", "segments", "oldest_ts", "written_total", "dropped_total", "disk_free_percent"} {
		if _, ok := st.body[k]; !ok {
			t.Fatalf("status lacks %s: %s", k, st.raw)
		}
	}
	// export
	req, _ := http.NewRequest("GET", srv.URL+"/v1/querylog/export?format=csv&name=*.example.com", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(resp.Body)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	resp.Body.Close()
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "ts,client,proto,name") || resp.Header.Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Fatal(lines)
	}
	ex := call(t, srv, "GET", "/v1/querylog/export", "")
	if n := strings.Count(ex.raw, "\n"); n != 4 {
		t.Fatal(ex.raw)
	}
	if r := call(t, srv, "GET", "/v1/querylog/export?limit=2", ""); strings.Count(r.raw, "\n") != 2 {
		t.Fatal(r.raw)
	}
	if r := call(t, srv, "GET", "/v1/querylog/export?format=xml", ""); r.status != 422 {
		t.Fatal(r.status)
	}
	// delete by client, then everything
	if r := call(t, srv, "DELETE", "/v1/querylog", `{"client":"bogus"}`); r.status != 400 {
		t.Fatal(r.raw)
	}
	d := call(t, srv, "DELETE", "/v1/querylog", `{"client":"203.0.113.1"}`)
	if d.status != 200 || d.body["deleted_rows"] != float64(3) {
		t.Fatal(d.raw)
	}
	d = call(t, srv, "DELETE", "/v1/querylog", `{"before":"2999-01-01T00:00:00Z"}`)
	if d.body["deleted_rows"] != float64(1) {
		t.Fatal(d.raw)
	}
	d = call(t, srv, "DELETE", "/v1/querylog", ``)
	if d.status != 200 || d.body["deleted_rows"] != float64(0) {
		t.Fatal(d.raw)
	}
}

func TestStreamEndpoint(t *testing.T) {
	srv, e := setup(t)
	s, v := e.Settings()
	s.QueryLog.StreamMaxEPS = 5
	if _, _, err := e.PutSettings(s, v); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/v1/querylog/stream?name=*.example.com", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatal(resp.Header)
	}
	lines := make(chan map[string]any, 100)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			var m map[string]any
			_ = json.Unmarshal(sc.Bytes(), &m)
			lines <- m
		}
		close(lines)
	}()
	next := func() map[string]any {
		select {
		case m := <-lines:
			return m
		case <-time.After(5 * time.Second):
			t.Fatal("stream timeout")
		}
		return nil
	}
	if h := next(); h["type"] != "hello" || h["max_eps"] != float64(5) {
		t.Fatal(h)
	}
	var names []string
	for i := 0; i < 50; i++ {
		names = append(names, "n.example.com.")
	}
	send(e, "203.0.113.9", "x.other.org.")
	send(e, "203.0.113.9", names...)
	entries, sampled := 0, 0.0
	deadline := time.After(4 * time.Second)
loop:
	for {
		select {
		case m := <-lines:
			switch m["type"] {
			case "entry":
				entries++
				if m["name"] != "n.example.com" {
					t.Fatal("filter", m)
				}
			case "sampled":
				sampled += m["skipped"].(float64)
				break loop
			}
		case <-deadline:
			break loop
		}
	}
	if entries == 0 || entries > 6 || sampled == 0 {
		t.Fatalf("entries %d sampled %v", entries, sampled)
	}
	// at most 20 concurrent streams
	var extra []*http.Response
	for i := 0; i < 19; i++ {
		rq, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/v1/querylog/stream", nil)
		rq.Header.Set("Authorization", "Bearer "+tok)
		rs, err := http.DefaultClient.Do(rq)
		if err != nil || rs.StatusCode != 200 {
			t.Fatal(err, rs.StatusCode)
		}
		extra = append(extra, rs)
	}
	if r := call(t, srv, "GET", "/v1/querylog/stream", ""); r.status != 429 || errCode(r) != "too_many_streams" {
		t.Fatal(r.status, r.raw)
	}
	for _, rs := range extra {
		rs.Body.Close()
	}
}

func TestStatsPressureMitigationsEvents(t *testing.T) {
	srv, e := setup(t)
	send(e, "203.0.113.1", "a.example.com.")
	r := call(t, srv, "GET", "/v1/stats?range=24h", "")
	if r.status != 200 || r.body["resolution_seconds"] != float64(900) || len(r.body["points"].([]any)) != 96 {
		t.Fatal(r.raw[:200])
	}
	tot := r.body["totals"].(map[string]any)
	if tot["queries"] != float64(1) {
		t.Fatal(tot)
	}
	top := r.body["top"].(map[string]any)
	for _, k := range []string{"domains", "clients", "nxdomain", "refused_clients"} {
		if _, ok := top[k]; !ok {
			t.Fatal(k)
		}
	}
	if r := call(t, srv, "GET", "/v1/stats?range=2d", ""); r.status != 400 {
		t.Fatal(r.status)
	}
	p := call(t, srv, "GET", "/v1/pressure", "")
	for _, k := range []string{"level", "since", "reasons", "metrics", "active_actions", "hot"} {
		if _, ok := p.body[k]; !ok {
			t.Fatalf("pressure lacks %s: %s", k, p.raw)
		}
	}
	hot := p.body["hot"].(map[string]any)
	if _, ok := hot["attacks"].([]any); !ok {
		t.Fatal(p.raw)
	}
	if r := call(t, srv, "POST", "/v1/host-metrics", `{"cpu_percent":40,"memory_percent":50,"load1":0.5,"ts":"`+
		time.Now().UTC().Format(time.RFC3339)+`"}`); r.status != 200 || r.body["accepted"] != true {
		t.Fatal(r.raw)
	}
	if r := call(t, srv, "POST", "/v1/host-metrics", `{"cpu_percent":40,"memory_percent":50,"ts":1000}`); r.body["accepted"] != false {
		t.Fatal(r.raw)
	}
	if r := call(t, srv, "POST", "/v1/host-metrics", `{"cpu_percent":400,"memory_percent":50}`); r.status != 400 {
		t.Fatal(r.raw)
	}
	// mitigations
	if r := call(t, srv, "POST", "/v1/mitigations", `{"kind":"client","match":"nope","action":"block","minutes":5}`); r.status != 422 || errCode(r) != "mitigation_invalid" {
		t.Fatal(r.raw)
	}
	c := call(t, srv, "POST", "/v1/mitigations", `{"kind":"domain","match":"Bad.Example.","action":"throttle","qps":5,"minutes":15,"reason":"test"}`)
	if c.status != 201 || c.body["match"] != "bad.example" || c.body["source"] != "user" || c.body["hits"] != float64(0) {
		t.Fatal(c.raw)
	}
	for _, k := range []string{"id", "kind", "match", "action", "qps", "created_at", "expires_at", "source", "reason", "hits"} {
		if _, ok := c.body[k]; !ok {
			t.Fatal(k)
		}
	}
	l := call(t, srv, "GET", "/v1/mitigations", "")
	if len(l.body["items"].([]any)) != 1 {
		t.Fatal(l.raw)
	}
	if r := call(t, srv, "DELETE", "/v1/mitigations/"+c.body["id"].(string), ""); r.status != 204 {
		t.Fatal(r.status)
	}
	if r := call(t, srv, "DELETE", "/v1/mitigations/m_x", ""); r.status != 404 || errCode(r) != "mitigation_not_found" {
		t.Fatal(r.raw)
	}
	// events
	e.EventRing().Emit("pressure.level", "warning", map[string]any{"level": "warning"})
	ev := call(t, srv, "GET", "/v1/events?after=0", "")
	items := ev.body["items"].([]any)
	if len(items) != 1 || ev.body["next"] == nil {
		t.Fatal(ev.raw)
	}
	nx := int64(ev.body["next"].(float64))
	if r := call(t, srv, "GET", "/v1/events?after="+strconv.FormatInt(nx, 10), ""); len(r.body["items"].([]any)) != 0 {
		t.Fatal(r.raw)
	}
	if r := call(t, srv, "GET", "/v1/events?after=x", ""); r.status != 400 {
		t.Fatal(r.status)
	}
	// partial nested settings update keeps the other fields
	g := call(t, srv, "GET", "/v1/settings", "")
	ver := g.body["config_version"].(float64)
	u := call(t, srv, "PUT", "/v1/settings", `{"config_version":`+strconv.FormatInt(int64(ver), 10)+`,"pressure":{"thresholds":{"warning":{"cpu":60}}},"querylog":{"client_ip":"hash"}}`)
	if u.status != 200 {
		t.Fatal(u.raw)
	}
	pr := u.body["pressure"].(map[string]any)
	w := pr["thresholds"].(map[string]any)["warning"].(map[string]any)
	if w["cpu"] != float64(60) || w["memory"] != float64(75) || u.body["querylog"].(map[string]any)["client_ip"] != "hash" ||
		u.body["querylog"].(map[string]any)["mode"] != "all" {
		t.Fatal(u.raw)
	}
	bad := call(t, srv, "PUT", "/v1/settings", `{"config_version":`+strconv.FormatInt(int64(ver)+1, 10)+`,"querylog":{"mode":"verbose"}}`)
	if bad.status != 422 || !strings.Contains(bad.raw, "querylog.mode") {
		t.Fatal(bad.raw)
	}
}
