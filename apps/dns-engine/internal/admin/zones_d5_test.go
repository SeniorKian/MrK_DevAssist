package admin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestZonesD5API(t *testing.T) {
	srv, e := setup(t)
	// TSIG: secret only at creation, file 0600
	r := call(t, srv, "POST", "/v1/tsig", `{"name":"Xfr.Key.","algorithm":"hmac-sha512"}`)
	if r.status != 201 || r.body["name"] != "xfr.key" || r.body["algorithm"] != "hmac-sha512" || len(r.body["secret"].(string)) < 40 {
		t.Fatalf("create tsig: %d %s", r.status, r.raw)
	}
	r = call(t, srv, "GET", "/v1/tsig", "")
	if r.status != 200 || strings.Contains(r.raw, "secret") || !strings.Contains(r.raw, `"xfr.key"`) {
		t.Fatalf("list tsig: %s", r.raw)
	}
	if r := call(t, srv, "POST", "/v1/tsig", `{"name":"xfr.key"}`); r.status != 409 || errCode(r) != "tsig_key_exists" {
		t.Fatalf("duplicate: %d %s", r.status, r.raw)
	}
	if r := call(t, srv, "POST", "/v1/tsig", `{"name":"bad key","secret":"!!"}`); r.status != 422 || errCode(r) != "tsig_invalid" {
		t.Fatalf("invalid: %d %s", r.status, r.raw)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dataDir(t, e), "tsig.json"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("tsig.json mode %v %v", fi.Mode(), err)
		}
	}
	// secondary zone
	r = call(t, srv, "POST", "/v1/zones", `{"name":"sec.test","type":"secondary","primaries":["192.0.2.53"],"tsig_key":"xfr.key","notify_allow":["192.0.2.0/24"]}`)
	if r.status != 201 || r.body["type"] != "secondary" || r.body["secondary"] == nil {
		t.Fatalf("create secondary: %d %s", r.status, r.raw)
	}
	if p := r.body["primaries"].([]any); p[0] != "192.0.2.53:53" {
		t.Fatalf("primaries %v", p)
	}
	if r := call(t, srv, "POST", "/v1/zones/sec.test/records", `{"name":"a","type":"A","data":{"address":"192.0.2.1"}}`); r.status != 409 || errCode(r) != "zone_read_only" {
		t.Fatalf("record on secondary: %d %s", r.status, r.raw)
	}
	if r := call(t, srv, "POST", "/v1/zones", `{"name":"bad.test","type":"secondary","primaries":["nope"]}`); r.status != 422 {
		t.Fatalf("bad primary: %d %s", r.status, r.raw)
	}
	if r := call(t, srv, "POST", "/v1/zones", `{"name":"p.test","primaries":["192.0.2.1"]}`); r.status != 422 {
		t.Fatalf("primaries on primary: %d %s", r.status, r.raw)
	}
	if r := call(t, srv, "DELETE", "/v1/tsig/xfr.key", ""); r.status != 409 || errCode(r) != "tsig_key_in_use" {
		t.Fatalf("delete in use: %d %s", r.status, r.raw)
	}
	// primary: transfer / notify / update / dnssec
	if r := call(t, srv, "POST", "/v1/zones", `{"name":"pri.test"}`); r.status != 201 {
		t.Fatal(r.raw)
	}
	r = call(t, srv, "GET", "/v1/zones/pri.test", "")
	for _, k := range []string{`"transfer":{"allow":[]}`, `"notify":{"targets":[],"enabled":false}`,
		`"update":{"enabled":false,"allow":[],"require_tsig":true}`, `"dnssec":{"enabled":false,"algorithm":"ECDSAP256SHA256"`} {
		if !strings.Contains(r.raw, k) {
			t.Fatalf("zone detail lacks %s: %s", k, r.raw)
		}
	}
	r = call(t, srv, "PATCH", "/v1/zones/pri.test", `{"transfer":{"allow":["10.0.0.0/8"],"tsig_key":"xfr.key"},
		"notify":{"targets":["10.0.0.2"],"enabled":true},"update":{"enabled":true,"tsig_key":"xfr.key"},
		"dnssec":{"enabled":true,"denial":"nsec3","nsec3":{"iterations":0,"salt":""}}}`)
	if r.status != 200 || !strings.Contains(r.raw, `"targets":["10.0.0.2:53"]`) || !strings.Contains(r.raw, `"denial":"nsec3"`) {
		t.Fatalf("patch: %d %s", r.status, r.raw)
	}
	if r := call(t, srv, "PATCH", "/v1/zones/pri.test", `{"transfer":{"allow":["nope"]},"update":{"tsig_key":"missing"}}`); r.status != 422 ||
		!strings.Contains(r.raw, "transfer.allow[0]") || !strings.Contains(r.raw, "unknown_tsig_key") {
		t.Fatalf("invalid patch: %d %s", r.status, r.raw)
	}
	if r := call(t, srv, "PATCH", "/v1/zones/pri.test", `{"dnssec":{"algorithm":"ED25519"}}`); r.status != 422 || !strings.Contains(r.raw, "algorithm_locked") {
		t.Fatalf("algorithm change while signing: %d %s", r.status, r.raw)
	}
	r = call(t, srv, "GET", "/v1/zones/pri.test/dnssec", "")
	if r.status != 200 || r.body["enabled"] != true || len(r.body["keys"].([]any)) != 2 || len(r.body["ds"].([]any)) != 1 || r.body["next_resign"] == nil {
		t.Fatalf("dnssec: %d %s", r.status, r.raw)
	}
	ds := r.body["ds"].([]any)[0].(map[string]any)
	if ds["digest_type"].(float64) != 2 || !strings.Contains(ds["text"].(string), "IN\tDS\t") {
		t.Fatalf("ds %v", ds)
	}
	if strings.Contains(r.raw, "private") {
		t.Fatal("private key material in the API")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dataDir(t, e), "dnssec-keys", "pri.test.keys.json"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode %v %v", fi, err)
		}
	}
	r = call(t, srv, "POST", "/v1/zones/pri.test/dnssec/rollover", `{"role":"zsk"}`)
	if r.status != 200 || len(r.body["keys"].([]any)) != 3 {
		t.Fatalf("rollover: %d %s", r.status, r.raw)
	}
	if r := call(t, srv, "POST", "/v1/zones/pri.test/dnssec/rollover", `{"role":"zsk"}`); r.status != 409 || errCode(r) != "rollover_in_progress" {
		t.Fatalf("second rollover: %d %s", r.status, r.raw)
	}
	if r := call(t, srv, "POST", "/v1/zones/pri.test/refresh", ``); r.status != 409 || errCode(r) != "zone_type_mismatch" {
		t.Fatalf("refresh primary: %d %s", r.status, r.raw)
	}
	r = call(t, srv, "GET", "/v1/zones/pri.test/records", "")
	if r.status != 200 || strings.Contains(r.raw, "RRSIG") {
		t.Fatalf("records: %s", r.raw)
	}
	// history keeps the actor of the signing changes
	if r := call(t, srv, "GET", "/v1/zones/pri.test/history", ""); !strings.Contains(r.raw, "dnssec.rollover:zsk") {
		t.Fatalf("history: %s", r.raw)
	}
}

func dataDir(t *testing.T, e interface{ DataDir() string }) string { return e.DataDir() }
