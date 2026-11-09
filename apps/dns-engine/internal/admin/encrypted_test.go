package admin

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTLSAndTokenAPI(t *testing.T) {
	srv, _ := setup(t)
	if r := call(t, srv, "GET", "/v1/tls", ""); r.status != 200 || r.body["present"] != false || r.body["source"] != nil {
		t.Fatalf("empty tls: %+v", r)
	}
	if r := call(t, srv, "PUT", "/v1/tls", `{"cert_pem":"x","key_pem":"y"}`); r.status != 422 || errCode(r) != "tls_invalid" ||
		!strings.Contains(r.raw, `"reason_code":"bad_pem"`) {
		t.Fatalf("bad pem: %+v", r)
	}
	// enabling DoT without a certificate
	r := call(t, srv, "GET", "/v1/settings", "")
	cv := r.body["config_version"].(float64)
	body := `{"config_version":` + itoa(cv) + `,"encrypted":{"dot":{"enabled":true,"listen":["127.0.0.1:8853"]}}}`
	if r := call(t, srv, "PUT", "/v1/settings", body); r.status != 422 || errCode(r) != "certificate_required" {
		t.Fatalf("certificate_required: %+v", r)
	}
	r = call(t, srv, "POST", "/v1/tls/self-signed", `{"names":["dns.example.com","127.0.0.1"]}`)
	if r.status != 200 || r.body["present"] != true || r.body["source"] != "self_signed" || r.body["self_signed"] != true {
		t.Fatalf("self-signed: %+v", r)
	}
	if strings.Contains(strings.ToLower(r.raw), "private") || strings.Contains(r.raw, "key_pem") {
		t.Fatal("private key leaked")
	}
	if r := call(t, srv, "PUT", "/v1/settings", body); r.status != 200 {
		t.Fatalf("enable dot: %+v", r)
	}
	if r := call(t, srv, "DELETE", "/v1/tls", ""); r.status != 409 || errCode(r) != "certificate_in_use" {
		t.Fatalf("delete in use: %+v", r)
	}
	st := call(t, srv, "GET", "/v1/status", "")
	enc, _ := st.body["encrypted"].(map[string]any)
	if c, _ := enc["certificate"].(map[string]any); c["present"] != true || c["days_left"] == nil {
		t.Fatalf("status.encrypted %v", enc)
	}

	r = call(t, srv, "POST", "/v1/doh/tokens", `{"name":"laptop","qps":20}`)
	if r.status != 201 || len(r.body["token"].(string)) != 43 || r.body["qps"] != float64(20) {
		t.Fatalf("create token: %+v", r)
	}
	id := r.body["id"].(string)
	l := call(t, srv, "GET", "/v1/doh/tokens", "")
	if l.status != 200 || strings.Contains(l.raw, r.body["token"].(string)) || strings.Contains(l.raw, "sha256") {
		t.Fatalf("list leaks the token: %s", l.raw)
	}
	var lv struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal([]byte(l.raw), &lv)
	if len(lv.Items) != 1 || lv.Items[0]["queries"] != float64(0) || lv.Items[0]["name"] != "laptop" {
		t.Fatalf("items %v", lv.Items)
	}
	if r := call(t, srv, "PATCH", "/v1/doh/tokens/"+id, `{"qps":0}`); r.status != 422 {
		t.Fatalf("bad qps: %+v", r)
	}
	if r := call(t, srv, "PATCH", "/v1/doh/tokens/"+id, `{"name":"work"}`); r.status != 200 || r.body["name"] != "work" {
		t.Fatalf("patch: %+v", r)
	}
	if r := call(t, srv, "DELETE", "/v1/doh/tokens/"+id, ""); r.status != 204 {
		t.Fatalf("delete: %+v", r)
	}
	if r := call(t, srv, "DELETE", "/v1/doh/tokens/"+id, ""); r.status != 404 || errCode(r) != "token_not_found" {
		t.Fatalf("delete again: %+v", r)
	}
}
