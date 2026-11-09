package config

import (
	"encoding/json"
	"testing"
)

func reasons(s Settings) map[string]string {
	out := map[string]string{}
	for _, f := range s.Validate() {
		out[f.Field] = f.ReasonCode
	}
	return out
}

func TestEncryptedDefaultsAndValidation(t *testing.T) {
	d := Defaults("")
	if l := d.Validate(); len(l) > 0 {
		t.Fatal(l)
	}
	// settings stored before D4 get the section from defaults
	var old Settings
	_ = json.Unmarshal([]byte(`{"listen":[{"address":"127.0.0.1:53","udp":true,"tcp":true}]}`), &old)
	old.FillD4Defaults()
	if old.Encrypted.MaxConnections != 2000 || old.Encrypted.DoH.Path != "/dns-query" || old.Encrypted.Allow != nil ||
		len(old.Encrypted.DoH.TrustedProxies) != 5 {
		t.Fatalf("defaults %+v", old.Encrypted)
	}
	b, _ := json.Marshal(d.Encrypted)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if v, ok := m["allow"]; !ok || v != nil {
		t.Fatalf("allow must serialise as null: %s", b)
	}

	s := Defaults("127.0.0.1:53")
	s.Encrypted.DoT = EncListener{Enabled: true, Listen: []string{"0.0.0.0:853"}}
	s.Encrypted.DoQ = EncListener{Enabled: true, Listen: []string{"0.0.0.0:853"}} // tcp and udp: no conflict
	if r := reasons(s); len(r) > 0 {
		t.Fatal(r)
	}
	s.Encrypted.DoH.Enabled = true
	s.Encrypted.DoH.Listen = []string{"127.0.0.1:853"} // same tcp port as DoT on 0.0.0.0
	if r := reasons(s); r["encrypted.doh.listen[0]"] != "listen_conflict" {
		t.Fatal(r)
	}
	s.Encrypted.DoH.Listen = []string{"127.0.0.1:53"} // the plain TCP listener
	if r := reasons(s); r["encrypted.doh.listen[0]"] != "listen_conflict" {
		t.Fatal(r)
	}
	s.Encrypted.DoH.Listen = []string{"0.0.0.0:8053"}
	s.Encrypted.DoH.TLS = false
	if r := reasons(s); r["encrypted.doh.listen[0]"] != "plain_doh_public" {
		t.Fatal(r)
	}
	s.Encrypted.DoH.Listen = []string{"127.0.0.1:8053", "172.17.0.1:8053", "203.0.113.5:8053"}
	if r := reasons(s); r["encrypted.doh.listen[2]"] != "plain_doh_public" || len(r) != 1 {
		t.Fatal(r)
	}
	s.Encrypted.DoH.Listen = []string{"127.0.0.1:8053", "127.0.0.1:8053"}
	if r := reasons(s); r["encrypted.doh.listen[1]"] != "duplicate" {
		t.Fatal(r)
	}
	s.Encrypted.DoH.Listen = []string{"127.0.0.1:8053"}
	allow := []string{"203.0.113.0/24", "0.0.0.0/0"}
	s.Encrypted.Allow = &allow
	s.Encrypted.DoH.Path = "dns-query"
	s.Encrypted.DoH.TrustedProxies = []string{"bad"}
	s.Encrypted.MaxConnections = 5
	if r := reasons(s); r["encrypted.allow[1]"] != "open_resolver" || r["encrypted.doh.path"] != "invalid_path" ||
		r["encrypted.doh.trusted_proxies[0]"] != "invalid_network" || r["encrypted.max_connections"] != "out_of_range" {
		t.Fatal(r)
	}
	// clone is deep
	allow = []string{"10.0.0.0/8"}
	c := s.Clone()
	(*c.Encrypted.Allow)[0] = "192.168.0.0/16"
	c.Encrypted.DoT.Listen[0] = "x"
	if (*s.Encrypted.Allow)[0] != "10.0.0.0/8" || s.Encrypted.DoT.Listen[0] != "0.0.0.0:853" {
		t.Fatal("clone shares slices")
	}
}

func TestParseQUICUpstream(t *testing.T) {
	a, err := ParseUpstream("quic://94.140.14.14#dns.adguard-dns.com")
	if err != nil || a.Proto != ProtoDoQ || a.Addr != "94.140.14.14:853" || a.ServerName != "dns.adguard-dns.com" {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := ParseUpstream("quic://dns.example:853"); err == nil {
		t.Fatal("host name without bootstrap accepted")
	}
}
