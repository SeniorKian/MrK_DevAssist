package config

import "testing"

func TestDefaultsValid(t *testing.T) {
	s := Defaults("")
	if l := s.Validate(); len(l) > 0 {
		t.Fatalf("defaults invalid: %v", l)
	}
	if len(s.Listen) != 2 || s.Listen[1].Address != "172.17.0.1:53" {
		t.Fatalf("listen %v", s.Listen)
	}
	if s.Recursion.Allow[0] != "127.0.0.0/8" || s.Limits.UDPMaxSize != 1232 {
		t.Fatal("defaults")
	}
}

func TestValidate(t *testing.T) {
	s := Defaults("127.0.0.1:53")
	s.Listen = append(s.Listen, Listen{Address: "nope"}, Listen{Address: "127.0.0.1:53", UDP: true})
	s.Recursion.Allow = []string{"10.0.0.0/8", "bogus", "0.0.0.0/0", "!::/0"}
	s.Upstreams = append(s.Upstreams, Upstream{ID: "Bad ID", Address: "x"}, Upstream{ID: "google", Address: "8.8.4.4"})
	s.UpstreamStrategy = "random"
	s.Cache.MaxBytes = 10
	s.Cache.MinTTL, s.Cache.MaxTTL = 100, 50
	s.Limits.ClientQPS, s.Limits.ClientBurst = 100, 10
	s.Limits.UDPMaxSize = 100
	l := s.Validate()
	want := []string{"listen[1].address", "listen[2].address", "recursion.allow[1]", "recursion.allow[2]", "upstreams[3].id", "upstreams[3].address",
		"upstreams[4].id", "upstream_strategy", "cache.max_bytes", "cache.min_ttl", "limits.client_burst", "limits.udp_max_size"}
	got := map[string]bool{}
	for _, f := range l {
		got[f.Field] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing field error %s (got %v)", w, l)
		}
	}
}

func TestParseUpstream(t *testing.T) {
	ok := map[string]UpstreamAddr{
		"1.1.1.1":                              {Proto: ProtoUDP, Addr: "1.1.1.1:53"},
		"1.1.1.1:5353":                         {Proto: ProtoUDP, Addr: "1.1.1.1:5353"},
		"[2606:4700::1111]:53":                 {Proto: ProtoUDP, Addr: "[2606:4700::1111]:53"},
		"tcp://9.9.9.9":                        {Proto: ProtoTCP, Addr: "9.9.9.9:53"},
		"tls://1.1.1.1:853#cloudflare-dns.com": {Proto: ProtoDoT, Addr: "1.1.1.1:853", ServerName: "cloudflare-dns.com"},
		"tls://1.1.1.1":                        {Proto: ProtoDoT, Addr: "1.1.1.1:853", ServerName: "1.1.1.1"},
		"https://1.1.1.1/dns-query":            {Proto: ProtoDoH, Addr: "1.1.1.1:443", ServerName: "1.1.1.1", URL: "https://1.1.1.1/dns-query"},
	}
	for in, want := range ok {
		got, err := ParseUpstream(in)
		if err != nil || got.Proto != want.Proto || got.Addr != want.Addr || got.ServerName != want.ServerName || (want.URL != "" && got.URL != want.URL) {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	d, err := ParseUpstream("https://dns.google/dns-query#8.8.8.8,8.8.4.4")
	if err != nil || d.Addr != "" || len(d.Bootstrap) != 2 || d.ServerName != "dns.google" {
		t.Errorf("doh bootstrap %+v %v", d, err)
	}
	for _, bad := range []string{"", "dns.google", "tls://dns.google:853", "https://user@x/q", "https://x/q?a=1",
		"1.1.1.1:0", "https://x/#bad-ip", "tls://1.1.1.1#bad name"} {
		if _, err := ParseUpstream(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
