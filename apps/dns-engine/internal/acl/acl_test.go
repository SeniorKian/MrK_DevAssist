package acl

import (
	"net/netip"
	"testing"
)

func TestACL(t *testing.T) {
	l := MustCompile([]string{"!10.0.0.5", "10.0.0.0/8", "::1/128", "::ffff:192.168.1.0/120"})
	for addr, want := range map[string]bool{
		"10.1.2.3": true, "10.0.0.5": false, "11.0.0.1": false, "::1": true, "::ffff:10.2.3.4": true,
		"192.168.1.7": true, "2001:db8::1": false,
	} {
		if got := l.Allowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: got %v want %v", addr, got, want)
		}
	}
	if (&List{}).Allowed(netip.MustParseAddr("127.0.0.1")) || (*List)(nil).Allowed(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("empty list must deny")
	}
	all := MustCompile([]string{"0.0.0.0/0", "::/0"})
	if !all.Allowed(netip.MustParseAddr("8.8.8.8")) || !all.allowAll {
		t.Fatal("allow all")
	}
	if _, err := Compile([]string{"10.0.0.0/33"}); err == nil {
		t.Fatal("bad prefix accepted")
	}
	if _, err := Compile([]string{"!"}); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestPrivate(t *testing.T) {
	for addr, want := range map[string]bool{
		"10.0.0.1": true, "172.17.0.1": true, "192.168.0.1": true, "127.0.0.1": true, "100.64.1.1": true,
		"169.254.1.1": true, "0.0.0.0": true, "fd00::1": true, "fe80::1": true, "::1": true,
		"8.8.8.8": false, "2606:4700::1111": false, "1.1.1.1": false,
	} {
		if Private(netip.MustParseAddr(addr)) != want {
			t.Errorf("%s want %v", addr, want)
		}
	}
}
