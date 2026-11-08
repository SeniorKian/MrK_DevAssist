package main

import "testing"

func TestParseBytes(t *testing.T) {
	for in, want := range map[string]int64{"512MiB": 512 << 20, "450m": 450 << 20, "1g": 1 << 30, "400MB": 400e6, "1048576": 1 << 20} {
		if got, err := parseBytes(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "-1m", "0"} {
		if _, err := parseBytes(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseRunAs(t *testing.T) {
	if u, g, err := parseRunAs(""); err != nil || u != 10001 || g != 10001 {
		t.Fatal(u, g, err)
	}
	if u, g, err := parseRunAs("2000:3000"); err != nil || u != 2000 || g != 3000 {
		t.Fatal(u, g, err)
	}
	for _, bad := range []string{"0:0", "0:10001", "10001:0", "x:y", "10001", "-1:5"} {
		if _, _, err := parseRunAs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
