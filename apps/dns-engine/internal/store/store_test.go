package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mrk/dns-engine/internal/zone"
)

func newZone(v int) *zone.Zone {
	return &zone.Zone{Name: "example.com.", Type: zone.TypePrimary, Serial: uint32(2026010100 + v), Version: v,
		UpdatedAt: time.Now(), SOA: zone.DefaultSOA("example.com."),
		Records: []zone.Record{{ID: "ns", Name: "@", Type: "NS", TTL: 60, Data: json.RawMessage(`{"nameserver":"ns1.example.com"}`)}}}
}

func TestAtomicWriteAndPerms(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteJSON("settings.json", map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "settings.json"))
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("perm %v %v", fi.Mode(), err)
	}
	var v map[string]int
	if err := s.ReadJSON("settings.json", &v); err != nil || v["a"] != 1 {
		t.Fatal(v, err)
	}
	// leftover temp files from a crash are removed on open
	tmp := filepath.Join(dir, "zones", ".tmp-123")
	_ = os.WriteFile(tmp, []byte("partial"), 0o600)
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("tmp not cleaned")
	}
}

func TestHistoryPruneAndLoad(t *testing.T) {
	s, _ := Open(t.TempDir())
	for v := 1; v <= HistoryLimit+7; v++ {
		if err := s.SaveZone(newZone(v)); err != nil {
			t.Fatal(err)
		}
	}
	h, err := s.History("example.com.")
	if err != nil || len(h) != HistoryLimit || h[0].Version != HistoryLimit+7 || h[len(h)-1].Version != 8 {
		t.Fatalf("history %d %v", len(h), err)
	}
	if _, err := s.LoadVersion("example.com.", 3); err == nil {
		t.Fatal("pruned version still present")
	}
	zs, warn := s.LoadZones()
	if len(zs) != 1 || zs[0].Version != HistoryLimit+7 || len(warn) != 0 {
		t.Fatalf("load %v %v", zs, warn)
	}
	if err := s.DeleteZone("example.com."); err != nil {
		t.Fatal(err)
	}
	if zs, _ := s.LoadZones(); len(zs) != 0 {
		t.Fatal("deleted zone came back")
	}
}

func TestCrashRecovery(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	_ = s.SaveZone(newZone(1))
	_ = s.SaveZone(newZone(2))
	// 1) corrupt main file (torn write on a filesystem without atomic rename): history wins
	_ = os.WriteFile(filepath.Join(dir, "zones", "example.com.json"), []byte("{trunc"), 0o640)
	zs, warn := s.LoadZones()
	if len(zs) != 1 || zs[0].Version != 2 || len(warn) != 1 {
		t.Fatalf("recover corrupt: %v %v", zs, warn)
	}
	// 2) crash after writing history v3 but before the main file: v3 is loaded
	z3, _ := json.Marshal(newZone(3))
	_ = os.WriteFile(filepath.Join(dir, "zones", "example.com.history", "00000003.json"), z3, 0o640)
	_ = s.SaveZone(newZone(2)) // main is v2 again
	_ = os.WriteFile(filepath.Join(dir, "zones", "example.com.history", "00000003.json"), z3, 0o640)
	zs, _ = s.LoadZones()
	if zs[0].Version != 3 {
		t.Fatalf("want v3 got %d", zs[0].Version)
	}
	// 3) a new zone whose main file never got written is recovered from history
	other := newZone(1)
	other.Name = "example.org."
	b, _ := json.Marshal(other)
	_ = os.MkdirAll(filepath.Join(dir, "zones", "example.org.history"), 0o750)
	_ = os.WriteFile(filepath.Join(dir, "zones", "example.org.history", "00000001.json"), b, 0o640)
	zs, _ = s.LoadZones()
	if len(zs) != 2 {
		t.Fatalf("want 2 zones, got %d", len(zs))
	}
}
