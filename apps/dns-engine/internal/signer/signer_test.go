package signer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestKeyStoreAndRollover(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	ks, err := NewKeySet("example.test.", AlgED25519, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(ks); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "example.test.keys.json"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode())
		}
	}
	back, err := st.Load("example.test.")
	if err != nil || len(back.Keys) != 2 || back.Keys[0].signer == nil {
		t.Fatalf("load %v %v", back, err)
	}
	tm := Timing{ZSKPublish: time.Hour, ZSKRetire: 2 * time.Hour, KSKRetire: 3 * time.Hour}
	if err := back.Rollover(RoleZSK, now); err != nil {
		t.Fatal(err)
	}
	if err := back.Rollover(RoleZSK, now); err != ErrRolloverInProgress {
		t.Fatalf("second rollover: %v", err)
	}
	if back.Advance(now.Add(30*time.Minute), tm) {
		t.Fatal("advanced too early")
	}
	if !back.Advance(now.Add(time.Hour), tm) || len(back.signers(RoleZSK)) != 1 || len(back.Keys) != 3 {
		t.Fatalf("switch: %+v", back.Keys)
	}
	if !back.Advance(now.Add(3*time.Hour), tm) || len(back.Keys) != 2 {
		t.Fatalf("retire: %+v", back.Keys)
	}
	if err := back.Rollover(RoleKSK, now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(back.signers(RoleKSK)) != 2 || len(back.DS()) != 2 {
		t.Fatal("double signature")
	}
	back.Advance(now.Add(7*time.Hour), tm)
	if len(back.KSKs()) != 1 {
		t.Fatal("old ksk kept")
	}
	// signing output
	soa, _ := dns.NewRR("example.test. 900 IN SOA ns1.example.test. h.example.test. 1 3600 600 604800 300")
	a, _ := dns.NewRR("www.example.test. 300 IN A 192.0.2.1")
	res, err := Sign("example.test.", []dns.RR{soa, a}, back, Params{Validity: 14 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Expiration.Equal(now.Add(14 * 24 * time.Hour)) {
		t.Fatal(res.Expiration)
	}
	types := map[uint16]int{}
	for _, rr := range res.RRs {
		types[rr.Header().Rrtype]++
	}
	if types[dns.TypeDNSKEY] != 2 || types[dns.TypeNSEC] != 2 || types[dns.TypeCDS] != 1 || types[dns.TypeRRSIG] < 6 {
		t.Fatalf("types %v", types)
	}
}
