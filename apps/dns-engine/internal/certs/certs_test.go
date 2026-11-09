package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mrk/dns-engine/internal/fielderr"
)

func mkCert(t *testing.T, key crypto.Signer, names []string, nb, na time.Time) (string, string) {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: nb, NotAfter: na,
		DNSNames: names}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

func reason(t *testing.T, err error) string {
	t.Helper()
	var fe *fielderr.Error
	if !errors.As(err, &fe) || fe.Code != CodeInvalid || len(fe.Fields) != 1 {
		t.Fatalf("want tls_invalid, got %v", err)
	}
	return fe.Fields[0].ReasonCode
}

func TestUploadValidation(t *testing.T) {
	now := time.Now()
	s, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good, goodKey := mkCert(t, k1, []string{"dns.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	_, otherKey := mkCert(t, k2, []string{"x"}, now.Add(-time.Hour), now.Add(time.Hour))
	expired, expiredKey := mkCert(t, k1, []string{"dns.example.com"}, now.Add(-48*time.Hour), now.Add(-time.Hour))
	noNames, noNamesKey := mkCert(t, k1, nil, now.Add(-time.Hour), now.Add(time.Hour))
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakCert, weakKey := mkCert(t, weak, []string{"a.example"}, now.Add(-time.Hour), now.Add(time.Hour))
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	p224Cert, p224Key := mkCert(t, p224, []string{"a.example"}, now.Add(-time.Hour), now.Add(time.Hour))

	cases := []struct {
		name, cert, key, want string
	}{
		{"garbage", "hello", goodKey, "bad_pem"},
		{"key as cert", goodKey, goodKey, "bad_pem"},
		{"bad key", good, "nope", "bad_pem"},
		{"mismatch", good, otherKey, "key_mismatch"},
		{"expired", expired, expiredKey, "expired"},
		{"no names", noNames, noNamesKey, "no_names"},
		{"weak rsa", weakCert, weakKey, "weak_key"},
		{"p224", p224Cert, p224Key, "weak_key"},
		{"too large", good + strings.Repeat(" ", MaxPEM), goodKey, "too_large"},
	}
	for _, c := range cases {
		if _, err := s.Put(c.cert, c.key); reason(t, err) != c.want {
			t.Fatalf("%s: want %s, got %v", c.name, c.want, err)
		}
	}
	if s.Present() {
		t.Fatal("invalid uploads must not be stored")
	}
	// a chain (leaf + another certificate) is accepted
	v, err := s.Put(good+noNames, goodKey)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Present || *v.Source != SourceUploaded || v.Names[0] != "dns.example.com" || v.KeyType != "ECDSA-P-256" || len(v.Fingerprint) != 64 {
		t.Fatalf("view %+v", v)
	}
	b, _ := os.ReadFile(filepath.Join(s.dir, "key.pem"))
	if string(b) != goodKey {
		t.Fatal("key not stored")
	}
	if fi, _ := os.Stat(filepath.Join(s.dir, "key.pem")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", fi.Mode())
	}
	// reload from disk
	s2, err := Open(filepath.Dir(s.dir), nil)
	if err != nil || s2.Fingerprint() != s.Fingerprint() || len(s2.cur.Load().cert.Certificate) != 2 {
		t.Fatalf("reload: %v", err)
	}
	if err := s2.Delete(); err != nil || s2.Present() {
		t.Fatal("delete")
	}
	if v := s2.View(); v.Present || v.Source != nil || v.Names == nil {
		t.Fatalf("empty view %+v", v)
	}
}

func TestSelfSignedAndRenew(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s, _ := Open(t.TempDir(), clock)
	if _, err := s.SelfSigned([]string{"bad name!"}); err == nil {
		t.Fatal("invalid name accepted")
	}
	if _, err := s.SelfSigned(nil); err == nil {
		t.Fatal("empty names accepted")
	}
	v, err := s.SelfSigned([]string{"DNS.Example.com.", "192.0.2.1", "dns.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !v.SelfSigned || *v.Source != SourceSelfSigned || v.KeyType != "ECDSA-P-256" || len(v.Names) != 2 {
		t.Fatalf("view %+v", v)
	}
	leaf, _ := s.Leaf()
	if d := leaf.NotAfter.Sub(now); d < 396*24*time.Hour || d > 398*24*time.Hour {
		t.Fatalf("validity %v", d)
	}
	fp := s.Fingerprint()
	if renewed, _ := s.RenewIfDue(); renewed {
		t.Fatal("renewed too early")
	}
	now = leaf.NotAfter.Add(-29 * 24 * time.Hour)
	if renewed, err := s.RenewIfDue(); !renewed || err != nil || s.Fingerprint() == fp {
		t.Fatalf("not renewed: %v", err)
	}
	if v := s.View(); len(v.Names) != 2 {
		t.Fatalf("names lost on renew: %v", v.Names)
	}
	// uploaded certificates are never renewed
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, kp := mkCert(t, k, []string{"a.example"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := s.Put(c, kp); err != nil {
		t.Fatal(err)
	}
	if renewed, _ := s.RenewIfDue(); renewed {
		t.Fatal("uploaded certificate renewed")
	}
}
