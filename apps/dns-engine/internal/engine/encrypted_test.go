package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"mrk/dns-engine/internal/events"
)

func certEvents(e *Engine) (exp []any, expired int) {
	evs, _ := e.Events(0, 1000)
	for _, ev := range evs {
		switch ev.Type {
		case events.TLSCertificateExpiring:
			exp = append(exp, ev.Data["days_left"])
		case events.TLSCertificateExpired:
			expired++
		}
	}
	return exp, expired
}

func TestCertificateExpiryEvents(t *testing.T) {
	ck := &fakeClock{t: time.Now()}
	e := newEngineClock(t, "127.0.0.1:1", ck, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "dns.example"},
		NotBefore: ck.now().Add(-time.Hour), NotAfter: ck.now().Add(20 * 24 * time.Hour), DNSNames: []string{"dns.example"}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	if _, err := e.PutTLS(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))); err != nil {
		t.Fatal(err)
	}
	e.CheckCertificate()
	if exp, _ := certEvents(e); len(exp) != 0 {
		t.Fatalf("early events %v", exp)
	}
	for _, step := range []time.Duration{7 * 24 * time.Hour, 12 * time.Hour, 7 * 24 * time.Hour, 3 * 24 * time.Hour, 36 * time.Hour} {
		ck.add(step)
		e.CheckCertificate()
	}
	exp, _ := certEvents(e)
	if len(exp) != 4 || exp[0] != 12 || exp[1] != 5 || exp[2] != 2 || exp[3] != 0 {
		t.Fatalf("expiring events %v", exp)
	}
	if st := e.encryptedStatus(); !st.Certificate.Present || *st.Certificate.DaysLeft != 0 || *st.Certificate.SelfSigned {
		t.Fatalf("status %+v", st.Certificate)
	}
	ck.add(2 * 24 * time.Hour)
	e.CheckCertificate()
	e.CheckCertificate()
	if _, n := certEvents(e); n != 1 {
		t.Fatalf("expired events %d", n)
	}
	// a self-signed certificate is renewed by the same check
	if _, err := e.SelfSignedTLS([]string{"dns.example"}); err != nil {
		t.Fatal(err)
	}
	fp := e.enc.certs.Fingerprint()
	ck.add(370 * 24 * time.Hour)
	e.CheckCertificate()
	if e.enc.certs.Fingerprint() == fp {
		t.Fatal("self-signed certificate not renewed")
	}
}
