// Package certs is the TLS certificate store of the encrypted listeners
// (docs/40 §3 /v1/tls): an uploaded chain or a self-signed ECDSA P-256
// certificate, persisted 0600 in the engine data dir and served through
// tls.Config.GetCertificate so a change applies without restarting
// listeners. The private key is never returned.
package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/store"
)

// Sources.
const (
	SourceUploaded   = "uploaded"
	SourceSelfSigned = "self_signed"
)

// Limits and schedules.
const (
	MaxPEM         = 64 << 10
	SelfSignedLife = 397 * 24 * time.Hour
	RenewBefore    = 30 * 24 * time.Hour
	MaxNames       = 32
)

// Error codes.
const (
	CodeInvalid = "tls_invalid"
)

// View is GET /v1/tls.
type View struct {
	Present     bool     `json:"present"`
	Source      *string  `json:"source"`
	Subject     string   `json:"subject,omitempty"`
	Names       []string `json:"names"`
	Issuer      string   `json:"issuer,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	Fingerprint string   `json:"fingerprint_sha256,omitempty"`
	SelfSigned  bool     `json:"self_signed"`
	KeyType     string   `json:"key_type,omitempty"`
}

type loaded struct {
	cert   *tls.Certificate
	leaf   *x509.Certificate
	source string
}

// Store holds the current certificate.
type Store struct {
	dir string
	mu  sync.Mutex
	cur atomic.Pointer[loaded]
	now func() time.Time
}

type meta struct {
	Source string `json:"source"`
}

// Open loads the stored certificate (if any) from dir/tls.
func Open(dataDir string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{dir: filepath.Join(dataDir, "tls"), now: now}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	cp, err := os.ReadFile(filepath.Join(s.dir, "cert.pem"))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	} else if err != nil {
		return nil, err
	}
	kp, err := os.ReadFile(filepath.Join(s.dir, "key.pem"))
	if err != nil {
		return nil, err
	}
	var m meta
	if b, err := os.ReadFile(filepath.Join(s.dir, "meta.json")); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if m.Source != SourceSelfSigned {
		m.Source = SourceUploaded
	}
	l, err := parse(cp, kp, time.Time{}) // a stored certificate is loaded even when expired (events report it)
	if err != nil {
		return nil, fmt.Errorf("stored certificate: %w", err)
	}
	l.source = m.Source
	s.cur.Store(l)
	return s, nil
}

func invalid(reason, msg string) error {
	field := "cert_pem"
	if strings.HasPrefix(msg, "key_pem") || strings.HasPrefix(msg, "private key") || reason == "weak_key" {
		field = "key_pem"
	}
	return fielderr.Single(CodeInvalid, msg, field, reason)
}

// parse validates a PEM chain and key. now zero skips the expiry check.
func parse(certPEM, keyPEM []byte, now time.Time) (*loaded, error) {
	if len(certPEM)+len(keyPEM) > MaxPEM {
		return nil, invalid("too_large", "certificate and key exceed 64 KiB")
	}
	var chain [][]byte
	rest := certPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, invalid("bad_pem", "cert_pem may contain only CERTIFICATE blocks")
		}
		chain = append(chain, b.Bytes)
	}
	if len(chain) == 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, invalid("bad_pem", "cert_pem is not a PEM certificate chain")
	}
	var leaf *x509.Certificate
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, invalid("bad_pem", fmt.Sprintf("certificate %d cannot be parsed", i+1))
		}
		if i == 0 {
			leaf = c
		}
	}
	kb, krest := pem.Decode(keyPEM)
	if kb == nil || len(bytes.TrimSpace(krest)) > 0 || !strings.HasSuffix(kb.Type, "PRIVATE KEY") {
		return nil, invalid("bad_pem", "key_pem is not a single PEM private key")
	}
	key, err := parseKey(kb.Bytes)
	if err != nil {
		return nil, invalid("bad_pem", "private key cannot be parsed")
	}
	if !samePublic(leaf.PublicKey, key) {
		return nil, invalid("key_mismatch", "private key does not match the certificate")
	}
	if !strongKey(leaf.PublicKey) {
		return nil, invalid("weak_key", "key must be RSA >= 2048, ECDSA P-256/P-384 or Ed25519")
	}
	if !now.IsZero() && (now.After(leaf.NotAfter) || now.Before(leaf.NotBefore.Add(-24*time.Hour))) {
		return nil, invalid("expired", "certificate is expired or not yet valid")
	}
	if len(names(leaf)) == 0 {
		return nil, invalid("no_names", "certificate has no DNS name or IP address")
	}
	tc := &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}
	return &loaded{cert: tc, leaf: leaf}, nil
}

func parseKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("unsupported key")
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported key")
}

func samePublic(pub any, key crypto.Signer) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	p, ok := key.Public().(eq)
	return ok && p.Equal(pub)
}

func strongKey(pub any) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384()
	case ed25519.PublicKey:
		return true
	}
	return false
}

func keyType(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return "unknown"
}

func names(c *x509.Certificate) []string {
	out := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// Put validates and stores an uploaded chain and key.
func (s *Store) Put(certPEM, keyPEM string) (View, error) {
	l, err := parse([]byte(certPEM), []byte(keyPEM), s.now())
	if err != nil {
		return View{}, err
	}
	l.source = SourceUploaded
	if err := s.save(l, []byte(certPEM), []byte(keyPEM)); err != nil {
		return View{}, err
	}
	return s.View(), nil
}

var hostRe = regexp.MustCompile(`^(?i)(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ValidateNames checks self-signed names (host names or IP literals).
func ValidateNames(in []string) ([]string, fielderr.List) {
	var l fielderr.List
	if len(in) == 0 {
		l.Add("names", "required")
	}
	if len(in) > MaxNames {
		l.Add("names", "too_many", "max", MaxNames)
		return nil, l
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for i, n := range in {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if a, err := netip.ParseAddr(n); err == nil {
			n = a.Unmap().String()
		} else if len(n) > 253 || !hostRe.MatchString(n) {
			l.Add(fmt.Sprintf("names[%d]", i), "invalid_name")
			continue
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, l
}

// SelfSigned creates and stores a self-signed ECDSA P-256 certificate.
func (s *Store) SelfSigned(nameList []string) (View, error) {
	ns, l := ValidateNames(nameList)
	if len(l) > 0 {
		return View{}, l.Err(CodeInvalid, "invalid certificate names")
	}
	certPEM, keyPEM, err := generate(ns, s.now())
	if err != nil {
		return View{}, err
	}
	ld, err := parse(certPEM, keyPEM, time.Time{})
	if err != nil {
		return View{}, err
	}
	ld.source = SourceSelfSigned
	if err := s.save(ld, certPEM, keyPEM); err != nil {
		return View{}, err
	}
	return s.View(), nil
}

func generate(ns []string, now time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: ns[0], Organization: []string{"MRK DevAssist DNS"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(SelfSignedLife),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, n := range ns {
		if a, err := netip.ParseAddr(n); err == nil {
			tpl.IPAddresses = append(tpl.IPAddresses, a.AsSlice())
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), nil
}

func (s *Store) save(l *loaded, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mb, _ := json.Marshal(meta{Source: l.source})
	// key first: a crash between the writes leaves the old certificate unusable
	// with the new key, which Open reports instead of serving a mismatched pair
	if err := store.WriteFileAtomic(filepath.Join(s.dir, "key.pem"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := store.WriteFileAtomic(filepath.Join(s.dir, "cert.pem"), certPEM, 0o600); err != nil {
		return err
	}
	if err := store.WriteFileAtomic(filepath.Join(s.dir, "meta.json"), mb, 0o600); err != nil {
		return err
	}
	s.cur.Store(l)
	return nil
}

// Delete removes the certificate.
func (s *Store) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range []string{"cert.pem", "key.pem", "meta.json"} {
		if err := os.Remove(filepath.Join(s.dir, f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	s.cur.Store(nil)
	return nil
}

// Present reports whether a certificate is loaded.
func (s *Store) Present() bool { return s.cur.Load() != nil }

// Valid reports whether a loaded certificate is currently valid.
func (s *Store) Valid() bool {
	l := s.cur.Load()
	return l != nil && s.now().Before(l.leaf.NotAfter)
}

// GetCertificate is for tls.Config (hot reload).
func (s *Store) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if l := s.cur.Load(); l != nil {
		return l.cert, nil
	}
	return nil, errors.New("no certificate configured")
}

// Fingerprint returns the SHA-256 of the leaf ("" when absent).
func (s *Store) Fingerprint() string {
	if l := s.cur.Load(); l != nil {
		h := sha256.Sum256(l.leaf.Raw)
		return hex.EncodeToString(h[:])
	}
	return ""
}

// Leaf returns the current leaf certificate and source.
func (s *Store) Leaf() (*x509.Certificate, string) {
	if l := s.cur.Load(); l != nil {
		return l.leaf, l.source
	}
	return nil, ""
}

// View describes the certificate without the key.
func (s *Store) View() View {
	l := s.cur.Load()
	if l == nil {
		return View{Names: []string{}}
	}
	src := l.source
	c := l.leaf
	return View{Present: true, Source: &src, Subject: c.Subject.String(), Names: names(c), Issuer: c.Issuer.String(),
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		Fingerprint: s.Fingerprint(), SelfSigned: l.source == SourceSelfSigned || bytes.Equal(c.RawIssuer, c.RawSubject),
		KeyType: keyType(c.PublicKey)}
}

// RenewIfDue re-issues a self-signed certificate within RenewBefore of its
// expiry (same names). It reports whether it renewed.
func (s *Store) RenewIfDue() (bool, error) {
	l := s.cur.Load()
	if l == nil || l.source != SourceSelfSigned || s.now().Before(l.leaf.NotAfter.Add(-RenewBefore)) {
		return false, nil
	}
	if _, err := s.SelfSigned(names(l.leaf)); err != nil {
		return false, err
	}
	return true, nil
}
