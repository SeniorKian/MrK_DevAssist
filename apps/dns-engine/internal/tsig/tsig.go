// Package tsig keeps the engine's TSIG keys (RFC 8945) and signs/verifies
// messages with them. Keys live in <data dir>/tsig.json with mode 0600; the
// secret is returned only once, by Create.
package tsig

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/store"
)

// Algorithms accepted by the API.
const (
	HMACSHA256 = "hmac-sha256"
	HMACSHA512 = "hmac-sha512"
)

// MaxKeys bounds the key store.
const MaxKeys = 256

// Fudge is the permitted clock skew in seconds (RFC 8945 recommends 300).
const Fudge = 300

// Error codes.
const (
	CodeInvalid  = "tsig_invalid"
	CodeExists   = "tsig_key_exists"
	CodeNotFound = "tsig_key_not_found"
	CodeInUse    = "tsig_key_in_use"
)

// Key is one stored key.
type Key struct {
	Name      string    `json:"name"` // display form, no trailing dot
	Algorithm string    `json:"algorithm"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
}

// View is a key without its secret.
type View struct {
	Name      string    `json:"name"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
}

// Created is the one response that includes the secret.
type Created struct {
	View
	Secret string `json:"secret"`
}

type doc struct {
	V    int   `json:"v"`
	Keys []Key `json:"keys"`
}

// Store is safe for concurrent use.
type Store struct {
	path string
	mu   sync.RWMutex
	keys map[string]Key // FQDN -> key
}

// Open loads path (missing = empty store).
func Open(path string) (*Store, error) {
	keys, err := readKeys(path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return &Store{path: path, keys: keys}, nil
}

// readKeys parses a key file (missing = no keys).
func readKeys(path string) (map[string]Key, error) {
	keys := map[string]Key{}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return keys, nil
	}
	if err != nil {
		return nil, err
	}
	var d doc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("tsig keys: %w", err)
	}
	for _, k := range d.Keys {
		keys[dns.Fqdn(k.Name)] = k
	}
	return keys, nil
}

// Validate checks a key file without loading it (backup restore).
func Validate(path string) error {
	_, err := readKeys(path)
	return err
}

// Reload replaces the keys with the content of the file (backup restore).
func (s *Store) Reload() error {
	keys, err := readKeys(s.path)
	if err != nil {
		return err
	}
	_ = os.Chmod(s.path, 0o600)
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
	return nil
}

func (s *Store) saveLocked() error {
	d := doc{V: 1, Keys: []Key{}}
	for _, k := range s.keys {
		d.Keys = append(d.Keys, k)
	}
	sort.Slice(d.Keys, func(i, j int) bool { return d.Keys[i].Name < d.Keys[j].Name })
	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	return store.WriteFileAtomic(s.path, append(b, '\n'), 0o600)
}

// NormalizeName validates a key name and returns its FQDN.
func NormalizeName(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	if n == "" || len(n) > 253 {
		return "", false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return n + ".", true
}

// WireAlgorithm maps the API name to the TSIG algorithm name.
func WireAlgorithm(alg string) string {
	if alg == HMACSHA512 {
		return dns.HmacSHA512
	}
	return dns.HmacSHA256
}

// List returns all keys without secrets, sorted by name.
func (s *Store) List() []View {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]View, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, View{Name: k.Name, Algorithm: k.Algorithm, CreatedAt: k.CreatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Has reports whether a key exists (name in any form).
func (s *Store) Has(name string) bool {
	_, ok := s.Get(name)
	return ok
}

// Get returns a key by name.
func (s *Store) Get(name string) (Key, bool) {
	fq, ok := NormalizeName(name)
	if !ok {
		return Key{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[fq]
	return k, ok
}

// Create adds a key; an empty secret is generated (32 random bytes).
func (s *Store) Create(name, alg, secret string, now time.Time) (Created, error) {
	var l fielderr.List
	fq, ok := NormalizeName(name)
	if !ok {
		l.Add("name", "invalid_name")
	}
	if alg == "" {
		alg = HMACSHA256
	}
	if alg != HMACSHA256 && alg != HMACSHA512 {
		l.Add("algorithm", "invalid_choice", "choices", []string{HMACSHA256, HMACSHA512})
	}
	if secret == "" {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return Created{}, err
		}
		secret = base64.StdEncoding.EncodeToString(b[:])
	} else if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(secret)); err != nil {
		l.Add("secret", "invalid_base64")
	} else if len(raw) < 16 || len(raw) > 128 {
		l.Add("secret", "invalid_length", "min_bytes", 16, "max_bytes", 128)
	} else {
		secret = base64.StdEncoding.EncodeToString(raw)
	}
	if len(l) > 0 {
		return Created{}, l.Err(CodeInvalid, "invalid TSIG key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[fq]; ok {
		return Created{}, fielderr.Single(CodeExists, "a TSIG key with this name exists", "name", "duplicate")
	}
	if len(s.keys) >= MaxKeys {
		return Created{}, fielderr.New("limit_reached", "too many TSIG keys")
	}
	k := Key{Name: strings.TrimSuffix(fq, "."), Algorithm: alg, Secret: secret, CreatedAt: now.UTC().Truncate(time.Second)}
	s.keys[fq] = k
	if err := s.saveLocked(); err != nil {
		delete(s.keys, fq)
		return Created{}, err
	}
	return Created{View: View{Name: k.Name, Algorithm: k.Algorithm, CreatedAt: k.CreatedAt}, Secret: secret}, nil
}

// Delete removes a key.
func (s *Store) Delete(name string) error {
	fq, ok := NormalizeName(name)
	if !ok {
		return fielderr.New(CodeNotFound, "TSIG key not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.keys[fq]
	if !ok {
		return fielderr.New(CodeNotFound, "TSIG key not found")
	}
	delete(s.keys, fq)
	if err := s.saveLocked(); err != nil {
		s.keys[fq] = old
		return err
	}
	return nil
}

// Secrets returns name (FQDN) -> secret for miekg/dns clients.
func (s *Store) Secrets() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := make(map[string]string, len(s.keys))
	for fq, k := range s.keys {
		m[fq] = k.Secret
	}
	return m
}

// ---------------------------------------------------------------- messages

// Verdict of a request TSIG check.
type Verdict struct {
	Signed bool   // the request carries a TSIG RR
	OK     bool   // signature valid
	Key    string // key name (FQDN) when signed
	MAC    string // request MAC (for signing the response)
	Error  uint16 // TSIG error (BADKEY, BADSIG, BADTIME) when !OK
}

// Check verifies the TSIG of a request (raw wire bytes and decoded form).
func (s *Store) Check(pkt []byte, m *dns.Msg) Verdict {
	t := m.IsTsig()
	if t == nil {
		return Verdict{}
	}
	v := Verdict{Signed: true, Key: strings.ToLower(t.Hdr.Name), MAC: t.MAC}
	k, ok := s.Get(v.Key)
	if !ok || !strings.EqualFold(dns.Fqdn(t.Algorithm), WireAlgorithm(k.Algorithm)) {
		v.Error = dns.RcodeBadKey
		return v
	}
	if err := dns.TsigVerify(pkt, k.Secret, "", false); err != nil {
		v.Error = dns.RcodeBadSig
		if errors.Is(err, dns.ErrTime) {
			v.Error = dns.RcodeBadTime
		}
		return v
	}
	v.OK = true
	return v
}

// Sign packs m signed with key; reqMAC is the request MAC (or the previous
// message MAC with timersOnly for later messages of a transfer).
func (s *Store) Sign(m *dns.Msg, key, reqMAC string, timersOnly bool) ([]byte, string, error) {
	k, ok := s.Get(key)
	if !ok {
		return nil, "", fmt.Errorf("tsig key %s not found", key)
	}
	m.SetTsig(dns.Fqdn(strings.ToLower(k.Name)), WireAlgorithm(k.Algorithm), Fudge, time.Now().Unix())
	return dns.TsigGenerate(m, k.Secret, reqMAC, timersOnly)
}

// ErrorResponse turns resp into the unsigned NOTAUTH answer for a failed
// request TSIG (RFC 8945 §5.2).
func ErrorResponse(resp *dns.Msg, req *dns.Msg, v Verdict) []byte {
	resp.Rcode = dns.RcodeNotAuth
	t := req.IsTsig()
	if t != nil {
		resp.Extra = append(resp.Extra, &dns.TSIG{Hdr: dns.RR_Header{Name: t.Hdr.Name, Rrtype: dns.TypeTSIG, Class: dns.ClassANY},
			Algorithm: t.Algorithm, TimeSigned: uint64(time.Now().Unix()), Fudge: Fudge, OrigId: req.Id, Error: v.Error})
	}
	b, err := resp.Pack()
	if err != nil {
		return nil
	}
	return b
}
