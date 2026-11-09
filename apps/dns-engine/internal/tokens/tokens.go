// Package tokens holds the DoH access tokens (docs/40 §2.4): a client
// presenting a valid token in /dns-query/<token> is admitted from any IP,
// limited by the token's own qps. Only the SHA-256 of a token is stored
// (tokens.json, 0600) and the lookup compares every hash in constant time.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/store"
)

// Limits.
const (
	MaxTokens  = 200
	DefaultQPS = 50
	MaxQPS     = 10000
	MaxName    = 64
)

// Error codes.
const (
	CodeNotFound     = "token_not_found"
	CodeInvalid      = "token_invalid"
	CodeLimitReached = "limit_reached"
)

// Token is one access token (the secret itself is never kept).
type Token struct {
	ID        string
	Name      string
	QPS       int
	hash      [32]byte
	CreatedAt time.Time

	lastUsed atomic.Int64 // unix nanos
	queries  atomic.Uint64

	mu     sync.Mutex
	tokens float64
	last   int64
}

// Tag is the value stored in the query log's upstream slot.
func (t *Token) Tag() string { return "t:" + t.ID }

// Allow takes one query from the token's bucket (burst = 2 s of qps).
func (t *Token) Allow(now int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	burst := float64(t.QPS * 2)
	if t.last == 0 {
		t.tokens = burst
	} else if dt := float64(now-t.last) / 1e9; dt > 0 {
		t.tokens += dt * float64(t.QPS)
		if t.tokens > burst {
			t.tokens = burst
		}
	}
	t.last = now
	if t.tokens < 1 {
		return false
	}
	t.tokens--
	return true
}

// Used records one query.
func (t *Token) Used(now time.Time) {
	t.queries.Add(1)
	t.lastUsed.Store(now.UnixNano())
}

// View is the API form (GET /v1/doh/tokens items).
type View struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	QPS        int     `json:"qps"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	Queries    uint64  `json:"queries"`
}

// Created is the POST response (the only time the token is shown).
type Created struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	QPS       int    `json:"qps"`
	Token     string `json:"token"`
	CreatedAt string `json:"created_at"`
}

type rec struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	QPS        int       `json:"qps"`
	Hash       string    `json:"sha256"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt int64     `json:"last_used_at,omitempty"`
	Queries    uint64    `json:"queries"`
}

type doc struct {
	V     int   `json:"v"`
	Items []rec `json:"items"`
}

// Store is the token set.
type Store struct {
	st  *store.Store
	now func() time.Time

	mu    sync.Mutex
	list  atomic.Pointer[[]*Token]
	saved uint64 // total queries at the last write (Save skips unchanged usage)
}

const file = "doh-tokens.json"

// Open loads tokens from the engine store.
func Open(st *store.Store, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{st: st, now: now}
	var d doc
	if err := st.ReadJSON(file, &d); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	l := make([]*Token, 0, len(d.Items))
	for _, r := range d.Items {
		b, err := hex.DecodeString(r.Hash)
		if err != nil || len(b) != 32 {
			continue
		}
		t := &Token{ID: r.ID, Name: r.Name, QPS: r.QPS, CreatedAt: r.CreatedAt}
		copy(t.hash[:], b)
		t.lastUsed.Store(r.LastUsedAt)
		t.queries.Store(r.Queries)
		l = append(l, t)
	}
	s.list.Store(&l)
	s.saved = total(l)
	return s, nil
}

func (s *Store) items() []*Token { return *s.list.Load() }

// Lookup finds the token whose hash matches secret. Every stored hash is
// compared in constant time so the timing does not reveal a partial match.
func (s *Store) Lookup(secret string) *Token {
	if secret == "" || len(secret) > 128 {
		return nil
	}
	h := sha256.Sum256([]byte(secret))
	var found *Token
	for _, t := range s.items() {
		if subtle.ConstantTimeCompare(h[:], t.hash[:]) == 1 {
			found = t
		}
	}
	return found
}

// Len returns the number of tokens.
func (s *Store) Len() int { return len(s.items()) }

func view(t *Token) View {
	v := View{ID: t.ID, Name: t.Name, QPS: t.QPS, CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339), Queries: t.queries.Load()}
	if lu := t.lastUsed.Load(); lu > 0 {
		s := time.Unix(0, lu).UTC().Format(time.RFC3339)
		v.LastUsedAt = &s
	}
	return v
}

// List returns all tokens (oldest first).
func (s *Store) List() []View {
	out := []View{}
	for _, t := range s.items() {
		out = append(out, view(t))
	}
	return out
}

func checkName(l *fielderr.List, name string) string {
	name = strings.TrimSpace(name)
	n := utf8.RuneCountInString(name)
	if n < 1 || n > MaxName {
		l.Add("name", "out_of_range", "min", 1, "max", MaxName)
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			l.Add("name", "invalid_characters")
			break
		}
	}
	return name
}

func checkQPS(l *fielderr.List, q int) {
	if q < 1 || q > MaxQPS {
		l.Add("qps", "out_of_range", "min", 1, "max", MaxQPS)
	}
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create adds a token; qps nil = DefaultQPS.
func (s *Store) Create(name string, qps *int) (Created, error) {
	var l fielderr.List
	name = checkName(&l, name)
	q := DefaultQPS
	if qps != nil {
		q = *qps
		checkQPS(&l, q)
	}
	if len(l) > 0 {
		return Created{}, l.Err(CodeInvalid, "invalid token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.items()
	if len(cur) >= MaxTokens {
		return Created{}, &fielderr.Error{Code: CodeLimitReached, Message: fmt.Sprintf("at most %d tokens", MaxTokens)}
	}
	secret, err := randomString(32) // 43 characters
	if err != nil {
		return Created{}, err
	}
	id, err := randomString(9) // 12 characters
	if err != nil {
		return Created{}, err
	}
	t := &Token{ID: id, Name: name, QPS: q, hash: sha256.Sum256([]byte(secret)), CreatedAt: s.now().UTC().Truncate(time.Second)}
	next := append(append([]*Token{}, cur...), t)
	if err := s.saveLocked(next); err != nil {
		return Created{}, err
	}
	s.list.Store(&next)
	return Created{ID: id, Name: name, QPS: q, Token: secret, CreatedAt: t.CreatedAt.Format(time.RFC3339)}, nil
}

// Patch renames a token or changes its qps.
func (s *Store) Patch(id string, name *string, qps *int) (View, error) {
	var l fielderr.List
	nn := ""
	if name != nil {
		nn = checkName(&l, *name)
	}
	if qps != nil {
		checkQPS(&l, *qps)
	}
	if len(l) > 0 {
		return View{}, l.Err(CodeInvalid, "invalid token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.items()
	next := make([]*Token, len(cur))
	var found *Token
	for i, t := range cur {
		next[i] = t
		if t.ID != id {
			continue
		}
		c := &Token{ID: t.ID, Name: t.Name, QPS: t.QPS, hash: t.hash, CreatedAt: t.CreatedAt}
		c.lastUsed.Store(t.lastUsed.Load())
		c.queries.Store(t.queries.Load())
		if name != nil {
			c.Name = nn
		}
		if qps != nil {
			c.QPS = *qps
		}
		next[i], found = c, c
	}
	if found == nil {
		return View{}, fielderr.New(CodeNotFound, "no such token")
	}
	if err := s.saveLocked(next); err != nil {
		return View{}, err
	}
	s.list.Store(&next)
	return view(found), nil
}

// Delete removes a token.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.items()
	next := make([]*Token, 0, len(cur))
	for _, t := range cur {
		if t.ID != id {
			next = append(next, t)
		}
	}
	if len(next) == len(cur) {
		return fielderr.New(CodeNotFound, "no such token")
	}
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.list.Store(&next)
	return nil
}

// Save persists usage counters (called periodically and on close); it does
// nothing when no token was used since the last write.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if total(s.items()) == s.saved {
		return nil
	}
	return s.saveLocked(s.items())
}

func total(l []*Token) uint64 {
	var n uint64
	for _, t := range l {
		n += t.queries.Load()
	}
	return n
}

func (s *Store) saveLocked(l []*Token) error {
	s.saved = total(l)
	d := doc{V: 1, Items: make([]rec, 0, len(l))}
	for _, t := range l {
		d.Items = append(d.Items, rec{ID: t.ID, Name: t.Name, QPS: t.QPS, Hash: hex.EncodeToString(t.hash[:]),
			CreatedAt: t.CreatedAt, LastUsedAt: t.lastUsed.Load(), Queries: t.queries.Load()})
	}
	sort.SliceStable(d.Items, func(i, j int) bool { return d.Items[i].CreatedAt.Before(d.Items[j].CreatedAt) })
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(filepath.Join(s.st.Dir(), file), append(b, 10), 0o600) // trailing newline
}
