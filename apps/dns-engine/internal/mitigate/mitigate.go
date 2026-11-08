// Package mitigate holds temporary query restrictions (docs/38 §3
// /v1/mitigations): per client (IP/CIDR, longest-prefix match in a binary
// trie) or per domain suffix (wire-form suffix map), with action throttle
// (qps cap), block or refuse, an expiry and hit counters. The compiled index
// is swapped atomically; the query path never takes the store lock.
package mitigate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/store"
)

// Kinds, actions and sources.
const (
	KindClient = "client"
	KindDomain = "domain"

	ActThrottle = "throttle"
	ActBlock    = "block"
	ActRefuse   = "refuse"

	SourceUser = "user"
	SourceAuto = "auto"
)

// Max is the maximum number of active mitigations.
const Max = 10000

// Error codes.
const (
	CodeInvalid  = "mitigation_invalid"
	CodeNotFound = "mitigation_not_found"
	CodeTooMany  = "limit_reached"
)

// Item is the API view.
type Item struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Match     string    `json:"match"`
	Action    string    `json:"action"`
	QPS       int       `json:"qps"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason"`
	Hits      uint64    `json:"hits"`
}

// Input is POST /v1/mitigations.
type Input struct {
	Kind    string `json:"kind"`
	Match   string `json:"match"`
	Action  string `json:"action"`
	QPS     int    `json:"qps"`
	Minutes int    `json:"minutes"`
	Reason  string `json:"reason"`
}

// Live is a mitigation as seen by the query path.
type Live struct {
	Item   Item // immutable except Hits (use HitCount)
	Action uint8
	hits   atomic.Uint64
	expire int64

	mu     sync.Mutex
	tokens float64
	last   int64
}

// Compiled actions.
const (
	DoThrottle uint8 = iota + 1
	DoBlock
	DoRefuse
)

// Hit counts a match and, for throttles, reports whether the query is within
// the qps cap (always true for block/refuse).
func (l *Live) Hit(now int64) bool {
	l.hits.Add(1)
	if l.Action != DoThrottle {
		return true
	}
	rate := float64(l.Item.QPS)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == 0 {
		l.tokens = rate
	} else if now > l.last {
		l.tokens += float64(now-l.last) / 1e9 * rate
		if l.tokens > rate {
			l.tokens = rate
		}
	}
	l.last = now
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// HitCount returns the number of matched queries.
func (l *Live) HitCount() uint64 { return l.hits.Load() }

type node struct {
	child [2]*node
	item  *Live
}

// Index is an immutable compiled set.
type Index struct {
	root    *node
	domains map[string]*Live // wire-form lower-case suffix
	n       int
	clients int
}

// Empty reports whether nothing is active (the query path skips lookups).
func (x *Index) Empty() bool { return x == nil || x.n == 0 }

// HasClients reports whether any client mitigation is active.
func (x *Index) HasClients() bool { return x != nil && x.clients > 0 }

// HasDomains reports whether any domain mitigation is active.
func (x *Index) HasDomains() bool { return x != nil && len(x.domains) > 0 }

func key16(a netip.Addr) [16]byte {
	if a.Is4() {
		return netip.AddrFrom16(a.As16()).As16() // IPv4-mapped
	}
	return a.As16()
}

func prefixBits(p netip.Prefix) int {
	if p.Addr().Is4() {
		return p.Bits() + 96
	}
	return p.Bits()
}

func (x *Index) insert(p netip.Prefix, l *Live) {
	k := key16(p.Addr())
	n := x.root
	for i := 0; i < prefixBits(p); i++ {
		b := (k[i/8] >> (7 - i%8)) & 1
		if n.child[b] == nil {
			n.child[b] = &node{}
		}
		n = n.child[b]
	}
	n.item = l
}

// Client returns the longest-prefix client mitigation for a (nil if none).
func (x *Index) Client(a netip.Addr) *Live {
	if x == nil || x.clients == 0 {
		return nil
	}
	k := key16(a.Unmap())
	var best *Live
	n := x.root
	for i := 0; n != nil; i++ {
		if n.item != nil {
			best = n.item
		}
		if i == 128 {
			break
		}
		n = n.child[(k[i/8]>>(7-i%8))&1]
	}
	return best
}

// Domain returns the most specific domain mitigation for a lower-case
// wire-form name (nil if none). It does not allocate.
func (x *Index) Domain(name []byte) *Live {
	if x == nil || len(x.domains) == 0 {
		return nil
	}
	for off := 0; off < len(name); {
		if l, ok := x.domains[string(name[off:])]; ok {
			return l
		}
		ln := int(name[off])
		if ln == 0 {
			break
		}
		off += 1 + ln
	}
	return nil
}

// Store owns the mitigations.
type Store struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
	m    map[string]*Live
	idx  atomic.Pointer[Index]
}

type doc struct {
	Schema int    `json:"schema"`
	Items  []Item `json:"items"`
}

// Open loads path (a missing file is an empty set).
func Open(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{path: path, now: now, m: map[string]*Live{}}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		var d doc
		if jerr := jsonUnmarshal(b, &d); jerr != nil {
			return nil, fmt.Errorf("mitigations: %w", jerr)
		}
		for _, it := range d.Items {
			l, err := compileItem(it)
			if err != nil {
				continue
			}
			l.hits.Store(it.Hits)
			s.m[it.ID] = l
		}
	}
	s.rebuildLocked()
	return s, nil
}

// Index returns the current compiled set.
func (s *Store) Index() *Index { return s.idx.Load() }

func compileItem(it Item) (*Live, error) {
	l := &Live{Item: it, expire: it.ExpiresAt.UnixNano()}
	switch it.Action {
	case ActThrottle:
		l.Action = DoThrottle
	case ActBlock:
		l.Action = DoBlock
	case ActRefuse:
		l.Action = DoRefuse
	default:
		return nil, errors.New("action")
	}
	return l, nil
}

func wireOf(name string) string {
	buf := make([]byte, 256)
	n, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

func (s *Store) rebuildLocked() {
	x := &Index{root: &node{}, domains: map[string]*Live{}}
	for _, l := range s.m {
		switch l.Item.Kind {
		case KindClient:
			p, _, err := acl.ParseEntry(l.Item.Match)
			if err != nil {
				continue
			}
			x.insert(p, l)
			x.clients++
		case KindDomain:
			if w := wireOf(l.Item.Match); w != "" {
				x.domains[w] = l
			}
		}
		x.n++
	}
	s.idx.Store(x)
}

func (s *Store) saveLocked() error {
	items := s.listLocked()
	return store.WriteFileAtomic(s.path, jsonMarshal(doc{Schema: 1, Items: items}), 0o640)
}

func (s *Store) listLocked() []Item {
	out := make([]Item, 0, len(s.m))
	for _, l := range s.m {
		it := l.Item
		it.Hits = l.hits.Load()
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// List returns active mitigations, newest first.
func (s *Store) List() []Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked()
}

// Get returns one item.
func (s *Store) Get(id string) (Item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.m[id]
	if l == nil {
		return Item{}, false
	}
	it := l.Item
	it.Hits = l.hits.Load()
	return it, true
}

// Validate normalises in and returns field errors.
func Validate(in *Input) fielderr.List {
	var l fielderr.List
	switch in.Kind {
	case KindClient:
		p, deny, err := acl.ParseEntry(in.Match)
		switch {
		case err != nil || deny:
			l.Add("match", "invalid_network")
		case p.Bits() == 0:
			l.Add("match", "too_broad")
		default:
			in.Match = p.String()
		}
	case KindDomain:
		v, ok := config.NormalizeSuffix(in.Match)
		if !ok {
			l.Add("match", "invalid_name")
		} else {
			in.Match = v
		}
	default:
		l.Add("kind", "invalid_choice", "choices", []string{KindClient, KindDomain})
	}
	switch in.Action {
	case ActThrottle:
		if in.QPS < 1 || in.QPS > 1_000_000 {
			l.Add("qps", "out_of_range", "min", 1, "max", 1_000_000)
		}
	case ActBlock, ActRefuse:
		in.QPS = 0
	default:
		l.Add("action", "invalid_choice", "choices", []string{ActThrottle, ActBlock, ActRefuse})
	}
	if in.Minutes < 1 || in.Minutes > 525600 {
		l.Add("minutes", "out_of_range", "min", 1, "max", 525600)
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if len(in.Reason) > 256 {
		l.Add("reason", "too_long", "max", 256)
	}
	return l
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "m_" + hex.EncodeToString(b[:])
}

// Create adds (or replaces the same kind+match) a mitigation.
func (s *Store) Create(in Input, source string) (Item, error) {
	if l := Validate(&in); len(l) > 0 {
		return Item{}, l.Err(CodeInvalid, "invalid mitigation")
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	it := Item{ID: newID(), Kind: in.Kind, Match: in.Match, Action: in.Action, QPS: in.QPS, CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(in.Minutes) * time.Minute), Source: source, Reason: in.Reason}
	l, err := compileItem(it)
	if err != nil {
		return Item{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var replaced *Live
	for id, o := range s.m {
		if o.Item.Kind == it.Kind && o.Item.Match == it.Match {
			replaced = o
			delete(s.m, id)
		}
	}
	if len(s.m) >= Max {
		if replaced != nil {
			s.m[replaced.Item.ID] = replaced
		}
		return Item{}, &fielderr.Error{Code: CodeTooMany, Message: fmt.Sprintf("at most %d mitigations", Max), Status: 409}
	}
	s.m[it.ID] = l
	s.rebuildLocked()
	if err := s.saveLocked(); err != nil {
		return it, err
	}
	return it, nil
}

// Delete removes a mitigation.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		return &fielderr.Error{Code: CodeNotFound, Message: "mitigation not found", Status: 404}
	}
	delete(s.m, id)
	s.rebuildLocked()
	return s.saveLocked()
}

// Find returns the active mitigation for kind+match, if any.
func (s *Store) Find(kind, match string) (Item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.m {
		if l.Item.Kind == kind && l.Item.Match == match {
			it := l.Item
			it.Hits = l.hits.Load()
			return it, true
		}
	}
	return Item{}, false
}

// Sweep removes expired mitigations and returns them.
func (s *Store) Sweep() []Item {
	now := s.now().UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []Item
	for id, l := range s.m {
		if l.expire <= now {
			it := l.Item
			it.Hits = l.hits.Load()
			gone = append(gone, it)
			delete(s.m, id)
		}
	}
	if len(gone) > 0 {
		s.rebuildLocked()
		_ = s.saveLocked()
	}
	return gone
}

// Save persists hit counters (call occasionally).
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}
