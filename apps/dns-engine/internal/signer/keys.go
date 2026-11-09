// Package signer implements automatic DNSSEC signing of primary zones
// (docs/41 §2.5): KSK+ZSK key sets stored 0600 in the engine data dir,
// pre-publish ZSK and double-signature KSK rollovers, NSEC or NSEC3 chains,
// RRSIGs over every authoritative RRset, CDS/CDNSKEY and DS output.
package signer

import (
	"crypto"
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

	"mrk/dns-engine/internal/store"
)

// Algorithm names accepted in the zone settings.
const (
	AlgECDSAP256 = "ECDSAP256SHA256"
	AlgED25519   = "ED25519"
)

// Roles and key states.
const (
	RoleKSK = "ksk"
	RoleZSK = "zsk"

	StatePublished = "published" // in the DNSKEY RRset, not signing yet (new ZSK)
	StateActive    = "active"    // signing
	StateRetired   = "retired"   // still published; a retired KSK keeps signing the DNSKEY RRset
)

// AlgNumber maps a name to the DNSSEC algorithm number.
func AlgNumber(name string) (uint8, bool) {
	switch name {
	case AlgECDSAP256:
		return dns.ECDSAP256SHA256, true
	case AlgED25519:
		return dns.ED25519, true
	}
	return 0, false
}

// Key is one DNSSEC key with its private part.
type Key struct {
	Tag        uint16    `json:"tag"`
	Role       string    `json:"role"`
	Algorithm  string    `json:"algorithm"`
	Created    time.Time `json:"created"`
	State      string    `json:"state"`
	StateSince time.Time `json:"state_since"`
	Public     string    `json:"public"`  // DNSKEY presentation form
	Private    string    `json:"private"` // BIND private-key format

	dnskey *dns.DNSKEY
	signer crypto.Signer
}

// DNSKEY returns the public key record.
func (k *Key) DNSKEY() *dns.DNSKEY { return k.dnskey }

// KeySet is the keys of one zone.
type KeySet struct {
	Zone string `json:"zone"`
	Keys []*Key `json:"keys"`
}

type keysDoc struct {
	V int `json:"v"`
	KeySet
}

// Store persists key sets as <dir>/<zone>.keys.json (0600, dir 0700).
type Store struct {
	dir string
	mu  sync.Mutex
}

// OpenStore creates dir.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	return &Store{dir: dir}, nil
}

func (s *Store) path(zone string) string {
	return filepath.Join(s.dir, strings.TrimSuffix(zone, ".")+".keys.json")
}

// Load reads a zone's keys (nil, nil when none).
func (s *Store) Load(zone string) (*KeySet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path(zone))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d keysDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("dnssec keys of %s: %w", zone, err)
	}
	ks := &d.KeySet
	for _, k := range ks.Keys {
		if err := k.load(); err != nil {
			return nil, fmt.Errorf("dnssec key %d of %s: %w", k.Tag, zone, err)
		}
	}
	return ks, nil
}

// ValidateDir loads every key set under dir (missing dir = none) without
// changing anything (backup restore).
func ValidateDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	s := &Store{dir: dir}
	for _, ent := range ents {
		name, ok := strings.CutSuffix(ent.Name(), ".keys.json")
		if ent.IsDir() || !ok || name == "" {
			continue
		}
		ks, err := s.Load(name + ".")
		if err != nil {
			return err
		}
		if ks == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSuffix(ks.Zone, "."), name) {
			return fmt.Errorf("%s holds the keys of %s", ent.Name(), ks.Zone)
		}
	}
	return nil
}

// Save writes a zone's keys atomically with mode 0600.
func (s *Store) Save(ks *KeySet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(keysDoc{V: 1, KeySet: *ks}, "", " ")
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(s.path(ks.Zone), append(b, '\n'), 0o600)
}

// Delete removes a zone's keys.
func (s *Store) Delete(zone string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path(zone)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (k *Key) load() error {
	rr, err := dns.NewRR(k.Public)
	if err != nil {
		return err
	}
	pk, ok := rr.(*dns.DNSKEY)
	if !ok {
		return errors.New("public key is not a DNSKEY")
	}
	priv, err := pk.NewPrivateKey(k.Private)
	if err != nil {
		return err
	}
	sg, ok := priv.(crypto.Signer)
	if !ok {
		return errors.New("private key cannot sign")
	}
	k.dnskey, k.signer = pk, sg
	return nil
}

// KeyTTL is the TTL of DNSKEY, CDS and CDNSKEY records.
const KeyTTL = 3600

// NewKey generates a key for zone.
func NewKey(zone, role, alg string, now time.Time) (*Key, error) {
	num, ok := AlgNumber(alg)
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
	flags := uint16(256)
	if role == RoleKSK {
		flags = 257
	}
	pk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: KeyTTL},
		Flags: flags, Protocol: 3, Algorithm: num}
	priv, err := pk.Generate(256)
	if err != nil {
		return nil, err
	}
	sg, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("generated key cannot sign")
	}
	now = now.UTC().Truncate(time.Second)
	return &Key{Tag: pk.KeyTag(), Role: role, Algorithm: alg, Created: now, State: StateActive, StateSince: now,
		Public: pk.String(), Private: pk.PrivateKeyString(priv), dnskey: pk, signer: sg}, nil
}

// NewKeySet generates an active KSK and ZSK.
func NewKeySet(zone, alg string, now time.Time) (*KeySet, error) {
	ksk, err := NewKey(zone, RoleKSK, alg, now)
	if err != nil {
		return nil, err
	}
	zsk, err := NewKey(zone, RoleZSK, alg, now)
	if err != nil {
		return nil, err
	}
	return &KeySet{Zone: zone, Keys: []*Key{ksk, zsk}}, nil
}

// Algorithm returns the algorithm of the set's keys.
func (ks *KeySet) Algorithm() string {
	if len(ks.Keys) == 0 {
		return ""
	}
	return ks.Keys[0].Algorithm
}

// Timing of rollovers.
type Timing struct {
	// ZSKPublish: how long a new ZSK is published before it signs.
	ZSKPublish time.Duration
	// ZSKRetire: how long the old ZSK stays published after the switch.
	ZSKRetire time.Duration
	// KSKRetire: how long the old KSK keeps signing the DNSKEY RRset (time to
	// replace the DS at the registrar).
	KSKRetire time.Duration
}

// DefaultTiming covers the DNSKEY TTL plus margins and a week for the DS.
func DefaultTiming() Timing {
	return Timing{ZSKPublish: 2 * time.Hour, ZSKRetire: 26 * time.Hour, KSKRetire: 7 * 24 * time.Hour}
}

// ErrRolloverInProgress is returned when a rollover of the role is running.
var ErrRolloverInProgress = errors.New("a rollover of this key role is already in progress")

// Rollover starts a rollover of role: a new ZSK is pre-published; a new KSK
// signs at once and the old one keeps signing the DNSKEY RRset until it is
// removed (double signature).
func (ks *KeySet) Rollover(role string, now time.Time) error {
	for _, k := range ks.Keys {
		if k.Role == role && k.State != StateActive {
			return ErrRolloverInProgress
		}
	}
	nk, err := NewKey(ks.Zone, role, ks.Algorithm(), now)
	if err != nil {
		return err
	}
	now = nk.Created
	if role == RoleZSK {
		nk.State = StatePublished
	} else {
		for _, k := range ks.Keys {
			if k.Role == RoleKSK && k.State == StateActive {
				k.State, k.StateSince = StateRetired, now
			}
		}
	}
	ks.Keys = append(ks.Keys, nk)
	return nil
}

// Advance moves rollovers along; it reports whether the key set changed.
func (ks *KeySet) Advance(now time.Time, t Timing) bool {
	changed := false
	now = now.UTC()
	for _, k := range ks.Keys {
		if k.Role == RoleZSK && k.State == StatePublished && now.Sub(k.StateSince) >= t.ZSKPublish {
			for _, o := range ks.Keys {
				if o != k && o.Role == RoleZSK && o.State == StateActive {
					o.State, o.StateSince = StateRetired, now
				}
			}
			k.State, k.StateSince = StateActive, now
			changed = true
		}
	}
	keep := ks.Keys[:0:0]
	for _, k := range ks.Keys {
		if k.State == StateRetired {
			hold := t.ZSKRetire
			if k.Role == RoleKSK {
				hold = t.KSKRetire
			}
			if now.Sub(k.StateSince) >= hold {
				changed = true
				continue
			}
		}
		keep = append(keep, k)
	}
	ks.Keys = keep
	return changed
}

// NextEvent returns when Advance will next change something (zero = never).
func (ks *KeySet) NextEvent(t Timing) time.Time {
	var next time.Time
	set := func(at time.Time) {
		if next.IsZero() || at.Before(next) {
			next = at
		}
	}
	for _, k := range ks.Keys {
		switch {
		case k.Role == RoleZSK && k.State == StatePublished:
			set(k.StateSince.Add(t.ZSKPublish))
		case k.Role == RoleZSK && k.State == StateRetired:
			set(k.StateSince.Add(t.ZSKRetire))
		case k.Role == RoleKSK && k.State == StateRetired:
			set(k.StateSince.Add(t.KSKRetire))
		}
	}
	return next
}

// DNSKEYs returns all published keys (every state), sorted by tag.
func (ks *KeySet) DNSKEYs() []*dns.DNSKEY {
	out := make([]*dns.DNSKEY, 0, len(ks.Keys))
	for _, k := range ks.Keys {
		out = append(out, k.dnskey)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyTag() < out[j].KeyTag() })
	return out
}

// KSKs returns the KSKs that have a DS (active and retired).
func (ks *KeySet) KSKs() []*Key {
	var out []*Key
	for _, k := range ks.Keys {
		if k.Role == RoleKSK {
			out = append(out, k)
		}
	}
	return out
}

func (ks *KeySet) signers(role string) []*Key {
	var out []*Key
	for _, k := range ks.Keys {
		if k.Role != role {
			continue
		}
		if k.State == StateActive || role == RoleKSK && k.State == StateRetired {
			out = append(out, k)
		}
	}
	return out
}

// DSView is one DS record for the parent zone.
type DSView struct {
	KeyTag     uint16 `json:"key_tag"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
	Text       string `json:"text"`
}

// DS returns the SHA-256 DS of every KSK.
func (ks *KeySet) DS() []DSView {
	var out []DSView
	for _, k := range ks.KSKs() {
		ds := k.dnskey.ToDS(dns.SHA256)
		if ds == nil {
			continue
		}
		ds.Hdr.Ttl = KeyTTL
		out = append(out, DSView{KeyTag: ds.KeyTag, DigestType: ds.DigestType, Digest: strings.ToUpper(ds.Digest), Text: ds.String()})
	}
	return out
}
