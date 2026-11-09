package dnssec

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/store"
)

// Trust anchor states (docs/40 §3).
const (
	TAValid   = "valid"
	TAPending = "pending"
	TARevoked = "revoked"
	TAMissing = "missing"
)

// HoldDown is the RFC 5011 add hold-down time.
const HoldDown = 30 * 24 * time.Hour

// Built-in root anchors: KSK-2017 and KSK-2024 (IANA root-anchors.xml).
var builtinDS = []struct {
	tag    uint16
	alg    uint8
	dt     uint8
	digest string
	from   time.Time // validFrom in root-anchors.xml
}{
	{20326, dns.RSASHA256, dns.SHA256, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		time.Date(2017, 2, 2, 0, 0, 0, 0, time.UTC)},
	{38696, dns.RSASHA256, dns.SHA256, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
		time.Date(2024, 7, 18, 0, 0, 0, 0, time.UTC)},
}

// Anchor is one root trust anchor (a DS digest or, learned via RFC 5011, a
// full DNSKEY).
type Anchor struct {
	KeyTag     uint16    `json:"key_tag"`
	Algorithm  uint8     `json:"algorithm"`
	DigestType uint8     `json:"digest_type,omitempty"`
	Digest     string    `json:"digest,omitempty"`
	PublicKey  string    `json:"public_key,omitempty"`
	State      string    `json:"state"`
	Since      time.Time `json:"since"`
	FirstSeen  time.Time `json:"first_seen,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	Builtin    bool      `json:"builtin,omitempty"`
}

// AnchorView is the API view.
type AnchorView struct {
	KeyTag    uint16    `json:"key_tag"`
	Algorithm uint8     `json:"algorithm"`
	State     string    `json:"state"`
	Since     time.Time `json:"since"`
}

type anchorFile struct {
	Version   int       `json:"v"`
	UpdatedAt time.Time `json:"updated_at"`
	Anchors   []Anchor  `json:"anchors"`
}

// Anchors is the root trust anchor store (trust-anchors.json, mode 0600).
type Anchors struct {
	mu        sync.Mutex
	path      string
	list      []Anchor
	updatedAt time.Time
	lastErr   string
	now       func() time.Time
}

// OpenAnchors loads path (missing or unreadable: the built-in anchors).
func OpenAnchors(path string, now func() time.Time) *Anchors { return OpenAnchorsWith(path, nil, now) }

// OpenAnchorsWith is OpenAnchors with other initial anchors than the
// built-in root KSKs (tests, private roots).
func OpenAnchorsWith(path string, initial []*dns.DS, now func() time.Time) *Anchors {
	if now == nil {
		now = time.Now
	}
	a := &Anchors{path: path, now: now}
	a.list = builtinAnchors()
	if initial != nil {
		a.list = nil
		for _, d := range initial {
			a.list = append(a.list, Anchor{KeyTag: d.KeyTag, Algorithm: d.Algorithm, DigestType: d.DigestType,
				Digest: strings.ToUpper(d.Digest), State: TAValid, Since: now().UTC(), Builtin: true})
		}
	}
	base := a.list
	if path == "" {
		return a
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			a.lastErr = "read trust anchors: " + err.Error()
		}
		return a
	}
	var f anchorFile
	if json.Unmarshal(b, &f) != nil || f.Version != 1 || len(f.Anchors) == 0 {
		a.lastErr = "trust-anchors.json is invalid; using the built-in anchors"
		return a
	}
	a.list, a.updatedAt = f.Anchors, f.UpdatedAt
	// the built-in anchors are always known (a stale file never removes them)
	for _, b := range base {
		found := false
		for _, x := range a.list {
			if x.KeyTag == b.KeyTag && x.Algorithm == b.Algorithm {
				found = true
			}
		}
		if !found {
			a.list = append(a.list, b)
		}
	}
	return a
}

func builtinAnchors() []Anchor {
	var out []Anchor
	for _, d := range builtinDS {
		out = append(out, Anchor{KeyTag: d.tag, Algorithm: d.alg, DigestType: d.dt, Digest: d.digest, State: TAValid,
			Since: d.from, Builtin: true})
	}
	return out
}

// Views returns the API list.
func (a *Anchors) Views() []AnchorView {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AnchorView, 0, len(a.list))
	for _, x := range a.list {
		out = append(out, AnchorView{KeyTag: x.KeyTag, Algorithm: x.Algorithm, State: x.State, Since: x.Since})
	}
	return out
}

// Status returns the last update time and error.
func (a *Anchors) Status() (time.Time, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.updatedAt, a.lastErr
}

// SetError records an update failure.
func (a *Anchors) SetError(err string) {
	a.mu.Lock()
	a.lastErr = err
	a.mu.Unlock()
}

func (x *Anchor) matches(k *dns.DNSKEY) bool {
	if k.Algorithm != x.Algorithm {
		return false
	}
	if x.PublicKey != "" {
		return strings.EqualFold(strings.ReplaceAll(k.PublicKey, " ", ""), x.PublicKey)
	}
	if k.KeyTag() != x.KeyTag {
		return false
	}
	ds := k.ToDS(x.DigestType)
	return ds != nil && strings.EqualFold(ds.Digest, x.Digest)
}

func trusted(state string) bool { return state == TAValid || state == TAMissing }

// Trusted returns the keys of set that match a trusted anchor (SEP keys not
// revoked).
func (a *Anchors) Trusted(set []*dns.DNSKEY) []*dns.DNSKEY {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []*dns.DNSKEY
	for _, k := range set {
		if k.Flags&dns.REVOKE != 0 || k.Flags&dns.ZONE == 0 {
			continue
		}
		for i := range a.list {
			if trusted(a.list[i].State) && a.list[i].matches(k) {
				out = append(out, k)
				break
			}
		}
	}
	return out
}

// Observe applies RFC 5011 to a root DNSKEY set that was validated by a
// trusted anchor. selfSigned reports, for a revoked key, whether it signed
// the set. It returns whether anything changed.
func (a *Anchors) Observe(set []*dns.DNSKEY, selfSigned func(*dns.DNSKEY) bool) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now().UTC()
	changed := false
	seen := make([]bool, len(a.list))
	for _, k := range set {
		if k.Flags&dns.SEP == 0 || k.Flags&dns.ZONE == 0 {
			continue
		}
		if k.Flags&dns.REVOKE != 0 {
			if !selfSigned(k) {
				continue
			}
			plain := *k
			plain.Flags &^= dns.REVOKE
			for i := range a.list {
				if a.list[i].matches(&plain) {
					seen[i] = true
					if a.list[i].State != TARevoked {
						a.list[i].State, a.list[i].Since = TARevoked, now
						changed = true
					}
				}
			}
			continue
		}
		found := false
		for i := range a.list {
			x := &a.list[i]
			if !x.matches(k) {
				continue
			}
			found, seen[i] = true, true
			x.LastSeen = now
			switch x.State {
			case TAMissing:
				x.State, x.Since = TAValid, now
				changed = true
			case TAPending:
				if now.Sub(x.FirstSeen) >= HoldDown {
					x.State, x.Since = TAValid, now
					changed = true
				}
			}
			if x.PublicKey == "" {
				x.PublicKey = strings.ReplaceAll(k.PublicKey, " ", "")
				changed = true
			}
		}
		if !found {
			a.list = append(a.list, Anchor{KeyTag: k.KeyTag(), Algorithm: k.Algorithm,
				PublicKey: strings.ReplaceAll(k.PublicKey, " ", ""), State: TAPending, Since: now, FirstSeen: now, LastSeen: now})
			seen = append(seen, true)
			changed = true
		}
	}
	out := a.list[:0]
	for i, x := range a.list {
		switch {
		case !seen[i] && x.State == TAValid:
			x.State, x.Since = TAMissing, now
			changed = true
		case !seen[i] && x.State == TAPending:
			changed = true
			continue // RFC 5011: a pending key that disappears is forgotten
		}
		out = append(out, x)
	}
	a.list = out
	a.updatedAt = now
	a.lastErr = ""
	return changed, a.saveLocked()
}

func (a *Anchors) saveLocked() error {
	if a.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(anchorFile{Version: 1, UpdatedAt: a.updatedAt, Anchors: a.list}, "", "  ")
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(a.path, b, 0o600)
}
