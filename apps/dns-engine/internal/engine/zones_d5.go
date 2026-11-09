package engine

// docs/41 §2: secondary zones, outgoing transfers, NOTIFY, TSIG, dynamic
// update and automatic DNSSEC signing. State specific to these features
// lives in d5state; zone settings live in zone.D5Config (zone documents).

import (
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

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/signer"
	"mrk/dns-engine/internal/store"
	"mrk/dns-engine/internal/tsig"
	"mrk/dns-engine/internal/xfr"
	"mrk/dns-engine/internal/zone"
)

// Error codes of docs/41 §2.
const (
	CodeZoneReadOnly       = "zone_read_only"
	CodeTSIGInvalid        = tsig.CodeInvalid
	CodeTSIGExists         = tsig.CodeExists
	CodeTSIGNotFound       = tsig.CodeNotFound
	CodeTSIGInUse          = tsig.CodeInUse
	CodeRolloverInProgress = "rollover_in_progress"
	CodeDNSSECDisabled     = "dnssec_disabled"
)

// Limits of docs/41 §2.2.
const (
	MaxConcurrentTransfers = 10
	MaxPrimaries           = 8
	MaxNotifyTargets       = 16
	MaxACLEntries          = 64
	notifyAttempts         = 5
)

// Event types emitted by the zone features.
const (
	EventSecondaryExpired   = "zone.secondary_expired"
	EventTransferFailed     = "zone.transfer_failed"
	EventTransferRecovered  = "zone.transfer_recovered"
	EventNotifyFailed       = "zone.notify_failed"
	EventSigningFailed      = "zone.dnssec_signing_failed"
	EventDNSSECKeysAdvanced = "zone.dnssec_keys_changed"
)

// ZoneTiming tunes the timers of the zone features (tests shorten them).
type ZoneTiming struct {
	Now func() time.Time
	// MinRefresh clamps SOA refresh/retry of secondaries.
	MinRefresh time.Duration
	// NotifyRetry is the first NOTIFY retry delay (doubles up to 5 attempts).
	NotifyRetry time.Duration
	// Tick is the period of the zone maintenance loop.
	Tick time.Duration
	Keys signer.Timing
}

func defaultZoneTiming() ZoneTiming {
	return ZoneTiming{Now: time.Now, MinRefresh: 10 * time.Second, NotifyRetry: time.Second, Tick: time.Second,
		Keys: signer.DefaultTiming()}
}

// SecondaryStatus is the "secondary" object of GET /v1/zones/{zone}.
type SecondaryStatus struct {
	Serial      uint32     `json:"serial"`
	Loaded      bool       `json:"loaded"`
	Expired     bool       `json:"expired"`
	LastRefresh *time.Time `json:"last_refresh"`
	LastSuccess *time.Time `json:"last_success"`
	NextRefresh *time.Time `json:"next_refresh"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Primary     string     `json:"primary,omitempty"`
	// LastTransfer is how the current data arrived: "axfr" or "ixfr".
	LastTransfer string `json:"last_transfer,omitempty"`
	Error        string `json:"error,omitempty"`
}

type secondary struct {
	refreshMu sync.Mutex // one refresh at a time
	running   bool
	soa       *dns.SOA
	rrs       []dns.RR
	st        SecondaryStatus
	failing   bool
	expiredEv bool
}

type signInfo struct {
	version    int
	expiration time.Time
	err        string
}

type d5state struct {
	mu       sync.Mutex // leaf lock (taken inside e.mu, never the other way)
	tsig     *tsig.Store
	keys     *signer.Store
	keysets  map[string]*signer.KeySet
	dir      string
	sec      map[string]*secondary
	signed   map[string]signInfo
	notifyID map[string]uint64
	xfr      chan struct{}
	kick     chan struct{}
	timing   ZoneTiming
}

func (e *Engine) openD5() error {
	d := &e.d5
	d.timing = defaultZoneTiming()
	d.keysets = map[string]*signer.KeySet{}
	d.sec = map[string]*secondary{}
	d.signed = map[string]signInfo{}
	d.notifyID = map[string]uint64{}
	d.xfr = make(chan struct{}, MaxConcurrentTransfers)
	d.kick = make(chan struct{}, 1)
	d.dir = filepath.Join(e.st.Dir(), "secondary")
	if err := os.MkdirAll(d.dir, 0o750); err != nil {
		return err
	}
	ts, err := tsig.Open(filepath.Join(e.st.Dir(), "tsig.json"))
	if err != nil {
		return err
	}
	d.tsig = ts
	ks, err := signer.OpenStore(filepath.Join(e.st.Dir(), "dnssec-keys"))
	if err != nil {
		return err
	}
	d.keys = ks
	return nil
}

// registerD5RestoreHooks lets a backup restore reload the TSIG keys and the
// DNSSEC key sets live (call after openPolicy, which resets the hook list).
// The DNSSEC key cache is dropped by reloadLocked before the restored zones
// are signed, so the hook only has to validate the staged files.
func (e *Engine) registerD5RestoreHooks() {
	e.RegisterRestoreHook(RestoreHook{
		Prefix:   "tsig.json",
		Validate: func(stage string) error { return tsig.Validate(filepath.Join(stage, "tsig.json")) },
		Reload:   func() error { return e.d5.tsig.Reload() },
	})
	e.RegisterRestoreHook(RestoreHook{
		Prefix:   "dnssec-keys/",
		Validate: func(stage string) error { return signer.ValidateDir(filepath.Join(stage, "dnssec-keys")) },
	})
}

// resetDNSSECCacheLocked forgets the cached key sets and signing status so
// the next compile reads the keys from disk (backup restore; e.mu held).
func (e *Engine) resetDNSSECCacheLocked() {
	e.d5.mu.Lock()
	e.d5.keysets = map[string]*signer.KeySet{}
	e.d5.signed = map[string]signInfo{}
	e.d5.mu.Unlock()
}

// SetZoneTiming replaces the zone timers (tests). Zero fields keep defaults.
func (e *Engine) SetZoneTiming(t ZoneTiming) {
	d := defaultZoneTiming()
	if t.Now != nil {
		d.Now = t.Now
	}
	if t.MinRefresh > 0 {
		d.MinRefresh = t.MinRefresh
	}
	if t.NotifyRetry > 0 {
		d.NotifyRetry = t.NotifyRetry
	}
	if t.Tick > 0 {
		d.Tick = t.Tick
	}
	if t.Keys != (signer.Timing{}) {
		d.Keys = t.Keys
	}
	e.d5.mu.Lock()
	e.d5.timing = d
	e.d5.mu.Unlock()
	e.kickD5()
}

func (e *Engine) timing() ZoneTiming {
	e.d5.mu.Lock()
	defer e.d5.mu.Unlock()
	return e.d5.timing
}

func (e *Engine) now() time.Time { return e.timing().Now() }

func (e *Engine) kickD5() {
	select {
	case e.d5.kick <- struct{}{}:
	default:
	}
}

// ---------------------------------------------------------------- compile

// compileZone compiles z, signing it or loading secondary data as needed.
func (e *Engine) compileZone(z *zone.Zone) (*zone.Compiled, error) {
	switch {
	case z.Type == zone.TypeSecondary:
		return e.compileSecondary(z), nil
	case z.Signed():
		return e.compileSigned(z)
	}
	return zone.Compile(z)
}

func (e *Engine) compileSecondary(z *zone.Zone) *zone.Compiled {
	s := e.secFor(z.Name)
	now := e.now()
	e.d5.mu.Lock()
	defer e.d5.mu.Unlock()
	if s.soa == nil || s.st.ExpiresAt != nil && !now.Before(*s.st.ExpiresAt) {
		return zone.UnavailableZone(z.Name, zone.TypeSecondary)
	}
	c, err := zone.CompileRaw(z.Name, zone.TypeSecondary, append([]dns.RR{s.soa}, s.rrs...))
	if err != nil {
		return zone.UnavailableZone(z.Name, zone.TypeSecondary)
	}
	return c
}

// unsignedRRs returns the SOA and enabled records of a primary zone.
func unsignedRRs(z *zone.Zone) ([]dns.RR, error) {
	out := []dns.RR{z.SOARR()}
	for i := range z.Records {
		r := &z.Records[i]
		if r.Disabled || r.View != "" { // split-horizon records are neither signed nor transferred
			continue
		}
		rr, err := r.RR(z.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	return out, nil
}

func (e *Engine) keySetFor(z *zone.Zone, create bool) (*signer.KeySet, error) {
	e.d5.mu.Lock()
	ks := e.d5.keysets[z.Name]
	e.d5.mu.Unlock()
	if ks == nil {
		var err error
		if ks, err = e.d5.keys.Load(z.Name); err != nil {
			return nil, err
		}
	}
	alg := z.DNSSEC.Algorithm
	if ks != nil && ks.Algorithm() != alg {
		ks = nil // re-enabled with another algorithm: new keys (the DS must be replaced)
	}
	if ks == nil {
		if !create {
			return nil, nil
		}
		nks, err := signer.NewKeySet(z.Name, alg, e.now())
		if err != nil {
			return nil, err
		}
		if err := e.d5.keys.Save(nks); err != nil {
			return nil, err
		}
		ks = nks
	}
	e.d5.mu.Lock()
	e.d5.keysets[z.Name] = ks
	e.d5.mu.Unlock()
	return ks, nil
}

func (e *Engine) compileSigned(z *zone.Zone) (*zone.Compiled, error) {
	fail := func(err error) (*zone.Compiled, error) {
		e.d5.mu.Lock()
		e.d5.signed[z.Name] = signInfo{version: z.Version, err: err.Error()}
		e.d5.mu.Unlock()
		if e.mon != nil {
			e.EventRing().Emit(EventSigningFailed, "error", map[string]any{"zone": zone.Display(z.Name), "error": err.Error()})
		}
		e.log.Error("dnssec signing failed", "zone", z.Name, "err", err)
		return nil, fielderr.New(CodeZoneInvalid, "DNSSEC signing failed: "+err.Error())
	}
	rrs, err := unsignedRRs(z)
	if err != nil {
		return fail(err)
	}
	ks, err := e.keySetFor(z, true)
	if err != nil {
		return fail(err)
	}
	res, err := signer.Sign(z.Name, rrs, ks, signer.ParamsFrom(*z.DNSSEC, e.now()))
	if err != nil {
		return fail(err)
	}
	c, err := zone.CompileRaw(z.Name, zone.TypePrimary, res.RRs)
	if err != nil {
		return fail(err)
	}
	e.d5.mu.Lock()
	e.d5.signed[z.Name] = signInfo{version: z.Version, expiration: res.Expiration}
	e.d5.mu.Unlock()
	return c, nil
}

// zoneCommittedD5 runs after a zone version is published (e.mu held).
func (e *Engine) zoneCommittedD5(old, z *zone.Zone) {
	if z.Type == zone.TypeSecondary {
		if old == nil || strings.Join(old.Primaries, ",") != strings.Join(z.Primaries, ",") || old.TSIGKey != z.TSIGKey {
			e.scheduleRefresh(z.Name, e.now())
		}
		return
	}
	if !z.Signed() {
		e.d5.mu.Lock()
		delete(e.d5.signed, z.Name)
		e.d5.mu.Unlock()
	}
	if z.Type == zone.TypePrimary && (old == nil || old.Serial != z.Serial) {
		e.sendNotifies(z)
	}
}

// zoneDeletedD5 removes the per-zone files (e.mu held).
func (e *Engine) zoneDeletedD5(z *zone.Zone) {
	e.d5.mu.Lock()
	delete(e.d5.sec, z.Name)
	delete(e.d5.signed, z.Name)
	delete(e.d5.keysets, z.Name)
	e.d5.notifyID[z.Name]++
	e.d5.mu.Unlock()
	base := filepath.Join(e.d5.dir, zone.Display(z.Name))
	_ = os.Remove(base + ".zone")
	_ = os.Remove(base + ".state.json")
	_ = e.d5.keys.Delete(z.Name)
}

// ---------------------------------------------------------------- settings

// ZoneCreateD5 are the extra POST /v1/zones fields of a secondary zone.
type ZoneCreateD5 struct {
	Primaries   []string `json:"primaries,omitempty"`
	TSIGKey     string   `json:"tsig_key,omitempty"`
	NotifyAllow []string `json:"notify_allow,omitempty"`
}

// Any reports whether a field is set.
func (c ZoneCreateD5) Any() bool {
	return len(c.Primaries) > 0 || c.TSIGKey != "" || len(c.NotifyAllow) > 0
}

// TransferInput patches transfer settings.
type TransferInput struct {
	Allow   *[]string `json:"allow"`
	TSIGKey *string   `json:"tsig_key"`
}

// NotifyInput patches NOTIFY settings.
type NotifyInput struct {
	Targets *[]string `json:"targets"`
	Enabled *bool     `json:"enabled"`
	TSIGKey *string   `json:"tsig_key"`
}

// UpdateInput patches dynamic-update settings.
type UpdateInput struct {
	Enabled     *bool     `json:"enabled"`
	Allow       *[]string `json:"allow"`
	TSIGKey     *string   `json:"tsig_key"`
	RequireTSIG *bool     `json:"require_tsig"`
}

// NSEC3Input patches NSEC3 parameters.
type NSEC3Input struct {
	Iterations *int    `json:"iterations"`
	Salt       *string `json:"salt"`
	OptOut     *bool   `json:"opt_out"`
}

// SigningInput patches signing settings.
type SigningInput struct {
	Enabled               *bool       `json:"enabled"`
	Algorithm             *string     `json:"algorithm"`
	Denial                *string     `json:"denial"`
	NSEC3                 *NSEC3Input `json:"nsec3"`
	SignatureValidityDays *int        `json:"signature_validity_days"`
	RefreshDays           *int        `json:"refresh_days"`
}

// ZonePatchD5 are the PATCH /v1/zones/{zone} fields of docs/41 §2.
type ZonePatchD5 struct {
	Primaries   *[]string      `json:"primaries,omitempty"`
	TSIGKey     *string        `json:"tsig_key,omitempty"`
	NotifyAllow *[]string      `json:"notify_allow,omitempty"`
	Transfer    *TransferInput `json:"transfer,omitempty"`
	Notify      *NotifyInput   `json:"notify,omitempty"`
	Update      *UpdateInput   `json:"update,omitempty"`
	DNSSEC      *SigningInput  `json:"dnssec,omitempty"`
}

// ZoneD5View is the docs/41 §2 part of GET /v1/zones/{zone}.
type ZoneD5View struct {
	Primaries   []string             `json:"primaries,omitempty"`
	TSIGKey     string               `json:"tsig_key,omitempty"`
	NotifyAllow []string             `json:"notify_allow,omitempty"`
	Secondary   *SecondaryStatus     `json:"secondary,omitempty"`
	Transfer    *zone.TransferConfig `json:"transfer,omitempty"`
	Notify      *zone.NotifyConfig   `json:"notify,omitempty"`
	Update      *zone.UpdateConfig   `json:"update,omitempty"`
	DNSSEC      *zone.SigningConfig  `json:"dnssec,omitempty"`
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func d5View(z *zone.Zone) ZoneD5View {
	var v ZoneD5View
	if z.Type == zone.TypeForwarder {
		return v
	}
	tr := zone.TransferConfig{Allow: []string{}}
	if z.Transfer != nil {
		tr = *z.Transfer
		tr.Allow = emptyIfNil(tr.Allow)
	}
	nt := zone.NotifyConfig{Targets: []string{}}
	if z.Notify != nil {
		nt = *z.Notify
		nt.Targets = emptyIfNil(nt.Targets)
	}
	v.Transfer, v.Notify = &tr, &nt
	if z.Type == zone.TypeSecondary {
		v.Primaries, v.TSIGKey, v.NotifyAllow = emptyIfNil(z.Primaries), z.TSIGKey, emptyIfNil(z.NotifyAllow)
		return v
	}
	up := zone.UpdateConfig{Allow: []string{}, RequireTSIG: true}
	if z.Update != nil {
		up = *z.Update
		up.Allow = emptyIfNil(up.Allow)
	}
	sg := zone.DefaultSigning()
	if z.DNSSEC != nil {
		sg = *z.DNSSEC
	}
	v.Update, v.DNSSEC = &up, &sg
	return v
}

// d5Status adds runtime status (secondary timers) to a zone detail.
func (e *Engine) d5Status(d *ZoneDetail, z *zone.Zone) {
	if z.Type != zone.TypeSecondary {
		return
	}
	s := e.secFor(z.Name)
	e.d5.mu.Lock()
	st := s.st
	e.d5.mu.Unlock()
	if st.ExpiresAt != nil && !e.now().Before(*st.ExpiresAt) {
		st.Expired = true
	}
	d.Secondary = &st
	d.Serial = st.Serial
	d.Records = len(s.rrs)
}

func (e *Engine) checkACL(l *fielderr.List, field string, items []string) {
	if len(items) > MaxACLEntries {
		l.Add(field, "too_many", "max", MaxACLEntries)
		return
	}
	if _, err := acl.Compile(items); err != nil {
		var ee *acl.EntryError
		if errors.As(err, &ee) {
			l.Add(fmt.Sprintf("%s[%d]", field, ee.Index), "invalid_cidr")
		} else {
			l.Add(field, "invalid_cidr")
		}
	}
}

func (e *Engine) checkKey(l *fielderr.List, field, name string) string {
	if name == "" {
		return ""
	}
	fq, ok := tsig.NormalizeName(name)
	if !ok {
		l.Add(field, "invalid_name")
		return name
	}
	if !e.d5.tsig.Has(fq) {
		l.Add(field, "unknown_tsig_key")
	}
	return zone.Display(fq)
}

func checkAddrs(l *fielderr.List, field string, in []string, max int) []string {
	if len(in) > max {
		l.Add(field, "too_many", "max", max)
		return in
	}
	out := make([]string, 0, len(in))
	for i, a := range in {
		n, ok := xfr.NormalizeAddr(a)
		if !ok {
			l.Add(fmt.Sprintf("%s[%d]", field, i), "invalid_address")
			continue
		}
		out = append(out, n)
	}
	return out
}

// applyPatchD5 merges p into z (a clone) and validates the result.
func (e *Engine) applyPatchD5(old, z *zone.Zone, p ZonePatchD5) error {
	var l fielderr.List
	sec := z.Type == zone.TypeSecondary
	notFor := func(field string, cond bool) bool {
		if cond {
			l.Add(field, "not_allowed")
		}
		return cond
	}
	if z.Type == zone.TypeForwarder {
		for f, set := range map[string]bool{"primaries": p.Primaries != nil, "tsig_key": p.TSIGKey != nil,
			"notify_allow": p.NotifyAllow != nil, "transfer": p.Transfer != nil, "notify": p.Notify != nil,
			"update": p.Update != nil, "dnssec": p.DNSSEC != nil} {
			notFor(f, set)
		}
		return l.Err(CodeZoneTypeMismatch, "forwarder zones have no transfer settings")
	}
	if p.Primaries != nil && !notFor("primaries", !sec) {
		if len(*p.Primaries) == 0 {
			l.Add("primaries", "required")
		}
		z.Primaries = checkAddrs(&l, "primaries", *p.Primaries, MaxPrimaries)
	}
	if p.TSIGKey != nil && !notFor("tsig_key", !sec) {
		z.TSIGKey = e.checkKey(&l, "tsig_key", *p.TSIGKey)
	}
	if p.NotifyAllow != nil && !notFor("notify_allow", !sec) {
		e.checkACL(&l, "notify_allow", *p.NotifyAllow)
		z.NotifyAllow = append([]string{}, (*p.NotifyAllow)...)
	}
	if t := p.Transfer; t != nil {
		c := zone.TransferConfig{}
		if z.Transfer != nil {
			c = *z.Transfer
		}
		if t.Allow != nil {
			e.checkACL(&l, "transfer.allow", *t.Allow)
			c.Allow = append([]string{}, (*t.Allow)...)
		}
		if t.TSIGKey != nil {
			c.TSIGKey = e.checkKey(&l, "transfer.tsig_key", *t.TSIGKey)
		}
		z.Transfer = &c
	}
	if n := p.Notify; n != nil {
		c := zone.NotifyConfig{}
		if z.Notify != nil {
			c = *z.Notify
		}
		if n.Targets != nil {
			c.Targets = checkAddrs(&l, "notify.targets", *n.Targets, MaxNotifyTargets)
		}
		if n.Enabled != nil {
			c.Enabled = *n.Enabled
		}
		if n.TSIGKey != nil {
			c.TSIGKey = e.checkKey(&l, "notify.tsig_key", *n.TSIGKey)
		}
		if c.Enabled && len(c.Targets) == 0 {
			l.Add("notify.targets", "required")
		}
		z.Notify = &c
	}
	if u := p.Update; u != nil && !notFor("update", sec) {
		c := zone.UpdateConfig{RequireTSIG: true}
		if z.Update != nil {
			c = *z.Update
		}
		if u.Enabled != nil {
			c.Enabled = *u.Enabled
		}
		if u.Allow != nil {
			e.checkACL(&l, "update.allow", *u.Allow)
			c.Allow = append([]string{}, (*u.Allow)...)
		}
		if u.TSIGKey != nil {
			c.TSIGKey = e.checkKey(&l, "update.tsig_key", *u.TSIGKey)
		}
		if u.RequireTSIG != nil {
			c.RequireTSIG = *u.RequireTSIG
		}
		if c.Enabled && !c.RequireTSIG && len(c.Allow) == 0 {
			l.Add("update.allow", "open_update") // without TSIG an address list is required
		}
		z.Update = &c
	}
	if s := p.DNSSEC; s != nil && !notFor("dnssec", sec) {
		c := zone.DefaultSigning()
		if z.DNSSEC != nil {
			c = *z.DNSSEC
		}
		if s.Enabled != nil {
			c.Enabled = *s.Enabled
		}
		if s.Algorithm != nil {
			c.Algorithm = strings.ToUpper(strings.TrimSpace(*s.Algorithm))
		}
		if s.Denial != nil {
			c.Denial = strings.ToLower(strings.TrimSpace(*s.Denial))
		}
		if n := s.NSEC3; n != nil {
			if n.Iterations != nil {
				c.NSEC3.Iterations = *n.Iterations
			}
			if n.Salt != nil {
				c.NSEC3.Salt = strings.ToUpper(strings.TrimSpace(*n.Salt))
				if c.NSEC3.Salt == "-" {
					c.NSEC3.Salt = ""
				}
			}
			if n.OptOut != nil {
				c.NSEC3.OptOut = *n.OptOut
			}
		}
		if s.SignatureValidityDays != nil {
			c.SignatureValidityDays = *s.SignatureValidityDays
		}
		if s.RefreshDays != nil {
			c.RefreshDays = *s.RefreshDays
		}
		if _, ok := signer.AlgNumber(c.Algorithm); !ok {
			l.Add("dnssec.algorithm", "invalid_choice", "choices", []string{signer.AlgECDSAP256, signer.AlgED25519})
		}
		if c.Denial != "nsec" && c.Denial != "nsec3" {
			l.Add("dnssec.denial", "invalid_choice", "choices", []string{"nsec", "nsec3"})
		}
		if c.NSEC3.Iterations < 0 || c.NSEC3.Iterations > 100 {
			l.Add("dnssec.nsec3.iterations", "out_of_range", "min", 0, "max", 100)
		}
		if !signer.ValidSalt(c.NSEC3.Salt) {
			l.Add("dnssec.nsec3.salt", "invalid_salt")
		}
		if c.SignatureValidityDays < 2 || c.SignatureValidityDays > 90 {
			l.Add("dnssec.signature_validity_days", "out_of_range", "min", 2, "max", 90)
		}
		if c.RefreshDays < 1 || c.RefreshDays >= c.SignatureValidityDays {
			l.Add("dnssec.refresh_days", "out_of_range", "min", 1, "max", c.SignatureValidityDays-1)
		}
		// changing the algorithm while signing would break the chain of trust
		if old != nil && old.Signed() && c.Enabled && old.DNSSEC.Algorithm != c.Algorithm {
			l.Add("dnssec.algorithm", "algorithm_locked")
		}
		z.DNSSEC = &c
	}
	return l.Err(CodeZoneInvalid, "invalid zone settings")
}

// CreateSecondary adds a secondary zone (docs/41 §2.1).
func (e *Engine) CreateSecondary(name string, in ZoneCreateD5) (ZoneDetail, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	fq, ok := zone.NormalizeZoneName(name)
	if !ok {
		return ZoneDetail{}, fielderr.Single(CodeInvalidZoneName, "invalid zone name", "name", "invalid_name")
	}
	if e.zones[fq] != nil {
		return ZoneDetail{}, fielderr.New(CodeZoneExists, "zone already exists")
	}
	if len(e.zones) >= MaxZones {
		return ZoneDetail{}, fielderr.New(CodeTooMany, "too many zones")
	}
	z := &zone.Zone{Name: fq, Type: zone.TypeSecondary, Records: []zone.Record{}}
	prim, key, allow := in.Primaries, in.TSIGKey, in.NotifyAllow
	if prim == nil {
		prim = []string{}
	}
	p := ZonePatchD5{Primaries: &prim}
	if key != "" {
		p.TSIGKey = &key
	}
	if allow != nil {
		p.NotifyAllow = &allow
	}
	if err := e.applyPatchD5(nil, z, p); err != nil {
		return ZoneDetail{}, err
	}
	// a stale data file of an earlier zone with this name is not reused
	e.zoneDeletedD5(z)
	if err := e.commitZoneLocked(nil, z, "create"); err != nil {
		return ZoneDetail{}, err
	}
	d := detail(z)
	e.d5Status(&d, z)
	return d, nil
}

// zoneDoc returns the current zone document (immutable) or nil.
func (e *Engine) zoneDoc(fq string) *zone.Zone {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.zones[fq]
}

// ---------------------------------------------------------------- TSIG API

// TSIGKeys lists keys (no secrets).
func (e *Engine) TSIGKeys() []tsig.View { return e.d5.tsig.List() }

// TSIGInput is POST /v1/tsig.
type TSIGInput struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Secret    string `json:"secret"`
}

// CreateTSIG adds a key; the secret is returned only here.
func (e *Engine) CreateTSIG(in TSIGInput) (tsig.Created, error) {
	return e.d5.tsig.Create(in.Name, in.Algorithm, in.Secret, time.Now())
}

// DeleteTSIG removes a key that no zone uses.
func (e *Engine) DeleteTSIG(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	fq, ok := tsig.NormalizeName(name)
	if !ok || !e.d5.tsig.Has(fq) {
		return fielderr.New(CodeTSIGNotFound, "TSIG key not found")
	}
	disp := zone.Display(fq)
	var users []string
	for _, z := range e.zones {
		uses := z.TSIGKey == disp || z.Transfer != nil && z.Transfer.TSIGKey == disp ||
			z.Notify != nil && z.Notify.TSIGKey == disp || z.Update != nil && z.Update.TSIGKey == disp
		if uses {
			users = append(users, zone.Display(z.Name))
		}
	}
	if len(users) > 0 {
		sort.Strings(users)
		return fielderr.Single(CodeTSIGInUse, "the key is used by zones", "name", "in_use", "zones", users)
	}
	return e.d5.tsig.Delete(fq)
}

func (e *Engine) xfrSigner(key string) *xfr.Signer {
	if key == "" {
		return nil
	}
	k, ok := e.d5.tsig.Get(key)
	if !ok {
		return nil
	}
	fq := dns.Fqdn(strings.ToLower(k.Name))
	return &xfr.Signer{Key: fq, Algorithm: tsig.WireAlgorithm(k.Algorithm), Secrets: map[string]string{fq: k.Secret}}
}

// ---------------------------------------------------------------- DNSSEC API

// DNSSECKeyView is one key of GET /v1/zones/{zone}/dnssec.
type DNSSECKeyView struct {
	Tag       uint16    `json:"tag"`
	Role      string    `json:"role"`
	Algorithm string    `json:"algorithm"`
	Created   time.Time `json:"created"`
	State     string    `json:"state"`
	Since     time.Time `json:"state_since"`
}

// ZoneDNSSECView is GET /v1/zones/{zone}/dnssec.
type ZoneDNSSECView struct {
	Enabled    bool               `json:"enabled"`
	Config     zone.SigningConfig `json:"config"`
	Keys       []DNSSECKeyView    `json:"keys"`
	DS         []signer.DSView    `json:"ds"`
	NextResign *time.Time         `json:"next_resign"`
	NextKeyEvt *time.Time         `json:"next_key_event"`
	Expiration *time.Time         `json:"signatures_expire"`
	Error      string             `json:"error,omitempty"`
}

func (e *Engine) dnssecViewLocked(z *zone.Zone) (ZoneDNSSECView, error) {
	v := ZoneDNSSECView{Config: zone.DefaultSigning(), Keys: []DNSSECKeyView{}, DS: []signer.DSView{}}
	if z.DNSSEC != nil {
		v.Config = *z.DNSSEC
	}
	v.Enabled = z.Signed()
	ks, err := e.keySetFor(&zone.Zone{Name: z.Name, DNSSEC: &v.Config}, false)
	if err != nil {
		return v, err
	}
	if ks != nil {
		for _, k := range ks.Keys {
			v.Keys = append(v.Keys, DNSSECKeyView{Tag: k.Tag, Role: k.Role, Algorithm: k.Algorithm, Created: k.Created,
				State: k.State, Since: k.StateSince})
		}
		if ds := ks.DS(); ds != nil {
			v.DS = ds
		}
		t := e.timing()
		if at := ks.NextEvent(t.Keys); !at.IsZero() && v.Enabled {
			v.NextKeyEvt = &at
		}
	}
	e.d5.mu.Lock()
	si, ok := e.d5.signed[z.Name]
	e.d5.mu.Unlock()
	if v.Enabled && ok {
		if si.err != "" {
			v.Error = si.err
		} else {
			exp := si.expiration
			at := exp.Add(-time.Duration(v.Config.RefreshDays) * 24 * time.Hour)
			v.NextResign, v.Expiration = &at, &exp
		}
	}
	return v, nil
}

// ZoneDNSSEC returns the signing status of a primary zone.
func (e *Engine) ZoneDNSSEC(name string) (ZoneDNSSECView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	z, err := e.primaryLocked(name)
	if err != nil {
		return ZoneDNSSECView{}, err
	}
	return e.dnssecViewLocked(z)
}

// RolloverDNSSEC starts a KSK or ZSK rollover.
func (e *Engine) RolloverDNSSEC(name, role string) (ZoneDNSSECView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	old, err := e.primaryLocked(name)
	if err != nil {
		return ZoneDNSSECView{}, err
	}
	if role != signer.RoleKSK && role != signer.RoleZSK {
		return ZoneDNSSECView{}, fielderr.Single(CodeInvalidRequest, "invalid role", "role", "invalid_choice",
			"choices", []string{signer.RoleKSK, signer.RoleZSK})
	}
	if !old.Signed() {
		return ZoneDNSSECView{}, fielderr.New(CodeDNSSECDisabled, "DNSSEC signing is not enabled for this zone")
	}
	ks, err := e.keySetFor(old, true)
	if err != nil {
		return ZoneDNSSECView{}, err
	}
	if err := ks.Rollover(role, e.now()); err != nil {
		if errors.Is(err, signer.ErrRolloverInProgress) {
			return ZoneDNSSECView{}, fielderr.New(CodeRolloverInProgress, err.Error())
		}
		return ZoneDNSSECView{}, err
	}
	if err := e.d5.keys.Save(ks); err != nil {
		return ZoneDNSSECView{}, err
	}
	z := old.Clone()
	z.Serial = old.Serial
	if err := e.commitZoneLocked(old, z, "dnssec.rollover:"+role); err != nil {
		return ZoneDNSSECView{}, err
	}
	return e.dnssecViewLocked(z)
}

// ---------------------------------------------------------------- maintenance loop

func (e *Engine) d5Loop() {
	defer e.wg.Done()
	for {
		t := e.timing()
		timer := time.NewTimer(t.Tick)
		select {
		case <-e.bg.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-e.d5.kick:
			timer.Stop()
		}
		e.d5Tick()
	}
}

func (e *Engine) d5Tick() {
	t := e.timing()
	now := t.Now()
	e.mu.Lock()
	var due, expire, signing []string
	for name, z := range e.zones {
		switch {
		case z.Type == zone.TypeSecondary && !z.Disabled:
			s := e.secFor(name)
			e.d5.mu.Lock()
			if !s.running && (s.st.NextRefresh == nil || !now.Before(*s.st.NextRefresh)) {
				due = append(due, name)
			}
			if s.soa != nil && s.st.ExpiresAt != nil && !now.Before(*s.st.ExpiresAt) && !s.expiredEv {
				expire = append(expire, name)
			}
			e.d5.mu.Unlock()
		case z.Signed():
			signing = append(signing, name)
		}
	}
	e.mu.Unlock()
	for _, name := range expire {
		e.expireSecondary(name)
	}
	for _, name := range signing {
		e.maintainSigning(name, t, now)
	}
	for _, name := range due {
		e.d5.mu.Lock()
		s := e.d5.sec[name]
		if s == nil || s.running {
			e.d5.mu.Unlock()
			continue
		}
		s.running = true
		e.d5.mu.Unlock()
		e.wg.Add(1)
		go func(name string) {
			defer e.wg.Done()
			_, _ = e.refreshSecondary(name)
		}(name)
	}
}

// maintainSigning advances key rollovers and re-signs before expiry.
func (e *Engine) maintainSigning(name string, t ZoneTiming, now time.Time) {
	_ = e.WithActor("dnssec", func() error {
		e.mu.Lock()
		defer e.mu.Unlock()
		old := e.zones[name]
		if old == nil || !old.Signed() {
			return nil
		}
		ks, err := e.keySetFor(old, true)
		if err != nil {
			return err
		}
		reason := ""
		if ks.Advance(now, t.Keys) {
			if err := e.d5.keys.Save(ks); err != nil {
				return err
			}
			reason = "dnssec.keys"
			e.EventRing().Emit(EventDNSSECKeysAdvanced, "info", map[string]any{"zone": zone.Display(name)})
		}
		e.d5.mu.Lock()
		si, ok := e.d5.signed[name]
		e.d5.mu.Unlock()
		refresh := time.Duration(old.DNSSEC.RefreshDays) * 24 * time.Hour
		if reason == "" && ok && si.err == "" && !now.Before(si.expiration.Add(-refresh)) {
			reason = "dnssec.resign"
		}
		if reason == "" && ok && si.err != "" && si.version == old.Version {
			reason = "dnssec.retry"
		}
		if reason == "" {
			return nil
		}
		z := old.Clone()
		z.Serial = old.Serial
		return e.commitZoneLocked(old, z, reason)
	})
}

// ---------------------------------------------------------------- secondary state

func (e *Engine) secPaths(fq string) (data, state string) {
	base := filepath.Join(e.d5.dir, zone.Display(fq))
	return base + ".zone", base + ".state.json"
}

// secFor returns the runtime state of a secondary, loading it from disk once.
func (e *Engine) secFor(fq string) *secondary {
	e.d5.mu.Lock()
	s := e.d5.sec[fq]
	e.d5.mu.Unlock()
	if s != nil {
		return s
	}
	s = &secondary{}
	dataPath, statePath := e.secPaths(fq)
	if b, err := os.ReadFile(statePath); err == nil {
		_ = jsonUnmarshal(b, &s.st)
	}
	if b, err := os.ReadFile(dataPath); err == nil {
		soa, rrs, err := parseZoneText(fq, string(b))
		if err == nil {
			s.soa, s.rrs = soa, rrs
			s.st.Loaded = true
			s.st.Serial = soa.Serial
		} else {
			e.log.Warn("secondary data unreadable; transferring again", "zone", fq, "err", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		e.log.Warn("secondary data unreadable", "zone", fq, "err", err)
	}
	if s.soa == nil {
		s.st.Loaded = false
		s.st.NextRefresh = nil
	}
	e.d5.mu.Lock()
	defer e.d5.mu.Unlock()
	if cur := e.d5.sec[fq]; cur != nil {
		return cur
	}
	e.d5.sec[fq] = s
	return s
}

func parseZoneText(origin, text string) (*dns.SOA, []dns.RR, error) {
	zp := dns.NewZoneParser(strings.NewReader(text), origin, "")
	zp.SetIncludeAllowed(false)
	var soa *dns.SOA
	var rrs []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if s, isSOA := rr.(*dns.SOA); isSOA && soa == nil {
			soa = s
			continue
		}
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, nil, err
	}
	if soa == nil {
		return nil, nil, errors.New("no SOA")
	}
	return soa, rrs, nil
}

func (e *Engine) saveSecondary(fq string, s *secondary, data bool) error {
	dataPath, statePath := e.secPaths(fq)
	if data {
		var b strings.Builder
		b.WriteString(s.soa.String())
		b.WriteByte('\n')
		for _, rr := range s.rrs {
			b.WriteString(rr.String())
			b.WriteByte('\n')
		}
		if err := store.WriteFileAtomic(dataPath, []byte(b.String()), 0o640); err != nil {
			return err
		}
	}
	js, err := jsonMarshal(s.st)
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(statePath, js, 0o640)
}

// scheduleRefresh makes a secondary refresh at (or before) at.
func (e *Engine) scheduleRefresh(fq string, at time.Time) {
	s := e.secFor(fq)
	e.d5.mu.Lock()
	if s.st.NextRefresh == nil || at.Before(*s.st.NextRefresh) {
		s.st.NextRefresh = &at
	}
	e.d5.mu.Unlock()
	e.kickD5()
}

func (e *Engine) expireSecondary(fq string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	z := e.zones[fq]
	if z == nil || z.Type != zone.TypeSecondary {
		return
	}
	s := e.secFor(fq)
	e.d5.mu.Lock()
	s.expiredEv = true
	s.st.Expired = true
	e.d5.mu.Unlock()
	e.compiled[fq] = e.compileSecondary(z)
	if err := e.rebuildLocked(); err != nil {
		e.log.Error("rebuild after secondary expiry", "zone", fq, "err", err)
	}
	e.Cache.Flush(fq)
	e.EventRing().Emit(EventSecondaryExpired, "error", map[string]any{"zone": zone.Display(fq)})
	e.log.Error("secondary zone expired; answering SERVFAIL", "zone", fq)
}

func clampDur(sec uint32, min time.Duration) time.Duration {
	d := time.Duration(sec) * time.Second
	if d < min {
		d = min
	}
	if d > 7*24*time.Hour {
		d = 7 * 24 * time.Hour
	}
	return d
}

func jsonMarshal(v any) ([]byte, error) { return json.MarshalIndent(v, "", " ") }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// secondaryRecordsLocked lists a secondary's data as read-only records:
// SOA first, then every RR of a type the record model knows (ok=false: not
// a secondary).
func (e *Engine) secondaryRecordsLocked(name string) ([]zone.Record, bool) {
	fq, ok := zone.NormalizeZoneName(name)
	if !ok {
		return nil, false
	}
	z := e.zones[fq]
	if z == nil || z.Type != zone.TypeSecondary {
		return nil, false
	}
	s := e.secFor(fq)
	e.d5.mu.Lock()
	soa, rrs := s.soa, s.rrs
	e.d5.mu.Unlock()
	out := []zone.Record{}
	if soa == nil {
		return out, true
	}
	sz := &zone.Zone{Name: fq, Serial: soa.Serial, SOA: zone.SOA{TTL: soa.Hdr.Ttl, MName: zone.Display(soa.Ns),
		RName: zone.Display(soa.Mbox), Refresh: soa.Refresh, Retry: soa.Retry, Expire: soa.Expire, Minimum: soa.Minttl}}
	out = append(out, sz.SOARecord())
	for i, rr := range rrs {
		r, err := zone.FromRR(rr, fq)
		if err != nil {
			continue
		}
		r.ID = fmt.Sprintf("x%d", i)
		out = append(out, r)
	}
	return out, true
}

// secondaryExportLocked renders a secondary's data as zone-file text.
func (e *Engine) secondaryExportLocked(name string) (string, bool) {
	fq, ok := zone.NormalizeZoneName(name)
	if !ok {
		return "", false
	}
	z := e.zones[fq]
	if z == nil || z.Type != zone.TypeSecondary {
		return "", false
	}
	s := e.secFor(fq)
	e.d5.mu.Lock()
	defer e.d5.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "; secondary zone %s exported by mrk-dns\n", zone.Display(fq))
	if s.soa == nil {
		return b.String(), true
	}
	b.WriteString(s.soa.String())
	b.WriteByte('\n')
	for _, rr := range s.rrs {
		b.WriteString(rr.String())
		b.WriteByte('\n')
	}
	return b.String(), true
}

// DataDir returns the engine data directory.
func (e *Engine) DataDir() string { return e.st.Dir() }
