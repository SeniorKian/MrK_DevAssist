package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/store"
	"mrk/dns-engine/internal/version"
	"mrk/dns-engine/internal/zone"
)

// Error codes returned by operations (the admin API maps them to HTTP).
const (
	CodeConfigConflict   = "config_conflict"
	CodeSettingsInvalid  = "settings_invalid"
	CodeZoneExists       = "zone_exists"
	CodeZoneNotFound     = "zone_not_found"
	CodeInvalidZoneName  = "invalid_zone_name"
	CodeZoneInvalid      = "zone_invalid"
	CodeZoneTypeMismatch = "zone_type_mismatch"
	CodeRecordNotFound   = "record_not_found"
	CodeRecordInvalid    = "record_invalid"
	CodeCNAMEConflict    = "cname_conflict"
	CodeOverrideNotFound = "override_not_found"
	CodeOverrideInvalid  = "override_invalid"
	CodeVersionNotFound  = "version_not_found"
	CodeImportInvalid    = "import_invalid"
	CodeInvalidRequest   = "invalid_request"
	CodeTooMany          = "limit_reached"
)

// MaxZones and MaxOverrides bound state size.
const (
	MaxZones     = 10_000
	MaxOverrides = 50_000
)

// ---------------------------------------------------------------- settings

// PutSettings replaces settings when expected matches the current version.
func (e *Engine) PutSettings(s config.Settings, expected int64) (config.Settings, int64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if expected != e.configVersion {
		return config.Settings{}, 0, &fielderr.Error{Code: CodeConfigConflict,
			Message: fmt.Sprintf("settings changed (current config_version %d)", e.configVersion)}
	}
	if l := s.Validate(); len(l) > 0 {
		return config.Settings{}, 0, l.Err(CodeSettingsInvalid, "settings are invalid")
	}
	prev, prevVersion := e.settings, e.configVersion
	e.settings, e.configVersion = s.Clone(), e.configVersion+1
	if err := e.rebuildLocked(); err != nil {
		e.settings, e.configVersion = prev, prevVersion
		_ = e.rebuildLocked()
		return config.Settings{}, 0, fielderr.New(CodeSettingsInvalid, err.Error())
	}
	if err := e.st.WriteJSON("settings.json", settingsDoc{Schema: store.Schema, ConfigVersion: e.configVersion, Settings: e.settings}); err != nil {
		e.settings, e.configVersion = prev, prevVersion
		_ = e.rebuildLocked()
		return config.Settings{}, 0, err
	}
	e.applyMonitorSettings(e.settings)
	if prev.RebindingProtection != s.RebindingProtection || prev.Cache.MinTTL != s.Cache.MinTTL || prev.Cache.MaxTTL != s.Cache.MaxTTL {
		e.Cache.Flush("")
	}
	if h := e.listenerHook.Load(); h != nil {
		go (*h)(e.settings.Clone())
	}
	return e.settings.Clone(), e.configVersion, nil
}

// ---------------------------------------------------------------- zones

// ZoneSummary is a list item.
type ZoneSummary struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Serial    uint32    `json:"serial"`
	Records   int       `json:"records"`
	Disabled  bool      `json:"disabled"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ZoneDetail is GET /v1/zones/{zone}.
type ZoneDetail struct {
	ZoneSummary
	Forwarders []string     `json:"forwarders"`
	Version    int          `json:"version"`
	SOA        *zone.Record `json:"soa,omitempty"`
}

func summary(z *zone.Zone) ZoneSummary {
	return ZoneSummary{Name: zone.Display(z.Name), Type: z.Type, Serial: z.Serial, Records: len(z.Records),
		Disabled: z.Disabled, UpdatedAt: z.UpdatedAt}
}

// Zones lists zones sorted by name.
func (e *Engine) Zones() []ZoneSummary {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ZoneSummary, 0, len(e.zones))
	for _, z := range e.zones {
		out = append(out, summary(z))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (e *Engine) zoneLocked(name string) (*zone.Zone, error) {
	fq, ok := zone.NormalizeZoneName(name)
	if !ok {
		return nil, fielderr.Single(CodeInvalidZoneName, "invalid zone name", "zone", "invalid_name")
	}
	z := e.zones[fq]
	if z == nil {
		return nil, fielderr.New(CodeZoneNotFound, "zone not found")
	}
	return z, nil
}

func detail(z *zone.Zone) ZoneDetail {
	d := ZoneDetail{ZoneSummary: summary(z), Forwarders: append([]string{}, z.Forwarders...), Version: z.Version}
	if z.Type == zone.TypePrimary {
		s := z.SOARecord()
		d.SOA = &s
	}
	return d
}

// Zone returns one zone.
func (e *Engine) Zone(name string) (ZoneDetail, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	z, err := e.zoneLocked(name)
	if err != nil {
		return ZoneDetail{}, err
	}
	return detail(z), nil
}

func parseUpstreamErr(s string) error { _, err := config.ParseUpstream(s); return err }

// CreateZone adds a primary or forwarder zone.
func (e *Engine) CreateZone(name, typ string, forwarders []string) (ZoneDetail, error) {
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
	z := &zone.Zone{Name: fq, Type: typ, Records: []zone.Record{}}
	switch typ {
	case zone.TypePrimary:
		if len(forwarders) > 0 {
			return ZoneDetail{}, fielderr.Single(CodeZoneInvalid, "primary zones have no forwarders", "forwarders", "not_allowed")
		}
		z.SOA = zone.DefaultSOA(fq)
		ns := json.RawMessage(fmt.Sprintf(`{"nameserver":%q}`, z.SOA.MName))
		z.Records = append(z.Records, zone.Record{ID: zone.NewID(), Name: "@", Type: "NS", TTL: 14400, Data: ns})
	case zone.TypeForwarder:
		if l := zone.ValidateForwarders(forwarders, parseUpstreamErr); len(l) > 0 {
			return ZoneDetail{}, l.Err(CodeZoneInvalid, "invalid forwarders")
		}
		z.Forwarders = append([]string(nil), forwarders...)
	default:
		return ZoneDetail{}, fielderr.Single(CodeZoneInvalid, "invalid zone type", "type", "invalid_choice",
			"choices", []string{zone.TypePrimary, zone.TypeForwarder})
	}
	if err := e.commitZoneLocked(nil, z, "create"); err != nil {
		return ZoneDetail{}, err
	}
	return detail(z), nil
}

// commitZoneLocked validates, compiles, persists and publishes z.
func (e *Engine) commitZoneLocked(old, z *zone.Zone, reason string) error {
	if z.Type == zone.TypePrimary {
		if l := zone.ValidateRecords(z.Name, z.Records); len(l) > 0 {
			code := CodeRecordInvalid
			for _, f := range l {
				if f.ReasonCode == "cname_conflict" || f.ReasonCode == "cname_at_apex" {
					code = CodeCNAMEConflict
				}
			}
			return l.Err(code, "zone records are invalid")
		}
	}
	now := time.Now().UTC()
	prevSerial := uint32(0)
	if old != nil {
		z.Version = old.Version + 1
		prevSerial = old.Serial
	} else {
		z.Version = 1
	}
	if z.Type == zone.TypePrimary {
		z.Serial = zone.SerialAfter(prevSerial, z.Serial, now)
		if old == nil || z.Serial == 0 {
			z.Serial = zone.NextSerial(prevSerial, now)
		}
	}
	z.UpdatedAt = now
	z.Reason = reason
	z.Actor = e.currentActor()
	c, err := zone.Compile(z)
	if err != nil {
		return fielderr.New(CodeRecordInvalid, err.Error())
	}
	if err := e.st.SaveZone(z); err != nil {
		return err
	}
	e.zones[z.Name] = z
	e.compiled[z.Name] = c
	if err := e.rebuildLocked(); err != nil {
		return err
	}
	e.Cache.Flush(z.Name)
	return nil
}

// ZonePatch is PATCH /v1/zones/{zone}.
type ZonePatch struct {
	Disabled   *bool     `json:"disabled"`
	Forwarders *[]string `json:"forwarders"`
}

// PatchZone toggles disabled or replaces forwarders.
func (e *Engine) PatchZone(name string, p ZonePatch) (ZoneDetail, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	old, err := e.zoneLocked(name)
	if err != nil {
		return ZoneDetail{}, err
	}
	z := old.Clone()
	z.Serial = old.Serial
	if p.Disabled != nil {
		z.Disabled = *p.Disabled
	}
	if p.Forwarders != nil {
		if z.Type != zone.TypeForwarder {
			return ZoneDetail{}, fielderr.Single(CodeZoneTypeMismatch, "only forwarder zones have forwarders", "forwarders", "not_allowed")
		}
		if l := zone.ValidateForwarders(*p.Forwarders, parseUpstreamErr); len(l) > 0 {
			return ZoneDetail{}, l.Err(CodeZoneInvalid, "invalid forwarders")
		}
		z.Forwarders = append([]string(nil), (*p.Forwarders)...)
	}
	if err := e.commitZoneLocked(old, z, "update"); err != nil {
		return ZoneDetail{}, err
	}
	return detail(z), nil
}

// DeleteZone removes a zone and its history.
func (e *Engine) DeleteZone(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	z, err := e.zoneLocked(name)
	if err != nil {
		return err
	}
	if err := e.st.DeleteZone(z.Name); err != nil {
		return err
	}
	delete(e.zones, z.Name)
	delete(e.compiled, z.Name)
	if err := e.rebuildLocked(); err != nil {
		return err
	}
	e.Cache.Flush(z.Name)
	return nil
}

func (e *Engine) primaryLocked(name string) (*zone.Zone, error) {
	z, err := e.zoneLocked(name)
	if err != nil {
		return nil, err
	}
	if z.Type != zone.TypePrimary {
		return nil, fielderr.New(CodeZoneTypeMismatch, "operation needs a primary zone")
	}
	return z, nil
}

// Export returns RFC 1035 text.
func (e *Engine) Export(name string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	z, err := e.primaryLocked(name)
	if err != nil {
		return "", err
	}
	return zone.Export(z)
}

// ImportResult summarises an import.
type ImportResult struct {
	Added   int    `json:"added"`
	Skipped int    `json:"skipped"`
	Serial  uint32 `json:"serial"`
	Version int    `json:"version"`
}

// Import loads zone-file text; replace=true replaces all records.
func (e *Engine) Import(name, text string, replace bool) (ImportResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	old, err := e.primaryLocked(name)
	if err != nil {
		return ImportResult{}, err
	}
	recs, soa, err := zone.Import(text, old.Name)
	if err != nil {
		var fe *fielderr.Error
		if errors.As(err, &fe) {
			fe.Code = CodeImportInvalid
		}
		return ImportResult{}, err
	}
	z := old.Clone()
	z.Serial = old.Serial
	res := ImportResult{}
	if replace {
		z.Records = recs
		res.Added = len(recs)
		if !hasApexNS(recs) {
			// keep the existing apex NS set so the zone stays valid
			for _, r := range old.Records {
				if r.Name == "@" && r.Type == "NS" {
					z.Records = append(z.Records, r)
				}
			}
		}
	} else {
		have := map[string]bool{}
		for _, r := range z.Records {
			have[r.Name+"\x00"+r.Type+"\x00"+string(r.Data)] = true
		}
		for _, r := range recs {
			k := r.Name + "\x00" + r.Type + "\x00" + string(r.Data)
			if have[k] {
				res.Skipped++
				continue
			}
			have[k] = true
			z.Records = append(z.Records, r)
			res.Added++
		}
	}
	if soa != nil {
		ser := soa.ImportedSerial()
		z.SOA = *soa
		if ser != 0 && (z.Serial == 0 || ser > z.Serial) {
			z.Serial = ser // SerialAfter in commit still makes it strictly increase
		}
	}
	if err := e.commitZoneLocked(old, z, "import"); err != nil {
		return ImportResult{}, err
	}
	res.Serial, res.Version = z.Serial, z.Version
	return res, nil
}

func hasApexNS(recs []zone.Record) bool {
	for _, r := range recs {
		if r.Name == "@" && r.Type == "NS" {
			return true
		}
	}
	return false
}

// History lists versions newest first.
func (e *Engine) History(name string) ([]store.HistoryEntry, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	z, err := e.zoneLocked(name)
	if err != nil {
		return nil, err
	}
	return e.st.History(z.Name)
}

// Rollback restores a stored version as a new version.
func (e *Engine) Rollback(name string, version int) (ZoneDetail, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	old, err := e.zoneLocked(name)
	if err != nil {
		return ZoneDetail{}, err
	}
	hv, err := e.st.LoadVersion(old.Name, version)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ZoneDetail{}, fielderr.New(CodeVersionNotFound, "version not found")
		}
		return ZoneDetail{}, err
	}
	z := hv.Clone()
	z.Name, z.Type = old.Name, old.Type
	z.Serial = old.Serial // commit bumps it so secondaries/caches see a change
	if err := e.commitZoneLocked(old, z, fmt.Sprintf("rollback:%d", version)); err != nil {
		return ZoneDetail{}, err
	}
	return detail(z), nil
}

// ---------------------------------------------------------------- records

// Records lists a primary zone's records, SOA first.
func (e *Engine) Records(name string) ([]zone.Record, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	z, err := e.primaryLocked(name)
	if err != nil {
		return nil, err
	}
	out := make([]zone.Record, 0, len(z.Records)+1)
	out = append(out, z.SOARecord())
	out = append(out, z.Records...)
	return out, nil
}

func recordErr(l fielderr.List) error {
	code := CodeRecordInvalid
	for _, f := range l {
		if f.ReasonCode == "cname_conflict" || f.ReasonCode == "cname_at_apex" {
			code = CodeCNAMEConflict
		}
	}
	return l.Err(code, "record is invalid")
}

// recordFieldsFor narrows zone-wide errors to the record id when possible.
func recordFieldsFor(l fielderr.List, id string) fielderr.List {
	var out fielderr.List
	for _, f := range l {
		if f.Params != nil && f.Params["id"] == id {
			f.Field = "name"
			if f.ReasonCode == "duplicate_record" {
				f.Field = "data"
			}
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return l
	}
	return out
}

// CreateRecord adds a record to a primary zone.
func (e *Engine) CreateRecord(name string, in zone.RecordInput) (zone.Record, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	old, err := e.primaryLocked(name)
	if err != nil {
		return zone.Record{}, err
	}
	r, _, l := zone.BuildRecord(in, old.Name)
	if len(l) > 0 {
		return zone.Record{}, recordErr(l)
	}
	r.ID = zone.NewID()
	z := old.Clone()
	z.Serial = old.Serial
	z.Records = append(z.Records, r)
	zone.SyncRRsetTTL(z.Records, len(z.Records)-1)
	if l := zone.ValidateRecords(z.Name, z.Records); len(l) > 0 {
		return zone.Record{}, recordErr(recordFieldsFor(l, r.ID))
	}
	if err := e.commitZoneLocked(old, z, "record.create"); err != nil {
		return zone.Record{}, err
	}
	return r, nil
}

// UpdateRecord replaces a record (or edits the SOA when id == "soa").
func (e *Engine) UpdateRecord(name, id string, in zone.RecordInput) (zone.Record, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	old, err := e.primaryLocked(name)
	if err != nil {
		return zone.Record{}, err
	}
	z := old.Clone()
	z.Serial = old.Serial
	if id == zone.SOAID {
		soa, l := zone.ParseSOAData(in.Data, z.Name)
		ttl := int(old.SOA.TTL)
		if in.TTL != nil {
			ttl = *in.TTL
		}
		if ttl < 0 || ttl > zone.MaxTTL {
			l.Add("ttl", "out_of_range", "min", 0, "max", zone.MaxTTL)
		}
		if len(l) > 0 {
			return zone.Record{}, l.Err(CodeRecordInvalid, "SOA is invalid")
		}
		soa.TTL = uint32(ttl)
		z.SOA = soa
		if err := e.commitZoneLocked(old, z, "soa.update"); err != nil {
			return zone.Record{}, err
		}
		return z.SOARecord(), nil
	}
	idx := -1
	for i := range z.Records {
		if z.Records[i].ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return zone.Record{}, fielderr.New(CodeRecordNotFound, "record not found")
	}
	r, _, l := zone.BuildRecord(in, z.Name)
	if len(l) > 0 {
		return zone.Record{}, recordErr(l)
	}
	r.ID = id
	z.Records[idx] = r
	zone.SyncRRsetTTL(z.Records, idx)
	if l := zone.ValidateRecords(z.Name, z.Records); len(l) > 0 {
		return zone.Record{}, recordErr(recordFieldsFor(l, id))
	}
	if err := e.commitZoneLocked(old, z, "record.update"); err != nil {
		return zone.Record{}, err
	}
	return r, nil
}

// DeleteRecord removes a record.
func (e *Engine) DeleteRecord(name, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	old, err := e.primaryLocked(name)
	if err != nil {
		return err
	}
	if id == zone.SOAID {
		return fielderr.Single(CodeRecordInvalid, "the SOA cannot be deleted", "id", "soa_managed")
	}
	z := old.Clone()
	z.Serial = old.Serial
	out := z.Records[:0:0]
	found := false
	for _, r := range z.Records {
		if r.ID == id {
			found = true
			continue
		}
		out = append(out, r)
	}
	if !found {
		return fielderr.New(CodeRecordNotFound, "record not found")
	}
	z.Records = out
	return e.commitZoneLocked(old, z, "record.delete")
}

// ---------------------------------------------------------------- overrides

// OverrideInput is a create/update body.
type OverrideInput struct {
	Name     *string `json:"name"`
	Type     *string `json:"type"`
	Value    *string `json:"value"`
	TTL      *int    `json:"ttl"`
	Source   string  `json:"source"`
	Disabled bool    `json:"disabled"`
}

func buildOverride(in OverrideInput) (Override, error) {
	var l fielderr.List
	var o Override
	if in.Name == nil {
		l.Add("name", "required")
	} else {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*in.Name), "."))
		base := strings.TrimPrefix(n, "*.")
		if _, ok := zone.NormalizeZoneName(base); !ok || strings.Contains(base, "*") {
			l.Add("name", "invalid_name")
		}
		o.Name = n
	}
	if in.Type == nil {
		l.Add("type", "required")
	} else {
		o.Type = strings.ToUpper(strings.TrimSpace(*in.Type))
		if o.Type != "A" && o.Type != "AAAA" && o.Type != "CNAME" {
			l.Add("type", "invalid_choice", "choices", []string{"A", "AAAA", "CNAME"})
		}
	}
	if in.Value == nil {
		l.Add("value", "required")
	} else {
		o.Value = strings.TrimSpace(*in.Value)
	}
	ttl := 300
	if in.TTL != nil {
		ttl = *in.TTL
	}
	if ttl < 0 || ttl > zone.MaxTTL {
		l.Add("ttl", "out_of_range", "min", 0, "max", zone.MaxTTL)
	}
	o.TTL = uint32(ttl)
	switch in.Source {
	case "", "user":
		o.Source = "user"
	case "services":
		o.Source = "services"
	default:
		l.Add("source", "invalid_choice", "choices", []string{"user", "services"})
	}
	o.Disabled = in.Disabled
	if len(l) == 0 {
		switch o.Type {
		case "A", "AAAA":
			a, err := netip.ParseAddr(o.Value)
			if err != nil || a.Zone() != "" || (o.Type == "A" && !a.Unmap().Is4()) || (o.Type == "AAAA" && (!a.Is6() || a.Is4In6())) {
				l.Add("value", "invalid_address")
			} else {
				if o.Type == "A" {
					a = a.Unmap()
				}
				o.Value = a.String()
			}
		case "CNAME":
			t := strings.ToLower(strings.TrimSuffix(o.Value, "."))
			if _, ok := zone.NormalizeZoneName(t); !ok {
				l.Add("value", "invalid_name")
			} else if t == o.Name {
				l.Add("value", "cname_loop")
			}
			o.Value = t
		}
	}
	if len(l) > 0 {
		return o, l.Err(CodeRecordInvalid, "override is invalid")
	}
	return o, nil
}

func checkOverrideSet(items []Override) error {
	// CNAME exclusivity per name, duplicates rejected
	byName := map[string][]Override{}
	for _, o := range items {
		byName[o.Name] = append(byName[o.Name], o)
	}
	for name, os := range byName {
		cn := 0
		seen := map[string]bool{}
		for _, o := range os {
			if o.Type == "CNAME" {
				cn++
			}
			k := o.Type + "|" + o.Value
			if seen[k] {
				return fielderr.Single(CodeRecordInvalid, "duplicate override", "value", "duplicate", "name", name)
			}
			seen[k] = true
		}
		if cn > 0 && len(os) > 1 {
			return fielderr.Single(CodeCNAMEConflict, "a CNAME override cannot coexist with other overrides for the same name", "type", "cname_conflict", "name", name)
		}
	}
	return nil
}

// Overrides lists overrides.
func (e *Engine) Overrides() []Override {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Override{}, e.overrides...)
}

func (e *Engine) commitOverridesLocked(items []Override) error {
	if err := checkOverrideSet(items); err != nil {
		return err
	}
	if err := e.st.WriteJSON("overrides.json", overridesDoc{Schema: store.Schema, Items: items}); err != nil {
		return err
	}
	e.overrides = items
	return e.rebuildLocked()
}

// CreateOverride adds an override.
func (e *Engine) CreateOverride(in OverrideInput) (Override, error) {
	o, err := buildOverride(in)
	if err != nil {
		return o, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.overrides) >= MaxOverrides {
		return o, fielderr.New(CodeTooMany, "too many overrides")
	}
	o.ID = zone.NewID()
	items := append(append([]Override{}, e.overrides...), o)
	return o, e.commitOverridesLocked(items)
}

// UpdateOverride replaces an override.
func (e *Engine) UpdateOverride(id string, in OverrideInput) (Override, error) {
	o, err := buildOverride(in)
	if err != nil {
		return o, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	items := append([]Override{}, e.overrides...)
	for i := range items {
		if items[i].ID == id {
			o.ID = id
			items[i] = o
			return o, e.commitOverridesLocked(items)
		}
	}
	return o, fielderr.New(CodeOverrideNotFound, "override not found")
}

// DeleteOverride removes an override.
func (e *Engine) DeleteOverride(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	items := make([]Override, 0, len(e.overrides))
	found := false
	for _, o := range e.overrides {
		if o.ID == id {
			found = true
			continue
		}
		items = append(items, o)
	}
	if !found {
		return fielderr.New(CodeOverrideNotFound, "override not found")
	}
	return e.commitOverridesLocked(items)
}

// ---------------------------------------------------------------- resolve / status

// ResolveAnswer is one answer RR in /v1/resolve.
type ResolveAnswer struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

// ResolveResult is POST /v1/resolve.
type ResolveResult struct {
	Rcode     string          `json:"rcode"`
	Answers   []ResolveAnswer `json:"answers"`
	Authority []ResolveAnswer `json:"authority,omitempty"`
	Source    string          `json:"source"`
	Upstream  string          `json:"upstream,omitempty"`
	Stale     bool            `json:"stale,omitempty"`
	RTTMS     float64         `json:"rtt_ms"`
}

func rrView(rr dns.RR) ResolveAnswer {
	h := rr.Header()
	full := rr.String()
	data := strings.TrimPrefix(full, h.String())
	return ResolveAnswer{Name: zone.Display(h.Name), Type: dns.TypeToString[h.Rrtype], TTL: h.Ttl, Data: strings.TrimSpace(data)}
}

// Resolve runs the full pipeline for a test query as if sent by client.
func (e *Engine) Resolve(ctx context.Context, name, qtype, client string) (ResolveResult, error) {
	var l fielderr.List
	fq := strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
	if _, ok := dns.IsDomainName(fq); !ok || len(fq) > 254 || strings.TrimSpace(name) == "" {
		l.Add("name", "invalid_name")
	}
	t, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(qtype))]
	if qtype == "" {
		t, ok = dns.TypeA, true
	}
	if !ok {
		l.Add("type", "invalid_type")
	}
	addr := netip.MustParseAddr("127.0.0.1")
	if client != "" {
		a, err := netip.ParseAddr(client)
		if err != nil {
			l.Add("client_ip", "invalid_address")
		}
		addr = a.Unmap()
	}
	if len(l) > 0 {
		return ResolveResult{}, l.Err(CodeRecordInvalid, "invalid resolve request")
	}
	p := e.pol.Load()
	start := time.Now()
	req := new(dns.Msg)
	req.SetQuestion(fq, t)
	req.RecursionDesired = true
	var resp *dns.Msg
	meta := answerMeta{src: metrics.SrcRefused}
	if !p.queryACL.Allowed(addr) {
		resp = refused(req)
	} else {
		resp, meta = e.answer(ctx, p, req, addr, API)
	}
	res := ResolveResult{Rcode: dns.RcodeToString[resp.Rcode], Answers: []ResolveAnswer{}, Source: sourceName(meta.src),
		Upstream: meta.upstream, Stale: meta.stale, RTTMS: float64(time.Since(start).Microseconds()) / 1000}
	if resp.Rcode == dns.RcodeRefused && meta.src == metrics.SrcRefused {
		res.Source = "refused"
	}
	for _, rr := range resp.Answer {
		res.Answers = append(res.Answers, rrView(rr))
	}
	for _, rr := range resp.Ns {
		res.Authority = append(res.Authority, rrView(rr))
	}
	return res, nil
}

// FlushCache removes name's subtree (or everything).
func (e *Engine) FlushCache(name string) (int, error) {
	if name != "" {
		if _, ok := dns.IsDomainName(name); !ok {
			return 0, fielderr.Single(CodeInvalidRequest, "invalid name", "name", "invalid_name")
		}
	}
	return e.Cache.Flush(name), nil
}

// ListenerStatus is reported by the server.
type ListenerStatus struct {
	Address string `json:"address"`
	Proto   string `json:"proto"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// UpstreamStatus is part of /v1/status.
type UpstreamStatus struct {
	ID      string  `json:"id"`
	Address string  `json:"address"`
	Proto   string  `json:"proto"`
	Healthy bool    `json:"healthy"`
	RTTMS   float64 `json:"rtt_ms"`
	Error   string  `json:"last_error,omitempty"`
}

// Status is GET /v1/status.
type Status struct {
	Version       string           `json:"version"`
	StartedAt     time.Time        `json:"started_at"`
	UptimeS       int64            `json:"uptime_s"`
	Listeners     []ListenerStatus `json:"listeners"`
	QPS1s         float64          `json:"qps_1s"`
	QPS1m         float64          `json:"qps_1m"`
	QueriesTotal  uint64           `json:"queries_total"`
	Cache         any              `json:"cache"`
	Upstreams     []UpstreamStatus `json:"upstreams"`
	Pressure      string           `json:"pressure"`
	MemoryBytes   uint64           `json:"memory_bytes"`
	Goroutines    int              `json:"goroutines"`
	ConfigVersion int64            `json:"config_version"`
	Zones         int              `json:"zones"`
	Overrides     int              `json:"overrides"`
}

// Status builds the status document.
func (e *Engine) Status(listeners []ListenerStatus) Status {
	p := e.pol.Load()
	q1, q60 := e.M.QPS()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	st := Status{Version: version.String(), StartedAt: e.started.UTC(), UptimeS: int64(time.Since(e.started).Seconds()),
		Listeners: listeners, QPS1s: q1, QPS1m: q60, QueriesTotal: e.M.Total(), Cache: e.Cache.Stats(),
		Upstreams: []UpstreamStatus{}, Pressure: e.PressureLevel(), MemoryBytes: ms.Sys - ms.HeapReleased, Goroutines: runtime.NumGoroutine(),
		ConfigVersion: p.configVersion, Zones: p.zones.Len(), Overrides: len(e.Overrides())}
	if st.Listeners == nil {
		st.Listeners = []ListenerStatus{}
	}
	for _, u := range p.upstreams {
		st.Upstreams = append(st.Upstreams, UpstreamStatus{ID: u.ID, Address: u.Raw, Proto: u.Addr.Proto,
			Healthy: u.Enabled && u.Healthy(), RTTMS: float64(u.RTT().Microseconds()) / 1000, Error: u.LastError()})
	}
	return st
}

// WritePrometheus renders all metrics.
func (e *Engine) WritePrometheus(w io.Writer) {
	cs := e.Cache.Stats()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	g := []metrics.Gauge{
		{Name: "mrk_dns_cache_entries", Help: "Cached responses.", Value: float64(cs.Entries)},
		{Name: "mrk_dns_cache_bytes", Help: "Approximate cache memory.", Value: float64(cs.Bytes)},
		{Name: "mrk_dns_cache_max_bytes", Help: "Cache memory bound.", Value: float64(cs.MaxBytes)},
		{Name: "mrk_dns_cache_hits_total", Help: "Cache hits.", Value: float64(cs.Hits)},
		{Name: "mrk_dns_cache_misses_total", Help: "Cache misses.", Value: float64(cs.Misses)},
		{Name: "mrk_dns_cache_evictions_total", Help: "LRU evictions.", Value: float64(cs.Evicted)},
		{Name: "mrk_dns_memory_bytes", Help: "Memory obtained from the OS minus released.", Value: float64(ms.Sys - ms.HeapReleased)},
		{Name: "mrk_dns_goroutines", Help: "Goroutines.", Value: float64(runtime.NumGoroutine())},
		{Name: "mrk_dns_uptime_seconds", Help: "Seconds since start.", Value: time.Since(e.started).Seconds()},
	}
	p := e.pol.Load()
	for _, u := range p.upstreams {
		h := 0.0
		if u.Healthy() {
			h = 1
		}
		g = append(g, metrics.Gauge{Name: "mrk_dns_upstream_healthy", Help: "Upstream health (1 = healthy).",
			Labels: fmt.Sprintf("upstream=%q", u.ID), Value: h})
		g = append(g, metrics.Gauge{Name: "mrk_dns_upstream_rtt_seconds", Help: "Smoothed upstream RTT.",
			Labels: fmt.Sprintf("upstream=%q", u.ID), Value: u.RTT().Seconds()})
	}
	g = append(g, e.monitorGauges()...)
	e.M.WritePrometheus(w, g)
}

// ---------------------------------------------------------------- actor

// WithActor runs fn with actor recorded on every zone version it commits
// (zone history "actor"). Calls are serialised so the actor cannot leak into
// a concurrent caller's change.
func (e *Engine) WithActor(actor string, fn func() error) error {
	e.actorMu.Lock()
	defer e.actorMu.Unlock()
	e.actor.Store(&actor)
	defer e.actor.Store(nil)
	return fn()
}

func (e *Engine) currentActor() string {
	if p := e.actor.Load(); p != nil && *p != "" {
		return *p
	}
	return "engine"
}
