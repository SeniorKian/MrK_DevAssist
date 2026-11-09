// Package zone implements the authoritative data model: zones, records with
// typed data, validation, compilation to an immutable lookup structure,
// RFC 1035 zone-file import/export and SOA serial management.
package zone

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/fielderr"
)

// Zone types.
const (
	TypePrimary   = "primary"
	TypeForwarder = "forwarder"
)

// Limits.
const (
	MaxTTL            = 604800
	MaxRecordsPerZone = 200_000
	MaxForwarders     = 8
	SOAID             = "soa"
)

// SupportedTypes are the record types editable in D1.
var SupportedTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "PTR", "CAA", "SOA"}

// Record is one resource record as stored and exposed by the API.
type Record struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	TTL      uint32          `json:"ttl"`
	Data     json.RawMessage `json:"data"`
	Disabled bool            `json:"disabled"`
	Comment  string          `json:"comment"`
	// View is the client group seeing this record (split horizon, docs/41
	// §3.3); empty = every client.
	View string `json:"view,omitempty"`
}

// SOA holds the editable SOA fields; the serial is managed by the engine.
type SOA struct {
	TTL     uint32 `json:"ttl"`
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`

	importedSerial uint32
}

// Zone is the persisted zone document.
type Zone struct {
	Name       string    `json:"name"` // FQDN, lower case, trailing dot
	Type       string    `json:"type"`
	Disabled   bool      `json:"disabled"`
	Forwarders []string  `json:"forwarders,omitempty"`
	Serial     uint32    `json:"serial"`
	Version    int       `json:"version"`
	UpdatedAt  time.Time `json:"updated_at"`
	Reason     string    `json:"reason,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	SOA        SOA       `json:"soa"`
	Records    []Record  `json:"records"`
	// D5Config: secondary, transfer, notify, update and signing (docs/41 §2).
	D5Config
	// Views are the split-horizon views (docs/41 §3.3, views.go).
	Views []View `json:"views,omitempty"`
}

// Clone deep-copies z (record data slices are shared; they are immutable).
func (z *Zone) Clone() *Zone {
	c := *z
	c.Forwarders = append([]string(nil), z.Forwarders...)
	c.Records = append([]Record(nil), z.Records...)
	c.Views = append([]View(nil), z.Views...)
	return &c
}

// NewID returns a random record identifier.
func NewID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------- names

func validLabel(l string, allowWildcard bool) bool {
	if l == "*" {
		return allowWildcard
	}
	if len(l) == 0 || len(l) > 63 {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// NormalizeZoneName validates a zone name and returns its FQDN form.
func NormalizeZoneName(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	for _, l := range strings.Split(s, ".") {
		// zone names follow the LDH rule (plus "_"): no leading/trailing hyphen
		if !validLabel(l, false) || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
	}
	return s + ".", true
}

// Display returns a FQDN without the trailing dot ("." stays ".").
func Display(fqdn string) string {
	if fqdn == "." {
		return fqdn
	}
	return strings.TrimSuffix(fqdn, ".")
}

// NormalizeOwner validates a relative owner name ("@", "www", "*.dev" or an
// absolute name inside origin) and returns the canonical relative form.
func NormalizeOwner(name, origin string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == "@" {
		return "@", true
	}
	if strings.HasSuffix(n, ".") {
		if n == origin {
			return "@", true
		}
		if !strings.HasSuffix(n, "."+origin) {
			return "", false
		}
		n = strings.TrimSuffix(n, "."+origin)
	} else if n+"." == origin {
		// The zone name typed without the dot means the apex.
		return "@", true
	} else if strings.HasSuffix(n+".", "."+origin) {
		// "www.example.com" typed without the final dot inside zone example.com:
		// users mean the absolute name, so strip the origin.
		n = strings.TrimSuffix(n+".", "."+origin)
	}
	labels := strings.Split(n, ".")
	for i, l := range labels {
		if !validLabel(l, i == 0) {
			return "", false
		}
	}
	if len(n)+1+len(origin) > 254 {
		return "", false
	}
	return n, true
}

// OwnerFQDN joins a relative owner with the origin.
func OwnerFQDN(rel, origin string) string {
	if rel == "@" {
		return origin
	}
	return rel + "." + origin
}

// RelativeName converts an FQDN inside origin to its relative form.
func RelativeName(fqdn, origin string) string {
	fqdn = strings.ToLower(fqdn)
	if fqdn == origin {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+origin)
}

// normTarget validates a host-name target (always absolute; trailing dot
// optional; "@" = origin). Returns the display form (no trailing dot).
func normTarget(s, origin string, allowRoot bool) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "@" {
		return Display(origin), true
	}
	if s == "." {
		return ".", allowRoot
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	for _, l := range strings.Split(s, ".") {
		if !validLabel(l, false) {
			return "", false
		}
	}
	return s, true
}

func fq(target string) string {
	if target == "." {
		return "."
	}
	return target + "."
}

// ---------------------------------------------------------------- typed data

type dataA struct {
	Address string `json:"address"`
}
type dataTarget struct {
	Target string `json:"target"`
}
type dataNS struct {
	Nameserver string `json:"nameserver"`
}
type dataMX struct {
	Preference *int   `json:"preference"`
	Exchange   string `json:"exchange"`
}
type dataTXT struct {
	Text    *string  `json:"text,omitempty"`
	Strings []string `json:"strings,omitempty"`
}
type dataSRV struct {
	Priority *int   `json:"priority"`
	Weight   *int   `json:"weight"`
	Port     *int   `json:"port"`
	Target   string `json:"target"`
}
type dataCAA struct {
	Flags *int   `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}
type dataSOA struct {
	MName   string  `json:"mname"`
	RName   string  `json:"rname"`
	Serial  *uint32 `json:"serial,omitempty"` // ignored (engine managed)
	Refresh *int    `json:"refresh"`
	Retry   *int    `json:"retry"`
	Expire  *int    `json:"expire"`
	Minimum *int    `json:"minimum"`
}

func strictDecode(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}

func u16(l *fielderr.List, field string, v *int) uint16 {
	if v == nil {
		l.Add(field, "required")
		return 0
	}
	if *v < 0 || *v > 65535 {
		l.Add(field, "out_of_range", "min", 0, "max", 65535)
		return 0
	}
	return uint16(*v)
}

func u32(l *fielderr.List, field string, v *int, lo, hi int) uint32 {
	if v == nil {
		l.Add(field, "required")
		return 0
	}
	if *v < lo || *v > hi {
		l.Add(field, "out_of_range", "min", lo, "max", hi)
		return 0
	}
	return uint32(*v)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// splitTXT splits text into <=255 octet character-strings.
func splitTXT(s string) []string {
	if s == "" {
		return []string{""}
	}
	var out []string
	for len(s) > 255 {
		out = append(out, s[:255])
		s = s[255:]
	}
	return append(out, s)
}

// txtEscape escapes a character-string for miekg/dns presentation form.
func txtEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// ParseData validates typed record data and returns its normalised JSON and
// the RR (with owner and TTL set). Field names in errors are "data.<field>".
func ParseData(rtype string, raw json.RawMessage, owner string, ttl uint32, origin string) (json.RawMessage, dns.RR, fielderr.List) {
	var l fielderr.List
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: owner, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
	}
	bad := func(err error) (json.RawMessage, dns.RR, fielderr.List) {
		l.Add("data", "invalid_data", "detail", err.Error())
		return nil, nil, l
	}
	switch rtype {
	case "A", "AAAA":
		var d dataA
		if err := strictDecode(raw, &d); err != nil {
			return bad(err)
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(d.Address))
		if err != nil || ip.Zone() != "" {
			l.Add("data.address", "invalid_address")
			return nil, nil, l
		}
		if rtype == "A" {
			if !ip.Unmap().Is4() {
				l.Add("data.address", "not_ipv4")
				return nil, nil, l
			}
			ip = ip.Unmap()
			return mustJSON(dataA{ip.String()}), &dns.A{Hdr: hdr(dns.TypeA), A: ip.AsSlice()}, nil
		}
		if !ip.Is6() || ip.Is4In6() {
			l.Add("data.address", "not_ipv6")
			return nil, nil, l
		}
		return mustJSON(dataA{ip.String()}), &dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: ip.AsSlice()}, nil
	case "CNAME", "PTR":
		var d dataTarget
		if err := strictDecode(raw, &d); err != nil {
			return bad(err)
		}
		t, ok := normTarget(d.Target, origin, false)
		if !ok {
			l.Add("data.target", "invalid_name")
			return nil, nil, l
		}
		if rtype == "CNAME" {
			return mustJSON(dataTarget{t}), &dns.CNAME{Hdr: hdr(dns.TypeCNAME), Target: fq(t)}, nil
		}
		return mustJSON(dataTarget{t}), &dns.PTR{Hdr: hdr(dns.TypePTR), Ptr: fq(t)}, nil
	case "NS":
		var d dataNS
		if err := strictDecode(raw, &d); err != nil {
			return bad(err)
		}
		t, ok := normTarget(d.Nameserver, origin, false)
		if !ok {
			l.Add("data.nameserver", "invalid_name")
			return nil, nil, l
		}
		return mustJSON(dataNS{t}), &dns.NS{Hdr: hdr(dns.TypeNS), Ns: fq(t)}, nil
	case "MX":
		var d dataMX
		if err := strictDecode(raw, &d); err != nil {
			return bad(err)
		}
		p := u16(&l, "data.preference", d.Preference)
		t, ok := normTarget(d.Exchange, origin, true) // "." = null MX (RFC 7505)
		if !ok {
			l.Add("data.exchange", "invalid_name")
		}
		if len(l) > 0 {
			return nil, nil, l
		}
		pp := int(p)
		return mustJSON(dataMX{&pp, t}), &dns.MX{Hdr: hdr(dns.TypeMX), Preference: p, Mx: fq(t)}, nil
	case "TXT":
		var d dataTXT
		if err := strictDecode(raw, &d); err != nil {
			return bad(err)
		}
		var parts []string
		switch {
		case len(d.Strings) > 0:
			parts = d.Strings
			for i, s := range parts {
				if len(s) > 255 {
					l.Add(fmt.Sprintf("data.strings[%d]", i), "too_long", "max", 255)
				}
			}
		case d.Text != nil:
			parts = splitTXT(*d.Text)
		default:
			l.Add("data.text", "required")
		}
		total := 0
		for _, s := range parts {
			total += len(s) + 1
		}
		if total > 8000 {
			l.Add("data.text", "too_long", "max", 8000)
		}
		if len(l) > 0 {
			return nil, nil, l
		}
		joined := strings.Join(parts, "")
		esc := make([]string, len(parts))
		for i, s := range parts {
			esc[i] = txtEscape(s)
		}
		out := dataTXT{Text: &joined}
		if strings.Join(splitTXT(joined), "\x00") != strings.Join(parts, "\x00") {
			out.Strings = parts // keep explicit character-string boundaries (e.g. imported DKIM)
		}
		return mustJSON(out), &dns.TXT{Hdr: hdr(dns.TypeTXT), Txt: esc}, nil
	case "SRV":
		var d dataSRV
		if err := strictDecode(raw, &d); err != nil {
			return bad(err)
		}
		pr := u16(&l, "data.priority", d.Priority)
		w := u16(&l, "data.weight", d.Weight)
		po := u16(&l, "data.port", d.Port)
		t, ok := normTarget(d.Target, origin, true) // "." = service not available
		if !ok {
			l.Add("data.target", "invalid_name")
		}
		if len(l) > 0 {
			return nil, nil, l
		}
		a, b, c := int(pr), int(w), int(po)
		return mustJSON(dataSRV{&a, &b, &c, t}), &dns.SRV{Hdr: hdr(dns.TypeSRV), Priority: pr, Weight: w, Port: po, Target: fq(t)}, nil
	case "CAA":
		var d dataCAA
		if err := strictDecode(raw, &d); err != nil {
			return bad(err)
		}
		var flags uint8
		if d.Flags == nil {
			z := 0
			d.Flags = &z
		}
		if *d.Flags < 0 || *d.Flags > 255 {
			l.Add("data.flags", "out_of_range", "min", 0, "max", 255)
		} else {
			flags = uint8(*d.Flags)
		}
		tag := strings.ToLower(strings.TrimSpace(d.Tag))
		if tag == "" || len(tag) > 15 || !isAlnum(tag) {
			l.Add("data.tag", "invalid_tag")
		}
		if len(d.Value) > 1024 {
			l.Add("data.value", "too_long", "max", 1024)
		}
		for i := 0; i < len(d.Value); i++ {
			if d.Value[i] < 0x20 || d.Value[i] > 0x7e {
				l.Add("data.value", "invalid_characters")
				break
			}
		}
		if len(l) > 0 {
			return nil, nil, l
		}
		f := int(flags)
		return mustJSON(dataCAA{&f, tag, d.Value}), &dns.CAA{Hdr: hdr(dns.TypeCAA), Flag: flags, Tag: tag, Value: d.Value}, nil
	default:
		l.Add("type", "unsupported_type", "supported", SupportedTypes)
		return nil, nil, l
	}
}

func isAlnum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// ParseSOAData validates SOA record data from the API.
func ParseSOAData(raw json.RawMessage, origin string) (SOA, fielderr.List) {
	var d dataSOA
	var l fielderr.List
	if err := strictDecode(raw, &d); err != nil {
		l.Add("data", "invalid_data", "detail", err.Error())
		return SOA{}, l
	}
	var s SOA
	var ok bool
	if s.MName, ok = normTarget(d.MName, origin, false); !ok {
		l.Add("data.mname", "invalid_name")
	}
	rn := strings.ReplaceAll(strings.TrimSpace(d.RName), "@", ".")
	if s.RName, ok = normTarget(rn, origin, false); !ok {
		l.Add("data.rname", "invalid_name")
	}
	s.Refresh = u32(&l, "data.refresh", d.Refresh, 60, 2419200)
	s.Retry = u32(&l, "data.retry", d.Retry, 60, 2419200)
	s.Expire = u32(&l, "data.expire", d.Expire, 300, 31536000)
	s.Minimum = u32(&l, "data.minimum", d.Minimum, 0, 86400)
	return s, l
}

// DefaultSOA returns the SOA for a new zone.
func DefaultSOA(origin string) SOA {
	o := Display(origin)
	return SOA{TTL: 900, MName: "ns1." + o, RName: "hostmaster." + o, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300}
}

// SOARecord renders the SOA as an API record.
func (z *Zone) SOARecord() Record {
	return Record{ID: SOAID, Name: "@", Type: "SOA", TTL: z.SOA.TTL, Data: mustJSON(map[string]any{
		"mname": z.SOA.MName, "rname": z.SOA.RName, "serial": z.Serial, "refresh": z.SOA.Refresh,
		"retry": z.SOA.Retry, "expire": z.SOA.Expire, "minimum": z.SOA.Minimum,
	})}
}

// SOARR builds the dns.SOA.
func (z *Zone) SOARR() *dns.SOA {
	return &dns.SOA{Hdr: dns.RR_Header{Name: z.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.SOA.TTL},
		Ns: fq(z.SOA.MName), Mbox: fq(z.SOA.RName), Serial: z.Serial, Refresh: z.SOA.Refresh,
		Retry: z.SOA.Retry, Expire: z.SOA.Expire, Minttl: z.SOA.Minimum}
}

// RecordInput is a create/update request body.
type RecordInput struct {
	Name     *string         `json:"name"`
	Type     *string         `json:"type"`
	TTL      *int            `json:"ttl"`
	Data     json.RawMessage `json:"data"`
	Disabled bool            `json:"disabled"`
	Comment  string          `json:"comment"`
	View     string          `json:"view"`
}

// DefaultRecordTTL applies when ttl is omitted.
const DefaultRecordTTL = 3600

// BuildRecord validates one input against origin and returns a normalised
// Record (ID is left to the caller).
func BuildRecord(in RecordInput, origin string) (Record, dns.RR, fielderr.List) {
	var l fielderr.List
	var r Record
	if in.Name == nil {
		l.Add("name", "required")
	} else if n, ok := NormalizeOwner(*in.Name, origin); !ok {
		l.Add("name", "invalid_name")
	} else {
		r.Name = n
	}
	if in.Type == nil || *in.Type == "" {
		l.Add("type", "required")
	} else {
		r.Type = strings.ToUpper(strings.TrimSpace(*in.Type))
	}
	ttl := DefaultRecordTTL
	if in.TTL != nil {
		ttl = *in.TTL
	}
	if ttl < 0 || ttl > MaxTTL {
		l.Add("ttl", "out_of_range", "min", 0, "max", MaxTTL)
	} else {
		r.TTL = uint32(ttl)
	}
	if len(in.Comment) > 500 {
		l.Add("comment", "too_long", "max", 500)
	}
	r.Comment = in.Comment
	r.Disabled = in.Disabled
	if in.View != "" {
		if !ValidViewID(in.View) {
			l.Add("view", "invalid_view")
		} else if r.Type == "NS" && r.Name == "@" {
			l.Add("view", "not_allowed") // the delegation of the zone is the same for everyone
		}
		r.View = in.View
	}
	if r.Type == "SOA" {
		l.Add("type", "soa_managed")
	}
	if len(l) > 0 {
		return r, nil, l
	}
	data, rr, dl := ParseData(r.Type, in.Data, OwnerFQDN(r.Name, origin), r.TTL, origin)
	if len(dl) > 0 {
		return r, nil, dl
	}
	r.Data = data
	return r, rr, nil
}

// RR returns the dns.RR of a stored record.
func (r *Record) RR(origin string) (dns.RR, error) {
	_, rr, l := ParseData(r.Type, r.Data, OwnerFQDN(r.Name, origin), r.TTL, origin)
	if len(l) > 0 {
		return nil, l.Err("record_invalid", "stored record is invalid")
	}
	return rr, nil
}

// dataKey identifies an RR's data for duplicate detection.
func dataKey(r *Record) string {
	return r.Name + "\x00" + r.Type + "\x00" + string(r.Data) + "\x00" + r.View
}
