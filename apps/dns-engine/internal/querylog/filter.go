package querylog

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/fielderr"
)

// CodeQueryInvalid is the error code of invalid filters (HTTP 422).
const CodeQueryInvalid = "query_invalid"

// Filter selects rows. The zero value matches everything.
type Filter struct {
	From, To     int64 // unix µs, inclusive; 0 = unbounded
	ClientPrefix netip.Prefix
	ClientExact  string // display form (hash mode)
	ClientNone   bool   // a client filter that can never match (client_ip=none)
	NameSuffix   string // "*.example.com" -> "example.com" (also matches example.com)
	NameSub      string // substring
	QType        uint16 // 0 = any
	Rcode        int    // -1 = any
	Source       int    // -1 = any
	Blocked      int    // 0 any, 1 only blocked, 2 only not blocked
	MinUS        uint32
	Limit        int
	Cursor       *Cursor
}

// Cursor is a position in newest-first order: rows with index < Row in
// segment Seq, then older segments.
type Cursor struct {
	Seq uint64
	Row int
}

func (c Cursor) String() string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("v1:%d:%d", c.Seq, c.Row)))
}

// ParseCursor decodes a cursor string.
func ParseCursor(s string) (*Cursor, bool) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) > 64 {
		return nil, false
	}
	parts := strings.Split(string(b), ":")
	if len(parts) != 3 || parts[0] != "v1" {
		return nil, false
	}
	seq, err1 := strconv.ParseUint(parts[1], 10, 64)
	row, err2 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || row < 0 || row > maxRows {
		return nil, false
	}
	return &Cursor{Seq: seq, Row: row}, true
}

// Blocked reports whether a source counts as blocked (blocked=true filter).
func Blocked(src uint8) bool {
	return src == SrcRefused || src == SrcRateLimited || src == SrcMitigated
}

// ParseTime accepts unix milliseconds or RFC 3339 and returns unix µs.
func ParseTime(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 || n > 1<<50 {
			return 0, false
		}
		return n * 1000, true
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, false
	}
	return t.UnixMicro(), true
}

// RcodeByName maps names (NOERROR, NXDOMAIN, ...) and numbers to rcodes.
func RcodeByName(s string) (int, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n < 16 {
		return n, true
	}
	if rc, ok := dns.StringToRcode[s]; ok && rc < 16 {
		return rc, true
	}
	return 0, false
}

// RcodeName renders an rcode.
func RcodeName(rc uint8) string {
	if n, ok := dns.RcodeToString[int(rc)]; ok {
		return n
	}
	return "RCODE" + strconv.Itoa(int(rc))
}

// QTypeName renders a qtype.
func QTypeName(t uint16) string {
	if n, ok := dns.TypeToString[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ParseFilter parses the docs/38 §3 query parameters
// (from, to, client, name, qtype, rcode, source, blocked, min_ms, limit, cursor).
func ParseFilter(v url.Values) (Filter, error) {
	f := Filter{Rcode: -1, Source: -1, Limit: 100}
	var l fielderr.List
	get := func(k string) string {
		s := v.Get(k)
		if len(s) > 512 {
			l.Add(k, "too_long")
			return ""
		}
		return strings.TrimSpace(s)
	}
	if s := get("from"); s != "" {
		if t, ok := ParseTime(s); ok {
			f.From = t
		} else {
			l.Add("from", "invalid_time")
		}
	}
	if s := get("to"); s != "" {
		if t, ok := ParseTime(s); ok {
			f.To = t
		} else {
			l.Add("to", "invalid_time")
		}
	}
	if f.From > 0 && f.To > 0 && f.From > f.To {
		l.Add("from", "after_to")
	}
	if s := get("client"); s != "" {
		switch {
		case strings.HasPrefix(s, "h:"):
			if len(s) != 18 {
				l.Add("client", "invalid_client")
			}
			f.ClientExact = strings.ToLower(s)
		case strings.Contains(s, "/"):
			p, err := netip.ParsePrefix(s)
			if err != nil {
				l.Add("client", "invalid_client")
			} else {
				if p.Addr().Is4In6() {
					p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
				}
				f.ClientPrefix = p.Masked()
			}
		default:
			a, err := netip.ParseAddr(s)
			if err != nil {
				l.Add("client", "invalid_client")
			} else {
				a = a.Unmap().WithZone("")
				f.ClientPrefix = netip.PrefixFrom(a, a.BitLen())
			}
		}
	}
	if s := strings.ToLower(get("name")); s != "" {
		s = strings.TrimSuffix(s, ".")
		if strings.HasPrefix(s, "*.") {
			f.NameSuffix = strings.TrimPrefix(s, "*.")
			if f.NameSuffix == "" || strings.Contains(f.NameSuffix, "*") {
				l.Add("name", "invalid_name")
			}
		} else if strings.Contains(s, "*") {
			l.Add("name", "invalid_name")
		} else {
			f.NameSub = s
		}
	}
	if s := get("qtype"); s != "" {
		if t, ok := dns.StringToType[strings.ToUpper(s)]; ok {
			f.QType = t
		} else if n, err := strconv.Atoi(s); err == nil && n > 0 && n < 65536 {
			f.QType = uint16(n)
		} else {
			l.Add("qtype", "invalid_type")
		}
	}
	if s := get("rcode"); s != "" {
		if rc, ok := RcodeByName(s); ok {
			f.Rcode = rc
		} else {
			l.Add("rcode", "invalid_rcode")
		}
	}
	if s := get("source"); s != "" {
		found := false
		for i, n := range SourceNames {
			if strings.EqualFold(n, s) {
				f.Source, found = i, true
			}
		}
		if !found {
			l.Add("source", "invalid_choice", "choices", SourceNames[:])
		}
	}
	switch strings.ToLower(get("blocked")) {
	case "":
	case "true", "1", "yes":
		f.Blocked = 1
	case "false", "0", "no":
		f.Blocked = 2
	default:
		l.Add("blocked", "invalid_bool")
	}
	if s := get("min_ms"); s != "" {
		ms, err := strconv.ParseFloat(s, 64)
		if err != nil || ms < 0 || ms > 3_600_000 || ms != ms {
			l.Add("min_ms", "invalid_number")
		} else {
			f.MinUS = uint32(ms * 1000)
		}
	}
	if s := get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 1000 {
			l.Add("limit", "out_of_range", "min", 1, "max", 1000)
		} else {
			f.Limit = n
		}
	}
	if s := get("cursor"); s != "" {
		c, ok := ParseCursor(s)
		if !ok {
			l.Add("cursor", "invalid_cursor")
		}
		f.Cursor = c
	}
	if err := l.Err(CodeQueryInvalid, "invalid query log filter"); err != nil {
		return f, err
	}
	return f, nil
}

// matchName reports whether a presentation name matches the name filter.
func (f *Filter) matchName(n string) bool {
	if f.NameSuffix != "" {
		return n == f.NameSuffix || (len(n) > len(f.NameSuffix) && strings.HasSuffix(n, f.NameSuffix) &&
			n[len(n)-len(f.NameSuffix)-1] == '.')
	}
	if f.NameSub != "" {
		return strings.Contains(n, f.NameSub)
	}
	return true
}

func (f *Filter) hasClient() bool {
	return f.ClientPrefix.IsValid() || f.ClientExact != "" || f.ClientNone
}

// matchClient reports whether a stored client string matches.
func (f *Filter) matchClient(c string) bool {
	if f.ClientNone {
		return false
	}
	if f.ClientExact != "" {
		return c == f.ClientExact
	}
	if f.ClientPrefix.IsValid() {
		a, err := netip.ParseAddr(c)
		return err == nil && f.ClientPrefix.Contains(a)
	}
	return true
}

// skipMeta reports whether a whole segment can be skipped from its index.
func (f *Filter) skipMeta(m *segMeta) bool {
	if f.From > 0 && m.MaxTS < f.From {
		return true
	}
	if f.To > 0 && m.MinTS > f.To {
		return true
	}
	if f.Rcode >= 0 && m.Rcodes[f.Rcode&15] == 0 {
		return true
	}
	if f.Source >= 0 && m.Sources[f.Source] == 0 {
		return true
	}
	if f.NameSuffix != "" && !m.names.has(f.NameSuffix) {
		return true
	}
	if f.ClientNone {
		return true
	}
	if f.ClientExact != "" && !m.clients.has(f.ClientExact) {
		return true
	}
	if p := f.ClientPrefix; p.IsValid() && p.Bits() == p.Addr().BitLen() && !m.clients.has(p.Addr().String()) {
		return true
	}
	return false
}

// matcher is a filter compiled against one block's dictionaries.
type matcher struct {
	f        *Filter
	nameOK   []bool
	clientOK []bool
}

func (f *Filter) compile(b *block, mt *matcher) {
	mt.f = f
	if f.NameSuffix != "" || f.NameSub != "" {
		for i := len(mt.nameOK); i < len(b.names); i++ {
			mt.nameOK = append(mt.nameOK, f.matchName(b.names[i]))
		}
	}
	if f.hasClient() {
		for i := len(mt.clientOK); i < len(b.clients); i++ {
			mt.clientOK = append(mt.clientOK, f.matchClient(b.clients[i]))
		}
	}
}

func (mt *matcher) match(b *block, i int) bool {
	f := mt.f
	if f.From > 0 && b.ts[i] < f.From {
		return false
	}
	if f.To > 0 && b.ts[i] > f.To {
		return false
	}
	if f.QType != 0 && b.qtype[i] != f.QType {
		return false
	}
	if f.Rcode >= 0 && int(b.rcode[i]) != f.Rcode {
		return false
	}
	if f.Source >= 0 && int(b.source[i]) != f.Source {
		return false
	}
	if f.Blocked == 1 && !Blocked(b.source[i]) || f.Blocked == 2 && Blocked(b.source[i]) {
		return false
	}
	if b.dur[i] < f.MinUS {
		return false
	}
	if mt.nameOK != nil && !mt.nameOK[b.name[i]] {
		return false
	}
	if mt.clientOK != nil && !mt.clientOK[b.client[i]] {
		return false
	}
	return true
}

// MatchRow applies the filter to a single row (streams).
func (f *Filter) MatchRow(r *Row) bool {
	if f.From > 0 && r.TS < f.From || f.To > 0 && r.TS > f.To {
		return false
	}
	if f.QType != 0 && r.QType != f.QType || f.Rcode >= 0 && int(r.Rcode) != f.Rcode || f.Source >= 0 && int(r.Source) != f.Source {
		return false
	}
	if f.Blocked == 1 && !Blocked(r.Source) || f.Blocked == 2 && Blocked(r.Source) || r.DurUS < f.MinUS {
		return false
	}
	if !f.matchName(r.Name) {
		return false
	}
	if f.hasClient() && !f.matchClient(r.Client) {
		return false
	}
	return true
}
