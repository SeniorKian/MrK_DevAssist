package zone

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/fielderr"
)

// MaxImportBytes bounds zone-file text accepted by Import.
const MaxImportBytes = 4 << 20

// Import parses RFC 1035 master-file text for origin. $INCLUDE is refused.
// It returns the records (with fresh IDs) and the SOA if one was present.
func Import(text, origin string) ([]Record, *SOA, error) {
	if len(text) > MaxImportBytes {
		return nil, nil, fielderr.Single("import_invalid", "zone file too large", "text", "too_long", "max", MaxImportBytes)
	}
	zp := dns.NewZoneParser(strings.NewReader(text), origin, "")
	zp.SetDefaultTTL(DefaultRecordTTL)
	zp.SetIncludeAllowed(false)
	var (
		recs []Record
		soa  *SOA
		errs fielderr.List
	)
	n := 0
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		n++
		if n > MaxRecordsPerZone {
			errs.Add("text", "too_many", "max", MaxRecordsPerZone)
			break
		}
		h := rr.Header()
		owner := strings.ToLower(h.Name)
		if h.Class != dns.ClassINET {
			errs.Add(fmt.Sprintf("rr[%d]", n), "unsupported_class", "name", h.Name)
			continue
		}
		if owner != origin && !strings.HasSuffix(owner, "."+origin) {
			errs.Add(fmt.Sprintf("rr[%d]", n), "out_of_zone", "name", h.Name)
			continue
		}
		if s, ok := rr.(*dns.SOA); ok {
			if owner != origin {
				errs.Add(fmt.Sprintf("rr[%d]", n), "soa_not_at_apex", "name", h.Name)
				continue
			}
			v := SOA{TTL: h.Ttl, MName: Display(strings.ToLower(s.Ns)), RName: Display(strings.ToLower(s.Mbox)),
				Refresh: s.Refresh, Retry: s.Retry, Expire: s.Expire, Minimum: s.Minttl}
			soa = &v
			if s.Serial != 0 {
				soa.importedSerial = s.Serial
			}
			continue
		}
		r, err := FromRR(rr, origin)
		if err != nil {
			errs.Add(fmt.Sprintf("rr[%d]", n), "unsupported_record", "name", h.Name, "type", dns.TypeToString[h.Rrtype], "detail", err.Error())
			continue
		}
		if h.Ttl > MaxTTL {
			errs.Add(fmt.Sprintf("rr[%d]", n), "ttl_out_of_range", "name", h.Name, "max", MaxTTL)
			continue
		}
		recs = append(recs, r)
	}
	if err := zp.Err(); err != nil {
		errs.Add("text", "parse_error", "detail", err.Error())
	}
	if len(errs) > 0 {
		return nil, nil, errs.Err("import_invalid", "zone file has errors")
	}
	return recs, soa, nil
}

// ImportedSerial returns the serial found in the imported SOA (0 if none).
func (s *SOA) ImportedSerial() uint32 { return s.importedSerial }

// FromRR converts a parsed RR into a Record (validated via ParseData).
func FromRR(rr dns.RR, origin string) (Record, error) {
	h := rr.Header()
	r := Record{ID: NewID(), Name: RelativeName(h.Name, origin), TTL: h.Ttl}
	if name, ok := NormalizeOwner(r.Name, origin); ok {
		r.Name = name
	} else {
		return r, fmt.Errorf("invalid owner name")
	}
	var data any
	switch v := rr.(type) {
	case *dns.A:
		r.Type = "A"
		a, _ := netip.AddrFromSlice(v.A)
		data = map[string]any{"address": a.Unmap().String()}
	case *dns.AAAA:
		r.Type = "AAAA"
		a, _ := netip.AddrFromSlice(v.AAAA)
		data = map[string]any{"address": a.String()}
	case *dns.CNAME:
		r.Type = "CNAME"
		data = map[string]any{"target": v.Target}
	case *dns.PTR:
		r.Type = "PTR"
		data = map[string]any{"target": v.Ptr}
	case *dns.NS:
		r.Type = "NS"
		data = map[string]any{"nameserver": v.Ns}
	case *dns.MX:
		r.Type = "MX"
		data = map[string]any{"preference": int(v.Preference), "exchange": v.Mx}
	case *dns.SRV:
		r.Type = "SRV"
		data = map[string]any{"priority": int(v.Priority), "weight": int(v.Weight), "port": int(v.Port), "target": v.Target}
	case *dns.CAA:
		r.Type = "CAA"
		data = map[string]any{"flags": int(v.Flag), "tag": v.Tag, "value": v.Value}
	case *dns.TXT:
		r.Type = "TXT"
		parts := make([]string, len(v.Txt))
		for i, s := range v.Txt {
			parts[i] = txtUnescape(s)
		}
		data = map[string]any{"strings": parts}
	default:
		return r, fmt.Errorf("type not supported in D1")
	}
	nd, _, l := ParseData(r.Type, mustJSON(data), h.Name, h.Ttl, origin)
	if len(l) > 0 {
		return r, l.Err("record_invalid", "invalid record data")
	}
	r.Data = nd
	return r, nil
}

func txtUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
			v, _ := strconv.Atoi(s[i+1 : i+4])
			b.WriteByte(byte(v))
			i += 3
			continue
		}
		b.WriteByte(s[i+1])
		i++
	}
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Export renders the zone as RFC 1035 text (enabled records only).
func Export(z *Zone) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "; zone %s serial %d exported by mrk-dns\n", Display(z.Name), z.Serial)
	fmt.Fprintf(&b, "$ORIGIN %s\n$TTL %d\n", z.Name, DefaultRecordTTL)
	b.WriteString(z.SOARR().String())
	b.WriteByte('\n')
	recs := append([]Record(nil), z.Records...)
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].Name != recs[j].Name {
			if recs[i].Name == "@" {
				return true
			}
			if recs[j].Name == "@" {
				return false
			}
			return recs[i].Name < recs[j].Name
		}
		return recs[i].Type < recs[j].Type
	})
	for i := range recs {
		if recs[i].Disabled {
			continue
		}
		rr, err := recs[i].RR(z.Name)
		if err != nil {
			return "", err
		}
		b.WriteString(rr.String())
		b.WriteByte('\n')
	}
	return b.String(), nil
}
