package zone

import (
	"fmt"
	"strings"
	"time"

	"mrk/dns-engine/internal/fielderr"
)

// NextSerial returns the next SOA serial using the YYYYMMDDnn scheme
// (RFC 1912 §2.2), falling back to +1 (RFC 1982 arithmetic) when the date
// based value would not increase the serial.
func NextSerial(old uint32, now time.Time) uint32 {
	u := now.UTC()
	date := uint32(u.Year()*1000000 + int(u.Month())*10000 + u.Day()*100)
	if old == 0 || serialLess(old, date) {
		return date
	}
	return old + 1
}

// serialLess implements RFC 1982 s1 < s2.
func serialLess(s1, s2 uint32) bool {
	return s1 != s2 && ((s1 < s2 && s2-s1 < 1<<31) || (s1 > s2 && s1-s2 > 1<<31))
}

// SerialAfter returns a serial strictly greater than both a and b.
func SerialAfter(a, b uint32, now time.Time) uint32 {
	s := NextSerial(a, now)
	if !serialLess(b, s) {
		s = b + 1
	}
	return s
}

// ownerTree helpers ------------------------------------------------------------

// isBelow reports whether rel owner a is strictly below rel owner b.
func isBelow(a, b string) bool {
	if b == "@" {
		return a != "@"
	}
	return strings.HasSuffix(a, "."+b)
}

// ValidateRecords checks zone-wide consistency rules. idx, when >=0, names the
// record being changed so field errors point at it.
func ValidateRecords(origin string, recs []Record) fielderr.List {
	var l fielderr.List
	if len(recs) > MaxRecordsPerZone {
		l.Add("records", "too_many", "max", MaxRecordsPerZone)
		return l
	}
	byOwner := make(map[string][]int, len(recs))
	seen := make(map[string]int, len(recs))
	cuts := map[string]bool{}
	apexNS := 0
	for i := range recs {
		r := &recs[i]
		byOwner[r.Name] = append(byOwner[r.Name], i)
		k := dataKey(r)
		if j, dup := seen[k]; dup {
			l.Add(fmt.Sprintf("records[%d]", i), "duplicate_record", "id", r.ID, "duplicate_of", recs[j].ID)
		}
		seen[k] = i
		if r.Type == "NS" {
			if r.Name == "@" {
				if !r.Disabled {
					apexNS++
				}
			} else {
				if strings.HasPrefix(r.Name, "*") {
					l.Add(fmt.Sprintf("records[%d]", i), "wildcard_ns", "id", r.ID)
				}
				cuts[r.Name] = true
			}
		}
	}
	if apexNS == 0 {
		l.Add("records", "apex_ns_required")
	}
	for owner, idxs := range byOwner {
		cname := 0
		for _, i := range idxs {
			if recs[i].Type == "CNAME" {
				cname++
			}
		}
		if cname > 0 {
			if owner == "@" {
				l.Add(fmt.Sprintf("records[%d]", idxs[0]), "cname_at_apex", "id", recs[idxs[0]].ID)
			}
			if cname > 1 || len(idxs) > cname {
				for _, i := range idxs {
					if recs[i].Type == "CNAME" {
						l.Add(fmt.Sprintf("records[%d]", i), "cname_conflict", "id", recs[i].ID, "name", owner)
						break
					}
				}
			}
		}
	}
	if len(cuts) > 0 {
		for i := range recs {
			r := &recs[i]
			for cut := range cuts {
				if r.Name != cut && !isBelow(r.Name, cut) {
					continue
				}
				glue := r.Type == "A" || r.Type == "AAAA"
				if glue || (r.Name == cut && r.Type == "NS") {
					continue
				}
				{
					l.Add(fmt.Sprintf("records[%d]", i), "occluded_by_delegation", "id", r.ID, "delegation", cut)
					break
				}
			}
		}
	}
	return l
}

// SyncRRsetTTL makes every record of the same owner/type share the TTL of
// recs[i] (RFC 2181 §5.2).
func SyncRRsetTTL(recs []Record, i int) {
	for j := range recs {
		if j != i && recs[j].Name == recs[i].Name && recs[j].Type == recs[i].Type {
			recs[j].TTL = recs[i].TTL
		}
	}
}

// ValidateForwarders checks a forwarder zone's upstream list with parse.
func ValidateForwarders(fw []string, parse func(string) error) fielderr.List {
	var l fielderr.List
	if len(fw) == 0 {
		l.Add("forwarders", "required")
	}
	if len(fw) > MaxForwarders {
		l.Add("forwarders", "too_many", "max", MaxForwarders)
	}
	for i, f := range fw {
		if err := parse(f); err != nil {
			l.Add(fmt.Sprintf("forwarders[%d]", i), "invalid_upstream", "detail", err.Error())
		}
	}
	return l
}
