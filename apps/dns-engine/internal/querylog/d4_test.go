package querylog

import (
	"encoding/binary"
	"net/url"
	"testing"
	"time"
)

func TestDNSSECFlagsViewAndFilters(t *testing.T) {
	r := Row{Name: "a.example", Client: "10.0.0.1", Source: SrcRecursive, Proto: ProtoDoQ, Flags: FlagCached | FlagSecure}
	it := View(&r)
	if it.DNSSEC != "secure" || it.Source != "recursive" || it.Proto != "doq" || !it.Flags.Cached {
		t.Fatalf("%+v", it)
	}
	if c := it.CSV(); len(c) != len(CSVHeader) || c[len(c)-1] != "secure" || CSVHeader[len(CSVHeader)-1] != "dnssec" {
		t.Fatal(c)
	}
	for _, c := range []struct {
		q    string
		flag uint8
		want bool
	}{
		{"dnssec=secure", FlagSecure, true},
		{"dnssec=secure", FlagInsecure, false},
		{"dnssec=bogus", FlagBogus, true},
		{"dnssec=insecure", FlagInsecure | FlagCached, true},
		{"dnssec=none", FlagCached, true},
		{"dnssec=none", FlagSecure, false},
		{"proto=doq", 0, true},
		{"proto=udp", 0, false},
		{"source=recursive", 0, true},
	} {
		v, _ := url.ParseQuery(c.q)
		f, err := ParseFilter(v)
		if err != nil {
			t.Fatal(c.q, err)
		}
		row := r
		row.Flags = c.flag
		if got := f.MatchRow(&row); got != c.want {
			t.Errorf("%s flags=%d: %v", c.q, c.flag, got)
		}
	}
	for _, q := range []string{"dnssec=maybe", "proto=carrier-pigeon"} {
		v, _ := url.ParseQuery(q)
		if _, err := ParseFilter(v); err == nil {
			t.Errorf("%s accepted", q)
		}
	}
	// the zero filter still matches everything (proto 0 = any)
	var zero Filter
	zero.Rcode, zero.Source = -1, -1
	if !zero.MatchRow(&Row{Proto: ProtoDoH}) {
		t.Fatal("zero filter")
	}
}

// Segments written before D4 index 8 sources (version 1); they must still load.
func TestSegmentIndexV1Compat(t *testing.T) {
	b := sampleBlock(30, time.Unix(1_800_000_000, 0))
	m := buildIndex(7, b)
	cur := m.marshalIndex()
	if cur[0] != 2 {
		t.Fatalf("index version %d", cur[0])
	}
	// hand-build the D2 layout: version 1 and exactly 8 source counters
	var d []byte
	d = append(d, 1)
	d = binary.AppendUvarint(d, m.Seq)
	d = binary.AppendUvarint(d, uint64(m.Rows))
	d = binary.AppendVarint(d, m.MinTS)
	d = binary.AppendVarint(d, m.MaxTS)
	for _, c := range m.Rcodes {
		d = binary.AppendUvarint(d, uint64(c))
	}
	for _, c := range m.Sources[:srcCountV1] {
		d = binary.AppendUvarint(d, uint64(c))
	}
	d = m.names.marshal(d)
	d = m.clients.marshal(d)
	old, err := parseIndex(d)
	if err != nil {
		t.Fatal(err)
	}
	if old.Rows != m.Rows || old.Sources[SrcCache] != m.Sources[SrcCache] || old.Sources[SrcRecursive] != 0 {
		t.Fatalf("%+v", old)
	}
	if nw, err := parseIndex(cur); err != nil || nw.Sources != m.Sources {
		t.Fatal(err)
	}
}
