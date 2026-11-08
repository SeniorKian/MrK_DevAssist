package zone

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func rec(t testing.TB, origin, name, typ string, ttl int, data string) Record {
	t.Helper()
	r, _, l := BuildRecord(RecordInput{Name: &name, Type: &typ, TTL: &ttl, Data: json.RawMessage(data)}, origin)
	if len(l) > 0 {
		t.Fatalf("%s %s %s: %v", name, typ, data, l)
	}
	r.ID = NewID()
	return r
}

func testZone(t testing.TB) *Zone {
	o := "example.com."
	z := &Zone{Name: o, Type: TypePrimary, Serial: 2026010101, SOA: DefaultSOA(o)}
	add := func(name, typ, data string) { z.Records = append(z.Records, rec(t, o, name, typ, 300, data)) }
	add("@", "NS", `{"nameserver":"ns1.example.com"}`)
	add("ns1", "A", `{"address":"192.0.2.53"}`)
	add("@", "A", `{"address":"192.0.2.1"}`)
	add("@", "MX", `{"preference":10,"exchange":"mail.example.com"}`)
	add("mail", "A", `{"address":"192.0.2.25"}`)
	add("www", "CNAME", `{"target":"web.example.com"}`)
	add("web", "A", `{"address":"192.0.2.80"}`)
	add("web", "AAAA", `{"address":"2001:db8::80"}`)
	add("ext", "CNAME", `{"target":"cdn.example.net"}`)
	add("loop1", "CNAME", `{"target":"loop2.example.com"}`)
	add("loop2", "CNAME", `{"target":"loop1.example.com"}`)
	add("a.b.c", "TXT", `{"text":"deep"}`) // b.c and c are empty non-terminals
	add("*.dev", "A", `{"address":"192.0.2.99"}`)
	add("*.dev", "TXT", `{"text":"wild"}`)
	add("host.dev", "A", `{"address":"192.0.2.98"}`)
	add("*.alias", "CNAME", `{"target":"web.example.com"}`)
	add("sub", "NS", `{"nameserver":"ns.sub.example.com"}`)
	add("ns.sub", "A", `{"address":"198.51.100.53"}`)
	add("_sip._tcp", "SRV", `{"priority":1,"weight":5,"port":5060,"target":"web.example.com"}`)
	add("@", "CAA", `{"flags":0,"tag":"issue","value":"letsencrypt.org"}`)
	return z
}

func set(t testing.TB, zs ...*Zone) *Set {
	var cs []*Compiled
	for _, z := range zs {
		c, err := Compile(z)
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
	}
	return NewSet(cs)
}

func types(rrs []dns.RR) string {
	var s []string
	for _, rr := range rrs {
		s = append(s, strings.ToLower(rr.Header().Name)+"/"+dns.TypeToString[rr.Header().Rrtype])
	}
	return strings.Join(s, ",")
}

func TestLookupSemantics(t *testing.T) {
	z := testZone(t)
	if l := ValidateRecords(z.Name, z.Records); len(l) > 0 {
		t.Fatalf("fixture invalid: %v", l)
	}
	other := &Zone{Name: "example.org.", Type: TypePrimary, Serial: 1, SOA: DefaultSOA("example.org.")}
	other.Records = []Record{rec(t, "example.org.", "@", "NS", 300, `{"nameserver":"ns1.example.com"}`),
		rec(t, "example.org.", "x", "CNAME", 300, `{"target":"web.example.com"}`)}
	s := set(t, z, other)
	cases := []struct {
		name     string
		qname    string
		qtype    uint16
		rcode    int
		aa       bool
		answer   string
		ns       string
		extra    string
		dangling string
	}{
		{"apex A", "example.com.", dns.TypeA, 0, true, "example.com./A", "", "", ""},
		{"NODATA at existing name", "web.example.com.", dns.TypeMX, 0, true, "", "example.com./SOA", "", ""},
		{"NXDOMAIN", "nope.example.com.", dns.TypeA, 3, true, "", "example.com./SOA", "", ""},
		{"empty non-terminal is NODATA", "b.c.example.com.", dns.TypeA, 0, true, "", "example.com./SOA", "", ""},
		{"ENT c", "c.example.com.", dns.TypeTXT, 0, true, "", "example.com./SOA", "", ""},
		{"below ENT is NXDOMAIN", "x.b.c.example.com.", dns.TypeA, 3, true, "", "example.com./SOA", "", ""},
		{"in-zone CNAME chase", "www.example.com.", dns.TypeAAAA, 0, true, "www.example.com./CNAME,web.example.com./AAAA", "", "", ""},
		{"CNAME query returns CNAME only", "www.example.com.", dns.TypeCNAME, 0, true, "www.example.com./CNAME", "", "", ""},
		{"out-of-zone CNAME dangles", "ext.example.com.", dns.TypeA, 0, true, "ext.example.com./CNAME", "", "", "cdn.example.net."},
		{"cross-zone CNAME chase", "x.example.org.", dns.TypeA, 0, true, "x.example.org./CNAME,web.example.com./A", "", "", ""},
		{"CNAME loop terminates", "loop1.example.com.", dns.TypeA, 0, true, "loop1.example.com./CNAME,loop2.example.com./CNAME", "", "", ""},
		{"wildcard synth", "foo.dev.example.com.", dns.TypeA, 0, true, "foo.dev.example.com./A", "", "", ""},
		{"wildcard deep", "a.b.dev.example.com.", dns.TypeTXT, 0, true, "a.b.dev.example.com./TXT", "", "", ""},
		{"wildcard NODATA", "foo.dev.example.com.", dns.TypeMX, 0, true, "", "example.com./SOA", "", ""},
		{"exact beats wildcard", "host.dev.example.com.", dns.TypeA, 0, true, "host.dev.example.com./A", "", "", ""},
		{"exact name blocks wildcard for other types", "host.dev.example.com.", dns.TypeTXT, 0, true, "", "example.com./SOA", "", ""},
		{"wildcard does not match its parent", "dev.example.com.", dns.TypeA, 0, true, "", "example.com./SOA", "", ""},
		{"wildcard CNAME chased", "z.alias.example.com.", dns.TypeA, 0, true, "z.alias.example.com./CNAME,web.example.com./A", "", "", ""},
		{"delegation referral with glue", "www.sub.example.com.", dns.TypeA, 0, false, "", "sub.example.com./NS", "ns.sub.example.com./A", ""},
		{"referral at cut", "sub.example.com.", dns.TypeA, 0, false, "", "sub.example.com./NS", "ns.sub.example.com./A", ""},
		{"DS at cut answered by parent", "sub.example.com.", dns.TypeDS, 0, true, "", "example.com./SOA", "", ""},
		{"MX additional", "example.com.", dns.TypeMX, 0, true, "example.com./MX", "", "mail.example.com./A", ""},
		{"SRV", "_sip._tcp.example.com.", dns.TypeSRV, 0, true, "_sip._tcp.example.com./SRV", "", "web.example.com./A,web.example.com./AAAA", ""},
		{"ANY returns all", "web.example.com.", dns.TypeANY, 0, true, "web.example.com./A,web.example.com./AAAA", "", "", ""},
		{"SOA", "example.com.", dns.TypeSOA, 0, true, "example.com./SOA", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, ok := s.Answer(c.qname, c.qtype)
			if !ok {
				t.Fatal("not authoritative")
			}
			if res.Rcode != c.rcode || res.Authoritative != c.aa {
				t.Fatalf("rcode %d aa %v", res.Rcode, res.Authoritative)
			}
			if got := types(res.Answer); got != c.answer {
				t.Fatalf("answer %q want %q", got, c.answer)
			}
			if got := types(res.Ns); got != c.ns {
				t.Fatalf("ns %q want %q", got, c.ns)
			}
			if got := types(res.Extra); got != c.extra {
				t.Fatalf("extra %q want %q", got, c.extra)
			}
			if res.Dangling != c.dangling {
				t.Fatalf("dangling %q", res.Dangling)
			}
		})
	}
	if _, ok := s.Answer("example.net.", dns.TypeA); ok {
		t.Fatal("non-authoritative name answered")
	}
	// negative SOA TTL is min(ttl, minimum) (RFC 2308)
	res, _ := s.Answer("nope.example.com.", dns.TypeA)
	if res.Ns[0].Header().Ttl != 300 {
		t.Fatalf("neg ttl %d", res.Ns[0].Header().Ttl)
	}
	// wildcard synthesis must not mutate shared records
	r1, _ := s.Answer("one.dev.example.com.", dns.TypeA)
	r2, _ := s.Answer("two.dev.example.com.", dns.TypeA)
	if r1.Answer[0].Header().Name == r2.Answer[0].Header().Name {
		t.Fatal("wildcard owner shared")
	}
}

func TestDeepestZoneWins(t *testing.T) {
	p := &Zone{Name: "example.com.", Type: TypePrimary, Serial: 1, SOA: DefaultSOA("example.com.")}
	p.Records = []Record{rec(t, p.Name, "@", "NS", 300, `{"nameserver":"ns1.example.com"}`)}
	f := &Zone{Name: "corp.example.com.", Type: TypeForwarder, Forwarders: []string{"10.0.0.1"}}
	s := set(t, p, f)
	if z := s.Find("a.corp.example.com."); z == nil || z.Type != TypeForwarder {
		t.Fatal("forwarder zone should win")
	}
	if _, ok := s.Answer("a.corp.example.com.", dns.TypeA); ok {
		t.Fatal("primary must not answer inside forwarder zone")
	}
	if z := s.Find("www.example.com."); z == nil || z.Origin != "example.com." {
		t.Fatal("find primary")
	}
}

func TestValidation(t *testing.T) {
	o := "example.com."
	base := []Record{rec(t, o, "@", "NS", 300, `{"nameserver":"ns1.example.com"}`)}
	type tc struct {
		name   string
		recs   []Record
		reason string
	}
	cases := []tc{
		{"cname + other", []Record{rec(t, o, "x", "CNAME", 60, `{"target":"y.example.com"}`), rec(t, o, "x", "A", 60, `{"address":"192.0.2.1"}`)}, "cname_conflict"},
		{"two cnames", []Record{rec(t, o, "x", "CNAME", 60, `{"target":"y.example.com"}`), rec(t, o, "x", "CNAME", 60, `{"target":"z.example.com"}`)}, "cname_conflict"},
		{"cname at apex", []Record{rec(t, o, "@", "CNAME", 60, `{"target":"y.example.net"}`)}, "cname_at_apex"},
		{"duplicate", []Record{rec(t, o, "x", "A", 60, `{"address":"192.0.2.1"}`), rec(t, o, "x", "A", 60, `{"address":"192.0.2.1"}`)}, "duplicate_record"},
		{"occluded", []Record{rec(t, o, "sub", "NS", 60, `{"nameserver":"ns.other.net"}`), rec(t, o, "www.sub", "TXT", 60, `{"text":"x"}`)}, "occluded_by_delegation"},
		{"wildcard ns", []Record{rec(t, o, "*.w", "NS", 60, `{"nameserver":"ns.other.net"}`)}, "wildcard_ns"},
	}
	for _, c := range cases {
		l := ValidateRecords(o, append(append([]Record{}, base...), c.recs...))
		found := false
		for _, f := range l {
			found = found || f.ReasonCode == c.reason
		}
		if !found {
			t.Errorf("%s: want %s got %v", c.name, c.reason, l)
		}
	}
	if l := ValidateRecords(o, nil); len(l) == 0 || l[0].ReasonCode != "apex_ns_required" {
		t.Errorf("apex NS: %v", l)
	}
	glue := append(append([]Record{}, base...), rec(t, o, "sub", "NS", 60, `{"nameserver":"ns.sub.example.com"}`),
		rec(t, o, "ns.sub", "A", 60, `{"address":"192.0.2.53"}`))
	if l := ValidateRecords(o, glue); len(l) > 0 {
		t.Errorf("glue rejected: %v", l)
	}
}

func TestBuildRecordErrors(t *testing.T) {
	o := "example.com."
	s := func(v string) *string { return &v }
	i := func(v int) *int { return &v }
	cases := []struct {
		in    RecordInput
		field string
	}{
		{RecordInput{Name: s("bad name!"), Type: s("A"), Data: json.RawMessage(`{"address":"1.2.3.4"}`)}, "name"},
		{RecordInput{Name: s("a"), Type: s("A"), TTL: i(700000), Data: json.RawMessage(`{"address":"1.2.3.4"}`)}, "ttl"},
		{RecordInput{Name: s("a"), Type: s("A"), Data: json.RawMessage(`{"address":"::1"}`)}, "data.address"},
		{RecordInput{Name: s("a"), Type: s("AAAA"), Data: json.RawMessage(`{"address":"1.2.3.4"}`)}, "data.address"},
		{RecordInput{Name: s("a"), Type: s("MX"), Data: json.RawMessage(`{"exchange":"m.example.com"}`)}, "data.preference"},
		{RecordInput{Name: s("a"), Type: s("SRV"), Data: json.RawMessage(`{"priority":1,"weight":1,"port":70000,"target":"x.example.com"}`)}, "data.port"},
		{RecordInput{Name: s("a"), Type: s("CAA"), Data: json.RawMessage(`{"tag":"is sue","value":"x"}`)}, "data.tag"},
		{RecordInput{Name: s("a"), Type: s("TXT"), Data: json.RawMessage(`{"strings":["` + strings.Repeat("x", 256) + `"]}`)}, "data.strings[0]"},
		{RecordInput{Name: s("a"), Type: s("CNAME"), Data: json.RawMessage(`{"target":"bad_host!"}`)}, "data.target"},
		{RecordInput{Name: s("a"), Type: s("A"), Data: json.RawMessage(`{"address":"1.2.3.4","extra":1}`)}, "data"},
		{RecordInput{Name: s("a"), Type: s("HINFO"), Data: json.RawMessage(`{}`)}, "type"},
		{RecordInput{Name: s("a"), Type: s("SOA"), Data: json.RawMessage(`{}`)}, "type"},
		{RecordInput{Type: s("A")}, "name"},
		{RecordInput{Name: s("a.*"), Type: s("A"), Data: json.RawMessage(`{"address":"1.2.3.4"}`)}, "name"},
	}
	for n, c := range cases {
		_, _, l := BuildRecord(c.in, o)
		if len(l) == 0 || l[0].Field != c.field {
			t.Errorf("case %d: want field %s got %v", n, c.field, l)
		}
	}
	// long TXT is split into 255-octet strings; names are normalised
	r, rr, l := BuildRecord(RecordInput{Name: s("WWW.Example.com"), Type: s("txt"), Data: json.RawMessage(`{"text":"` + strings.Repeat("a", 600) + `"}`)}, o)
	if len(l) > 0 || r.Name != "www" || len(rr.(*dns.TXT).Txt) != 3 || r.TTL != DefaultRecordTTL {
		t.Fatalf("%+v %v", r, l)
	}
	if n, ok := NormalizeOwner("x.example.com.", o); !ok || n != "x" {
		t.Fatal("absolute owner")
	}
	if _, ok := NormalizeOwner("x.example.net.", o); ok {
		t.Fatal("out of zone owner accepted")
	}
}

func TestSerial(t *testing.T) {
	day := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	if s := NextSerial(0, day); s != 2026110800 {
		t.Fatal(s)
	}
	if s := NextSerial(2026110800, day); s != 2026110801 {
		t.Fatal(s)
	}
	if s := NextSerial(2026110799, day); s != 2026110800 {
		t.Fatal(s)
	}
	if s := NextSerial(2027010100, day); s != 2027010101 {
		t.Fatal("must never go backwards", s)
	}
	if s := NextSerial(0xffffffff, day); s != 0 && !serialLess(0xffffffff, s) {
		t.Fatal("wrap", s)
	}
	if s := SerialAfter(2026110800, 2030000000, day); s != 2030000001 {
		t.Fatal(s)
	}
}

func recordSet(z *Zone) []string {
	var out []string
	for _, r := range z.Records {
		if !r.Disabled {
			out = append(out, r.Name+" "+r.Type+" "+string(r.Data))
		}
	}
	sort.Strings(out)
	return out
}

func TestImportExportRoundTrip(t *testing.T) {
	z := testZone(t)
	z.Records = append(z.Records, rec(t, z.Name, "dkim", "TXT", 300, `{"strings":["v=DKIM1; k=rsa; p=AAAA","BBBB \"quoted\" \\ end"]}`))
	text, err := Export(z)
	if err != nil {
		t.Fatal(err)
	}
	recs, soa, err := Import(text, z.Name)
	if err != nil {
		t.Fatalf("import: %v\n%s", err, text)
	}
	if soa == nil || soa.MName != z.SOA.MName || soa.ImportedSerial() != z.Serial {
		t.Fatalf("soa %+v", soa)
	}
	z2 := &Zone{Name: z.Name, Records: recs}
	a, b := recordSet(z), recordSet(z2)
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatalf("round trip differs:\n%s\n---\n%s", strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
}

func TestImportErrors(t *testing.T) {
	if _, _, err := Import("$INCLUDE /etc/passwd\n", "example.com."); err == nil {
		t.Fatal("$INCLUDE accepted")
	}
	if _, _, err := Import("www.example.net. 60 IN A 1.2.3.4\n", "example.com."); err == nil {
		t.Fatal("out of zone accepted")
	}
	if _, _, err := Import("x 60 IN HINFO a b\n", "example.com."); err == nil {
		t.Fatal("unsupported type accepted")
	}
	if _, _, err := Import("x 60 IN A not-an-ip\n", "example.com."); err == nil {
		t.Fatal("garbage accepted")
	}
	recs, _, err := Import("$TTL 120\nx IN A 192.0.2.1\ny 30 IN AAAA 2001:db8::1\n", "example.com.")
	if err != nil || len(recs) != 2 || recs[0].TTL != 120 {
		t.Fatalf("%v %v", recs, err)
	}
}

func FuzzImport(f *testing.F) {
	f.Add("$ORIGIN example.com.\n@ 3600 IN SOA ns1 host 1 2 3 4 5\nwww 60 IN A 192.0.2.1\n")
	f.Add("x IN TXT \"a\\\"b\" \"c\"\n*.w 1 IN CNAME y\n")
	f.Add("$TTL 1\n@ MX 10 mail\n_s._tcp SRV 1 2 3 t\n@ CAA 0 issue \"ca\"\n")
	f.Fuzz(func(t *testing.T, text string) {
		recs, _, err := Import(text, "example.com.")
		if err != nil {
			return
		}
		z := &Zone{Name: "example.com.", Type: TypePrimary, Serial: 1, SOA: DefaultSOA("example.com."), Records: recs}
		if _, err := Compile(z); err != nil {
			t.Fatalf("imported records do not compile: %v", err)
		}
		if _, err := Export(z); err != nil {
			t.Fatalf("export: %v", err)
		}
	})
}
