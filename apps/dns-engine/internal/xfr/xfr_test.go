package xfr

import (
	"testing"

	"github.com/miekg/dns"
)

func rr(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}

func soa(serial string) dns.RR {
	return rr("example.test. 900 IN SOA ns1.example.test. hostmaster.example.test. " + serial + " 3600 600 604800 300")
}

func TestParseAXFRAndIXFR(t *testing.T) {
	a := rr("www.example.test. 300 IN A 192.0.2.1")
	b := rr("api.example.test. 300 IN A 192.0.2.2")
	c := rr("old.example.test. 300 IN A 192.0.2.9")
	res, err := Parse("example.test.", []dns.RR{soa("2"), a, c, soa("2")}, nil, nil)
	if err != nil || len(res.RRs) != 2 || res.Incremental {
		t.Fatalf("axfr %v %v", res, err)
	}
	cur := soa("2").(*dns.SOA)
	// condensed IXFR 2 -> 4 via 3
	ix := []dns.RR{soa("4"), soa("2"), c, soa("3"), b, soa("3"), soa("4"), soa("4")}
	res, err = Parse("example.test.", ix, cur, []dns.RR{a, c})
	if err != nil || !res.Incremental || len(res.RRs) != 2 || res.SOA.Serial != 4 {
		t.Fatalf("ixfr %v %v", res, err)
	}
	// up to date
	res, err = Parse("example.test.", []dns.RR{soa("2")}, cur, []dns.RR{a})
	if err != nil || !res.UpToDate {
		t.Fatalf("up to date %v %v", res, err)
	}
	// errors: out of zone, deletion of a missing RR, wrong end
	if _, err := Parse("example.test.", []dns.RR{soa("2"), rr("x.other. 300 IN A 192.0.2.1"), soa("2")}, nil, nil); err == nil {
		t.Fatal("out-of-zone accepted")
	}
	if _, err := Parse("example.test.", []dns.RR{soa("3"), soa("2"), b, soa("3"), soa("3")}, cur, []dns.RR{a}); err == nil {
		t.Fatal("deleting a missing record accepted")
	}
	if _, err := Parse("example.test.", []dns.RR{soa("2"), a, soa("1")}, nil, nil); err == nil {
		t.Fatal("bad closing SOA accepted")
	}
	del, add := Diff([]dns.RR{a, c}, []dns.RR{a, b})
	if len(del) != 1 || len(add) != 1 || Key(del[0]) != Key(c) {
		t.Fatalf("diff %v %v", del, add)
	}
	var many []dns.RR
	for i := 0; i < 2000; i++ {
		many = append(many, a)
	}
	for _, ch := range Chunk(many) {
		m := new(dns.Msg)
		m.Answer = ch
		if m.Len() > MaxMessage {
			t.Fatalf("chunk of %d bytes", m.Len())
		}
	}
	if n, ok := NormalizeAddr("192.0.2.1"); !ok || n != "192.0.2.1:53" {
		t.Fatal(n)
	}
	if n, ok := NormalizeAddr("[2001:db8::1]:5353"); !ok || n != "[2001:db8::1]:5353" {
		t.Fatal(n)
	}
	if _, ok := NormalizeAddr("host.example:53"); ok {
		t.Fatal("host name accepted")
	}
}
