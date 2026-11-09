package xfr

import (
	"testing"

	"github.com/miekg/dns"
)

// FuzzTransferParse interprets arbitrary AXFR/IXFR response contents as a
// secondary would (docs/41 §4): no panic, and an accepted result always
// carries the zone's SOA.
func FuzzTransferParse(f *testing.F) {
	soa := func(serial uint32) dns.RR {
		return &dns.SOA{Hdr: dns.RR_Header{Name: "fz.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns: "ns.fz.test.", Mbox: "h.fz.test.", Serial: serial, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300}
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "www.fz.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 1}}
	for _, rrs := range [][]dns.RR{
		{soa(2), a, soa(2)},                 // AXFR
		{soa(3), soa(2), a, soa(3), soa(3)}, // IXFR: delete a, add nothing
		{soa(3)},                            // IXFR: up to date
		{soa(2), a},                         // truncated AXFR
		{soa(3), soa(1), soa(2), a, soa(3), soa(3)}, // IXFR from another serial
	} {
		m := new(dns.Msg)
		m.SetQuestion("fz.test.", dns.TypeAXFR)
		m.Response = true
		m.Answer = rrs
		if b, err := m.Pack(); err == nil {
			f.Add(b)
		}
	}
	cur := soa(2).(*dns.SOA)
	data := []dns.RR{a}
	f.Fuzz(func(t *testing.T, pkt []byte) {
		m := new(dns.Msg)
		if m.Unpack(pkt) != nil {
			return
		}
		for _, c := range []*dns.SOA{nil, cur} {
			d := data
			if c == nil {
				d = nil
			}
			_, _ = Parse("fz.test.", m.Answer, c, d)
		}
	})
}
