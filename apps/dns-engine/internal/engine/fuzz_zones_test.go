package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/zone"
)

// FuzzZoneMessages drives UPDATE (RFC 2136), NOTIFY (RFC 1996), IXFR/AXFR
// queries and TSIG-carrying messages through the query entry points of a
// zone that accepts updates and transfers from everyone (docs/41 §4): no
// panic, every answer is a well-formed response to the query.
func FuzzZoneMessages(f *testing.F) {
	add := func(m *dns.Msg) []byte {
		b, err := m.Pack()
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	up := new(dns.Msg)
	up.SetUpdate("fz.test.")
	up.Insert([]dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "new.fz.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A: []byte{192, 0, 2, 9}}})
	up.NameUsed([]dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "www.fz.test.", Rrtype: dns.TypeANY, Class: dns.ClassANY}}})
	f.Add(add(up))
	del := new(dns.Msg)
	del.SetUpdate("fz.test.")
	del.RemoveName([]dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "www.fz.test.", Rrtype: dns.TypeANY, Class: dns.ClassANY}}})
	f.Add(add(del))
	nt := new(dns.Msg)
	nt.SetNotify("fz.test.")
	f.Add(add(nt))
	ix := new(dns.Msg)
	ix.SetIxfr("fz.test.", 0, "ns.fz.test.", "h.fz.test.")
	f.Add(add(ix))
	ax := new(dns.Msg)
	ax.SetAxfr("fz.test.")
	f.Add(add(ax))
	tq := new(dns.Msg)
	tq.SetQuestion("fz.test.", dns.TypeSOA)
	tq.Extra = []dns.RR{&dns.TSIG{Hdr: dns.RR_Header{Name: "nokey.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY},
		Algorithm: dns.HmacSHA256, TimeSigned: uint64(time.Now().Unix()), Fudge: 300, MACSize: 4, MAC: "00000000"}}
	if b, err := tq.Pack(); err == nil {
		f.Add(b)
	}

	e, err := Open(Options{DataDir: f.TempDir(), DefaultListen: "127.0.0.1:5399"})
	if err != nil {
		f.Fatal(err)
	}
	st, v := e.Settings()
	st.Upstreams = nil
	st.Limits.ClientQPS, st.Limits.ClientBurst = 0, 0
	if _, _, err := e.PutSettings(st, v); err != nil {
		f.Fatal(err)
	}
	if _, err := e.CreateZone("fz.test", "primary", nil); err != nil {
		f.Fatal(err)
	}
	if _, err := e.CreateRecord("fz.test", zone.RecordInput{Name: s("www"), Type: s("A"), Data: json.RawMessage(`{"address":"192.0.2.1"}`)}); err != nil {
		f.Fatal(err)
	}
	e.mu.Lock()
	old := e.zones["fz.test."]
	z := old.Clone()
	z.Transfer = &zone.TransferConfig{Allow: []string{"0.0.0.0/0", "::/0"}}
	z.Update = &zone.UpdateConfig{Enabled: true, Allow: []string{"0.0.0.0/0", "::/0"}}
	err = e.commitZoneLocked(old, z, "fuzz")
	e.mu.Unlock()
	if err != nil {
		f.Fatal(err)
	}
	sc := NewScratch()
	f.Fuzz(func(t *testing.T, pkt []byte) {
		for _, proto := range []Proto{UDP, TCP} {
			out, v := e.Fast(pkt, lan, proto, sc)
			if v == Slow || v == SlowUnchecked {
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				out = e.Slow(ctx, pkt, lan, proto, v == Slow)
				cancel()
			}
			if out == nil {
				continue
			}
			if len(pkt) >= 2 && (out[0] != pkt[0] || out[1] != pkt[1]) {
				t.Fatal("response ID differs from query")
			}
			if len(out) < 12 || out[2]&0x80 == 0 {
				t.Fatal("response without QR")
			}
		}
	})
}
