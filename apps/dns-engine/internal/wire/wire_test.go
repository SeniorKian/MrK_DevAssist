package wire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func pack(t testing.TB, m *dns.Msg) []byte {
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseQuery(t *testing.T) {
	kb := make([]byte, 0, MaxKey)
	m := new(dns.Msg)
	m.SetQuestion("WwW.Example.COM.", dns.TypeAAAA)
	m.SetEdns0(1232, true)
	q, ok := ParseQuery(pack(t, m), kb)
	if !ok || q.QType != dns.TypeAAAA || !q.HasEDNS || q.UDPSize != 1232 || !q.DO || !q.RD() {
		t.Fatalf("parse: ok=%v %+v", ok, q)
	}
	want := AppendKey(nil, []byte("\x03www\x07example\x03com\x00"), dns.TypeAAAA)
	if !bytes.Equal(q.Key, want) {
		t.Fatalf("key %q want %q", q.Key, want)
	}
	cases := map[string]func(m *dns.Msg){
		"response":   func(m *dns.Msg) { m.Response = true },
		"opcode":     func(m *dns.Msg) { m.Opcode = dns.OpcodeNotify },
		"two-q":      func(m *dns.Msg) { m.Question = append(m.Question, m.Question[0]) },
		"answer":     func(m *dns.Msg) { rr, _ := dns.NewRR("a. 1 IN A 1.2.3.4"); m.Answer = []dns.RR{rr} },
		"chaos":      func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS },
		"edns-ver-1": func(m *dns.Msg) { m.SetEdns0(1232, false); m.IsEdns0().SetVersion(1) },
	}
	for name, mut := range cases {
		m := new(dns.Msg)
		m.SetQuestion("a.example.", dns.TypeA)
		mut(m)
		if _, ok := ParseQuery(pack(t, m), kb); ok {
			t.Errorf("%s: fast path must reject", name)
		}
	}
	b := pack(t, m)
	if _, ok := ParseQuery(append(b, 0), kb); ok {
		t.Error("trailing byte accepted")
	}
	for i := 0; i < len(b); i++ {
		if _, ok := ParseQuery(b[:i], kb); ok {
			t.Errorf("truncated at %d accepted", i)
		}
	}
}

func TestTemplateRender(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	m.Response, m.RecursionAvailable = true, true
	for _, s := range []string{"www.example.com. 300 IN CNAME a.example.com.", "a.example.com. 60 IN A 192.0.2.1"} {
		rr, _ := dns.NewRR(s)
		m.Answer = append(m.Answer, rr)
	}
	m.Compress = true
	tp, err := NewTemplate(pack(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if tp.MinTTL != 60 || len(tp.TTLOffsets) != 2 {
		t.Fatalf("min %d offsets %d", tp.MinTTL, len(tp.TTLOffsets))
	}
	tp.ClampTTLs(100, 200)
	if tp.TTLs[0] != 200 || tp.TTLs[1] != 100 || tp.MinTTL != 100 {
		t.Fatalf("clamp %v", tp.TTLs)
	}
	out := tp.Render(nil, &RenderOpts{ID: 0xBEEF, ReqFlags: FlagRD, QName: []byte("\x03WWW\x07example\x03com\x00"),
		Elapsed: 30, EDNS: true, UDPSize: 1232, EDE: 3})
	r := new(dns.Msg)
	if err := r.Unpack(out); err != nil {
		t.Fatal(err)
	}
	if r.Id != 0xBEEF || !r.RecursionDesired || r.Question[0].Name != "WWW.example.com." {
		t.Fatalf("header/question not patched: %v", r)
	}
	if r.Answer[0].Header().Ttl != 170 || r.Answer[1].Header().Ttl != 70 {
		t.Fatalf("ttl %d %d", r.Answer[0].Header().Ttl, r.Answer[1].Header().Ttl)
	}
	opt := r.IsEdns0()
	if opt == nil || len(opt.Option) != 1 {
		t.Fatalf("missing EDE: %v", r)
	}
	stale := tp.Render(nil, &RenderOpts{StaleTTL: 30, Elapsed: 99999})
	_ = r.Unpack(stale)
	if r.Answer[1].Header().Ttl != 30 {
		t.Fatal("stale ttl")
	}
	tc := tp.Render(nil, &RenderOpts{MaxSize: 40})
	r = new(dns.Msg)
	_ = r.Unpack(tc)
	if !r.Truncated || len(r.Answer) != 0 || len(r.Question) != 1 {
		t.Fatalf("truncation: %v", r)
	}
}

func TestTemplateRejects(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("x.", dns.TypeA)
	m.SetEdns0(1232, false)
	if _, err := NewTemplate(pack(t, m)); err == nil {
		t.Fatal("OPT must be rejected")
	}
	if _, err := NewTemplate([]byte{1, 2, 3}); err == nil {
		t.Fatal("short accepted")
	}
}

func TestErrorResponse(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("a.b.", dns.TypeMX)
	m.SetEdns0(4096, false)
	pkt := pack(t, m)
	q, _ := ParseQuery(pkt, make([]byte, 0, MaxKey))
	out := ErrorResponse(nil, pkt, &q, dns.RcodeRefused, false, 1232)
	r := new(dns.Msg)
	if err := r.Unpack(out); err != nil || r.Rcode != dns.RcodeRefused || r.Id != m.Id || r.IsEdns0() == nil {
		t.Fatalf("%v %v", err, r)
	}
	tc := TruncatedResponse(nil, pkt, &q, 1232)
	if binary.BigEndian.Uint16(tc[2:])&FlagTC == 0 {
		t.Fatal("TC not set")
	}
	if ClientUDPSize(&q, 1232) != 1232 {
		t.Fatal("size")
	}
	set := map[string]struct{}{"\x01b\x00": {}}
	if !HasSuffix([]byte("\x01a\x01b\x00"), set) || HasSuffix([]byte("\x01a\x01c\x00"), set) {
		t.Fatal("HasSuffix")
	}
}

func FuzzParseQuery(f *testing.F) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetEdns0(1232, false)
	b, _ := m.Pack()
	f.Add(b)
	f.Add([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, pkt []byte) {
		kb := make([]byte, 0, MaxKey)
		q, ok := ParseQuery(pkt, kb)
		if !ok {
			return
		}
		// everything the fast path accepts must also be a valid query for miekg/dns
		var r dns.Msg
		if err := r.Unpack(pkt); err != nil {
			// miekg/dns validates some EDNS option payloads the fast path never reads;
			// RFC 6891 §6.1.2 lets a server ignore options it does not use.
			if !strings.Contains(err.Error(), "OPT") {
				t.Fatalf("fast path accepted a message miekg rejects: %v", err)
			}
			return
		}
		if len(r.Question) != 1 || r.Question[0].Qtype != q.QType {
			t.Fatal("question mismatch")
		}
		_ = ErrorResponse(nil, pkt, &q, 5, true, 1232)
	})
}

func FuzzTemplate(f *testing.F) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	rr, _ := dns.NewRR("example.com. 60 IN A 1.2.3.4")
	m.Answer = []dns.RR{rr}
	b, _ := m.Pack()
	f.Add(b)
	f.Fuzz(func(t *testing.T, pkt []byte) {
		tp, err := NewTemplate(append([]byte(nil), pkt...))
		if err != nil {
			return
		}
		_ = tp.Render(nil, &RenderOpts{ID: 1, Elapsed: 5, EDNS: true, UDPSize: 1232, MaxSize: 512})
	})
}
