package tsig

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// FuzzTSIGCheck feeds arbitrary messages (signed, truncated, with bogus TSIG
// RRs) to the verifier: it must never panic and never accept a message it
// did not see signed with the key (docs/41 §4).
func FuzzTSIGCheck(f *testing.F) {
	s, err := Open(filepath.Join(f.TempDir(), "tsig.json"))
	if err != nil {
		f.Fatal(err)
	}
	if _, err := s.Create("fuzz-key", HMACSHA256, "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ=", time.Now()); err != nil {
		f.Fatal(err)
	}
	m := new(dns.Msg)
	m.SetQuestion("fz.test.", dns.TypeSOA)
	signed, _, err := s.Sign(m, "fuzz-key.", "", false)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(signed)
	plain, _ := m.Pack()
	f.Add(plain)
	u := new(dns.Msg)
	u.SetUpdate("fz.test.")
	u.SetTsig("unknown-key.", dns.HmacSHA256, 300, time.Now().Unix())
	if b, err := u.Pack(); err == nil {
		f.Add(b)
	}
	f.Add(signed[:len(signed)/2])
	f.Fuzz(func(t *testing.T, pkt []byte) {
		msg := new(dns.Msg)
		if msg.Unpack(pkt) != nil {
			return
		}
		v := s.Check(pkt, msg)
		if v.OK && !v.Signed {
			t.Fatal("unsigned message accepted as signed")
		}
	})
}
