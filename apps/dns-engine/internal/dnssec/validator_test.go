package dnssec

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/testutil"
)

type world struct {
	h     *testutil.Hierarchy
	root  *testutil.Zone
	zones map[string]*testutil.Zone
}

func (w *world) fetch(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
	return w.h.Resolve(dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET}, true), nil
}

// newWorld builds: . -> com -> {example.com (NSEC), n3.com (NSEC3),
// optout.com (NSEC3 opt-out) -> insecure.optout.com, unsigned.com,
// bad.com (signature tampered), expired.com, future.com, mismatch.com,
// stripped.com, algo.com (unsupported DS algorithm), iter.com (NSEC3
// iterations 500)}.
func newWorld(t testing.TB) *world {
	t.Helper()
	w := &world{zones: map[string]*testutil.Zone{}}
	root := testutil.NewZone(".", false)
	com := testutil.NewZone("com.", false)
	root.Delegate(com, "a.gtld.test.", "")
	w.root = root
	add := func(z *testutil.Zone, parent *testutil.Zone) *testutil.Zone {
		w.zones[z.Origin] = z
		if parent != nil {
			parent.Delegate(z, "ns1."+z.Origin, "192.0.2.53")
		}
		z.Add("ns1."+z.Origin+" 3600 IN A 192.0.2.53", z.Origin+" 3600 IN NS ns1."+z.Origin)
		return z
	}
	w.zones["."], w.zones["com."] = root, com
	ex := add(testutil.NewZone("example.com.", false), com)
	ex.Add("www.example.com. 300 IN A 192.0.2.1",
		"*.wild.example.com. 300 IN A 192.0.2.7",
		"alias.example.com. 300 IN CNAME www.n3.com.",
		"deep.ent.example.com. 300 IN A 192.0.2.9")
	n3 := add(testutil.NewZone("n3.com.", false), com)
	n3.NSEC3 = true
	n3.Add("www.n3.com. 300 IN A 192.0.2.2", "*.wild.n3.com. 300 IN A 192.0.2.8")
	oo := add(testutil.NewZone("optout.com.", false), com)
	oo.NSEC3, oo.OptOut = true, true
	ins := add(testutil.NewZone("insecure.optout.com.", true), oo)
	ins.Add("www.insecure.optout.com. 300 IN A 192.0.2.3")
	un := add(testutil.NewZone("unsigned.com.", true), com)
	un.Add("www.unsigned.com. 300 IN A 192.0.2.4")
	bad := add(testutil.NewZone("bad.com.", false), com)
	bad.Add("www.bad.com. 300 IN A 192.0.2.5")
	bad.Tamper = func(q dns.Question, m *dns.Msg) {
		for _, rr := range m.Answer {
			if a, ok := rr.(*dns.A); ok {
				a.A = []byte{198, 51, 100, 66} // spoofed address, signature no longer matches
			}
		}
	}
	exp := add(testutil.NewZone("expired.com.", false), com)
	exp.Add("www.expired.com. 300 IN A 192.0.2.6")
	exp.Inception, exp.Expiration = uint32(time.Now().Add(-60*24*time.Hour).Unix()), uint32(time.Now().Add(-30*24*time.Hour).Unix())
	fut := add(testutil.NewZone("future.com.", false), com)
	fut.Add("www.future.com. 300 IN A 192.0.2.6")
	fut.Inception, fut.Expiration = uint32(time.Now().Add(10*24*time.Hour).Unix()), uint32(time.Now().Add(40*24*time.Hour).Unix())
	mm := testutil.NewZone("mismatch.com.", false)
	w.zones[mm.Origin] = mm
	mm.Add("ns1.mismatch.com. 3600 IN A 192.0.2.53", "mismatch.com. 3600 IN NS ns1.mismatch.com.", "www.mismatch.com. 300 IN A 192.0.2.10")
	other := testutil.NewZone("mismatch.com.", false) // DS of a key the zone does not publish
	com.Add("mismatch.com. 3600 IN NS ns1.mismatch.com.")
	com.AddRR(other.DS())
	st := add(testutil.NewZone("stripped.com.", false), com)
	st.Add("www.stripped.com. 300 IN A 192.0.2.11")
	st.Tamper = func(q dns.Question, m *dns.Msg) {
		if q.Qtype == dns.TypeA {
			var keep []dns.RR
			for _, rr := range m.Answer {
				if rr.Header().Rrtype != dns.TypeRRSIG {
					keep = append(keep, rr)
				}
			}
			m.Answer = keep
		}
	}
	algo := testutil.NewZone("algo.com.", false)
	w.zones[algo.Origin] = algo
	algo.Add("ns1.algo.com. 3600 IN A 192.0.2.53", "algo.com. 3600 IN NS ns1.algo.com.", "www.algo.com. 300 IN A 192.0.2.12")
	com.Add("algo.com. 3600 IN NS ns1.algo.com.")
	ds := algo.DS()
	ds.Algorithm = dns.ED448 // not implemented: the zone must be treated as insecure
	com.AddRR(ds)
	it := add(testutil.NewZone("iter.com.", false), com)
	it.NSEC3, it.Iterations = true, 500
	it.Add("www.iter.com. 300 IN A 192.0.2.13")
	for _, z := range w.zones {
		w.h = nil
		_ = z
	}
	h := &testutil.Hierarchy{}
	for _, z := range w.zones {
		h.Zones = append(h.Zones, z)
	}
	w.h = h
	return w
}

func (w *world) validator(t testing.TB) *Validator {
	return New(OpenAnchorsWith("", []*dns.DS{w.root.DS()}, nil), nil)
}

func (w *world) check(t *testing.T, v *Validator, name string, qtype uint16) Result {
	t.Helper()
	msg := w.h.Resolve(dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET}, true)
	return v.Validate(context.Background(), w.fetch, name, qtype, msg)
}

func TestValidateStates(t *testing.T) {
	w := newWorld(t)
	v := w.validator(t)
	cases := []struct {
		name  string
		qtype uint16
		state State
		ede   int
	}{
		{"www.example.com.", dns.TypeA, Secure, NoEDE},
		{"nope.example.com.", dns.TypeA, Secure, NoEDE},      // NSEC NXDOMAIN
		{"www.example.com.", dns.TypeAAAA, Secure, NoEDE},    // NSEC NODATA
		{"ent.example.com.", dns.TypeA, Secure, NoEDE},       // empty non-terminal
		{"x.wild.example.com.", dns.TypeA, Secure, NoEDE},    // wildcard expansion
		{"x.wild.example.com.", dns.TypeAAAA, Secure, NoEDE}, // wildcard NODATA
		{"alias.example.com.", dns.TypeA, Secure, NoEDE},     // CNAME into another signed zone
		{"www.n3.com.", dns.TypeA, Secure, NoEDE},            // NSEC3
		{"nope.n3.com.", dns.TypeA, Secure, NoEDE},           // NSEC3 NXDOMAIN
		{"www.n3.com.", dns.TypeTXT, Secure, NoEDE},          // NSEC3 NODATA
		{"a.wild.n3.com.", dns.TypeA, Secure, NoEDE},         // NSEC3 wildcard
		{"www.insecure.optout.com.", dns.TypeA, Insecure, NoEDE},
		{"www.unsigned.com.", dns.TypeA, Insecure, NoEDE}, // insecure delegation (NSEC)
		{"www.algo.com.", dns.TypeA, Insecure, int(dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm)},
		{"www.iter.com.", dns.TypeA, Secure, NoEDE},    // positive answers need no NSEC3
		{"nope.iter.com.", dns.TypeA, Insecure, NoEDE}, // RFC 9276: too many iterations
		{"www.bad.com.", dns.TypeA, Bogus, int(dns.ExtendedErrorCodeDNSBogus)},
		{"www.expired.com.", dns.TypeA, Bogus, int(dns.ExtendedErrorCodeSignatureExpired)},
		{"www.future.com.", dns.TypeA, Bogus, int(dns.ExtendedErrorCodeSignatureNotYetValid)},
		{"www.mismatch.com.", dns.TypeA, Bogus, int(dns.ExtendedErrorCodeDNSKEYMissing)},
		{"www.stripped.com.", dns.TypeA, Bogus, int(dns.ExtendedErrorCodeRRSIGsMissing)},
	}
	for _, c := range cases {
		r := w.check(t, v, c.name, c.qtype)
		if r.State != c.state || (c.ede != NoEDE || c.state == Bogus) && r.EDE != c.ede {
			t.Errorf("%s %s: got %v ede=%d (%s %s), want %v ede=%d", c.name, dns.TypeToString[c.qtype], r.State, r.EDE,
				r.Reason, r.Detail, c.state, c.ede)
		}
	}
}

func TestValidateForgedDenial(t *testing.T) {
	w := newWorld(t)
	v := w.validator(t)
	// an NXDOMAIN for an existing name with the real proofs of another name
	msg := w.h.Resolve(dns.Question{Name: "nope.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, true)
	msg.Question[0].Name = "www.example.com."
	if r := v.Validate(context.Background(), w.fetch, "www.example.com.", dns.TypeA, msg); r.State != Bogus {
		t.Fatalf("forged NXDOMAIN accepted: %v %s", r.State, r.Reason)
	}
	// unsigned answer inside a signed zone
	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	rr, _ := dns.NewRR("www.example.com. 300 IN A 203.0.113.66")
	m.Answer = []dns.RR{rr}
	if r := v.Validate(context.Background(), w.fetch, "www.example.com.", dns.TypeA, m); r.State != Bogus ||
		r.EDE != int(dns.ExtendedErrorCodeRRSIGsMissing) {
		t.Fatalf("unsigned answer: %v %d", r.State, r.EDE)
	}
	// NSEC3 NXDOMAIN with the wildcard proof removed
	msg = w.h.Resolve(dns.Question{Name: "nope.n3.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, true)
	var keep []dns.RR
	n3s := 0
	for _, x := range msg.Ns {
		if x.Header().Rrtype == dns.TypeNSEC3 {
			n3s++
			if n3s == 3 {
				continue
			}
		}
		keep = append(keep, x)
	}
	msg.Ns = keep
	if n3s >= 3 {
		if r := v.Validate(context.Background(), w.fetch, "nope.n3.com.", dns.TypeA, msg); r.State == Secure {
			t.Fatalf("incomplete NSEC3 proof accepted")
		}
	}
}

func TestNegativeTrustAnchor(t *testing.T) {
	w := newWorld(t)
	v := w.validator(t)
	v.Configure(Config{NSEC3MaxIter: 150, Skew: time.Hour, BogusTTL: time.Minute, MaxTTL: time.Hour,
		NTAs: []NTA{{Domain: "bad.com."}, {Domain: "expired.com.", Expires: time.Now().Add(-time.Minute)}}})
	if r := w.check(t, v, "www.bad.com.", dns.TypeA); r.State != Insecure || r.Reason != ReasonNTA {
		t.Fatalf("NTA: %v %s", r.State, r.Reason)
	}
	if r := w.check(t, v, "www.expired.com.", dns.TypeA); r.State != Bogus {
		t.Fatalf("expired NTA must not apply: %v", r.State)
	}
}

func TestRootWithoutSignatures(t *testing.T) {
	w := newWorld(t)
	v := w.validator(t)
	strip := func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		m := w.h.Resolve(dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET}, false)
		return m, nil
	}
	msg := w.h.Resolve(dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)
	if r := v.Validate(context.Background(), strip, "www.example.com.", dns.TypeA, msg); r.State != Indeterminate {
		t.Fatalf("a path without DNSSEC: %v %s", r.State, r.Reason)
	}
}

func TestAggressiveNSEC(t *testing.T) {
	w := newWorld(t)
	v := w.validator(t)
	if r := w.check(t, v, "nope.example.com.", dns.TypeA); r.State != Secure {
		t.Fatal(r)
	}
	// a name in the same NSEC gap is synthesised without asking
	var gap string
	for _, n := range []string{"nopf.example.com.", "noq.example.com.", "nooo.example.com.", "nop.example.com."} {
		if v.Synthesize(n, dns.TypeA) != nil {
			gap = n
			break
		}
	}
	if gap == "" {
		t.Fatal("no synthesis for names next to nope.example.com")
	}
	m := v.Synthesize(gap, dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Fatal(m)
	}
	if r := v.Validate(context.Background(), w.fetch, gap, dns.TypeA, m); r.State != Secure {
		t.Fatalf("synthesised answer does not validate: %v %s %s", r.State, r.Reason, r.Detail)
	}
	if v.Synthesize("www.example.com.", dns.TypeA) != nil {
		t.Fatal("existing name synthesised as NXDOMAIN")
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func TestRFC5011(t *testing.T) {
	ck := &clock{t: time.Now()}
	root := testutil.NewZone(".", false)
	path := filepath.Join(t.TempDir(), "trust-anchors.json")
	ta := OpenAnchorsWith(path, []*dns.DS{root.DS()}, ck.now)
	// a new KSK is published, signed by the current one
	newKSK, _ := genKSK()
	root.AddRR(newKSK)
	keys := root.Answer(dns.Question{Name: ".", Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}, true)
	var set []*dns.DNSKEY
	for _, rr := range keys.Answer {
		if k, ok := rr.(*dns.DNSKEY); ok {
			set = append(set, k)
		}
	}
	never := func(*dns.DNSKEY) bool { return false }
	if ch, err := ta.Observe(set, never); err != nil || !ch {
		t.Fatal(ch, err)
	}
	state := func(tag uint16) string {
		for _, a := range ta.Views() {
			if a.KeyTag == tag {
				return a.State
			}
		}
		return ""
	}
	if s := state(newKSK.KeyTag()); s != TAPending {
		t.Fatalf("new key: %q", s)
	}
	ck.add(HoldDown + time.Hour)
	_, _ = ta.Observe(set, never)
	if s := state(newKSK.KeyTag()); s != TAValid {
		t.Fatalf("after hold-down: %q", s)
	}
	// the file survives a restart (0600)
	ta2 := OpenAnchorsWith(path, []*dns.DS{root.DS()}, ck.now)
	if len(ta2.Views()) != 2 {
		t.Fatalf("reloaded %v", ta2.Views())
	}
	// the old key disappears: missing, still trusted
	_, _ = ta.Observe([]*dns.DNSKEY{newKSK}, never)
	if s := state(root.KSK.KeyTag()); s != TAMissing {
		t.Fatalf("old key: %q", s)
	}
	// revoked (self-signed) key
	rev := *newKSK
	rev.Flags |= dns.REVOKE
	_, _ = ta.Observe([]*dns.DNSKEY{&rev}, func(*dns.DNSKEY) bool { return true })
	if s := state(newKSK.KeyTag()); s != TARevoked {
		t.Fatalf("revoked: %q", s)
	}
	if len(ta.Trusted([]*dns.DNSKEY{newKSK})) != 0 {
		t.Fatal("revoked key still trusted")
	}
}

func genKSK() (*dns.DNSKEY, error) {
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	_, err := k.Generate(256)
	return k, err
}

func TestCanonicalOrder(t *testing.T) {
	ordered := []string{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.",
		"z.example.", "\\001.z.example.", "*.z.example.", "\\200.z.example."}
	for i := 0; i+1 < len(ordered); i++ {
		if canonicalCompare(ordered[i], ordered[i+1]) >= 0 {
			t.Errorf("%s !< %s", ordered[i], ordered[i+1])
		}
	}
}
