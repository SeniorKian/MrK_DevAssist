// Package dnssec is the validating part of the resolver (docs/40 §2.2):
// chain of trust from the root trust anchors (DS -> DNSKEY -> RRSIG),
// authenticated denial with NSEC and NSEC3 (NXDOMAIN, NODATA, wildcards,
// opt-out, insecure delegations), negative trust anchors, RFC 5011 trust
// anchor maintenance and aggressive use of NSEC (RFC 8198).
//
// The validator is transport-agnostic: a Fetcher retrieves DS and DNSKEY
// RRsets through the same path as the answer (forwarders with DO+CD, or the
// iterative resolver).
package dnssec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/resolver"
	"mrk/dns-engine/internal/trace"
)

// State is the security status of a response (RFC 4035 §4.3).
type State uint8

// States.
const (
	None State = iota // not validated (validation off, local data, errors)
	Secure
	Insecure
	Bogus
	Indeterminate
	stateCount
)

func (s State) String() string {
	switch s {
	case Secure:
		return "secure"
	case Insecure:
		return "insecure"
	case Bogus:
		return "bogus"
	case Indeterminate:
		return "indeterminate"
	}
	return ""
}

// Reason codes (short, machine readable; the panel maps them to text).
const (
	ReasonNTA             = "negative_trust_anchor"
	ReasonLocal           = "local_zone"
	ReasonUnsigned        = "unsigned_zone"
	ReasonRRSIGsMissing   = "rrsigs_missing"
	ReasonSigExpired      = "signature_expired"
	ReasonSigNotYet       = "signature_not_yet_valid"
	ReasonSigInvalid      = "signature_invalid"
	ReasonDNSKEYMissing   = "dnskey_missing"
	ReasonDSMismatch      = "ds_mismatch"
	ReasonNoProof         = "denial_proof_failed"
	ReasonUnsupportedAlg  = "unsupported_algorithm"
	ReasonUnsupportedDig  = "unsupported_digest"
	ReasonNSEC3Iterations = "nsec3_iterations"
	ReasonOptOut          = "nsec3_opt_out"
	ReasonUnreachable     = "no_reachable_authority"
	ReasonTrustAnchor     = "trust_anchor_unavailable"
	ReasonSignerMismatch  = "signer_mismatch"
	ReasonBudget          = "validation_budget"
)

// NoEDE marks a result without an extended error.
const NoEDE = -1

// Result of a validation.
type Result struct {
	State  State
	EDE    int // RFC 8914 info code, NoEDE for none
	Reason string
	Detail string
	// MaxTTL bounds the cache TTL by the signature expirations (0 = none).
	MaxTTL uint32
}

func secure() Result { return Result{State: Secure, EDE: NoEDE} }

func insecure(reason, detail string) Result {
	return Result{State: Insecure, EDE: NoEDE, Reason: reason, Detail: detail}
}

func bogus(ede int, reason, detail string) Result {
	return Result{State: Bogus, EDE: ede, Reason: reason, Detail: detail}
}

// rank orders states for combining: bogus > indeterminate > insecure > secure.
func rank(s State) int {
	switch s {
	case Bogus:
		return 4
	case Indeterminate:
		return 3
	case Insecure:
		return 2
	case Secure:
		return 1
	}
	return 0
}

func worst(a, b Result) Result {
	if rank(b.State) > rank(a.State) {
		if b.MaxTTL == 0 || a.MaxTTL != 0 && a.MaxTTL < b.MaxTTL {
			b.MaxTTL = a.MaxTTL
		}
		return b
	}
	if b.MaxTTL != 0 && (a.MaxTTL == 0 || b.MaxTTL < a.MaxTTL) {
		a.MaxTTL = b.MaxTTL
	}
	return a
}

// Fetcher retrieves name/qtype with DNSSEC records (DO=1, and CD=1 through
// forwarders).
type Fetcher func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)

// NTA is a compiled negative trust anchor.
type NTA struct {
	Domain  string // lower-case FQDN
	Expires time.Time
}

// Config is hot-swappable.
type Config struct {
	NSEC3MaxIter int
	Skew         time.Duration
	BogusTTL     time.Duration
	MaxTTL       time.Duration
	Aggressive   bool
	NTAs         []NTA
}

// Algorithms and digests this validator implements (RFC 8624 MUST/RECOMMENDED;
// ED448 is not offered by the DNS library and counts as unsupported).
func algSupported(a uint8) bool {
	switch a {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512, dns.ECDSAP256SHA256,
		dns.ECDSAP384SHA384, dns.ED25519:
		return true
	}
	return false
}

func digestSupported(d uint8) bool { return d == dns.SHA1 || d == dns.SHA256 || d == dns.SHA384 }

// entry kinds of the zone cache.
const (
	kSecure = iota
	kNotCut
	kInsecure
	kBogus
	kIndeterminate
	kNonexistent
)

type zoneEntry struct {
	kind   int
	zone   string
	keys   []*dns.DNSKEY
	res    Result
	expire time.Time
}

const maxZoneEntries = 20000

// maxFetches bounds DS/DNSKEY lookups of one validation.
const maxFetches = 48

// Validator is safe for concurrent use.
type Validator struct {
	cfg atomic.Pointer[Config]
	TA  *Anchors
	now func() time.Time

	mu     sync.Mutex
	zones  map[string]*zoneEntry
	order  []string
	flight resolver.Flight
	nsec   *nsecCache

	counts [stateCount]atomic.Uint64
}

// New returns a validator using ta (nil = built-in anchors only).
func New(ta *Anchors, now func() time.Time) *Validator {
	if now == nil {
		now = time.Now
	}
	if ta == nil {
		ta = OpenAnchors("", now)
	}
	v := &Validator{TA: ta, now: now, zones: map[string]*zoneEntry{}, nsec: newNSECCache()}
	v.cfg.Store(&Config{NSEC3MaxIter: 150, Skew: time.Hour, BogusTTL: time.Minute, MaxTTL: 24 * time.Hour, Aggressive: true})
	return v
}

// Configure swaps the configuration.
func (v *Validator) Configure(c Config) { v.cfg.Store(&c) }

// Flush drops cached zone keys and NSEC ranges (trust anchor or NTA change).
func (v *Validator) Flush() {
	v.mu.Lock()
	v.zones = map[string]*zoneEntry{}
	v.order = nil
	v.mu.Unlock()
	v.nsec.flush()
}

// Counters returns validation counts by state.
func (v *Validator) Counters() (sec, insec, bog, indet uint64) {
	return v.counts[Secure].Load(), v.counts[Insecure].Load(), v.counts[Bogus].Load(), v.counts[Indeterminate].Load()
}

// Count records a result (the engine counts the results it uses).
func (v *Validator) Count(s State) {
	if s < stateCount {
		v.counts[s].Add(1)
	}
}

// NTAFor reports whether name is under an active negative trust anchor.
func (v *Validator) NTAFor(name string) bool {
	c := v.cfg.Load()
	if len(c.NTAs) == 0 {
		return false
	}
	now := v.now()
	name = lower(name)
	for _, n := range c.NTAs {
		if (n.Expires.IsZero() || now.Before(n.Expires)) && dns.IsSubDomain(n.Domain, name) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- cache

func (v *Validator) cached(name string, st *vstate) *zoneEntry {
	if st.noCache {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	e := v.zones[name]
	if e == nil {
		return nil
	}
	if v.now().After(e.expire) {
		delete(v.zones, name)
		return nil
	}
	return e
}

func (v *Validator) put(name string, e *zoneEntry, ttl time.Duration) *zoneEntry {
	cfg := v.cfg.Load()
	if cfg.MaxTTL > 0 && ttl > cfg.MaxTTL {
		ttl = cfg.MaxTTL
	}
	if ttl <= 0 {
		return e
	}
	e.expire = v.now().Add(ttl)
	v.mu.Lock()
	if _, ok := v.zones[name]; !ok {
		v.order = append(v.order, name)
	}
	v.zones[name] = e
	for len(v.zones) > maxZoneEntries && len(v.order) > 0 {
		delete(v.zones, v.order[0])
		v.order = v.order[1:]
	}
	if len(v.order) > 2*maxZoneEntries {
		live := v.order[:0]
		for _, n := range v.order {
			if _, ok := v.zones[n]; ok {
				live = append(live, n)
			}
		}
		v.order = live
	}
	v.mu.Unlock()
	return e
}

func (v *Validator) bogusTTL() time.Duration { return v.cfg.Load().BogusTTL }

// ---------------------------------------------------------------- per validation state

type vstate struct {
	fetches int
	tr      *trace.Trace
	noCache bool
}

var errBudget = errors.New("dnssec: validation budget exhausted")

func (st *vstate) fetch(ctx context.Context, f Fetcher, name string, qtype uint16) (*dns.Msg, error) {
	if st.fetches >= maxFetches {
		return nil, errBudget
	}
	st.fetches++
	return f(ctx, name, qtype)
}

func (st *vstate) step(zone string, qtype uint16, r Result) {
	if st.tr == nil {
		return
	}
	s := trace.Step{Zone: strings.TrimSuffix(zone, "."), QName: zone, QType: dns.TypeToString[qtype], DNSSEC: r.State.String(),
		Server: "validator"}
	if r.Reason != "" {
		s.Error = r.Reason
		if r.Detail != "" {
			s.Error += ": " + r.Detail
		}
	}
	if s.Zone == "" {
		s.Zone = "."
	}
	st.tr.Add(s)
}

// ---------------------------------------------------------------- rrsets

type rrset struct {
	name string
	t    uint16
	rrs  []dns.RR
	sigs []*dns.RRSIG
}

func group(rrs []dns.RR) []*rrset {
	var out []*rrset
	idx := map[string]*rrset{}
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG || h.Rrtype == dns.TypeOPT {
			continue
		}
		k := lower(h.Name) + "\x00" + fmt.Sprint(h.Rrtype)
		s := idx[k]
		if s == nil {
			s = &rrset{name: lower(h.Name), t: h.Rrtype}
			idx[k] = s
			out = append(out, s)
		}
		s.rrs = append(s.rrs, rr)
	}
	for _, rr := range rrs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if s := idx[lower(sig.Hdr.Name)+"\x00"+fmt.Sprint(sig.TypeCovered)]; s != nil {
			s.sigs = append(s.sigs, sig)
		}
	}
	return out
}

const year68 = 1 << 31

// validity reports 0 when sig is valid at now (with skew), 7 when expired
// and 8 when not yet valid (RFC 8914 codes), using RFC 1982 arithmetic.
func validity(sig *dns.RRSIG, now time.Time, skew time.Duration) int {
	utc := now.UTC().Unix()
	modi := (int64(sig.Inception) - utc) / year68
	mode := (int64(sig.Expiration) - utc) / year68
	ti := int64(sig.Inception) + modi*year68
	te := int64(sig.Expiration) + mode*year68
	s := int64(skew / time.Second)
	if utc+s < ti {
		return int(dns.ExtendedErrorCodeSignatureNotYetValid)
	}
	if utc-s > te {
		return int(dns.ExtendedErrorCodeSignatureExpired)
	}
	return 0
}

func expiresIn(sig *dns.RRSIG, now time.Time) uint32 {
	utc := now.UTC().Unix()
	mode := (int64(sig.Expiration) - utc) / year68
	te := int64(sig.Expiration) + mode*year68
	if te <= utc {
		return 1
	}
	if te-utc > 1<<31-1 {
		return 1<<31 - 1
	}
	return uint32(te - utc)
}

// verify checks rrset against sigs with keys (signer already checked).
func (v *Validator) verify(s *rrset, keys []*dns.DNSKEY) (Result, *dns.RRSIG) {
	cfg := v.cfg.Load()
	now := v.now()
	what := strings.TrimSuffix(s.name, ".") + " " + dns.TypeToString[s.t]
	if s.name == "." {
		what = ". " + dns.TypeToString[s.t]
	}
	if len(s.sigs) == 0 {
		return bogus(int(dns.ExtendedErrorCodeRRSIGsMissing), ReasonRRSIGsMissing, what), nil
	}
	res := Result{}
	tried := false
	for _, sig := range s.sigs {
		if !algSupported(sig.Algorithm) {
			continue
		}
		if c := validity(sig, now, cfg.Skew); c != 0 {
			reason := ReasonSigExpired
			if c == int(dns.ExtendedErrorCodeSignatureNotYetValid) {
				reason = ReasonSigNotYet
			}
			if !tried {
				res = bogus(c, reason, what)
			}
			continue
		}
		for _, k := range keys {
			if k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm || k.Flags&dns.REVOKE != 0 {
				continue
			}
			tried = true
			if err := sig.Verify(k, s.rrs); err == nil {
				r := secure()
				r.MaxTTL = expiresIn(sig, now)
				return r, sig
			}
			res = bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonSigInvalid, what)
		}
		if !tried && res.State == None {
			res = bogus(int(dns.ExtendedErrorCodeDNSKEYMissing), ReasonDNSKEYMissing, what)
		}
	}
	if res.State == None {
		res = bogus(int(dns.ExtendedErrorCodeRRSIGsMissing), ReasonRRSIGsMissing, what+" (no supported signature algorithm)")
	}
	return res, nil
}

// ---------------------------------------------------------------- chain of trust

func ttlOf(rrs []dns.RR) time.Duration {
	m := ^uint32(0)
	for _, rr := range rrs {
		if rr.Header().Ttl < m {
			m = rr.Header().Ttl
		}
	}
	if m == ^uint32(0) {
		return 0
	}
	return time.Duration(m) * time.Second
}

func keysOf(rrs []dns.RR) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok && k.Protocol == 3 && k.Flags&dns.ZONE != 0 {
			out = append(out, k)
		}
	}
	return out
}

func findSet(sets []*rrset, name string, t uint16) *rrset {
	for _, s := range sets {
		if s.name == lower(name) && s.t == t {
			return s
		}
	}
	return nil
}

func minDur(a time.Duration, b uint32) time.Duration {
	if b > 0 && time.Duration(b)*time.Second < a {
		return time.Duration(b) * time.Second
	}
	return a
}

// rootEntry validates the root DNSKEY set against the trust anchors.
func (v *Validator) rootEntry(ctx context.Context, f Fetcher, st *vstate) *zoneEntry {
	if e := v.cached(".", st); e != nil {
		return e
	}
	val, _, _ := v.flight.Do("key:.", func() (any, error) {
		msg, err := st.fetch(ctx, f, ".", dns.TypeDNSKEY)
		if err != nil {
			r := Result{State: Indeterminate, EDE: NoEDE, Reason: ReasonTrustAnchor, Detail: err.Error()}
			e := &zoneEntry{kind: kIndeterminate, zone: ".", res: r}
			return v.put(".", e, 5*time.Second), nil
		}
		set := findSet(group(msg.Answer), ".", dns.TypeDNSKEY)
		if set == nil || len(set.sigs) == 0 {
			// the path does not carry DNSSEC (e.g. a forwarder stripping it):
			// the trust anchor cannot be applied
			r := Result{State: Indeterminate, EDE: NoEDE, Reason: ReasonTrustAnchor, Detail: "root DNSKEY not available with signatures"}
			e := &zoneEntry{kind: kIndeterminate, zone: ".", res: r}
			return v.put(".", e, 30*time.Second), nil
		}
		all := keysOf(set.rrs)
		tk := v.TA.Trusted(all)
		if len(tk) == 0 {
			r := bogus(int(dns.ExtendedErrorCodeDNSKEYMissing), ReasonDNSKEYMissing, "no root DNSKEY matches a trust anchor")
			return v.put(".", &zoneEntry{kind: kBogus, zone: ".", res: r}, v.bogusTTL()), nil
		}
		r, _ := v.verify(set, tk)
		if r.State != Secure {
			return v.put(".", &zoneEntry{kind: kBogus, zone: ".", res: r}, v.bogusTTL()), nil
		}
		e := &zoneEntry{kind: kSecure, zone: ".", keys: all, res: r}
		return v.put(".", e, minDur(ttlOf(set.rrs), r.MaxTTL)), nil
	})
	return val.(*zoneEntry)
}

// RootKeySet fetches and validates the root DNSKEY set (for RFC 5011).
func (v *Validator) RootKeySet(ctx context.Context, f Fetcher) ([]*dns.DNSKEY, func(*dns.DNSKEY) bool, error) {
	st := &vstate{noCache: true}
	msg, err := st.fetch(ctx, f, ".", dns.TypeDNSKEY)
	if err != nil {
		return nil, nil, err
	}
	set := findSet(group(msg.Answer), ".", dns.TypeDNSKEY)
	if set == nil {
		return nil, nil, errors.New("no root DNSKEY set")
	}
	all := keysOf(set.rrs)
	tk := v.TA.Trusted(all)
	if len(tk) == 0 {
		return nil, nil, errors.New("no root DNSKEY matches a trusted anchor")
	}
	if r, _ := v.verify(set, tk); r.State != Secure {
		return nil, nil, fmt.Errorf("root DNSKEY set does not validate: %s %s", r.Reason, r.Detail)
	}
	self := func(k *dns.DNSKEY) bool {
		for _, sig := range set.sigs {
			if sig.KeyTag == k.KeyTag() && sig.Algorithm == k.Algorithm && sig.Verify(k, set.rrs) == nil {
				return true
			}
		}
		return false
	}
	return all, self, nil
}

// chain returns the security context of target: the deepest secure zone
// enclosing it, or the insecure/bogus/indeterminate result found on the way.
func (v *Validator) chain(ctx context.Context, f Fetcher, st *vstate, target string) *zoneEntry {
	target = lower(target)
	if v.NTAFor(target) {
		return &zoneEntry{kind: kInsecure, res: insecure(ReasonNTA, target)}
	}
	cur := v.rootEntry(ctx, f, st)
	if cur.kind != kSecure {
		return cur
	}
	idx := dns.Split(target)
	for i := len(idx) - 1; i >= 0; i-- {
		a := target[idx[i]:]
		if v.NTAFor(a) {
			return &zoneEntry{kind: kInsecure, res: insecure(ReasonNTA, a)}
		}
		ch := v.child(ctx, f, st, cur, a)
		switch ch.kind {
		case kNotCut:
		case kSecure:
			cur = ch
		case kNonexistent:
			return cur
		default:
			return ch
		}
	}
	return cur
}

// child establishes whether a (directly below secure zone p's subtree) is a
// signed zone cut, an insecure delegation, not a cut, or does not exist.
func (v *Validator) child(ctx context.Context, f Fetcher, st *vstate, p *zoneEntry, a string) *zoneEntry {
	if e := v.cached(a, st); e != nil {
		return e
	}
	val, _, _ := v.flight.Do("key:"+a, func() (any, error) {
		e, ttl := v.childUncached(ctx, f, st, p, a)
		st.step(a, dns.TypeDS, e.res)
		return v.put(a, e, ttl), nil
	})
	return val.(*zoneEntry)
}

func (v *Validator) childUncached(ctx context.Context, f Fetcher, st *vstate, p *zoneEntry, a string) (*zoneEntry, time.Duration) {
	cfg := v.cfg.Load()
	short := 5 * time.Second
	what := strings.TrimSuffix(a, ".")
	msg, err := st.fetch(ctx, f, a, dns.TypeDS)
	if err != nil {
		reason := ReasonUnreachable
		if errors.Is(err, errBudget) {
			reason = ReasonBudget
		}
		return &zoneEntry{kind: kBogus, res: bogus(int(dns.ExtendedErrorCodeNoReachableAuthority), reason, what+" DS: "+err.Error())}, short
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return &zoneEntry{kind: kBogus, res: bogus(int(dns.ExtendedErrorCodeNoReachableAuthority), ReasonUnreachable,
			what+" DS: "+dns.RcodeToString[msg.Rcode])}, short
	}
	ans := group(msg.Answer)
	if ds := findSet(ans, a, dns.TypeDS); ds != nil {
		r, _ := v.verifySigned(ds, p)
		if r.State != Secure {
			return &zoneEntry{kind: kBogus, res: r}, v.bogusTTL()
		}
		var usable []*dns.DS
		anyAlg, anyDig := false, false
		for _, rr := range ds.rrs {
			d := rr.(*dns.DS)
			if algSupported(d.Algorithm) {
				anyAlg = true
			}
			if digestSupported(d.DigestType) {
				anyDig = true
			}
			if algSupported(d.Algorithm) && digestSupported(d.DigestType) {
				usable = append(usable, d)
			}
		}
		ttl := minDur(ttlOf(ds.rrs), r.MaxTTL)
		if len(usable) == 0 {
			res := insecure(ReasonUnsupportedDig, what)
			res.EDE = int(dns.ExtendedErrorCodeUnsupportedDSDigestType)
			if !anyAlg {
				res.Reason, res.EDE = ReasonUnsupportedAlg, int(dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm)
			}
			_ = anyDig
			return &zoneEntry{kind: kInsecure, res: res}, ttl
		}
		km, err := st.fetch(ctx, f, a, dns.TypeDNSKEY)
		if err != nil {
			return &zoneEntry{kind: kBogus, res: bogus(int(dns.ExtendedErrorCodeDNSKEYMissing), ReasonDNSKEYMissing, what+": "+err.Error())}, short
		}
		ks := findSet(group(km.Answer), a, dns.TypeDNSKEY)
		if ks == nil {
			return &zoneEntry{kind: kBogus, res: bogus(int(dns.ExtendedErrorCodeDNSKEYMissing), ReasonDNSKEYMissing, what)}, v.bogusTTL()
		}
		all := keysOf(ks.rrs)
		var sep []*dns.DNSKEY
		for _, k := range all {
			for _, d := range usable {
				if k.KeyTag() == d.KeyTag && k.Algorithm == d.Algorithm && k.Flags&dns.REVOKE == 0 {
					if kd := k.ToDS(d.DigestType); kd != nil && strings.EqualFold(kd.Digest, d.Digest) {
						sep = append(sep, k)
						break
					}
				}
			}
		}
		if len(sep) == 0 {
			res := bogus(int(dns.ExtendedErrorCodeDNSKEYMissing), ReasonDSMismatch, what+": no DNSKEY matches the DS")
			return &zoneEntry{kind: kBogus, res: res}, v.bogusTTL()
		}
		kr, _ := v.verify(ks, sep)
		if kr.State != Secure {
			return &zoneEntry{kind: kBogus, res: kr}, v.bogusTTL()
		}
		st.step(a, dns.TypeDNSKEY, kr)
		return &zoneEntry{kind: kSecure, zone: a, keys: all, res: kr}, minDur(minDur(ttl, kr.MaxTTL), uint32(ttlOf(ks.rrs)/time.Second))
	}
	// a CNAME owner is not a zone cut
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeCNAME && lower(rr.Header().Name) == a {
			return &zoneEntry{kind: kNotCut, res: secure()}, ttlOf(msg.Answer)
		}
	}
	// negative: authenticated denial signed by the parent side
	auth := group(msg.Ns)
	nsecs, n3, r, signer := v.verifyDenial(auth, p)
	if r.State != Secure {
		if signer != "" && signer == a {
			r = bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonSignerMismatch, what+" DS answered by the child zone")
		}
		return &zoneEntry{kind: kBogus, res: r}, v.bogusTTL()
	}
	ttl := ttlOf(msg.Ns)
	if s := soaMin(msg.Ns); s > 0 && s < ttl {
		ttl = s
	}
	ttl = minDur(ttl, r.MaxTTL)
	if len(nsecs) > 0 {
		if m := nsecMatch(nsecs, a); m != nil {
			switch {
			case hasType(m.TypeBitMap, dns.TypeDS):
				return &zoneEntry{kind: kBogus, res: bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonNoProof, what+" DS denied but present")}, v.bogusTTL()
			case hasType(m.TypeBitMap, dns.TypeNS) && !hasType(m.TypeBitMap, dns.TypeSOA):
				return &zoneEntry{kind: kInsecure, res: insecure(ReasonUnsigned, what)}, ttl
			}
			return &zoneEntry{kind: kNotCut, res: secure()}, ttl
		}
		if cov := nsecCovering(nsecs, a); cov != nil {
			if msg.Rcode == dns.RcodeNameError {
				return &zoneEntry{kind: kNonexistent, res: secure()}, ttl
			}
			return &zoneEntry{kind: kNotCut, res: secure()}, ttl // empty non-terminal
		}
		return &zoneEntry{kind: kBogus, res: bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonNoProof, what+" DS")}, v.bogusTTL()
	}
	if len(n3) > 0 {
		if !nsec3Usable(n3, cfg.NSEC3MaxIter) {
			return &zoneEntry{kind: kInsecure, res: insecure(ReasonNSEC3Iterations, what)}, ttl
		}
		if m := nsec3Match(n3, a); m != nil {
			switch {
			case hasType(m.TypeBitMap, dns.TypeDS):
				return &zoneEntry{kind: kBogus, res: bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonNoProof, what+" DS denied but present")}, v.bogusTTL()
			case hasType(m.TypeBitMap, dns.TypeNS) && !hasType(m.TypeBitMap, dns.TypeSOA):
				return &zoneEntry{kind: kInsecure, res: insecure(ReasonUnsigned, what)}, ttl
			}
			return &zoneEntry{kind: kNotCut, res: secure()}, ttl
		}
		if _, cov, ok := closestEncloser(n3, a); ok {
			if optOut(cov) {
				return &zoneEntry{kind: kInsecure, res: insecure(ReasonOptOut, what)}, ttl
			}
			if msg.Rcode == dns.RcodeNameError {
				return &zoneEntry{kind: kNonexistent, res: secure()}, ttl
			}
		}
		return &zoneEntry{kind: kBogus, res: bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonNoProof, what+" DS")}, v.bogusTTL()
	}
	return &zoneEntry{kind: kBogus, res: bogus(int(dns.ExtendedErrorCodeRRSIGsMissing), ReasonRRSIGsMissing, what+" DS denial")}, v.bogusTTL()
}

func soaMin(rrs []dns.RR) time.Duration {
	for _, rr := range rrs {
		if s, ok := rr.(*dns.SOA); ok {
			m := s.Minttl
			if s.Hdr.Ttl < m {
				m = s.Hdr.Ttl
			}
			return time.Duration(m) * time.Second
		}
	}
	return 0
}

// verifySigned validates s with the keys of secure zone p (signer must be p).
func (v *Validator) verifySigned(s *rrset, p *zoneEntry) (Result, *dns.RRSIG) {
	var sigs []*dns.RRSIG
	for _, sig := range s.sigs {
		if lower(sig.SignerName) == p.zone {
			sigs = append(sigs, sig)
		}
	}
	if len(sigs) == 0 && len(s.sigs) > 0 {
		return bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonSignerMismatch, strings.TrimSuffix(s.name, ".")+" "+
			dns.TypeToString[s.t]+" not signed by "+p.zone), nil
	}
	cp := *s
	cp.sigs = sigs
	return v.verify(&cp, p.keys)
}

// verifyDenial validates the SOA/NSEC/NSEC3 RRsets of an authority section
// with the keys of p and returns the denial records.
func (v *Validator) verifyDenial(auth []*rrset, p *zoneEntry) ([]*dns.NSEC, []*dns.NSEC3, Result, string) {
	res := secure()
	var nsecs []*dns.NSEC
	var n3 []*dns.NSEC3
	signer := ""
	for _, s := range auth {
		if s.t != dns.TypeNSEC && s.t != dns.TypeNSEC3 && s.t != dns.TypeSOA {
			continue
		}
		if len(s.sigs) > 0 {
			signer = lower(s.sigs[0].SignerName)
		}
		r, _ := v.verifySigned(s, p)
		if r.State != Secure {
			return nil, nil, r, signer
		}
		res = worst(res, r)
		for _, rr := range s.rrs {
			switch x := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, x)
			case *dns.NSEC3:
				n3 = append(n3, x)
			}
		}
	}
	if len(nsecs) == 0 && len(n3) == 0 {
		return nil, nil, bogus(int(dns.ExtendedErrorCodeRRSIGsMissing), ReasonRRSIGsMissing, "no signed NSEC/NSEC3 records"), signer
	}
	return nsecs, n3, res, signer
}

// ---------------------------------------------------------------- answers

// Validate determines the security status of msg, the response to
// qname/qtype.
func (v *Validator) Validate(ctx context.Context, f Fetcher, qname string, qtype uint16, msg *dns.Msg) Result {
	qname = lower(qname)
	if msg == nil || msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return Result{State: None, EDE: NoEDE}
	}
	if v.NTAFor(qname) {
		return insecure(ReasonNTA, strings.TrimSuffix(qname, "."))
	}
	st := &vstate{tr: trace.From(ctx), noCache: trace.NoCache(ctx)}
	res := secure()
	sets := group(msg.Answer)
	for _, s := range sets {
		if s.t == dns.TypeCNAME && len(s.sigs) == 0 && synthesized(s, sets) {
			continue // RFC 6672: the CNAME synthesised from a signed DNAME is unsigned
		}
		res = worst(res, v.validateSet(ctx, f, st, s, msg))
		if res.State == Bogus {
			return res
		}
	}
	end, final := chainEnd(sets, qname, qtype)
	if msg.Rcode == dns.RcodeNameError || !final {
		res = worst(res, v.validateNegative(ctx, f, st, end, qtype, msg))
	}
	if res.State == Secure && msg.Rcode == dns.RcodeNameError && v.cfg.Load().Aggressive {
		v.nsec.learn(msg, v.now())
	}
	return res
}

func synthesized(cn *rrset, sets []*rrset) bool {
	for _, s := range sets {
		if s.t != dns.TypeDNAME {
			continue
		}
		d := s.rrs[0].(*dns.DNAME)
		if dns.IsSubDomain(s.name, cn.name) && cn.name != s.name {
			want := strings.TrimSuffix(cn.name, s.name) + lower(d.Target)
			if lower(cn.rrs[0].(*dns.CNAME).Target) == lower(want) {
				return true
			}
		}
	}
	return false
}

// chainEnd follows the CNAME chain from qname; final reports whether data of
// qtype exists at its end.
func chainEnd(sets []*rrset, qname string, qtype uint16) (string, bool) {
	cur := qname
	for i := 0; i < 16; i++ {
		if qtype == dns.TypeCNAME {
			return cur, findSet(sets, cur, dns.TypeCNAME) != nil
		}
		if findSet(sets, cur, qtype) != nil {
			return cur, true
		}
		if qtype == dns.TypeANY {
			for _, s := range sets {
				if s.name == cur {
					return cur, true
				}
			}
		}
		cn := findSet(sets, cur, dns.TypeCNAME)
		if cn == nil {
			return cur, false
		}
		cur = lower(cn.rrs[0].(*dns.CNAME).Target)
	}
	return cur, true
}

func (v *Validator) validateSet(ctx context.Context, f Fetcher, st *vstate, s *rrset, msg *dns.Msg) Result {
	what := strings.TrimSuffix(s.name, ".") + " " + dns.TypeToString[s.t]
	if len(s.sigs) == 0 {
		ze := v.chain(ctx, f, st, s.name)
		switch ze.kind {
		case kSecure:
			return bogus(int(dns.ExtendedErrorCodeRRSIGsMissing), ReasonRRSIGsMissing, what)
		case kNotCut, kNonexistent:
			return bogus(int(dns.ExtendedErrorCodeRRSIGsMissing), ReasonRRSIGsMissing, what)
		}
		return ze.res
	}
	signer := ""
	for _, sig := range s.sigs {
		if sn := lower(sig.SignerName); dns.IsSubDomain(sn, s.name) {
			signer = sn
			break
		}
	}
	if signer == "" {
		return bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonSignerMismatch, what)
	}
	ze := v.chain(ctx, f, st, signer)
	if ze.kind != kSecure {
		return ze.res
	}
	if ze.zone != signer {
		return bogus(int(dns.ExtendedErrorCodeDNSKEYMissing), ReasonSignerMismatch, what+" signed by "+signer+", which is not a secure zone")
	}
	r, sig := v.verifySigned(s, ze)
	if r.State != Secure {
		return r
	}
	labels := dns.CountLabel(s.name)
	if strings.HasPrefix(s.name, "*.") {
		labels--
	}
	if int(sig.Labels) < labels {
		// wildcard expansion: the next closer name must be proven absent
		var nsecs []*dns.NSEC
		var n3 []*dns.NSEC3
		auth := group(msg.Ns)
		dn, dn3, dr, _ := v.verifyDenial(auth, ze)
		if dr.State != Secure {
			return bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonNoProof, what+" wildcard expansion without proof")
		}
		nsecs, n3 = dn, dn3
		switch wildcardProof(nsecs, n3, s.name, sig.Labels, v.cfg.Load().NSEC3MaxIter) {
		case proofFail:
			return bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonNoProof, what+" wildcard expansion without proof")
		case proofInsecure:
			return insecure(ReasonNSEC3Iterations, what)
		}
		r = worst(r, dr)
	}
	return r
}

func (v *Validator) validateNegative(ctx context.Context, f Fetcher, st *vstate, name string, qtype uint16, msg *dns.Msg) Result {
	what := strings.TrimSuffix(name, ".") + " " + dns.TypeToString[qtype]
	auth := group(msg.Ns)
	signer := ""
	for _, s := range auth {
		for _, sig := range s.sigs {
			if sn := lower(sig.SignerName); dns.IsSubDomain(sn, name) && (signer == "" || dns.CountLabel(sn) > dns.CountLabel(signer)) {
				signer = sn
			}
		}
	}
	if signer == "" {
		ze := v.chain(ctx, f, st, name)
		switch ze.kind {
		case kSecure, kNotCut, kNonexistent:
			return bogus(int(dns.ExtendedErrorCodeRRSIGsMissing), ReasonRRSIGsMissing, what+" (unsigned denial)")
		}
		return ze.res
	}
	ze := v.chain(ctx, f, st, signer)
	if ze.kind != kSecure {
		return ze.res
	}
	if ze.zone != signer {
		return bogus(int(dns.ExtendedErrorCodeDNSKEYMissing), ReasonSignerMismatch, what+" denial signed by "+signer)
	}
	nsecs, n3, r, _ := v.verifyDenial(auth, ze)
	if r.State != Secure {
		return r
	}
	maxIter := v.cfg.Load().NSEC3MaxIter
	var p proof
	switch {
	case msg.Rcode == dns.RcodeNameError && len(nsecs) > 0:
		p = nxNSEC(nsecs, name)
	case msg.Rcode == dns.RcodeNameError:
		p = nxNSEC3(n3, name, maxIter)
	case len(nsecs) > 0:
		p = nodataNSEC(nsecs, name, qtype)
	default:
		p = nodataNSEC3(n3, name, qtype, maxIter)
	}
	switch p {
	case proofFail:
		return bogus(int(dns.ExtendedErrorCodeDNSBogus), ReasonNoProof, what)
	case proofInsecure:
		reason := ReasonOptOut
		if !nsec3Usable(n3, maxIter) {
			reason = ReasonNSEC3Iterations
		}
		return insecure(reason, what)
	}
	return r
}
