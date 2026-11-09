package testutil

import (
	"bytes"
	"crypto"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Zone is a small authoritative zone for DNSSEC and iterative-resolution
// tests: it signs itself (Ed25519 KSK + ZSK), builds an NSEC or NSEC3 chain
// and answers like an authoritative server (referrals with DS or denial,
// NXDOMAIN/NODATA proofs, wildcard expansion with proofs).
type Zone struct {
	Origin     string
	Unsigned   bool
	NSEC3      bool
	OptOut     bool
	Iterations uint16
	Inception  uint32
	Expiration uint32
	// Tamper, when set, may modify every answer (bogus tests).
	Tamper func(q dns.Question, m *dns.Msg)

	KSK, ZSK       *dns.DNSKEY
	kskKey, zskKey crypto.Signer

	recs   []dns.RR
	sigs   map[string][]dns.RR // owner|type -> RRSIGs
	nsec   map[string]dns.RR   // owner -> NSEC
	nsec3  []*dns.NSEC3        // sorted by hash
	names  map[string]bool     // authoritative names (incl. delegation points)
	cuts   map[string]bool
	signed bool
}

// NewZone creates a zone with SOA and an NS ns1.<origin> record set.
func NewZone(origin string, unsigned bool) *Zone {
	origin = strings.ToLower(dns.Fqdn(origin))
	z := &Zone{Origin: origin, Unsigned: unsigned}
	now := time.Now()
	z.Inception = uint32(now.Add(-time.Hour).Unix())
	z.Expiration = uint32(now.Add(30 * 24 * time.Hour).Unix())
	z.Add(fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 3600 1209600 300", origin, trim(origin), trim(origin)))
	if !unsigned {
		z.KSK, z.kskKey = genKey(origin, 257)
		z.ZSK, z.zskKey = genKey(origin, 256)
	}
	return z
}

func trim(origin string) string {
	if origin == "." {
		return ""
	}
	return origin
}

func genKey(origin string, flags uint16) (*dns.DNSKEY, crypto.Signer) {
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: flags, Protocol: 3, Algorithm: dns.ED25519}
	priv, err := k.Generate(256)
	if err != nil {
		panic(err)
	}
	return k, priv.(crypto.Signer)
}

// Add adds records in presentation format (relative names are not
// supported; use FQDNs).
func (z *Zone) Add(rrs ...string) {
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(fmt.Sprintf("%q: %v", s, err))
		}
		rr.Header().Name = strings.ToLower(rr.Header().Name)
		z.recs = append(z.recs, rr)
	}
	z.signed = false
}

// AddRR adds parsed records.
func (z *Zone) AddRR(rrs ...dns.RR) { z.recs = append(z.recs, rrs...); z.signed = false }

// DS returns the DS record of the zone's KSK (SHA-256).
func (z *Zone) DS() *dns.DS {
	ds := z.KSK.ToDS(dns.SHA256)
	ds.Hdr.Ttl = 3600
	return ds
}

// Delegate adds the NS (+glue +DS when the child is signed) for child.
func (z *Zone) Delegate(child *Zone, nsName, nsAddr string) {
	nsName = strings.ToLower(dns.Fqdn(nsName))
	z.Add(fmt.Sprintf("%s 3600 IN NS %s", child.Origin, nsName))
	if nsAddr != "" && dns.IsSubDomain(z.Origin, nsName) {
		t := "A"
		if strings.Contains(nsAddr, ":") {
			t = "AAAA"
		}
		z.Add(fmt.Sprintf("%s 3600 IN %s %s", nsName, t, nsAddr))
	}
	if !child.Unsigned {
		z.AddRR(child.DS())
	}
}

func key(owner string, t uint16) string { return strings.ToLower(owner) + "|" + dns.TypeToString[t] }

func (z *Zone) rrset(owner string, t uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range z.all() {
		if strings.EqualFold(rr.Header().Name, owner) && rr.Header().Rrtype == t {
			out = append(out, rr)
		}
	}
	return out
}

func (z *Zone) all() []dns.RR {
	out := append([]dns.RR{}, z.recs...)
	if !z.Unsigned && z.KSK != nil {
		out = append(out, z.KSK, z.ZSK)
	}
	return out
}

// cutOf returns the delegation point at or above name (below origin), or "".
func (z *Zone) cutOf(name string) string {
	best := ""
	for c := range z.cuts {
		if dns.IsSubDomain(c, name) && len(c) > len(best) {
			best = c
		}
	}
	return best
}

func (z *Zone) sign(rrset []dns.RR, k *dns.DNSKEY, priv crypto.Signer) dns.RR {
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Ttl: rrset[0].Header().Ttl}, Algorithm: k.Algorithm, KeyTag: k.KeyTag(),
		SignerName: z.Origin, Inception: z.Inception, Expiration: z.Expiration}
	if err := sig.Sign(priv, rrset); err != nil {
		panic(err)
	}
	return sig
}

// Sign (re)builds signatures and the denial chain. Answer calls it lazily.
func (z *Zone) Sign() {
	z.sigs = map[string][]dns.RR{}
	z.nsec = map[string]dns.RR{}
	z.nsec3 = nil
	z.names = map[string]bool{}
	z.cuts = map[string]bool{}
	for _, rr := range z.recs {
		h := rr.Header()
		if h.Rrtype == dns.TypeNS && h.Name != z.Origin {
			z.cuts[h.Name] = true
		}
	}
	types := map[string]map[uint16]bool{}
	for _, rr := range z.all() {
		h := rr.Header()
		c := z.cutOf(h.Name)
		if c != "" && h.Name != c {
			continue // glue below a cut is not authoritative
		}
		z.names[h.Name] = true
		if types[h.Name] == nil {
			types[h.Name] = map[uint16]bool{}
		}
		types[h.Name][h.Rrtype] = true
	}
	z.signed = true
	if z.Unsigned {
		return
	}
	for name, ts := range types {
		for t := range ts {
			if z.cuts[name] && t != dns.TypeDS {
				continue // delegation NS is not signed
			}
			set := z.rrset(name, t)
			if t == dns.TypeDNSKEY {
				z.sigs[key(name, t)] = []dns.RR{z.sign(set, z.KSK, z.kskKey)}
				continue
			}
			z.sigs[key(name, t)] = []dns.RR{z.sign(set, z.ZSK, z.zskKey)}
		}
	}
	if z.NSEC3 {
		z.buildNSEC3(types)
		return
	}
	var owners []string
	for n := range z.names {
		owners = append(owners, n)
	}
	sort.Slice(owners, func(i, j int) bool { return canon(owners[i], owners[j]) < 0 })
	for i, n := range owners {
		next := owners[(i+1)%len(owners)]
		bm := []uint16{dns.TypeNSEC, dns.TypeRRSIG}
		for t := range types[n] {
			bm = append(bm, t)
		}
		if z.cuts[n] && !types[n][dns.TypeDS] {
			bm = []uint16{dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG}
		}
		sort.Slice(bm, func(i, j int) bool { return bm[i] < bm[j] })
		nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: n, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: next, TypeBitMap: bm}
		z.nsec[n] = nsec
		z.sigs[key(n, dns.TypeNSEC)] = []dns.RR{z.sign([]dns.RR{nsec}, z.ZSK, z.zskKey)}
	}
}

func (z *Zone) buildNSEC3(types map[string]map[uint16]bool) {
	all := map[string]bool{}
	for n := range z.names {
		if z.OptOut && z.cuts[n] && !types[n][dns.TypeDS] {
			continue
		}
		all[n] = true
		// empty non-terminals between n and the origin
		for p := parentName(n); p != z.Origin && dns.IsSubDomain(z.Origin, p) && p != "."; p = parentName(p) {
			all[p] = true
		}
	}
	type h struct {
		hash string
		name string
	}
	var hs []h
	for n := range all {
		hs = append(hs, h{dns.HashName(n, dns.SHA1, z.Iterations, ""), n})
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].hash < hs[j].hash })
	var flags uint8
	if z.OptOut {
		flags = 1
	}
	for i, x := range hs {
		var bm []uint16
		for t := range types[x.name] {
			bm = append(bm, t)
		}
		if len(bm) > 0 && !(z.cuts[x.name] && !types[x.name][dns.TypeDS]) {
			bm = append(bm, dns.TypeRRSIG)
		}
		sort.Slice(bm, func(i, j int) bool { return bm[i] < bm[j] })
		owner := strings.ToLower(x.hash) + "." + z.Origin
		n3 := &dns.NSEC3{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
			Hash: dns.SHA1, Flags: flags, Iterations: z.Iterations, Salt: "", SaltLength: 0,
			NextDomain: hs[(i+1)%len(hs)].hash, HashLength: 20, TypeBitMap: bm}
		z.nsec3 = append(z.nsec3, n3)
		z.sigs[key(owner, dns.TypeNSEC3)] = []dns.RR{z.sign([]dns.RR{n3}, z.ZSK, z.zskKey)}
	}
}

func parentName(n string) string {
	off, end := dns.NextLabel(n, 0)
	if end {
		return "."
	}
	return n[off:]
}

func canon(a, b string) int {
	la, lb := dns.SplitDomainName(strings.ToLower(a)), dns.SplitDomainName(strings.ToLower(b))
	for i, j := len(la)-1, len(lb)-1; i >= 0 || j >= 0; i, j = i-1, j-1 {
		if i < 0 {
			return -1
		}
		if j < 0 {
			return 1
		}
		if c := bytes.Compare([]byte(la[i]), []byte(lb[j])); c != 0 {
			return c
		}
	}
	return 0
}

func (z *Zone) withSigs(rrs []dns.RR, do bool) []dns.RR {
	if !do || z.Unsigned || len(rrs) == 0 {
		return rrs
	}
	return append(append([]dns.RR{}, rrs...), z.sigs[key(rrs[0].Header().Name, rrs[0].Header().Rrtype)]...)
}

func (z *Zone) exists(name string) bool {
	for n := range z.names {
		if dns.IsSubDomain(name, n) {
			return true // name itself or an empty non-terminal above existing data
		}
	}
	return false
}

// coverNSEC returns the NSEC covering (or matching) name.
func (z *Zone) coverNSEC(name string) dns.RR {
	var owners []string
	for n := range z.nsec {
		owners = append(owners, n)
	}
	sort.Slice(owners, func(i, j int) bool { return canon(owners[i], owners[j]) < 0 })
	prev := owners[len(owners)-1]
	for _, o := range owners {
		if canon(o, name) > 0 {
			break
		}
		prev = o
	}
	return z.nsec[prev]
}

func (z *Zone) n3For(name string, match bool) *dns.NSEC3 {
	if len(z.nsec3) == 0 {
		return nil
	}
	h := dns.HashName(name, dns.SHA1, z.Iterations, "")
	var prev *dns.NSEC3
	for _, n := range z.nsec3 {
		owner := strings.ToUpper(strings.SplitN(n.Hdr.Name, ".", 2)[0])
		if owner == h {
			if match {
				return n
			}
			return nil
		}
		if owner < h {
			prev = n
		}
	}
	if match {
		return nil
	}
	if prev == nil {
		return z.nsec3[len(z.nsec3)-1] // before the first hash: the last record wraps around
	}
	return prev
}

func (z *Zone) addN3(m *dns.Msg, n *dns.NSEC3) {
	if n == nil {
		return
	}
	for _, rr := range m.Ns {
		if rr.Header().Name == n.Hdr.Name && rr.Header().Rrtype == dns.TypeNSEC3 {
			return
		}
	}
	m.Ns = append(m.Ns, n)
	m.Ns = append(m.Ns, z.sigs[key(n.Hdr.Name, dns.TypeNSEC3)]...)
}

func (z *Zone) addNSEC(m *dns.Msg, n dns.RR) {
	if n == nil {
		return
	}
	for _, rr := range m.Ns {
		if rr.Header().Name == n.Header().Name && rr.Header().Rrtype == dns.TypeNSEC {
			return
		}
	}
	m.Ns = append(m.Ns, n)
	m.Ns = append(m.Ns, z.sigs[key(n.Header().Name, dns.TypeNSEC)]...)
}

func (z *Zone) closestEncloser(name string) string {
	for c := parentName(name); ; c = parentName(c) {
		if z.exists(c) || c == z.Origin {
			return c
		}
		if c == "." {
			return c
		}
	}
}

func childToward(ce, name string) string {
	idx := dns.Split(name)
	cl := dns.CountLabel(ce)
	return name[idx[len(idx)-cl-1]:]
}

// denyName adds the proof that name does not exist (and no wildcard).
func (z *Zone) denyName(m *dns.Msg, name string) {
	ce := z.closestEncloser(name)
	wild := "*." + trim(ce)
	if ce == "." {
		wild = "*."
	}
	if z.NSEC3 {
		z.addN3(m, z.n3For(ce, true))
		z.addN3(m, z.n3For(childToward(ce, name), false))
		z.addN3(m, z.n3For(wild, false))
		return
	}
	z.addNSEC(m, z.coverNSEC(name))
	z.addNSEC(m, z.coverNSEC(wild))
}

func (z *Zone) soa(m *dns.Msg, do bool) {
	m.Ns = append(m.Ns, z.withSigs(z.rrset(z.Origin, dns.TypeSOA), do)...)
}

// nodata adds the proof that name exists without qtype.
func (z *Zone) nodata(m *dns.Msg, name string) {
	if z.NSEC3 {
		if n := z.n3For(name, true); n != nil {
			z.addN3(m, n)
			return
		}
		// opt-out: closest encloser + covering of the next closer
		ce := z.closestEncloser(name)
		z.addN3(m, z.n3For(ce, true))
		z.addN3(m, z.n3For(childToward(ce, name), false))
		return
	}
	if n, ok := z.nsec[name]; ok {
		z.addNSEC(m, n)
		return
	}
	z.addNSEC(m, z.coverNSEC(name)) // empty non-terminal
}

// Answer answers q like an authoritative server for the zone.
func (z *Zone) Answer(q dns.Question, do bool) *dns.Msg {
	if !z.signed {
		z.Sign()
	}
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.Response = true
	name := strings.ToLower(q.Name)
	do = do && !z.Unsigned
	defer func() {
		if z.Tamper != nil {
			z.Tamper(q, m)
		}
	}()
	if !dns.IsSubDomain(z.Origin, name) {
		m.Rcode = dns.RcodeRefused
		return m
	}
	if c := z.cutOf(name); c != "" && !(q.Qtype == dns.TypeDS && name == c) {
		// referral
		m.Ns = append(m.Ns, z.rrset(c, dns.TypeNS)...)
		if do {
			if ds := z.rrset(c, dns.TypeDS); len(ds) > 0 {
				m.Ns = append(m.Ns, z.withSigs(ds, true)...)
			} else {
				z.nodata(m, c)
			}
		}
		for _, rr := range z.rrset(c, dns.TypeNS) {
			ns := strings.ToLower(rr.(*dns.NS).Ns)
			m.Extra = append(m.Extra, z.rrset(ns, dns.TypeA)...)
			m.Extra = append(m.Extra, z.rrset(ns, dns.TypeAAAA)...)
		}
		return m
	}
	m.Authoritative = true
	if z.names[name] {
		if set := z.rrset(name, q.Qtype); len(set) > 0 {
			m.Answer = z.withSigs(set, do)
			return m
		}
		if q.Qtype != dns.TypeCNAME {
			if cn := z.rrset(name, dns.TypeCNAME); len(cn) > 0 {
				m.Answer = z.withSigs(cn, do)
				target := strings.ToLower(cn[0].(*dns.CNAME).Target)
				if dns.IsSubDomain(z.Origin, target) && z.names[target] {
					m.Answer = append(m.Answer, z.withSigs(z.rrset(target, q.Qtype), do)...)
				}
				return m
			}
		}
		z.soa(m, do)
		if do {
			z.nodata(m, name)
		}
		return m
	}
	if z.exists(name) { // empty non-terminal
		z.soa(m, do)
		if do {
			z.nodata(m, name)
		}
		return m
	}
	ce := z.closestEncloser(name)
	wild := "*." + trim(ce)
	if ce == "." {
		wild = "*."
	}
	if z.names[wild] {
		if set := z.rrset(wild, q.Qtype); len(set) > 0 {
			for _, rr := range set {
				c := dns.Copy(rr)
				c.Header().Name = q.Name
				m.Answer = append(m.Answer, c)
			}
			if do {
				for _, s := range z.sigs[key(wild, q.Qtype)] {
					c := dns.Copy(s)
					c.Header().Name = q.Name
					m.Answer = append(m.Answer, c)
				}
				if z.NSEC3 {
					z.addN3(m, z.n3For(childToward(ce, name), false))
				} else {
					z.addNSEC(m, z.coverNSEC(name))
				}
			}
			return m
		}
		z.soa(m, do)
		if do {
			if z.NSEC3 {
				z.addN3(m, z.n3For(ce, true))
				z.addN3(m, z.n3For(childToward(ce, name), false))
				z.addN3(m, z.n3For(wild, true))
			} else {
				z.addNSEC(m, z.coverNSEC(name))
				z.addNSEC(m, z.nsec[wild])
			}
		}
		return m
	}
	m.Rcode = dns.RcodeNameError
	z.soa(m, do)
	if do {
		z.denyName(m, name)
	}
	return m
}

// Hierarchy routes questions to the deepest zone, except DS which goes to
// the parent side, like a validating resolver's view of the DNS.
type Hierarchy struct{ Zones []*Zone }

// Resolve answers q (DO set when do) from the right zone and follows CNAMEs
// into other zones, like a recursive resolver.
func (h *Hierarchy) Resolve(q dns.Question, do bool) *dns.Msg {
	m := h.resolveOne(q, do)
	for i := 0; i < 8 && m.Rcode == dns.RcodeSuccess && q.Qtype != dns.TypeCNAME; i++ {
		target := ""
		has := map[string]bool{}
		for _, rr := range m.Answer {
			has[strings.ToLower(rr.Header().Name)+dns.TypeToString[rr.Header().Rrtype]] = true
		}
		for _, rr := range m.Answer {
			if cn, ok := rr.(*dns.CNAME); ok && !has[strings.ToLower(cn.Target)+dns.TypeToString[q.Qtype]] &&
				!has[strings.ToLower(cn.Target)+"CNAME"] {
				target = strings.ToLower(cn.Target)
			}
		}
		if target == "" {
			break
		}
		next := h.resolveOne(dns.Question{Name: target, Qtype: q.Qtype, Qclass: dns.ClassINET}, do)
		m.Answer = append(m.Answer, next.Answer...)
		m.Ns = next.Ns
		m.Rcode = next.Rcode
	}
	return m
}

func (h *Hierarchy) resolveOne(q dns.Question, do bool) *dns.Msg {
	name := strings.ToLower(q.Name)
	var best *Zone
	for _, z := range h.Zones {
		if !dns.IsSubDomain(z.Origin, name) {
			continue
		}
		if q.Qtype == dns.TypeDS && z.Origin == name && name != "." {
			continue
		}
		if best == nil || dns.CountLabel(z.Origin) > dns.CountLabel(best.Origin) {
			best = z
		}
	}
	if best == nil {
		m := new(dns.Msg)
		m.SetQuestion(q.Name, q.Qtype)
		m.Rcode = dns.RcodeServerFailure
		return m
	}
	m := best.Answer(q, do)
	m.Authoritative = false
	m.RecursionAvailable = true
	return m
}
