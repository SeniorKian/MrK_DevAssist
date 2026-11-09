package signer

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/zone"
)

// Params are the signing parameters of one run.
type Params struct {
	NSEC3      bool
	Iterations uint16
	Salt       string // hex, "" = none
	OptOut     bool
	Validity   time.Duration
	Now        time.Time
}

// ParamsFrom converts the zone setting.
func ParamsFrom(c zone.SigningConfig, now time.Time) Params {
	return Params{NSEC3: c.Denial == "nsec3", Iterations: uint16(c.NSEC3.Iterations), Salt: strings.ToUpper(c.NSEC3.Salt),
		OptOut: c.NSEC3.OptOut, Validity: time.Duration(c.SignatureValidityDays) * 24 * time.Hour, Now: now}
}

// ValidSalt reports whether s is an acceptable NSEC3 salt (hex, <= 32 bytes).
func ValidSalt(s string) bool {
	if s == "" {
		return true
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) <= 32
}

// Result of signing a zone.
type Result struct {
	RRs []dns.RR // SOA first, then data, keys, chain and signatures
	// Expiration is the earliest RRSIG expiration.
	Expiration time.Time
}

type nameInfo struct {
	types map[uint16]bool
}

// Sign signs rrs (one SOA at the apex plus data) of origin with ks.
func Sign(origin string, rrs []dns.RR, ks *KeySet, p Params) (Result, error) {
	if len(ks.signers(RoleKSK)) == 0 || len(ks.signers(RoleZSK)) == 0 {
		return Result{}, fmt.Errorf("zone %s has no active signing keys", origin)
	}
	var soa *dns.SOA
	var data []dns.RR
	for _, rr := range rrs {
		rr = dns.Copy(rr)
		h := rr.Header()
		h.Name = strings.ToLower(h.Name)
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			soa = rr.(*dns.SOA)
			continue
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeDNSKEY, dns.TypeCDS, dns.TypeCDNSKEY:
			continue // generated below
		}
		data = append(data, rr)
	}
	if soa == nil {
		return Result{}, fmt.Errorf("zone %s has no SOA", origin)
	}
	negTTL := soa.Minttl
	if soa.Hdr.Ttl < negTTL {
		negTTL = soa.Hdr.Ttl
	}
	out := append([]dns.RR{soa}, data...)
	for _, k := range ks.DNSKEYs() {
		c := dns.Copy(k).(*dns.DNSKEY)
		c.Hdr.Ttl = KeyTTL
		out = append(out, c)
	}
	for _, k := range ks.KSKs() {
		if k.State != StateActive {
			continue
		}
		if ds := k.dnskey.ToDS(dns.SHA256); ds != nil {
			out = append(out, &dns.CDS{DS: dns.DS{Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: KeyTTL},
				KeyTag: ds.KeyTag, Algorithm: ds.Algorithm, DigestType: ds.DigestType, Digest: ds.Digest}})
		}
		cd := &dns.CDNSKEY{DNSKEY: *dns.Copy(k.dnskey).(*dns.DNSKEY)}
		cd.Hdr.Rrtype, cd.Hdr.Ttl = dns.TypeCDNSKEY, KeyTTL
		out = append(out, cd)
	}
	if p.NSEC3 {
		var flags uint8
		out = append(out, &dns.NSEC3PARAM{Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: 0},
			Hash: dns.SHA1, Flags: flags, Iterations: p.Iterations, SaltLength: uint8(len(p.Salt) / 2), Salt: saltOrDash(p.Salt)})
	}

	// delegation points and authoritative names
	cuts := map[string]bool{}
	for _, rr := range out {
		h := rr.Header()
		if h.Rrtype == dns.TypeNS && h.Name != origin {
			cuts[h.Name] = true
		}
	}
	below := func(name string) bool { // strictly below a cut (glue, occluded)
		for n := parentOf(name); n != origin && dns.IsSubDomain(origin, n); n = parentOf(n) {
			if cuts[n] {
				return true
			}
		}
		return false
	}
	names := map[string]*nameInfo{}
	sets := map[string][]dns.RR{}
	var order []string
	for _, rr := range out {
		h := rr.Header()
		if below(h.Name) {
			continue
		}
		ni := names[h.Name]
		if ni == nil {
			ni = &nameInfo{types: map[uint16]bool{}}
			names[h.Name] = ni
		}
		ni.types[h.Rrtype] = true
		k := h.Name + "|" + dns.TypeToString[h.Rrtype]
		if _, ok := sets[k]; !ok {
			order = append(order, k)
		}
		sets[k] = append(sets[k], rr)
	}
	inception := uint32(p.Now.Add(-time.Hour).Unix())
	expiration := uint32(p.Now.Add(p.Validity).Unix())
	var sigs []dns.RR
	sign := func(set []dns.RR, keys []*Key) error {
		for _, k := range keys {
			sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: set[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET,
				Ttl: set[0].Header().Ttl}, Algorithm: k.dnskey.Algorithm, KeyTag: k.dnskey.KeyTag(), SignerName: origin,
				Inception: inception, Expiration: expiration}
			if err := sig.Sign(k.signer, set); err != nil {
				return fmt.Errorf("sign %s %s: %w", set[0].Header().Name, dns.TypeToString[set[0].Header().Rrtype], err)
			}
			sigs = append(sigs, sig)
		}
		return nil
	}
	zsks, ksks := ks.signers(RoleZSK), ks.signers(RoleKSK)
	for _, k := range order {
		set := sets[k]
		h := set[0].Header()
		if cuts[h.Name] && h.Rrtype != dns.TypeDS {
			continue // delegation NS (and glue at the cut) is not signed
		}
		keys := zsks
		switch h.Rrtype {
		case dns.TypeDNSKEY, dns.TypeCDS, dns.TypeCDNSKEY:
			keys = ksks
		}
		if err := sign(set, keys); err != nil {
			return Result{}, err
		}
	}

	// denial of existence
	var chain []dns.RR
	if p.NSEC3 {
		chain = nsec3Chain(origin, names, cuts, p, negTTL)
	} else {
		chain = nsecChain(names, cuts, negTTL)
	}
	for _, rr := range chain {
		if err := sign([]dns.RR{rr}, zsks); err != nil {
			return Result{}, err
		}
	}
	out = append(out, chain...)
	out = append(out, sigs...)
	return Result{RRs: out, Expiration: time.Unix(int64(expiration), 0).UTC()}, nil
}

func saltOrDash(s string) string {
	if s == "" {
		return ""
	}
	return s
}

func parentOf(n string) string {
	off, end := dns.NextLabel(n, 0)
	if end {
		return "."
	}
	return n[off:]
}

func bitmap(ts map[uint16]bool, extra ...uint16) []uint16 {
	seen := map[uint16]bool{}
	var bm []uint16
	for t := range ts {
		if !seen[t] {
			seen[t] = true
			bm = append(bm, t)
		}
	}
	for _, t := range extra {
		if !seen[t] {
			seen[t] = true
			bm = append(bm, t)
		}
	}
	sort.Slice(bm, func(i, j int) bool { return bm[i] < bm[j] })
	return bm
}

func nsecChain(names map[string]*nameInfo, cuts map[string]bool, ttl uint32) []dns.RR {
	owners := make([]string, 0, len(names))
	for n := range names {
		owners = append(owners, n)
	}
	sort.Slice(owners, func(i, j int) bool { return zone.CanonicalCompare(owners[i], owners[j]) < 0 })
	out := make([]dns.RR, 0, len(owners))
	for i, n := range owners {
		ts := names[n].types
		var bm []uint16
		if cuts[n] && !ts[dns.TypeDS] {
			bm = bitmap(map[uint16]bool{dns.TypeNS: true}, dns.TypeNSEC, dns.TypeRRSIG)
		} else if cuts[n] {
			bm = bitmap(map[uint16]bool{dns.TypeNS: true, dns.TypeDS: true}, dns.TypeNSEC, dns.TypeRRSIG)
		} else {
			bm = bitmap(ts, dns.TypeNSEC, dns.TypeRRSIG)
		}
		out = append(out, &dns.NSEC{Hdr: dns.RR_Header{Name: n, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
			NextDomain: owners[(i+1)%len(owners)], TypeBitMap: bm})
	}
	return out
}

func nsec3Chain(origin string, names map[string]*nameInfo, cuts map[string]bool, p Params, ttl uint32) []dns.RR {
	all := map[string]map[uint16]bool{}
	for n, ni := range names {
		insecureCut := cuts[n] && !ni.types[dns.TypeDS]
		if p.OptOut && insecureCut {
			continue
		}
		ts := ni.types
		if cuts[n] {
			ts = map[uint16]bool{dns.TypeNS: true}
			if ni.types[dns.TypeDS] {
				ts[dns.TypeDS] = true
			}
		}
		all[n] = ts
		for a := parentOf(n); a != origin && dns.IsSubDomain(origin, a); a = parentOf(a) {
			if _, ok := all[a]; !ok {
				all[a] = nil // empty non-terminal
			}
		}
	}
	// a name added as ENT may be real data (map iteration order)
	for n, ni := range names {
		if _, ok := all[n]; ok && all[n] == nil {
			all[n] = ni.types
		}
	}
	type h struct {
		hash string
		name string
	}
	hs := make([]h, 0, len(all))
	for n := range all {
		hs = append(hs, h{strings.ToUpper(dns.HashName(n, dns.SHA1, p.Iterations, p.Salt)), n})
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].hash < hs[j].hash })
	var flags uint8
	if p.OptOut {
		flags = 1
	}
	out := make([]dns.RR, 0, len(hs))
	for i, x := range hs {
		ts := all[x.name]
		var bm []uint16
		if len(ts) > 0 {
			if cuts[x.name] && !ts[dns.TypeDS] {
				bm = bitmap(ts)
			} else {
				bm = bitmap(ts, dns.TypeRRSIG)
			}
		}
		out = append(out, &dns.NSEC3{Hdr: dns.RR_Header{Name: strings.ToLower(x.hash) + "." + origin, Rrtype: dns.TypeNSEC3,
			Class: dns.ClassINET, Ttl: ttl}, Hash: dns.SHA1, Flags: flags, Iterations: p.Iterations,
			SaltLength: uint8(len(p.Salt) / 2), Salt: p.Salt, HashLength: 20, NextDomain: hs[(i+1)%len(hs)].hash, TypeBitMap: bm})
	}
	return out
}
