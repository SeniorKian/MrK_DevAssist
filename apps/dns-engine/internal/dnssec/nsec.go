package dnssec

import (
	"github.com/miekg/dns"
)

// proof outcomes.
type proof int

const (
	proofFail proof = iota
	proofOK
	proofInsecure // NSEC3 opt-out or parameters beyond limits (RFC 5155 §9.2, RFC 9276)
)

// ---------------------------------------------------------------- NSEC

func nsecMatch(nsecs []*dns.NSEC, name string) *dns.NSEC {
	for _, n := range nsecs {
		if lower(n.Hdr.Name) == lower(name) {
			return n
		}
	}
	return nil
}

func nsecCovering(nsecs []*dns.NSEC, name string) *dns.NSEC {
	for _, n := range nsecs {
		if nsecCovers(n, name) {
			// an NSEC at a delegation (or DNAME) above name cannot deny it
			if isSub(n.Hdr.Name, name) && delegationBelow(n.TypeBitMap) {
				continue
			}
			return n
		}
	}
	return nil
}

// nsecCloser returns the closest encloser implied by a covering NSEC.
func nsecCloser(cov *dns.NSEC, name string) string {
	a := commonAncestor(name, cov.Hdr.Name)
	b := commonAncestor(name, cov.NextDomain)
	if dns.CountLabel(b) > dns.CountLabel(a) {
		return b
	}
	return a
}

// nxNSEC proves that name does not exist and no wildcard could have matched.
func nxNSEC(nsecs []*dns.NSEC, name string) proof {
	if nsecMatch(nsecs, name) != nil {
		return proofFail
	}
	cov := nsecCovering(nsecs, name)
	if cov == nil {
		return proofFail
	}
	ce := nsecCloser(cov, name)
	wild := "*." + ce
	if ce == "." {
		wild = "*."
	}
	if nsecMatch(nsecs, wild) != nil || nsecCovering(nsecs, wild) == nil {
		return proofFail
	}
	return proofOK
}

// nodataNSEC proves that name exists without qtype (exact, wildcard or
// empty non-terminal).
func nodataNSEC(nsecs []*dns.NSEC, name string, qtype uint16) proof {
	if m := nsecMatch(nsecs, name); m != nil {
		if hasType(m.TypeBitMap, qtype) || hasType(m.TypeBitMap, dns.TypeCNAME) {
			return proofFail
		}
		if qtype != dns.TypeDS && hasType(m.TypeBitMap, dns.TypeNS) && !hasType(m.TypeBitMap, dns.TypeSOA) {
			return proofFail // parent-side NSEC cannot deny child data
		}
		return proofOK
	}
	cov := nsecCovering(nsecs, name)
	if cov == nil {
		return proofFail
	}
	// empty non-terminal: the next name is below name
	if isSub(name, cov.NextDomain) && lower(cov.NextDomain) != lower(name) {
		return proofOK
	}
	ce := nsecCloser(cov, name)
	wild := "*." + ce
	if ce == "." {
		wild = "*."
	}
	if m := nsecMatch(nsecs, wild); m != nil && !hasType(m.TypeBitMap, qtype) && !hasType(m.TypeBitMap, dns.TypeCNAME) {
		return proofOK
	}
	return proofFail
}

// ---------------------------------------------------------------- NSEC3

func nsec3Usable(n3 []*dns.NSEC3, maxIter int) bool {
	for _, n := range n3 {
		if n.Hash != dns.SHA1 || int(n.Iterations) > maxIter {
			return false
		}
	}
	return true
}

func nsec3Match(n3 []*dns.NSEC3, name string) *dns.NSEC3 {
	for _, n := range n3 {
		if n.Match(lower(name)) {
			return n
		}
	}
	return nil
}

func nsec3Covering(n3 []*dns.NSEC3, name string) *dns.NSEC3 {
	for _, n := range n3 {
		if !n.Match(lower(name)) && n.Cover(lower(name)) {
			return n
		}
	}
	return nil
}

// childToward returns the name one label below ce on the way to name.
func childToward(ce, name string) string {
	name = lower(name)
	idx := dns.Split(name)
	cl := dns.CountLabel(ce)
	nl := len(idx)
	if cl >= nl {
		return name
	}
	return name[idx[nl-cl-1]:]
}

// closestEncloser implements RFC 5155 §8.3 for a name that has no matching
// NSEC3. It returns the closest encloser, the covering NSEC3 of the next
// closer name, and ok.
func closestEncloser(n3 []*dns.NSEC3, name string) (string, *dns.NSEC3, bool) {
	for c := parentOf(lower(name)); ; c = parentOf(c) {
		if m := nsec3Match(n3, c); m != nil {
			if delegationBelow(m.TypeBitMap) {
				return "", nil, false
			}
			nc := childToward(c, name)
			cov := nsec3Covering(n3, nc)
			if cov == nil {
				return "", nil, false
			}
			return c, cov, true
		}
		if c == "." {
			return "", nil, false
		}
	}
}

func optOut(n *dns.NSEC3) bool { return n.Flags&1 == 1 }

func nxNSEC3(n3 []*dns.NSEC3, name string, maxIter int) proof {
	if !nsec3Usable(n3, maxIter) {
		return proofInsecure
	}
	if nsec3Match(n3, name) != nil {
		return proofFail
	}
	ce, cov, ok := closestEncloser(n3, name)
	if !ok {
		return proofFail
	}
	wild := "*." + ce
	if ce == "." {
		wild = "*."
	}
	if nsec3Match(n3, wild) != nil || nsec3Covering(n3, wild) == nil {
		return proofFail
	}
	if optOut(cov) {
		return proofInsecure
	}
	return proofOK
}

func nodataNSEC3(n3 []*dns.NSEC3, name string, qtype uint16, maxIter int) proof {
	if !nsec3Usable(n3, maxIter) {
		return proofInsecure
	}
	if m := nsec3Match(n3, name); m != nil {
		if hasType(m.TypeBitMap, qtype) || hasType(m.TypeBitMap, dns.TypeCNAME) {
			return proofFail
		}
		if qtype != dns.TypeDS && hasType(m.TypeBitMap, dns.TypeNS) && !hasType(m.TypeBitMap, dns.TypeSOA) {
			return proofFail
		}
		return proofOK
	}
	ce, cov, ok := closestEncloser(n3, name)
	if !ok {
		return proofFail
	}
	if qtype == dns.TypeDS && optOut(cov) {
		return proofInsecure // RFC 5155 §8.6: unsigned delegation in an opt-out span
	}
	wild := "*." + ce
	if ce == "." {
		wild = "*."
	}
	if m := nsec3Match(n3, wild); m != nil && !hasType(m.TypeBitMap, qtype) && !hasType(m.TypeBitMap, dns.TypeCNAME) {
		return proofOK
	}
	return proofFail
}

// wildcardProof proves that an answer synthesised from a wildcard was
// legitimate: the next closer name of the expanded owner does not exist.
func wildcardProof(nsecs []*dns.NSEC, n3 []*dns.NSEC3, owner string, labels uint8, maxIter int) proof {
	idx := dns.Split(lower(owner))
	if int(labels) >= len(idx) {
		return proofOK
	}
	ce := lower(owner)[idx[len(idx)-int(labels)]:]
	if labels == 0 {
		ce = "."
	}
	if len(nsecs) > 0 {
		if nsecMatch(nsecs, owner) == nil && nsecCovering(nsecs, owner) != nil {
			return proofOK
		}
		return proofFail
	}
	if len(n3) > 0 {
		if !nsec3Usable(n3, maxIter) {
			return proofInsecure
		}
		nc := childToward(ce, owner)
		if nsec3Covering(n3, nc) != nil {
			return proofOK
		}
	}
	return proofFail
}
