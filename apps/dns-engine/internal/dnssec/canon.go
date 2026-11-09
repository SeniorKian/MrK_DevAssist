package dnssec

import (
	"bytes"
	"strings"

	"github.com/miekg/dns"
)

// wireLabels returns the lower-cased labels of name, root last excluded.
func wireLabels(name string) [][]byte {
	buf := make([]byte, 256)
	n, err := dns.PackDomainName(strings.ToLower(dns.Fqdn(name)), buf, 0, nil, false)
	if err != nil {
		return nil
	}
	var out [][]byte
	for off := 0; off < n; {
		l := int(buf[off])
		if l == 0 {
			break
		}
		out = append(out, buf[off+1:off+1+l])
		off += 1 + l
	}
	return out
}

// canonicalCompare orders names as RFC 4034 §6.1.
func canonicalCompare(a, b string) int {
	la, lb := wireLabels(a), wireLabels(b)
	for i, j := len(la)-1, len(lb)-1; i >= 0 || j >= 0; i, j = i-1, j-1 {
		if i < 0 {
			return -1
		}
		if j < 0 {
			return 1
		}
		if c := bytes.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	return 0
}

func lower(s string) string { return strings.ToLower(dns.Fqdn(s)) }

func isSub(parent, child string) bool { return dns.IsSubDomain(lower(parent), lower(child)) }

func parentOf(name string) string {
	if name == "." {
		return "."
	}
	off, end := dns.NextLabel(name, 0)
	if end {
		return "."
	}
	return name[off:]
}

// commonAncestor returns the longest common suffix (in labels) of a and b.
func commonAncestor(a, b string) string {
	n := dns.CompareDomainName(lower(a), lower(b))
	if n == 0 {
		return "."
	}
	idx := dns.Split(lower(a))
	return lower(a)[idx[len(idx)-n]:]
}

func hasType(bitmap []uint16, t uint16) bool {
	for _, x := range bitmap {
		if x == t {
			return true
		}
	}
	return false
}

// nsecCovers reports whether name falls strictly between the owner and the
// next name of n (the last NSEC of a zone wraps to the apex).
func nsecCovers(n *dns.NSEC, name string) bool {
	owner, next := lower(n.Hdr.Name), lower(n.NextDomain)
	name = lower(name)
	if canonicalCompare(owner, name) >= 0 {
		return false
	}
	if canonicalCompare(owner, next) < 0 {
		return canonicalCompare(name, next) < 0
	}
	// wrap-around: next is the apex
	return isSub(next, name)
}

// delegationBelow reports whether an NSEC/NSEC3 type bitmap marks a zone cut
// (NS without SOA) or a DNAME: such a record cannot deny names below it
// (RFC 6840 §4.1).
func delegationBelow(bitmap []uint16) bool {
	return hasType(bitmap, dns.TypeNS) && !hasType(bitmap, dns.TypeSOA) || hasType(bitmap, dns.TypeDNAME)
}
