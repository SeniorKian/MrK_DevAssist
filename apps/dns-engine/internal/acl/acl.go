// Package acl implements ordered network access lists.
//
// An entry is "addr/prefix", a bare address (host route) or a negated entry
// prefixed with "!". The first matching entry wins; no match means deny.
package acl

import (
	"fmt"
	"net/netip"
	"strings"
)

type entry struct {
	prefix netip.Prefix
	deny   bool
}

// List is an immutable compiled ACL. The zero value denies everything.
type List struct {
	entries []entry
	// fast paths for the common "everything allowed" case
	allowAll bool
}

// ParseEntry validates one entry and returns its canonical text.
func ParseEntry(s string) (netip.Prefix, bool, error) {
	s = strings.TrimSpace(s)
	deny := false
	if strings.HasPrefix(s, "!") {
		deny = true
		s = strings.TrimSpace(s[1:])
	}
	if s == "" {
		return netip.Prefix{}, false, fmt.Errorf("empty entry")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false, fmt.Errorf("invalid prefix %q", s)
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), deny, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("invalid address %q", s)
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), deny, nil
}

// Compile builds a List; invalid entries return an error naming the index.
func Compile(items []string) (*List, error) {
	l := &List{}
	for i, s := range items {
		p, deny, err := ParseEntry(s)
		if err != nil {
			return nil, &EntryError{Index: i, Err: err}
		}
		l.entries = append(l.entries, entry{prefix: p, deny: deny})
	}
	if len(l.entries) > 0 && !l.entries[0].deny && l.entries[0].prefix.Bits() == 0 {
		// "0.0.0.0/0" first only covers IPv4; allowAll needs both families
		v4, v6 := false, false
		for _, e := range l.entries {
			if e.deny {
				break
			}
			if e.prefix.Bits() == 0 {
				if e.prefix.Addr().Is4() {
					v4 = true
				} else {
					v6 = true
				}
			}
		}
		l.allowAll = v4 && v6
	}
	return l, nil
}

// MustCompile panics on error (tests and defaults only).
func MustCompile(items []string) *List {
	l, err := Compile(items)
	if err != nil {
		panic(err)
	}
	return l
}

// EntryError reports the offending index.
type EntryError struct {
	Index int
	Err   error
}

func (e *EntryError) Error() string { return fmt.Sprintf("entry %d: %v", e.Index, e.Err) }

// Allowed reports whether addr is permitted.
func (l *List) Allowed(addr netip.Addr) bool {
	if l == nil {
		return false
	}
	if l.allowAll {
		return true
	}
	addr = addr.Unmap()
	for i := range l.entries {
		if l.entries[i].prefix.Contains(addr) {
			return !l.entries[i].deny
		}
	}
	return false
}

// Len returns the number of entries.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}

// Private reports whether addr is not globally routable: loopback, RFC 1918,
// CGNAT, link-local, ULA, unspecified, multicast and documentation/benchmark
// ranges. Used for DNS rebinding protection.
func Private(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() ||
		addr.IsMulticast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range nonPublic {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
}
