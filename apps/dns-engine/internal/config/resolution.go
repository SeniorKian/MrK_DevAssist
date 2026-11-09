package config

import (
	"fmt"
	"net/netip"
	"strings"

	"mrk/dns-engine/internal/fielderr"
)

// Resolution modes (docs/40 §2.1).
const (
	ModeForward              = "forward"
	ModeRecursive            = "recursive"
	ModeForwardThenRecursive = "forward_then_recursive"
)

// QNAME minimisation levels (RFC 9156).
const (
	QNameMinOff     = "off"
	QNameMinRelaxed = "relaxed"
	QNameMinStrict  = "strict"
)

// IP versions used to reach authoritative servers.
const (
	IPv4Only = "ipv4"
	IPv6Only = "ipv6"
	IPBoth   = "both"
)

// RootHint is one configured root server (empty list = built-in named.root).
type RootHint struct {
	Name string `json:"name"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

// Resolution configures how names are resolved (docs/40 §2.1).
type Resolution struct {
	Mode                    string     `json:"mode"`
	QNameMinimization       string     `json:"qname_minimization"`
	IPVersions              string     `json:"ip_versions"`
	CaseRandomization       bool       `json:"case_randomization"`
	RootHints               []RootHint `json:"root_hints"`
	AllowPrivateNS          bool       `json:"allow_private_ns"`
	MaxReferrals            int        `json:"max_referrals"`
	MaxQueriesPerResolution int        `json:"max_queries_per_resolution"`
	MaxNSPerZone            int        `json:"max_ns_per_zone"`
	QueryTimeoutMS          int        `json:"query_timeout_ms"`
	ResolveTimeoutMS        int        `json:"resolve_timeout_ms"`
	InfraCacheEntries       int        `json:"infra_cache_entries"`
}

// DefaultResolution returns the factory resolution section: forwarding, so
// existing installations keep their D1/D2 behaviour.
func DefaultResolution() Resolution {
	return Resolution{Mode: ModeForward, QNameMinimization: QNameMinRelaxed, IPVersions: IPv4Only,
		CaseRandomization: true, RootHints: []RootHint{}, MaxReferrals: 30, MaxQueriesPerResolution: 100,
		MaxNSPerZone: 13, QueryTimeoutMS: 1500, ResolveTimeoutMS: 4000, InfraCacheEntries: 10000}
}

// FillD4Defaults fills the D4 sections absent from settings stored by older
// versions (loading = defaults + stored document).
func (s *Settings) FillD4Defaults() {
	if s.Resolution.Mode == "" {
		s.Resolution = DefaultResolution()
	}
	if s.Resolution.RootHints == nil {
		s.Resolution.RootHints = []RootHint{}
	}
	if s.DNSSEC.Mode == "" {
		s.DNSSEC = DefaultDNSSEC()
	}
	if s.DNSSEC.NegativeTrustAnchors == nil {
		s.DNSSEC.NegativeTrustAnchors = []NTA{}
	}
	s.fillEncryptedDefaults()
}

func (r Resolution) clone() Resolution {
	c := r
	c.RootHints = append([]RootHint{}, r.RootHints...)
	return c
}

func choice(l *fielderr.List, field, v string, choices ...string) {
	for _, c := range choices {
		if v == c {
			return
		}
	}
	l.Add(field, "invalid_choice", "choices", choices)
}

func validateResolution(s *Settings, l *fielderr.List) {
	r := &s.Resolution
	choice(l, "resolution.mode", r.Mode, ModeForward, ModeRecursive, ModeForwardThenRecursive)
	choice(l, "resolution.qname_minimization", r.QNameMinimization, QNameMinOff, QNameMinRelaxed, QNameMinStrict)
	choice(l, "resolution.ip_versions", r.IPVersions, IPv4Only, IPv6Only, IPBoth)
	if len(r.RootHints) > 26 {
		l.Add("resolution.root_hints", "too_many", "max", 26)
	}
	seen := map[string]bool{}
	for i, h := range r.RootHints {
		f := fmt.Sprintf("resolution.root_hints[%d]", i)
		name := strings.ToLower(strings.TrimSpace(h.Name))
		if name != "" && !strings.HasSuffix(name, ".") {
			name += "."
		}
		if !validHostname(name) {
			l.Add(f+".name", "invalid_name")
		} else if seen[name] {
			l.Add(f+".name", "duplicate")
		}
		seen[name] = true
		r.RootHints[i].Name = name
		if h.IPv4 == "" && h.IPv6 == "" {
			l.Add(f, "address_required")
		}
		if h.IPv4 != "" {
			a, err := netip.ParseAddr(strings.TrimSpace(h.IPv4))
			if err != nil || !a.Unmap().Is4() {
				l.Add(f+".ipv4", "invalid_address")
			} else {
				r.RootHints[i].IPv4 = a.Unmap().String()
			}
		}
		if h.IPv6 != "" {
			a, err := netip.ParseAddr(strings.TrimSpace(h.IPv6))
			if err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" {
				l.Add(f+".ipv6", "invalid_address")
			} else {
				r.RootHints[i].IPv6 = a.String()
			}
		}
	}
	rng(l, "resolution.max_referrals", r.MaxReferrals, 1, 64)
	rng(l, "resolution.max_queries_per_resolution", r.MaxQueriesPerResolution, 10, 500)
	rng(l, "resolution.max_ns_per_zone", r.MaxNSPerZone, 1, 32)
	rng(l, "resolution.query_timeout_ms", r.QueryTimeoutMS, 200, 10000)
	rng(l, "resolution.resolve_timeout_ms", r.ResolveTimeoutMS, 1000, 30000)
	rng(l, "resolution.infra_cache_entries", r.InfraCacheEntries, 100, 1000000)
	if r.ResolveTimeoutMS < r.QueryTimeoutMS {
		l.Add("resolution.resolve_timeout_ms", "less_than_query_timeout")
	}
}
