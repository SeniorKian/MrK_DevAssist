package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/fielderr"
)

// DNSSEC modes (docs/40 §2.2).
const (
	DNSSECOff      = "off"
	DNSSECValidate = "validate"
	DNSSECLogOnly  = "log_only"
)

// MaxNTAs bounds the negative trust anchor list.
const MaxNTAs = 500

// NTA is a negative trust anchor (RFC 7646): names at or below Domain are
// treated as insecure until ExpiresAt (RFC 3339, empty = never).
type NTA struct {
	Domain    string `json:"domain"`
	Reason    string `json:"reason,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// Expires returns the parsed expiry (zero = never).
func (n NTA) Expires() time.Time {
	if n.ExpiresAt == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, n.ExpiresAt)
	return t
}

// DNSSEC configures validation (docs/40 §2.2).
type DNSSEC struct {
	Mode                  string `json:"mode"`
	TrustAnchorAutoUpdate bool   `json:"trust_anchor_auto_update"`
	NegativeTrustAnchors  []NTA  `json:"negative_trust_anchors"`
	AutoInsecureLocal     bool   `json:"auto_insecure_local"`
	AggressiveNSEC        bool   `json:"aggressive_nsec"`
	NSEC3MaxIterations    int    `json:"nsec3_max_iterations"`
	BogusTTL              int    `json:"bogus_ttl"`
	SigSkewSeconds        int    `json:"sig_skew_seconds"`
}

// DefaultDNSSEC returns the factory DNSSEC section (validation on, also for
// installations upgraded from settings without this section).
func DefaultDNSSEC() DNSSEC {
	return DNSSEC{Mode: DNSSECValidate, TrustAnchorAutoUpdate: true, NegativeTrustAnchors: []NTA{},
		AutoInsecureLocal: true, AggressiveNSEC: true, NSEC3MaxIterations: 150, BogusTTL: 60, SigSkewSeconds: 3600}
}

func (d DNSSEC) clone() DNSSEC {
	c := d
	c.NegativeTrustAnchors = append([]NTA{}, d.NegativeTrustAnchors...)
	return c
}

func validateDNSSEC(s *Settings, l *fielderr.List) {
	d := &s.DNSSEC
	choice(l, "dnssec.mode", d.Mode, DNSSECOff, DNSSECValidate, DNSSECLogOnly)
	if len(d.NegativeTrustAnchors) > MaxNTAs {
		l.Add("dnssec.negative_trust_anchors", "too_many", "max", MaxNTAs)
	}
	seen := map[string]bool{}
	for i, n := range d.NegativeTrustAnchors {
		f := fmt.Sprintf("dnssec.negative_trust_anchors[%d]", i)
		dom := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n.Domain), "."))
		if _, ok := dns.IsDomainName(dom); !ok || dom == "" || len(dom) > 253 || strings.Contains(dom, "*") {
			l.Add(f+".domain", "invalid_name")
		} else if seen[dom] {
			l.Add(f+".domain", "duplicate")
		}
		seen[dom] = true
		d.NegativeTrustAnchors[i].Domain = dom
		if len(n.Reason) > 256 {
			l.Add(f+".reason", "too_long", "max", 256)
		}
		if n.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339, strings.TrimSpace(n.ExpiresAt))
			if err != nil {
				l.Add(f+".expires_at", "invalid_time")
			} else {
				d.NegativeTrustAnchors[i].ExpiresAt = t.UTC().Format(time.RFC3339)
			}
		}
	}
	rng(l, "dnssec.nsec3_max_iterations", d.NSEC3MaxIterations, 0, 2500)
	rng(l, "dnssec.bogus_ttl", d.BogusTTL, 0, 3600)
	rng(l, "dnssec.sig_skew_seconds", d.SigSkewSeconds, 0, 86400)
}
