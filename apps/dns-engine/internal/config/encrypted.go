package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/fielderr"
)

// EncListener is a DoT or DoQ listener section (docs/40 §2.3).
type EncListener struct {
	Enabled bool     `json:"enabled"`
	Listen  []string `json:"listen"`
}

// DoH is the DNS-over-HTTPS listener section.
type DoH struct {
	Enabled bool     `json:"enabled"`
	Listen  []string `json:"listen"`
	// TLS=false serves plain HTTP for a reverse proxy (Traefik) in front.
	TLS            bool     `json:"tls"`
	Path           string   `json:"path"`
	AllowGET       bool     `json:"allow_get"`
	TrustedProxies []string `json:"trusted_proxies"`
}

// Encrypted configures incoming encrypted DNS (docs/40 §2.3).
type Encrypted struct {
	DoT EncListener `json:"dot"`
	DoQ EncListener `json:"doq"`
	DoH DoH         `json:"doh"`
	// Allow nil = recursion.allow (and query_allow) apply; otherwise this list
	// admits encrypted clients (the open-resolver rule applies).
	Allow                   *[]string `json:"allow"`
	MaxConnections          int       `json:"max_connections"`
	MaxConnectionsPerClient int       `json:"max_connections_per_client"`
	IdleTimeoutMS           int       `json:"idle_timeout_ms"`
	MaxStreamsPerConnection int       `json:"max_streams_per_connection"`
	HandshakeTimeoutMS      int       `json:"handshake_timeout_ms"`
}

// DefaultTrustedProxies are the reverse proxies whose X-Forwarded-For is believed.
var DefaultTrustedProxies = []string{"127.0.0.0/8", "::1/128", "172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"}

// DefaultEncrypted returns the factory section: everything off.
func DefaultEncrypted() Encrypted {
	return Encrypted{
		DoT: EncListener{Listen: []string{"0.0.0.0:853"}},
		DoQ: EncListener{Listen: []string{"0.0.0.0:853"}},
		DoH: DoH{Listen: []string{"0.0.0.0:443"}, TLS: true, Path: "/dns-query", AllowGET: true,
			TrustedProxies: append([]string(nil), DefaultTrustedProxies...)},
		MaxConnections: 2000, MaxConnectionsPerClient: 50, IdleTimeoutMS: 30000, MaxStreamsPerConnection: 100,
		HandshakeTimeoutMS: 5000,
	}
}

// AnyEnabled reports whether an encrypted listener is on.
func (x Encrypted) AnyEnabled() bool { return x.DoT.Enabled || x.DoQ.Enabled || x.DoH.Enabled }

// NeedsCertificate reports whether the enabled listeners need a TLS certificate.
func (x Encrypted) NeedsCertificate() bool {
	return x.DoT.Enabled || x.DoQ.Enabled || x.DoH.Enabled && x.DoH.TLS
}

func (x Encrypted) clone() Encrypted {
	c := x
	c.DoT.Listen = append([]string{}, x.DoT.Listen...)
	c.DoQ.Listen = append([]string{}, x.DoQ.Listen...)
	c.DoH.Listen = append([]string{}, x.DoH.Listen...)
	c.DoH.TrustedProxies = append([]string{}, x.DoH.TrustedProxies...)
	if x.Allow != nil {
		a := append([]string{}, (*x.Allow)...)
		c.Allow = &a
	}
	return c
}

// fillEncryptedDefaults fills the section for settings stored before D4.
func (s *Settings) fillEncryptedDefaults() {
	d := DefaultEncrypted()
	x := &s.Encrypted
	if x.MaxConnections == 0 && x.MaxConnectionsPerClient == 0 && x.IdleTimeoutMS == 0 {
		allow := x.Allow
		*x = d
		x.Allow = allow
		return
	}
	if x.DoT.Listen == nil {
		x.DoT.Listen = d.DoT.Listen
	}
	if x.DoQ.Listen == nil {
		x.DoQ.Listen = d.DoQ.Listen
	}
	if x.DoH.Listen == nil {
		x.DoH.Listen = d.DoH.Listen
	}
	if x.DoH.Path == "" {
		x.DoH.Path = d.DoH.Path
	}
	if x.DoH.TrustedProxies == nil {
		x.DoH.TrustedProxies = d.DoH.TrustedProxies
	}
}

var dohPathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)

// MaxEncListen bounds the listen list of each encrypted protocol.
const MaxEncListen = 16

type bindKey struct {
	transport string // tcp | udp
	addr      netip.AddrPort
}

func validateEncrypted(s *Settings, l *fielderr.List) {
	x := &s.Encrypted
	// sockets already bound by the plain listeners
	taken := map[bindKey]string{}
	for i, ls := range s.Listen {
		ap, err := netip.ParseAddrPort(ls.Address)
		if err != nil {
			continue
		}
		f := fmt.Sprintf("listen[%d].address", i)
		if ls.UDP {
			taken[bindKey{"udp", ap}] = f
		}
		if ls.TCP {
			taken[bindKey{"tcp", ap}] = f
		}
	}
	conflict := func(k bindKey) bool {
		for o := range taken {
			if o.transport != k.transport || o.addr.Port() != k.addr.Port() {
				continue
			}
			if o.addr.Addr() == k.addr.Addr() || o.addr.Addr().IsUnspecified() || k.addr.Addr().IsUnspecified() {
				return true
			}
		}
		return false
	}
	check := func(field, transport string, items []string, enabled bool) {
		if len(items) == 0 && enabled {
			l.Add(field, "required")
		}
		if len(items) > MaxEncListen {
			l.Add(field, "too_many", "max", MaxEncListen)
			return
		}
		mine := map[netip.AddrPort]bool{}
		for i, a := range items {
			f := fmt.Sprintf("%s[%d]", field, i)
			ap, err := netip.ParseAddrPort(strings.TrimSpace(a))
			if err != nil || ap.Port() == 0 {
				l.Add(f, "invalid_address")
				continue
			}
			ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			items[i] = ap.String()
			if mine[ap] {
				l.Add(f, "duplicate")
				continue
			}
			mine[ap] = true
			k := bindKey{transport, ap}
			if enabled && conflict(k) {
				l.Add(f, "listen_conflict")
			}
		}
		if enabled {
			for ap := range mine {
				taken[bindKey{transport, ap}] = field
			}
		}
	}
	check("encrypted.dot.listen", "tcp", x.DoT.Listen, x.DoT.Enabled)
	check("encrypted.doh.listen", "tcp", x.DoH.Listen, x.DoH.Enabled)
	check("encrypted.doq.listen", "udp", x.DoQ.Listen, x.DoQ.Enabled)
	if x.DoH.Enabled && !x.DoH.TLS {
		for i, a := range x.DoH.Listen {
			ap, err := netip.ParseAddrPort(a)
			if err != nil {
				continue
			}
			ip := ap.Addr()
			if ip.IsUnspecified() || !acl.Private(ip) {
				l.Add(fmt.Sprintf("encrypted.doh.listen[%d]", i), "plain_doh_public")
			}
		}
	}
	if len(x.DoH.Path) > 128 || !dohPathRe.MatchString(x.DoH.Path) {
		l.Add("encrypted.doh.path", "invalid_path")
	}
	if len(x.DoH.TrustedProxies) > 64 {
		l.Add("encrypted.doh.trusted_proxies", "too_many", "max", 64)
	} else {
		for i, it := range x.DoH.TrustedProxies {
			p, deny, err := acl.ParseEntry(it)
			if err != nil || deny {
				l.Add(fmt.Sprintf("encrypted.doh.trusted_proxies[%d]", i), "invalid_network")
				continue
			}
			x.DoH.TrustedProxies[i] = p.String()
		}
	}
	if x.Allow != nil {
		items := *x.Allow
		if len(items) > 1024 {
			l.Add("encrypted.allow", "too_many", "max", 1024)
		} else {
			for i, it := range items {
				f := fmt.Sprintf("encrypted.allow[%d]", i)
				p, deny, err := acl.ParseEntry(it)
				if err != nil {
					l.Add(f, "invalid_network")
					continue
				}
				if !deny && p.Bits() == 0 {
					l.Add(f, "open_resolver") // never an open resolver (D1 rule)
					continue
				}
				v := p.String()
				if deny {
					v = "!" + v
				}
				items[i] = v
			}
		}
	}
	rng(l, "encrypted.max_connections", x.MaxConnections, 10, 100000)
	rng(l, "encrypted.max_connections_per_client", x.MaxConnectionsPerClient, 1, 10000)
	rng(l, "encrypted.idle_timeout_ms", x.IdleTimeoutMS, 1000, 600000)
	rng(l, "encrypted.max_streams_per_connection", x.MaxStreamsPerConnection, 1, 1000)
	rng(l, "encrypted.handshake_timeout_ms", x.HandshakeTimeoutMS, 500, 30000)
}
