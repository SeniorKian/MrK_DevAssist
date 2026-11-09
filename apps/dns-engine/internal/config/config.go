// Package config defines the engine settings document (docs/37 §2), its
// defaults and validation.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/fielderr"
)

// Listen is one DNS listener address.
type Listen struct {
	Address string `json:"address"`
	UDP     bool   `json:"udp"`
	TCP     bool   `json:"tcp"`
}

// Recursion controls who may use the resolver.
type Recursion struct {
	Enabled bool     `json:"enabled"`
	Allow   []string `json:"allow"`
}

// Upstream is one forwarder.
type Upstream struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
}

// Cache settings.
type Cache struct {
	MaxBytes       int64  `json:"max_bytes"`
	MinTTL         uint32 `json:"min_ttl"`
	MaxTTL         uint32 `json:"max_ttl"`
	NegativeMaxTTL uint32 `json:"negative_max_ttl"`
	ServeStale     bool   `json:"serve_stale"`
	StaleTTL       uint32 `json:"stale_ttl"`
	Prefetch       bool   `json:"prefetch"`
}

// Limits are the abuse and resource limits.
type Limits struct {
	ClientQPS             int `json:"client_qps"`
	ClientBurst           int `json:"client_burst"`
	RRLResponsesPerSecond int `json:"rrl_responses_per_second"`
	RRLSlip               int `json:"rrl_slip"`
	RRLIPv4Prefix         int `json:"rrl_ipv4_prefix"`
	RRLIPv6Prefix         int `json:"rrl_ipv6_prefix"`
	MaxTCPConnections     int `json:"max_tcp_connections"`
	TCPIdleTimeoutMS      int `json:"tcp_idle_timeout_ms"`
	UDPMaxSize            int `json:"udp_max_size"`
	MaxInflightUpstream   int `json:"max_inflight_upstream"`
}

// Overrides toggles local name overrides.
type Overrides struct {
	Enabled bool `json:"enabled"`
}

// Settings is the whole engine settings object.
type Settings struct {
	Listen              []Listen   `json:"listen"`
	Recursion           Recursion  `json:"recursion"`
	QueryAllow          []string   `json:"query_allow"`
	Upstreams           []Upstream `json:"upstreams"`
	UpstreamStrategy    string     `json:"upstream_strategy"`
	Cache               Cache      `json:"cache"`
	Limits              Limits     `json:"limits"`
	MinimalANY          bool       `json:"minimal_any"`
	RefuseANY           bool       `json:"refuse_any"`
	RebindingProtection bool       `json:"rebinding_protection"`
	Overrides           Overrides  `json:"overrides"`
	QueryLog            QueryLog   `json:"querylog"`
	Stats               Stats      `json:"stats"`
	Pressure            Pressure   `json:"pressure"`
	Resolution          Resolution `json:"resolution"`
	DNSSEC              DNSSEC     `json:"dnssec"`
	Encrypted           Encrypted  `json:"encrypted"`
}

// Strategies.
const (
	StrategyFastest  = "fastest"
	StrategyParallel = "parallel"
	StrategyInOrder  = "in_order"
)

// PrivateNetworks is the default recursion/query ACL.
var PrivateNetworks = []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

// DefaultListen is used on first start when MRK_DNS_LISTEN is unset.
const DefaultListen = "127.0.0.1:53,172.17.0.1:53"

// Defaults returns the factory settings. listen is a comma separated list of
// host:port (MRK_DNS_LISTEN); empty uses DefaultListen.
func Defaults(listen string) Settings {
	if strings.TrimSpace(listen) == "" {
		listen = DefaultListen
	}
	var ls []Listen
	for _, a := range strings.Split(listen, ",") {
		if a = strings.TrimSpace(a); a != "" {
			ls = append(ls, Listen{Address: a, UDP: true, TCP: true})
		}
	}
	return Settings{
		Listen:     ls,
		Recursion:  Recursion{Enabled: true, Allow: append([]string(nil), PrivateNetworks...)},
		QueryAllow: append([]string(nil), PrivateNetworks...),
		Upstreams: []Upstream{
			{ID: "cloudflare", Address: "1.1.1.1:53", Enabled: true},
			{ID: "google", Address: "8.8.8.8:53", Enabled: true},
			{ID: "quad9", Address: "9.9.9.9:53", Enabled: true},
		},
		UpstreamStrategy: StrategyFastest,
		Cache: Cache{MaxBytes: 64 << 20, MinTTL: 0, MaxTTL: 86400, NegativeMaxTTL: 3600,
			ServeStale: true, StaleTTL: 86400, Prefetch: true},
		Limits: Limits{ClientQPS: 200, ClientBurst: 400, RRLResponsesPerSecond: 20, RRLSlip: 2,
			RRLIPv4Prefix: 24, RRLIPv6Prefix: 56, MaxTCPConnections: 1000, TCPIdleTimeoutMS: 10000,
			UDPMaxSize: 1232, MaxInflightUpstream: 2000},
		MinimalANY:          true,
		RefuseANY:           false,
		RebindingProtection: true,
		Overrides:           Overrides{Enabled: true},
		QueryLog:            DefaultQueryLog(),
		Stats:               DefaultStats(),
		Pressure:            DefaultPressure(),
		Resolution:          DefaultResolution(),
		DNSSEC:              DefaultDNSSEC(),
		Encrypted:           DefaultEncrypted(),
	}
}

// Clone deep-copies s.
func (s Settings) Clone() Settings {
	c := s
	c.Listen = append([]Listen(nil), s.Listen...)
	c.Recursion.Allow = append([]string(nil), s.Recursion.Allow...)
	c.QueryAllow = append([]string(nil), s.QueryAllow...)
	c.Upstreams = append([]Upstream(nil), s.Upstreams...)
	c.QueryLog.ExcludeNames = append([]string{}, s.QueryLog.ExcludeNames...)
	c.QueryLog.ExcludeClients = append([]string{}, s.QueryLog.ExcludeClients...)
	c.Resolution = s.Resolution.clone()
	c.DNSSEC = s.DNSSEC.clone()
	c.Encrypted = s.Encrypted.clone()
	return c
}

var upstreamID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

func rng(l *fielderr.List, field string, v, lo, hi int) {
	if v < lo || v > hi {
		l.Add(field, "out_of_range", "min", lo, "max", hi)
	}
}

// Validate checks s and returns field errors (nil if valid). It also
// normalises ACL entries in place.
func (s *Settings) Validate() fielderr.List {
	var l fielderr.List
	if len(s.Listen) == 0 {
		l.Add("listen", "required")
	}
	if len(s.Listen) > 32 {
		l.Add("listen", "too_many", "max", 32)
	}
	seen := map[string]bool{}
	for i, ls := range s.Listen {
		f := fmt.Sprintf("listen[%d]", i)
		ap, err := netip.ParseAddrPort(strings.TrimSpace(ls.Address))
		if err != nil || ap.Port() == 0 {
			l.Add(f+".address", "invalid_address")
			continue
		}
		s.Listen[i].Address = ap.String()
		if !ls.UDP && !ls.TCP {
			l.Add(f, "no_protocol")
		}
		if seen[ap.String()] {
			l.Add(f+".address", "duplicate")
		}
		seen[ap.String()] = true
	}
	checkACL := func(field string, items []string) {
		if len(items) > 1024 {
			l.Add(field, "too_many", "max", 1024)
			return
		}
		for i, it := range items {
			p, deny, err := acl.ParseEntry(it)
			if err != nil {
				l.Add(fmt.Sprintf("%s[%d]", field, i), "invalid_network")
				continue
			}
			if field == "recursion.allow" && !deny && p.Bits() == 0 {
				// recursion for the whole Internet is an open resolver: never allowed
				l.Add(fmt.Sprintf("%s[%d]", field, i), "open_resolver")
				continue
			}
			v := p.String()
			if deny {
				v = "!" + v
			}
			items[i] = v
		}
	}
	checkACL("recursion.allow", s.Recursion.Allow)
	checkACL("query_allow", s.QueryAllow)
	if len(s.Upstreams) > 16 {
		l.Add("upstreams", "too_many", "max", 16)
	}
	ids := map[string]bool{}
	for i, u := range s.Upstreams {
		f := fmt.Sprintf("upstreams[%d]", i)
		if !upstreamID.MatchString(u.ID) {
			l.Add(f+".id", "invalid_id")
		} else if ids[u.ID] {
			l.Add(f+".id", "duplicate")
		}
		ids[u.ID] = true
		if _, err := ParseUpstream(u.Address); err != nil {
			l.Add(f+".address", "invalid_upstream", "detail", err.Error())
		}
	}
	switch s.UpstreamStrategy {
	case StrategyFastest, StrategyParallel, StrategyInOrder:
	default:
		l.Add("upstream_strategy", "invalid_choice", "choices", []string{StrategyFastest, StrategyParallel, StrategyInOrder})
	}
	c := s.Cache
	if c.MaxBytes < 1<<20 || c.MaxBytes > 8<<30 {
		l.Add("cache.max_bytes", "out_of_range", "min", 1<<20, "max", int64(8<<30))
	}
	rng(&l, "cache.min_ttl", int(c.MinTTL), 0, 86400)
	rng(&l, "cache.max_ttl", int(c.MaxTTL), 1, 604800)
	if c.MinTTL > c.MaxTTL {
		l.Add("cache.min_ttl", "greater_than_max_ttl")
	}
	rng(&l, "cache.negative_max_ttl", int(c.NegativeMaxTTL), 0, 86400)
	rng(&l, "cache.stale_ttl", int(c.StaleTTL), 0, 604800)
	m := s.Limits
	rng(&l, "limits.client_qps", m.ClientQPS, 0, 10_000_000)
	rng(&l, "limits.client_burst", m.ClientBurst, 0, 10_000_000)
	if m.ClientQPS > 0 && m.ClientBurst < m.ClientQPS {
		l.Add("limits.client_burst", "less_than_client_qps")
	}
	rng(&l, "limits.rrl_responses_per_second", m.RRLResponsesPerSecond, 0, 1_000_000)
	rng(&l, "limits.rrl_slip", m.RRLSlip, 0, 10)
	rng(&l, "limits.rrl_ipv4_prefix", m.RRLIPv4Prefix, 8, 32)
	rng(&l, "limits.rrl_ipv6_prefix", m.RRLIPv6Prefix, 16, 128)
	rng(&l, "limits.max_tcp_connections", m.MaxTCPConnections, 1, 100_000)
	rng(&l, "limits.tcp_idle_timeout_ms", m.TCPIdleTimeoutMS, 100, 300_000)
	rng(&l, "limits.udp_max_size", m.UDPMaxSize, 512, 4096)
	rng(&l, "limits.max_inflight_upstream", m.MaxInflightUpstream, 1, 100_000)
	validateMonitor(s, &l)
	validateResolution(s, &l)
	validateDNSSEC(s, &l)
	validateEncrypted(s, &l)
	return l
}

// Upstream protocols.
const (
	ProtoUDP = "udp" // UDP with TCP fallback on truncation
	ProtoTCP = "tcp"
	ProtoDoT = "tls"
	ProtoDoH = "https"
	ProtoDoQ = "quic" // DNS over QUIC (RFC 9250), docs/40 §3
)

// UpstreamAddr is a parsed upstream address.
type UpstreamAddr struct {
	Proto      string
	Addr       string   // host:port to dial (IP literal) — empty for DoH needing bootstrap
	ServerName string   // TLS server name (DoT/DoH)
	URL        string   // DoH URL without fragment
	Bootstrap  []string // DoH bootstrap IPs from the "#ip,ip" fragment
}

// ParseUpstream accepts:
//
//	1.1.1.1 | 1.1.1.1:53 | [2606:4700::1111]:53 | udp://1.1.1.1:53 | tcp://1.1.1.1:53
//	tls://1.1.1.1:853#cloudflare-dns.com   (SNI / certificate name after '#')
//	https://dns.google/dns-query           (optionally "#8.8.8.8,8.8.4.4" bootstrap IPs)
//	quic://94.140.14.14:853#dns.adguard-dns.com (DoQ; SNI / certificate name after '#')
func ParseUpstream(s string) (UpstreamAddr, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 512 {
		return UpstreamAddr{}, fmt.Errorf("empty or too long")
	}
	switch {
	case strings.HasPrefix(s, "https://"):
		raw, frag, _ := strings.Cut(s, "#")
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" {
			return UpstreamAddr{}, fmt.Errorf("invalid DoH URL")
		}
		host := u.Hostname()
		if host == "" {
			return UpstreamAddr{}, fmt.Errorf("invalid DoH host")
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return UpstreamAddr{}, fmt.Errorf("invalid port")
		}
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		ua := UpstreamAddr{Proto: ProtoDoH, URL: u.String(), ServerName: host}
		if ip, err := netip.ParseAddr(host); err == nil {
			ua.Addr = net.JoinHostPort(ip.String(), port)
		}
		if frag != "" {
			for _, b := range strings.Split(frag, ",") {
				ip, err := netip.ParseAddr(strings.TrimSpace(b))
				if err != nil {
					return UpstreamAddr{}, fmt.Errorf("invalid bootstrap IP %q", b)
				}
				ua.Bootstrap = append(ua.Bootstrap, net.JoinHostPort(ip.String(), port))
			}
		}
		return ua, nil
	case strings.HasPrefix(s, "tls://"), strings.HasPrefix(s, "quic://"):
		scheme, rest0, _ := strings.Cut(s, "://")
		rest, name, _ := strings.Cut(rest0, "#")
		ap, err := hostPort(rest, 853)
		if err != nil {
			return UpstreamAddr{}, err
		}
		if name == "" {
			name = ap.Addr().String()
		} else if !validHostname(name) {
			return UpstreamAddr{}, fmt.Errorf("invalid TLS server name")
		}
		proto := ProtoDoT
		if scheme == "quic" {
			proto = ProtoDoQ
		}
		return UpstreamAddr{Proto: proto, Addr: ap.String(), ServerName: name}, nil
	case strings.HasPrefix(s, "tcp://"):
		ap, err := hostPort(strings.TrimPrefix(s, "tcp://"), 53)
		if err != nil {
			return UpstreamAddr{}, err
		}
		return UpstreamAddr{Proto: ProtoTCP, Addr: ap.String()}, nil
	default:
		ap, err := hostPort(strings.TrimPrefix(s, "udp://"), 53)
		if err != nil {
			return UpstreamAddr{}, err
		}
		return UpstreamAddr{Proto: ProtoUDP, Addr: ap.String()}, nil
	}
}

func hostPort(s string, def uint16) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() == 0 {
			return netip.AddrPort{}, fmt.Errorf("invalid port")
		}
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("address must be an IP literal (host names need a bootstrap)")
	}
	return netip.AddrPortFrom(a.Unmap(), def), nil
}

var hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)

func validHostname(s string) bool { return len(s) <= 253 && hostnameRe.MatchString(s) }
