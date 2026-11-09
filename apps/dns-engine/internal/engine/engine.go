// Package engine is the DNS core: it owns the persisted state (settings,
// zones, overrides), compiles it into an immutable policy snapshot that the
// query path reads lock-free, answers queries (fast wire path for cache hits
// and a full path for everything else) and applies administrative changes
// atomically with hot reload.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/cache"
	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/dnssec"
	"mrk/dns-engine/internal/iterative"
	"mrk/dns-engine/internal/limits"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/querylog"
	"mrk/dns-engine/internal/resolver"
	"mrk/dns-engine/internal/store"
	"mrk/dns-engine/internal/zone"
)

// Options configure an Engine.
type Options struct {
	DataDir       string
	DefaultListen string // MRK_DNS_LISTEN, first start only
	Logger        *slog.Logger
	// MaxClients bounds rate-limiter tables (0 = default).
	MaxClients int
	// Now is the clock of the monitoring components (default time.Now; the
	// query path always uses the real clock).
	Now func() time.Time
	// DiskFree overrides the query log's disk-free probe (tests).
	DiskFree querylog.DiskFreeFunc
	// IterTransport replaces the network of the iterative resolver (tests).
	IterTransport iterative.Transport
	// TrustAnchors replaces the built-in root trust anchors (tests).
	TrustAnchors []*dns.DS
	// FilterClient downloads block lists (tests; default: HTTPS-only client).
	FilterClient *http.Client
}

// Override is a local answer for a name without owning a zone.
type Override struct {
	ID       string `json:"id"`
	Name     string `json:"name"` // display form, may start with "*."
	Type     string `json:"type"` // A | AAAA | CNAME
	Value    string `json:"value"`
	TTL      uint32 `json:"ttl"`
	Source   string `json:"source"` // user | services
	Disabled bool   `json:"disabled"`
}

type settingsDoc struct {
	Schema        int             `json:"schema"`
	ConfigVersion int64           `json:"config_version"`
	Settings      config.Settings `json:"settings"`
}

type overridesDoc struct {
	Schema int        `json:"schema"`
	Items  []Override `json:"items"`
}

// policy is the immutable snapshot read by the query path.
type policy struct {
	s             config.Settings
	configVersion int64
	queryACL      *acl.List
	recACL        *acl.List
	zones         *zone.Set
	overrides     map[string]map[uint16][]dns.RR
	wildOverrides bool
	local         map[string]struct{} // wire-form suffixes needing the full path
	group         *resolver.Group
	fwd           map[string]*resolver.Group
	clientLim     *limits.ClientLimiter
	rrl           *limits.RRL
	upstreams     []*resolver.Upstream
	d4            d4policy
	enc           encPolicy
	pc            *policyCompiled // docs/41 §3: filtering, client groups, views (policy.go)
}

func (p *policy) recursionAllowed(a netip.Addr) bool {
	return p.s.Recursion.Enabled && p.recACL.Allowed(a)
}

// Engine is the DNS core.
type Engine struct {
	opts  Options
	log   *slog.Logger
	st    *store.Store
	pol   atomic.Pointer[policy]
	Cache *cache.Cache
	M     *metrics.Metrics
	mon   *monitor

	mu            sync.Mutex // serialises all state changes
	settings      config.Settings
	configVersion int64
	zones         map[string]*zone.Zone
	compiled      map[string]*zone.Compiled
	overrides     []Override
	upstreams     map[string]*resolver.Upstream // key id|address
	limiter       *resolver.Limiter
	limiterSize   int

	flight  resolver.Flight
	started time.Time
	bg      context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	listenerHook atomic.Pointer[func(config.Settings)]

	iter *iterative.Resolver // D4: resolution from the root
	val  *dnssec.Validator   // D4: DNSSEC validation
	d4   d4state
	enc  encState // D4 part B: encrypted transports, certificate, DoH tokens
	d5   d5state  // docs/41 §2: secondary, transfers, TSIG, update, signing (zones_d5.go)
	pst  polState // docs/41 §3: block lists, client groups, views (policy.go)

	actorMu sync.Mutex
	actor   atomic.Pointer[string]
}

// Open loads (or initialises) state from opts.DataDir.
func Open(opts Options) (*Engine, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := recoverRestore(opts.DataDir); err != nil { // an interrupted restore (backup.go)
		return nil, err
	}
	st, err := store.Open(opts.DataDir)
	if err != nil {
		return nil, fmt.Errorf("open data dir: %w", err)
	}
	e := &Engine{opts: opts, log: opts.Logger, st: st, M: metrics.New(),
		zones: map[string]*zone.Zone{}, compiled: map[string]*zone.Compiled{},
		upstreams: map[string]*resolver.Upstream{}, started: time.Now()}
	e.bg, e.cancel = context.WithCancel(context.Background())

	var sd settingsDoc
	switch err := st.ReadJSON("settings.json", &sd); {
	case errors.Is(err, fs.ErrNotExist):
		sd = settingsDoc{Schema: store.Schema, ConfigVersion: 1, Settings: config.Defaults(opts.DefaultListen)}
		if l := sd.Settings.Validate(); len(l) > 0 {
			return nil, fmt.Errorf("invalid MRK_DNS_LISTEN: %v", l.Err("settings_invalid", "invalid defaults"))
		}
		if err := st.WriteJSON("settings.json", sd); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("read settings: %w", err)
	}
	// fill fields added in later versions from defaults, then validate
	merged := config.Defaults(opts.DefaultListen)
	mergeSettings(&merged, sd.Settings)
	if l := merged.Validate(); len(l) > 0 {
		return nil, fmt.Errorf("stored settings invalid: %v", l.Err("settings_invalid", "invalid"))
	}
	e.settings, e.configVersion = merged, sd.ConfigVersion

	var od overridesDoc
	if err := st.ReadJSON("overrides.json", &od); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read overrides: %w", err)
	}
	e.overrides = od.Items

	if err := e.openD5(); err != nil {
		return nil, err
	}
	zs, warns := st.LoadZones()
	for _, w := range warns {
		e.log.Warn("zone load", "err", w)
	}
	for _, z := range zs {
		c, err := e.compileZone(z)
		if err != nil {
			e.log.Error("zone compile failed; zone not served", "zone", z.Name, "err", err)
			continue
		}
		e.zones[z.Name] = z
		e.compiled[z.Name] = c
	}
	e.Cache = cache.New(e.settings.Cache.MaxBytes)
	e.openD4()
	if err := e.openMonitor(); err != nil {
		return nil, err
	}
	e.openPolicy()
	if err := e.openEncrypted(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	err = e.rebuildLocked()
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	e.wg.Add(4)
	go e.maintenance()
	go e.pipeline()
	go e.d4Loop()
	go e.d5Loop()
	return e, nil
}

// mergeSettings overlays stored onto defaults (stored wins for set fields).
func mergeSettings(dst *config.Settings, src config.Settings) {
	if len(src.Listen) > 0 || src.UpstreamStrategy != "" {
		*dst = src
		d := config.Defaults("")
		if dst.UpstreamStrategy == "" {
			dst.UpstreamStrategy = d.UpstreamStrategy
		}
		if dst.Cache.MaxBytes == 0 {
			dst.Cache = d.Cache
		}
		if dst.Limits.UDPMaxSize == 0 {
			dst.Limits = d.Limits
		}
	}
	// D2 sections are absent from D1 settings files
	if dst.QueryLog.Mode == "" {
		dst.QueryLog = config.DefaultQueryLog()
	}
	if dst.Stats.TopK == 0 {
		dst.Stats = config.DefaultStats()
	}
	if dst.Pressure.CapacityQPS == 0 {
		dst.Pressure = config.DefaultPressure()
	}
	if dst.Pressure.AttackDetection.Mode == "" {
		dst.Pressure.AttackDetection = config.DefaultPressure().AttackDetection
	}
	// D4 sections (resolution, dnssec) are absent from D1-D3 settings files
	dst.FillD4Defaults()
}

// Close stops background work and upstream connections.
func (e *Engine) Close() {
	e.cancel()
	e.wg.Wait()
	e.closePolicy()
	e.closeEncrypted()
	e.closeMonitor()
	e.mu.Lock()
	for _, u := range e.upstreams {
		u.Close()
	}
	e.mu.Unlock()
}

// SetListenerHook registers a callback invoked after settings change.
func (e *Engine) SetListenerHook(f func(config.Settings)) { e.listenerHook.Store(&f) }

// Settings returns the current settings and config version.
func (e *Engine) Settings() (config.Settings, int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.settings.Clone(), e.configVersion
}

// Started returns the start time.
func (e *Engine) Started() time.Time { return e.started }

func (e *Engine) maintenance() {
	defer e.wg.Done()
	sec := time.NewTicker(time.Second)
	defer sec.Stop()
	n := 0
	for {
		select {
		case <-e.bg.Done():
			return
		case <-sec.C:
		}
		e.M.Tick()
		n++
		p := e.pol.Load()
		if n%10 == 0 {
			now := time.Now().UnixNano()
			p.clientLim.Sweep(now)
			p.rrl.Sweep(now)
		}
		if n%15 == 0 {
			ctx, cancel := context.WithTimeout(e.bg, 5*time.Second)
			p.group.HealthCheck(ctx, 15*time.Second)
			for _, g := range p.fwd {
				g.HealthCheck(ctx, 15*time.Second)
			}
			cancel()
		}
	}
}

// localNames are always answered on the full path (RFC 6761/6303 and the
// special names handled in localAnswer).
var localNames = []string{
	"localhost.", "invalid.",
	"10.in-addr.arpa.", "127.in-addr.arpa.", "254.169.in-addr.arpa.", "168.192.in-addr.arpa.", "0.in-addr.arpa.",
	"16.172.in-addr.arpa.", "17.172.in-addr.arpa.", "18.172.in-addr.arpa.", "19.172.in-addr.arpa.",
	"20.172.in-addr.arpa.", "21.172.in-addr.arpa.", "22.172.in-addr.arpa.", "23.172.in-addr.arpa.",
	"24.172.in-addr.arpa.", "25.172.in-addr.arpa.", "26.172.in-addr.arpa.", "27.172.in-addr.arpa.",
	"28.172.in-addr.arpa.", "29.172.in-addr.arpa.", "30.172.in-addr.arpa.", "31.172.in-addr.arpa.",
	"c.f.ip6.arpa.", "d.f.ip6.arpa.", "8.e.f.ip6.arpa.", "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", "b.e.f.ip6.arpa.",
	"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
	"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
}

func wireName(name string) string {
	buf := make([]byte, 256)
	n, err := dns.PackDomainName(strings.ToLower(dns.Fqdn(name)), buf, 0, nil, false)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

func (e *Engine) upstreamFor(id, raw string, enabled bool, boot resolver.Bootstrap, reuse map[string]*resolver.Upstream) (*resolver.Upstream, error) {
	key := fmt.Sprintf("%s|%s|%t", id, raw, enabled)
	if old := e.upstreams[key]; old != nil {
		reuse[key] = old // keep pooled connections and health state
		return old, nil
	}
	if old := reuse[key]; old != nil {
		return old, nil
	}
	u, err := resolver.NewUpstream(id, raw, enabled, boot, e.M)
	if err != nil {
		return nil, err
	}
	reuse[key] = u
	return u, nil
}

// rebuildLocked compiles a new policy from the current state and swaps it in.
func (e *Engine) rebuildLocked() error {
	s := e.settings
	qa, err := acl.Compile(s.QueryAllow)
	if err != nil {
		return err
	}
	ra, err := acl.Compile(s.Recursion.Allow)
	if err != nil {
		return err
	}
	if e.limiter == nil || e.limiterSize != s.Limits.MaxInflightUpstream {
		e.limiter = resolver.NewLimiter(s.Limits.MaxInflightUpstream)
		e.limiterSize = s.Limits.MaxInflightUpstream
	}
	p := &policy{s: s.Clone(), configVersion: e.configVersion, queryACL: qa, recACL: ra,
		fwd: map[string]*resolver.Group{}, local: map[string]struct{}{}, overrides: map[string]map[uint16][]dns.RR{}}

	next := map[string]*resolver.Upstream{}
	var ups []*resolver.Upstream
	for _, cu := range s.Upstreams {
		u, err := e.upstreamFor(cu.ID, cu.Address, cu.Enabled, e.bootstrap, next)
		if err != nil {
			return err
		}
		ups = append(ups, u)
	}
	p.upstreams = ups
	p.group = resolver.NewGroup(ups, s.UpstreamStrategy, e.limiter)

	var comp []*zone.Compiled
	for name, z := range e.zones {
		c := e.compiled[name]
		if c == nil || z.Disabled {
			continue
		}
		comp = append(comp, c)
		p.local[wireName(name)] = struct{}{}
		if z.Type == zone.TypeForwarder {
			var fu []*resolver.Upstream
			for i, f := range z.Forwarders {
				u, err := e.upstreamFor(fmt.Sprintf("zone:%s#%d", zone.Display(name), i), f, true, e.bootstrap, next)
				if err != nil {
					return err
				}
				fu = append(fu, u)
			}
			p.fwd[name] = resolver.NewGroup(fu, config.StrategyInOrder, e.limiter)
		}
	}
	p.zones = zone.NewSet(comp)
	for _, n := range localNames {
		p.local[wireName(n)] = struct{}{}
	}
	if s.Overrides.Enabled {
		for _, o := range e.overrides {
			if o.Disabled {
				continue
			}
			rr, err := overrideRR(o)
			if err != nil {
				continue
			}
			name := strings.ToLower(dns.Fqdn(o.Name))
			m := p.overrides[name]
			if m == nil {
				m = map[uint16][]dns.RR{}
				p.overrides[name] = m
			}
			m[rr.Header().Rrtype] = append(m[rr.Header().Rrtype], rr)
			if strings.HasPrefix(name, "*.") {
				p.wildOverrides = true
				p.local[wireName(name[2:])] = struct{}{}
			} else {
				p.local[wireName(name)] = struct{}{}
			}
		}
	}
	old := e.pol.Load()
	l := s.Limits
	if old != nil && old.s.Limits.ClientQPS == l.ClientQPS && old.s.Limits.ClientBurst == l.ClientBurst {
		p.clientLim = old.clientLim
	} else {
		p.clientLim = limits.NewClientLimiterFor(l.ClientQPS, l.ClientBurst, e.opts.MaxClients)
		if e.mon != nil {
			p.clientLim.SetScale(e.acts().ClientQPSScale)
		}
	}
	if old != nil && old.s.Limits.RRLResponsesPerSecond == l.RRLResponsesPerSecond && old.s.Limits.RRLSlip == l.RRLSlip &&
		old.s.Limits.RRLIPv4Prefix == l.RRLIPv4Prefix && old.s.Limits.RRLIPv6Prefix == l.RRLIPv6Prefix {
		p.rrl = old.rrl
	} else {
		p.rrl = limits.NewRRL(l.RRLResponsesPerSecond, l.RRLSlip, l.RRLIPv4Prefix, l.RRLIPv6Prefix, e.opts.MaxClients)
	}
	if e.Cache != nil && e.Cache.MaxBytes() != s.Cache.MaxBytes {
		e.Cache.SetMaxBytes(s.Cache.MaxBytes)
	}
	e.configureD4Locked(p, old)
	e.configurePolicyLocked(p, old)
	if err := e.configureEncryptedLocked(p); err != nil {
		return err
	}
	e.pol.Store(p)
	// close transports of upstreams that are gone (after the swap)
	for k, u := range e.upstreams {
		if _, ok := next[k]; !ok || next[k] != u {
			go u.Close()
		}
	}
	e.upstreams = next
	return nil
}

func overrideRR(o Override) (dns.RR, error) {
	h := dns.RR_Header{Name: strings.ToLower(dns.Fqdn(o.Name)), Class: dns.ClassINET, Ttl: o.TTL}
	switch o.Type {
	case "A":
		a, err := netip.ParseAddr(o.Value)
		if err != nil || !a.Unmap().Is4() {
			return nil, fmt.Errorf("invalid IPv4")
		}
		h.Rrtype = dns.TypeA
		return &dns.A{Hdr: h, A: a.Unmap().AsSlice()}, nil
	case "AAAA":
		a, err := netip.ParseAddr(o.Value)
		if err != nil || !a.Is6() || a.Is4In6() {
			return nil, fmt.Errorf("invalid IPv6")
		}
		h.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: h, AAAA: a.AsSlice()}, nil
	case "CNAME":
		h.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: h, Target: strings.ToLower(dns.Fqdn(o.Value))}, nil
	}
	return nil, fmt.Errorf("unsupported type")
}

// bootstrap resolves DoH host names through the plain (UDP/TCP) upstreams.
func (e *Engine) bootstrap(ctx context.Context, host string) ([]string, error) {
	p := e.pol.Load()
	if p == nil {
		return nil, errors.New("not ready")
	}
	var plain []*resolver.Upstream
	for _, u := range p.upstreams {
		if u.Enabled && (u.Addr.Proto == config.ProtoUDP || u.Addr.Proto == config.ProtoTCP) {
			plain = append(plain, u)
		}
	}
	var out []string
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for _, u := range plain {
			cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			r, _, err := u.Exchange(cctx, resolver.NewQuery(host, t))
			cancel()
			if err != nil || r.Rcode != dns.RcodeSuccess {
				continue
			}
			for _, rr := range r.Answer {
				switch v := rr.(type) {
				case *dns.A:
					out = append(out, v.A.String())
				case *dns.AAAA:
					out = append(out, v.AAAA.String())
				}
			}
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("bootstrap: cannot resolve %s via plain upstreams", host)
	}
	return out, nil
}
