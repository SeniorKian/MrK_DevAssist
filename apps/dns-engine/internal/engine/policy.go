package engine

// Policy engine (docs/41 §3): block lists, client groups and split-horizon
// views. The compiled form lives in the immutable policy snapshot (p.pc) and
// is read lock-free by both query paths.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/cache"
	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/events"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/filter"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/pressure"
	"mrk/dns-engine/internal/resolver"
	"mrk/dns-engine/internal/zone"
)

// Event types of the policy engine.
const (
	EventFilterListFailed = "filter.list_failed"
)

// blockedTTL is the TTL of synthesised block answers.
const blockedTTL = 10

// polState is the mutable side of the policy engine (e.mu held).
type polState struct {
	svc     *filter.Service
	views   map[string]*viewEntry // zone name → compiled views
	gcaches map[string]*groupCache
	hooks   []RestoreHook // backup.go
}

type viewEntry struct {
	z      *zone.Zone
	byView map[string]*zone.Compiled
}

type groupCache struct {
	sig string
	c   *cache.Cache
}

// groupPolicy is the compiled policy of one client group (or the default).
type groupPolicy struct {
	id       string
	nets     *acl.List
	off      bool   // filtering "off": nothing is blocked or rewritten
	filter   bool   // the lists and the custom names apply
	mask     uint32 // active list bits (CustomBit included when filter)
	services *filter.Names
	group    *resolver.Group // nil = the default upstreams
	cache    *cache.Cache    // answers of group (separate from the shared cache)
	zones    *zone.Set       // split-horizon zone set (nil = p.zones)
}

// policyCompiled is the immutable policy of a snapshot.
type policyCompiled struct {
	groups  []*groupPolicy
	def     *groupPolicy
	fast    bool // the fast path must consult the policy
	action  string
	safe    bool
	matcher *filter.Service
}

func (pc *policyCompiled) groupFor(a netip.Addr) *groupPolicy {
	if pc == nil {
		return nil
	}
	if len(pc.groups) > 0 {
		a = a.Unmap()
		for _, g := range pc.groups {
			if g.nets.Allowed(a) {
				return g
			}
		}
	}
	return pc.def
}

// zonesFor returns the zone set seen by client (split horizon).
func (p *policy) zonesFor(client netip.Addr) *zone.Set {
	if g := p.pc.groupFor(client); g != nil && g.zones != nil {
		return g.zones
	}
	return p.zones
}

// decision is the policy outcome for one name.
type decision struct {
	block   bool
	safe    string // safe-search CNAME target
	listBit uint32
	custom  bool
	service string
	sub     bool
	off     int // matched suffix offset in the wire name
}

func (pc *policyCompiled) decide(gp *groupPolicy, wire []byte) decision {
	if gp == nil || gp.off {
		return decision{}
	}
	m := pc.matcher.Matcher()
	allowMask := uint32(0)
	if gp.filter {
		allowMask = gp.mask
	}
	if _, ok := m.AllowedBy(wire, allowMask|filter.CustomBit); ok {
		return decision{} // the allow list always wins
	}
	if gp.filter {
		if v, h := m.Match(wire, gp.mask); v == filter.Blocked {
			d := decision{block: true, sub: h.Sub, off: h.Off}
			if h.Mask&^filter.CustomBit != 0 {
				d.listBit = lowestBit(h.Mask &^ filter.CustomBit)
			} else {
				d.custom = true
			}
			return d
		}
	}
	if id, ok := gp.services.Match(wire); ok {
		return decision{block: true, service: id}
	}
	if pc.safe && gp.filter {
		if t, ok := filter.SafeSearch(wire); ok {
			return decision{safe: t}
		}
	}
	return decision{}
}

func lowestBit(m uint32) uint32 { return m & -m }

// fastPolicy reports whether a fast-path query must take the full path:
// the client's group resolves through its own upstreams, or the name is
// blocked or rewritten.
func (e *Engine) fastPolicy(p *policy, wire []byte, client netip.Addr) bool {
	gp := p.pc.groupFor(client)
	if gp == nil {
		return false
	}
	if gp.group != nil {
		return true
	}
	d := p.pc.decide(gp, wire)
	return d.block || d.safe != ""
}

// policyAnswer answers a blocked or rewritten name (ok=false: not affected).
func (e *Engine) policyAnswer(ctx context.Context, p *policy, gp *groupPolicy, req, resp *dns.Msg, qname string,
	qtype uint16) (*dns.Msg, answerMeta, bool) {
	var nb [256]byte
	d := p.pc.decide(gp, lowerWire(qname, nb[:]))
	switch {
	case d.block:
		meta := answerMeta{src: metrics.SrcBlocked}
		switch p.pc.action {
		case config.BlockRefuse:
			resp.Rcode = dns.RcodeRefused
		case config.BlockNullIP:
			h := dns.RR_Header{Name: req.Question[0].Name, Class: dns.ClassINET, Ttl: blockedTTL}
			switch qtype {
			case dns.TypeA:
				h.Rrtype = dns.TypeA
				resp.Answer = []dns.RR{&dns.A{Hdr: h, A: netip.IPv4Unspecified().AsSlice()}}
			case dns.TypeAAAA:
				h.Rrtype = dns.TypeAAAA
				resp.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: netip.IPv6Unspecified().AsSlice()}}
			}
		default:
			resp.Rcode = dns.RcodeNameError
		}
		addEDE(p, req, resp, dns.ExtendedErrorCodeBlocked, e.ruleText(d, qname))
		return resp, meta, true
	case d.safe != "":
		resp.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeCNAME,
			Class: dns.ClassINET, Ttl: 300}, Target: d.safe}}
		if qtype != dns.TypeCNAME && req.RecursionDesired {
			e.chase(ctx, p, resp, d.safe, qtype, 1)
		}
		return resp, answerMeta{src: metrics.SrcOverride}, true
	}
	return nil, answerMeta{}, false
}

// ruleText renders the matched rule ("list:<id> ||name^", "custom name", "service:<id>").
func (e *Engine) ruleText(d decision, qname string) string {
	name := matchedName(qname, d.off)
	switch {
	case d.service != "":
		return "service:" + d.service
	case d.custom:
		return "custom " + name
	}
	r := name
	if d.sub {
		r = "||" + name + "^"
	}
	return "list:" + e.pst.svc.ListOfBit(d.listBit) + " " + r
}

// matchedName returns the presentation name of the suffix at wire offset off
// (a wire offset equals the offset in the dotted form).
func matchedName(qname string, off int) string {
	n := strings.TrimSuffix(strings.ToLower(qname), ".")
	if off < 0 || off > len(n) {
		return n
	}
	return n[off:]
}

// ---------------------------------------------------------------- compile

func (e *Engine) openPolicy() {
	client := e.opts.FilterClient
	if client == nil {
		client = &http.Client{}
	}
	e.pst = polState{views: map[string]*viewEntry{}, gcaches: map[string]*groupCache{}}
	e.pst.svc = filter.New(filter.Options{Dir: filepath.Join(e.opts.DataDir, "filter-lists"), Client: client,
		Now: e.opts.Now, Log: e.log, MemCheck: pressure.CheckHeadroom,
		Busy: func() bool {
			l := e.PressureLevel()
			return l == "critical" || l == "emergency"
		},
		OnFail: func(id, code, detail string) {
			name := ""
			if p := e.pol.Load(); p != nil {
				for _, fl := range p.s.Filtering.Lists {
					if fl.ID == id {
						name = fl.Name
					}
				}
			}
			e.mon.ev.Emit(EventFilterListFailed, events.Warning, map[string]any{"list_id": id, "name": name,
				"error": code, "detail": detail})
		}})
}

func (e *Engine) closePolicy() {
	if e.pst.svc != nil {
		e.pst.svc.Close()
	}
}

// configurePolicyLocked compiles the policy of p (e.mu held).
func (e *Engine) configurePolicyLocked(p *policy, old *policy) {
	s := p.s
	f := s.Filtering
	anyOn := false
	for _, g := range s.ClientGroups {
		anyOn = anyOn || g.Filtering == config.GroupOn
	}
	eff := f
	eff.Enabled = f.Enabled || anyOn
	e.pst.svc.Configure(eff)

	all := filter.CustomBit
	for _, fl := range f.Lists {
		all |= e.pst.svc.BitOf(fl.ID)
	}
	pc := &policyCompiled{action: f.Action, safe: f.SafeSearch, matcher: e.pst.svc}
	pc.def = &groupPolicy{id: "", filter: f.Enabled, mask: all}

	flush := old != nil && (d4FlushNeeded(old.s, s) || old.s.RebindingProtection != s.RebindingProtection ||
		old.s.Cache.MinTTL != s.Cache.MinTTL || old.s.Cache.MaxTTL != s.Cache.MaxTTL)
	byID := map[string]*resolver.Upstream{}
	for _, u := range p.upstreams {
		byID[u.ID] = u
	}
	viewSets := e.viewSetsLocked(s)
	caches := map[string]*groupCache{}
	for _, g := range s.ClientGroups {
		nets, err := acl.Compile(g.Networks)
		if err != nil {
			continue // validated before; never happens
		}
		gp := &groupPolicy{id: g.ID, nets: nets, off: g.Filtering == config.GroupOff, zones: viewSets[g.ID]}
		switch g.Filtering {
		case config.GroupOn:
			gp.filter = true
		case config.GroupInherit:
			gp.filter = f.Enabled
		}
		gp.mask = all
		if len(g.Lists) > 0 {
			gp.mask = filter.CustomBit
			for _, id := range g.Lists {
				gp.mask |= e.pst.svc.BitOf(id)
			}
		}
		if len(g.BlockedServices) > 0 {
			m := map[string][]string{}
			for _, sv := range g.BlockedServices {
				m[sv] = config.BlockedServices[sv]
			}
			gp.services = filter.NewNames(m)
		}
		if len(g.Upstreams) > 0 {
			var ups []*resolver.Upstream
			for _, id := range g.Upstreams {
				if u := byID[id]; u != nil {
					ups = append(ups, u)
				}
			}
			gp.group = resolver.NewGroup(ups, s.UpstreamStrategy, e.limiter)
			size := s.Cache.MaxBytes / 8
			if size < 1<<20 {
				size = 1 << 20
			}
			sig := fmt.Sprintf("%s|%d", strings.Join(g.Upstreams, ","), size)
			gc := e.pst.gcaches[g.ID]
			if gc == nil || gc.sig != sig || flush {
				gc = &groupCache{sig: sig, c: cache.New(size)}
			}
			caches[g.ID] = gc
			gp.cache = gc.c
		}
		pc.groups = append(pc.groups, gp)
	}
	e.pst.gcaches = caches
	pc.fast = f.Enabled || anyOn
	for _, gp := range pc.groups {
		pc.fast = pc.fast || gp.group != nil || gp.services.Len() > 0
	}
	p.pc = pc
}

// viewSetsLocked builds, per client group that has view records in some
// zone, the zone set seen by that group.
func (e *Engine) viewSetsLocked(s config.Settings) map[string]*zone.Set {
	groups := map[string]bool{}
	for _, g := range s.ClientGroups {
		groups[g.ID] = true
	}
	next := map[string]*viewEntry{}
	used := map[string]bool{}
	for name, z := range e.zones {
		if z.Disabled || e.compiled[name] == nil {
			continue
		}
		ids := zone.ViewIDs(z)
		if len(ids) == 0 {
			continue
		}
		ve := e.pst.views[name]
		if ve == nil || ve.z != z {
			ve = &viewEntry{z: z, byView: map[string]*zone.Compiled{}}
		}
		for _, id := range ids {
			if !groups[id] {
				continue
			}
			if ve.byView[id] == nil {
				c, err := zone.CompileView(z, id)
				if err != nil {
					e.log.Warn("zone view compile failed; general records served", "zone", name, "view", id, "err", err)
					continue
				}
				ve.byView[id] = c
			}
			used[id] = true
		}
		next[name] = ve
	}
	e.pst.views = next
	out := map[string]*zone.Set{}
	for id := range used {
		var comp []*zone.Compiled
		for name, z := range e.zones {
			c := e.compiled[name]
			if c == nil || z.Disabled {
				continue
			}
			if ve := next[name]; ve != nil && ve.byView[id] != nil {
				c = ve.byView[id]
			}
			comp = append(comp, c)
		}
		out[id] = zone.NewSet(comp)
	}
	return out
}

// flushGroupCaches flushes name (or everything) in the group caches.
func (e *Engine) flushGroupCaches(name string) int {
	p := e.pol.Load()
	n := 0
	if p == nil || p.pc == nil {
		return 0
	}
	for _, g := range p.pc.groups {
		if g.cache != nil {
			n += g.cache.Flush(name)
		}
	}
	return n
}

// ---------------------------------------------------------------- group resolution

// recurseGroup resolves for a client group with its own upstreams, caching
// in the group's cache so its answers never mix with the shared cache.
func (e *Engine) recurseGroup(ctx context.Context, p *policy, gp *groupPolicy, req, resp *dns.Msg, qname string,
	qtype uint16) (*dns.Msg, answerMeta) {
	now := time.Now().UnixNano()
	key := cacheKey(qname, qtype)
	hit := func() *dns.Msg {
		if ent := gp.cache.Get(key, now); ent != nil && ent.Fresh(now) {
			return fromEntry(ent, qname, qtype, now, false)
		}
		if ent := gp.cache.Get(cacheKey(qname, nxType), now); ent != nil && ent.Fresh(now) {
			return fromEntry(ent, qname, qtype, now, false)
		}
		return nil
	}
	if r := hit(); r != nil {
		copySections(resp, r)
		meta := answerMeta{src: metrics.SrcCache}
		e.present(p, req, resp, &meta)
		return resp, meta
	}
	if !req.RecursionDesired {
		resp.Rcode = dns.RcodeRefused
		return resp, answerMeta{src: metrics.SrcRefused}
	}
	ch := e.flight.DoChan("g\x00"+gp.id+"\x00"+string(key), func() (any, error) {
		fctx, cancel := context.WithTimeout(e.bg, p.d4.resolveTimeout)
		defer cancel()
		q := resolver.NewQuery(qname, qtype)
		if p.s.DNSSEC.Mode != config.DNSSECOff {
			dnssecQuery(q)
		}
		e.M.Inflight.Add(1)
		r, u, err := gp.group.Exchange(fctx, q)
		e.M.Inflight.Add(-1)
		if err != nil {
			if errors.Is(err, resolver.ErrOverloaded) {
				e.M.Drop(metrics.DropOverload)
			}
			return nil, err
		}
		sec := e.validate(fctx, p, qname, qtype, r, gp.group, false)
		scrub(r, qname, qtype)
		if p.s.RebindingProtection && rebindFilter(r) {
			e.M.Rebinding.Add(1)
		}
		m := e.storeIn(gp.cache, p, qname, qtype, r, sec)
		return &fetchResult{msg: m, upstream: u.ID, sec: secInfo(sec)}, nil
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			resp.Rcode = dns.RcodeServerFailure
			return resp, answerMeta{src: metrics.SrcError}
		}
		fr := res.Val.(*fetchResult)
		copySections(resp, fr.msg)
		meta := fr.meta()
		e.present(p, req, resp, &meta)
		return resp, meta
	case <-ctx.Done():
		resp.Rcode = dns.RcodeServerFailure
		return resp, answerMeta{src: metrics.SrcError}
	}
}

// ---------------------------------------------------------------- API

// FilteringStatus is GET /v1/filtering/status.
type FilteringStatus struct {
	Enabled      bool                `json:"enabled"`
	Lists        []filter.ListStatus `json:"lists"`
	TotalEntries int                 `json:"total_entries"`
	Blocked1h    uint64              `json:"blocked_1h"`
	MemoryBytes  int64               `json:"memory_bytes"`
}

// FilteringStatus reports the lists.
func (e *Engine) FilteringStatus() FilteringStatus {
	p := e.pol.Load()
	m := e.pst.svc.Matcher()
	st := FilteringStatus{Enabled: p.s.Filtering.Enabled, Lists: e.pst.svc.Status(), TotalEntries: m.Len(),
		MemoryBytes: m.Bytes()}
	if r, ok := e.Stats("1h"); ok {
		st.Blocked1h = r.Totals.BySource["blocked"]
	}
	return st
}

// RefreshFiltering downloads every enabled list now and waits up to wait.
func (e *Engine) RefreshFiltering(ctx context.Context, wait time.Duration) FilteringStatus {
	cctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	e.pst.svc.Refresh(cctx)
	return e.FilteringStatus()
}

// WaitFiltering blocks until no list is due (tests, backup).
func (e *Engine) WaitFiltering(ctx context.Context) { e.pst.svc.WaitIdle(ctx) }

// FilterCheck is POST /v1/filtering/check.
type FilterCheck struct {
	Name     string `json:"name"`
	Blocked  bool   `json:"blocked"`
	ListID   string `json:"list_id,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Reason   string `json:"reason"` // list | custom_block | service | allow_list | safe_search | not_listed | filtering_off
	Service  string `json:"service,omitempty"`
	Group    string `json:"group,omitempty"`
	Rewrite  string `json:"rewrite,omitempty"`
	Filtered bool   `json:"filtering"` // filtering applies to this client
}

// CheckFilter explains the decision for name (client: optional IP selecting
// the client group).
func (e *Engine) CheckFilter(name, client string) (FilterCheck, error) {
	n, ok := config.NormalizeFilterName(name)
	if !ok || strings.HasPrefix(strings.TrimSpace(name), "*.") {
		return FilterCheck{}, fielderr.Single(CodeInvalidRequest, "invalid name", "name", "invalid_name")
	}
	var addr netip.Addr
	if client != "" {
		a, err := netip.ParseAddr(strings.TrimSpace(client))
		if err != nil {
			return FilterCheck{}, fielderr.Single(CodeInvalidRequest, "invalid client", "client", "invalid_client")
		}
		addr = a
	}
	p := e.pol.Load()
	pc := p.pc
	gp := pc.def
	if addr.IsValid() {
		gp = pc.groupFor(addr)
	}
	out := FilterCheck{Name: n, Group: gp.id, Filtered: gp.filter && !gp.off}
	wire := filter.AppendWire(nil, n)
	if gp.off {
		out.Reason = "filtering_off"
		return out, nil
	}
	allowMask := filter.CustomBit
	if gp.filter {
		allowMask |= gp.mask
	}
	if h, ok := pc.matcher.Matcher().AllowedBy(wire, allowMask); ok {
		out.Reason = "allow_list"
		out.Rule = matchedName(n+".", h.Off)
		if h.Mask&filter.CustomBit == 0 {
			out.ListID = e.pst.svc.ListOfBit(lowestBit(h.Mask))
			out.Rule = "@@||" + out.Rule + "^"
		}
		return out, nil
	}
	d := pc.decide(gp, wire)
	switch {
	case d.block && d.service != "":
		out.Blocked, out.Reason, out.Service = true, "service", d.service
	case d.block && d.custom:
		out.Blocked, out.Reason, out.Rule = true, "custom_block", matchedName(n+".", d.off)
	case d.block:
		out.Blocked, out.Reason, out.ListID = true, "list", e.pst.svc.ListOfBit(d.listBit)
		out.Rule = matchedName(n+".", d.off)
		if d.sub {
			out.Rule = "||" + out.Rule + "^"
		}
	case d.safe != "":
		out.Reason, out.Rewrite = "safe_search", strings.TrimSuffix(d.safe, ".")
	case !gp.filter && gp.services.Len() == 0:
		out.Reason = "filtering_off"
	default:
		out.Reason = "not_listed"
	}
	return out, nil
}

// ---------------------------------------------------------------- zone views

// ZoneView is one view declaration of a zone (docs/41 §3.3).
type ZoneView struct {
	GroupID         string `json:"group_id"`
	RecordsOverride *bool  `json:"records_override"`
}

// ZoneViewsView is the `views` key of GET /v1/zones/{zone} (primary zones):
// the declared views and the views used by records.
type ZoneViewsView struct {
	Views       []ZoneView `json:"views,omitempty"`
	RecordViews []string   `json:"record_views,omitempty"`
}

func zoneViewsView(z *zone.Zone) ZoneViewsView {
	if z.Type != zone.TypePrimary {
		return ZoneViewsView{}
	}
	out := ZoneViewsView{Views: []ZoneView{}, RecordViews: zone.ViewIDs(z)}
	if out.RecordViews == nil {
		out.RecordViews = []string{}
	}
	for _, v := range z.Views {
		o := v.Override()
		out.Views = append(out.Views, ZoneView{GroupID: v.GroupID, RecordsOverride: &o})
	}
	return out
}

// ZonePatchViews is the `views` key of PATCH /v1/zones/{zone}: the list
// replaces the declarations.
type ZonePatchViews struct {
	Views *[]ZoneView `json:"views"`
}

func applyPatchViews(z *zone.Zone, p ZonePatchViews) error {
	if p.Views == nil {
		return nil
	}
	if z.Type != zone.TypePrimary {
		return fielderr.Single(CodeZoneTypeMismatch, "only primary zones have views", "views", "not_allowed")
	}
	views := *p.Views
	var l fielderr.List
	if len(views) > config.MaxClientGroups {
		l.Add("views", "too_many", "max", config.MaxClientGroups)
	}
	seen := map[string]bool{}
	out := make([]zone.View, 0, len(views))
	for i, v := range views {
		if !zone.ValidViewID(v.GroupID) {
			l.Add(fmt.Sprintf("views[%d].group_id", i), "invalid_id")
		} else if seen[v.GroupID] {
			l.Add(fmt.Sprintf("views[%d].group_id", i), "duplicate")
		}
		seen[v.GroupID] = true
		out = append(out, zone.View{GroupID: v.GroupID, RecordsOverride: v.RecordsOverride})
	}
	if len(l) > 0 {
		return l.Err(CodeZoneInvalid, "invalid views")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].GroupID < out[j].GroupID })
	z.Views = out
	return nil
}
