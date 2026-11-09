package iterative

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/cache"
	"mrk/dns-engine/internal/testutil"
	"mrk/dns-engine/internal/trace"
)

// server behaviours of the simulated network
type server struct {
	zone      *testutil.Zone
	tcOnUDP   bool // always truncate over UDP
	lowerCase bool // does not preserve 0x20 case
	noEDNS    bool // FORMERR when EDNS is present
	dead      bool
	handler   func(q *dns.Msg) *dns.Msg
}

type simNet struct {
	mu      sync.Mutex
	servers map[netip.Addr]*server
	log     []string // "addr qname qtype tcp"
}

func (n *simNet) Exchange(ctx context.Context, ap netip.AddrPort, m *dns.Msg, tcp bool) (*dns.Msg, error) {
	n.mu.Lock()
	s := n.servers[ap.Addr()]
	proto := "udp"
	if tcp {
		proto = "tcp"
	}
	n.log = append(n.log, ap.Addr().String()+" "+m.Question[0].Name+" "+dns.TypeToString[m.Question[0].Qtype]+" "+proto)
	n.mu.Unlock()
	if s == nil || s.dead {
		<-ctx.Done()
		return nil, ErrTimeout
	}
	if s.noEDNS && m.IsEdns0() != nil {
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeFormatError)
		return r, nil
	}
	var r *dns.Msg
	if s.handler != nil {
		r = s.handler(m)
	} else {
		do := m.IsEdns0() != nil && m.IsEdns0().Do()
		r = s.zone.Answer(m.Question[0], do)
	}
	r = r.Copy()
	r.Id = m.Id
	r.Response = true
	r.Question = []dns.Question{m.Question[0]}
	if s.lowerCase {
		r.Question[0].Name = strings.ToLower(r.Question[0].Name)
	}
	if s.tcOnUDP && !tcp {
		r.Answer, r.Ns, r.Extra = nil, nil, nil
		r.Truncated = true
	}
	return r, nil
}

func (n *simNet) count(addr string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, l := range n.log {
		if strings.HasPrefix(l, addr+" ") {
			c++
		}
	}
	return c
}

func (n *simNet) queries(addr string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for _, l := range n.log {
		if strings.HasPrefix(l, addr+" ") {
			out = append(out, strings.TrimPrefix(l, addr+" "))
		}
	}
	return out
}

const (
	rootIP  = "192.0.2.1"
	comIP   = "192.0.2.10"
	orgIP   = "192.0.2.11"
	exIP    = "192.0.2.20"
	ex2IP   = "192.0.2.21"
	otherIP = "192.0.2.30"
)

type sim struct {
	n    *simNet
	r    *Resolver
	root *testutil.Zone
	com  *testutil.Zone
	org  *testutil.Zone
	ex   *testutil.Zone
}

func newSim(t *testing.T, mut func(c *Config)) *sim {
	t.Helper()
	root := testutil.NewZone(".", true)
	com := testutil.NewZone("com.", true)
	org := testutil.NewZone("org.", true)
	ex := testutil.NewZone("example.com.", true)
	other := testutil.NewZone("other.org.", true)
	root.Delegate(com, "a.gtld.net.", "")
	root.Add("a.gtld.net. 3600 IN A " + comIP) // out of bailiwick of com but inside the root zone
	root.Delegate(org, "a0.org.", "")
	root.Add("a0.org. 3600 IN A " + orgIP)
	com.Delegate(ex, "ns1.example.com.", exIP)
	com.Add("example.com. 3600 IN NS ns2.example.com.", "ns2.example.com. 3600 IN A "+ex2IP)
	ex.Add("example.com. 3600 IN NS ns1.example.com.", "example.com. 3600 IN NS ns2.example.com.",
		"ns1.example.com. 3600 IN A "+exIP, "ns2.example.com. 3600 IN A "+ex2IP,
		"www.example.com. 300 IN A 203.0.113.1",
		"alias.example.com. 300 IN CNAME www.other.org.",
		"loop1.example.com. 300 IN CNAME loop2.example.com.",
		"loop2.example.com. 300 IN CNAME loop1.example.com.")
	// other.org is served by a name server whose name is in .com and whose
	// "glue" in .org is out of bailiwick (must be ignored)
	org.Add("other.org. 3600 IN NS ns.other-dns.com.", "ns.other-dns.com. 3600 IN A 192.0.2.66")
	com.Add("other-dns.com. 3600 IN NS ns1.example.com.")
	ex.Add("ns.other-dns.com. 300 IN A " + otherIP)
	other.Add("other.org. 3600 IN NS ns.other-dns.com.", "www.other.org. 300 IN A 203.0.113.2")
	n := &simNet{servers: map[netip.Addr]*server{
		netip.MustParseAddr(rootIP):  {zone: root},
		netip.MustParseAddr(comIP):   {zone: com},
		netip.MustParseAddr(orgIP):   {zone: org},
		netip.MustParseAddr(exIP):    {zone: ex},
		netip.MustParseAddr(ex2IP):   {zone: ex},
		netip.MustParseAddr(otherIP): {zone: other},
	}}
	// other-dns.com's server (ns1.example.com) answers for both zones
	n.servers[netip.MustParseAddr(exIP)].handler = func(q *dns.Msg) *dns.Msg {
		if dns.IsSubDomain("other-dns.com.", strings.ToLower(q.Question[0].Name)) {
			m := new(dns.Msg)
			m.SetQuestion(q.Question[0].Name, q.Question[0].Qtype)
			m.Authoritative = true
			if strings.EqualFold(q.Question[0].Name, "ns.other-dns.com.") && q.Question[0].Qtype == dns.TypeA {
				rr, _ := dns.NewRR("ns.other-dns.com. 300 IN A " + otherIP)
				m.Answer = []dns.RR{rr}
			}
			return m
		}
		return ex.Answer(q.Question[0], false)
	}
	c := cache.New(8 << 20)
	r := New(c, n, 1000)
	cfg := Config{QNameMin: "relaxed", UseV4: true, CaseRandom: true, MaxReferrals: 30, MaxQueries: 100,
		MaxNSPerZone: 13, QueryTimeout: 300 * time.Millisecond, MaxTTL: 86400,
		Hints: []Server{{Name: "a.root-servers.net.", Addr: netip.MustParseAddr(rootIP)}}}
	if mut != nil {
		mut(&cfg)
	}
	r.Configure(cfg, nil, 1000)
	return &sim{n: n, r: r, root: root, com: com, org: org, ex: ex}
}

func firstA(t *testing.T, m *dns.Msg) string {
	t.Helper()
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

func TestIterativeBasic(t *testing.T) {
	s := newSim(t, nil)
	tr := &trace.Trace{}
	m, err := s.r.Resolve(trace.With(context.Background(), tr, false), "www.example.com.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if firstA(t, m) != "203.0.113.1" || m.Rcode != dns.RcodeSuccess {
		t.Fatalf("answer %v", m)
	}
	steps := tr.Steps()
	if len(steps) < 3 || steps[0].Zone != "." || len(steps[0].Referral) == 0 {
		t.Fatalf("trace %+v", steps)
	}
	// delegations are cached: the root is not asked again
	before := s.n.count(rootIP)
	if _, err := s.r.Resolve(context.Background(), "nope.example.com.", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if s.n.count(rootIP) != before {
		t.Fatal("root asked again despite the cached delegation")
	}
	m, _ = s.r.Resolve(context.Background(), "nope.example.com.", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("NXDOMAIN expected: %v", m.Rcode)
	}
}

func TestQNameMinimisation(t *testing.T) {
	s := newSim(t, nil)
	if _, err := s.r.Resolve(context.Background(), "a.b.www.example.com.", dns.TypeAAAA); err != nil {
		t.Fatal(err)
	}
	for _, q := range s.n.queries(rootIP) {
		if !strings.HasPrefix(strings.ToLower(q), "com. a ") {
			t.Fatalf("root saw more than needed: %q", q)
		}
	}
	for _, q := range s.n.queries(comIP) {
		if !strings.HasPrefix(strings.ToLower(q), "example.com. a ") {
			t.Fatalf("com saw more than needed: %q", q)
		}
	}
	off := newSim(t, func(c *Config) { c.QNameMin = "off" })
	if _, err := off.r.Resolve(context.Background(), "www.example.com.", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if q := off.n.queries(rootIP); len(q) == 0 || !strings.HasPrefix(strings.ToLower(q[0]), "www.example.com. a") {
		t.Fatalf("minimisation off: %v", q)
	}
}

func TestOutOfBailiwickGlueIgnored(t *testing.T) {
	s := newSim(t, nil)
	m, err := s.r.Resolve(context.Background(), "alias.example.com.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Answer) != 2 || firstA(t, m) != "203.0.113.2" {
		t.Fatalf("CNAME across zones: %v", m.Answer)
	}
	if s.n.count("192.0.2.66") != 0 {
		t.Fatal("out-of-bailiwick glue was used")
	}
}

func TestCNAMELoop(t *testing.T) {
	s := newSim(t, nil)
	if _, err := s.r.Resolve(context.Background(), "loop1.example.com.", dns.TypeA); !errors.Is(err, ErrLoop) {
		t.Fatalf("CNAME loop: %v", err)
	}
}

func TestReferralLimits(t *testing.T) {
	// a server that refers to itself for its own zone is lame, not followed forever
	s := newSim(t, nil)
	s.n.servers[netip.MustParseAddr(exIP)].handler = func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(q.Question[0].Name, q.Question[0].Qtype)
		ns, _ := dns.NewRR("sub.example.com. 300 IN NS ns1.example.com.")
		glue, _ := dns.NewRR("ns1.example.com. 300 IN A " + exIP)
		m.Ns, m.Extra = []dns.RR{ns}, []dns.RR{glue}
		return m
	}
	s.n.servers[netip.MustParseAddr(ex2IP)].dead = true
	if _, err := s.r.Resolve(context.Background(), "x.sub.example.com.", dns.TypeA); err == nil {
		t.Fatal("self-referral resolved")
	}
	if n := s.n.count(exIP); n > 10 {
		t.Fatalf("self-referral queried %d times", n)
	}
	// an endless chain of ever deeper delegations stops at max_referrals
	d := newSim(t, func(c *Config) { c.MaxReferrals = 3 })
	d.n.servers[netip.MustParseAddr(exIP)].handler = func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		qn := strings.ToLower(q.Question[0].Name)
		m.SetQuestion(qn, q.Question[0].Qtype)
		ns, _ := dns.NewRR(qn + " 300 IN NS ns1.example.com.")
		glue, _ := dns.NewRR("ns1.example.com. 300 IN A " + exIP)
		m.Ns, m.Extra = []dns.RR{ns}, []dns.RR{glue}
		return m
	}
	d.n.servers[netip.MustParseAddr(ex2IP)].dead = true
	_, err := d.r.Resolve(context.Background(), "a.b.c.d.e.f.g.example.com.", dns.TypeA)
	if !errors.Is(err, ErrTooManyReferrals) {
		t.Fatalf("deep delegation chain: %v", err)
	}
}

func TestTruncationFallsBackToTCP(t *testing.T) {
	s := newSim(t, nil)
	s.n.servers[netip.MustParseAddr(exIP)].tcOnUDP = true
	s.n.servers[netip.MustParseAddr(ex2IP)].tcOnUDP = true
	m, err := s.r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
	if err != nil || firstA(t, m) != "203.0.113.1" {
		t.Fatal(m, err)
	}
	tcp := false
	for _, q := range append(s.n.queries(exIP), s.n.queries(ex2IP)...) {
		if strings.HasSuffix(q, " tcp") {
			tcp = true
		}
	}
	if !tcp {
		t.Fatal("no TCP retry after TC")
	}
}

func TestDeadServerAndNoReachable(t *testing.T) {
	s := newSim(t, nil)
	s.n.servers[netip.MustParseAddr(exIP)].dead = true
	m, err := s.r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
	if err != nil || firstA(t, m) != "203.0.113.1" {
		t.Fatalf("one dead name server: %v %v", m, err)
	}
	s2 := newSim(t, nil)
	s2.n.servers[netip.MustParseAddr(exIP)].dead = true
	s2.n.servers[netip.MustParseAddr(ex2IP)].dead = true
	if _, err := s2.r.Resolve(context.Background(), "www.example.com.", dns.TypeA); !errors.Is(err, ErrNoReachable) {
		t.Fatalf("all dead: %v", err)
	}
}

func TestCaseRandomisationFallback(t *testing.T) {
	s := newSim(t, func(c *Config) { c.QNameMin = "off" })
	s.n.servers[netip.MustParseAddr(rootIP)].lowerCase = true
	if _, err := s.r.Resolve(context.Background(), "www.example.com.", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if !s.r.Infra.Get(netip.MustParseAddr(rootIP)).No0x20 {
		// the random case may have been all lower-case: retry a few names
		for _, n := range []string{"abcdefghij.example.com.", "klmnopqrst.example.com.", "uvwxyzabcd.example.com."} {
			_, _ = s.r.Resolve(trace.With(context.Background(), nil, true), n, dns.TypeA)
		}
	}
	if !s.r.Infra.Get(netip.MustParseAddr(rootIP)).No0x20 {
		t.Fatal("0x20 not disabled for a case-insensitive server")
	}
}

func TestEDNSFallback(t *testing.T) {
	s := newSim(t, nil)
	s.n.servers[netip.MustParseAddr(comIP)].noEDNS = true
	if _, err := s.r.Resolve(context.Background(), "www.example.com.", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if !s.r.Infra.Get(netip.MustParseAddr(comIP)).NoEDNS {
		t.Fatal("NoEDNS not remembered")
	}
}

func TestDSAskedFromParent(t *testing.T) {
	s := newSim(t, nil)
	if _, err := s.r.Resolve(context.Background(), "www.example.com.", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	before := s.n.count(exIP) + s.n.count(ex2IP)
	m, err := s.r.Resolve(context.Background(), "example.com.", dns.TypeDS)
	if err != nil {
		t.Fatal(err)
	}
	if s.n.count(exIP)+s.n.count(ex2IP) != before {
		t.Fatal("DS question sent to the child zone")
	}
	if m.Rcode != dns.RcodeSuccess {
		t.Fatal(m)
	}
}

func TestPrivateAndSelfServersRefused(t *testing.T) {
	s := newSim(t, nil)
	s.com.Add("private.com. 3600 IN NS ns.private.com.", "ns.private.com. 3600 IN A 10.0.0.53")
	s.n.servers[netip.MustParseAddr("10.0.0.53")] = &server{zone: s.ex}
	if _, err := s.r.Resolve(context.Background(), "www.private.com.", dns.TypeA); !errors.Is(err, ErrNoReachable) {
		t.Fatalf("private name server queried: %v", err)
	}
	if s.n.count("10.0.0.53") != 0 {
		t.Fatal("query sent to a private address")
	}
	self := newSim(t, func(c *Config) {
		c.Self = map[netip.AddrPort]struct{}{netip.MustParseAddrPort(exIP + ":53"): {}, netip.MustParseAddrPort(ex2IP + ":53"): {}}
	})
	if _, err := self.r.Resolve(context.Background(), "www.example.com.", dns.TypeA); err == nil {
		t.Fatal("resolved through our own address")
	}
	if self.n.count(exIP)+self.n.count(ex2IP) != 0 {
		t.Fatal("query sent to our own listen address")
	}
}

func TestBudget(t *testing.T) {
	s := newSim(t, func(c *Config) { c.MaxQueries = 10 })
	// twelve in-zone CNAME hops need a query each
	for i := 0; i < 12; i++ {
		s.ex.Add(fmt.Sprintf("c%d.example.com. 300 IN CNAME c%d.example.com.", i, i+1))
	}
	s.ex.Add("c12.example.com. 300 IN A 203.0.113.12")
	if _, err := s.r.Resolve(context.Background(), "c0.example.com.", dns.TypeA); !errors.Is(err, ErrBudget) {
		t.Fatalf("budget not enforced: %v", err)
	}
	ok := newSim(t, nil)
	for i := 0; i < 12; i++ {
		ok.ex.Add(fmt.Sprintf("c%d.example.com. 300 IN CNAME c%d.example.com.", i, i+1))
	}
	ok.ex.Add("c12.example.com. 300 IN A 203.0.113.12")
	m, err := ok.r.Resolve(context.Background(), "c0.example.com.", dns.TypeA)
	if err != nil || firstA(t, m) != "203.0.113.12" || len(m.Answer) != 13 {
		t.Fatalf("long chain: %v %v", m, err)
	}
}

func TestPriming(t *testing.T) {
	s := newSim(t, nil)
	rootSrv := s.n.servers[netip.MustParseAddr(rootIP)]
	rootSrv.handler = func(q *dns.Msg) *dns.Msg {
		if q.Question[0].Name == "." && q.Question[0].Qtype == dns.TypeNS {
			m := new(dns.Msg)
			m.SetQuestion(".", dns.TypeNS)
			m.Authoritative = true
			for _, s := range []string{". 518400 IN NS x.root-servers.net.", ". 518400 IN NS y.root-servers.net."} {
				rr, _ := dns.NewRR(s)
				m.Answer = append(m.Answer, rr)
			}
			for _, s := range []string{"x.root-servers.net. 518400 IN A " + rootIP, "y.root-servers.net. 518400 IN A 192.0.2.2"} {
				rr, _ := dns.NewRR(s)
				m.Extra = append(m.Extra, rr)
			}
			return m
		}
		return s.root.Answer(q.Question[0], false)
	}
	ps := s.r.Prime(context.Background())
	if !ps.OK || ps.ServersReachable != 1 || ps.Error != "" {
		t.Fatalf("priming %+v", ps)
	}
	if got := s.r.rootServers(); len(got) != 2 || got[0].Name != "x.root-servers.net." {
		t.Fatalf("root set %+v", got)
	}
	if st := s.r.PrimeStatus(); !st.OK {
		t.Fatal(st)
	}
	dead := newSim(t, nil)
	dead.n.servers[netip.MustParseAddr(rootIP)].dead = true
	if ps := dead.r.Prime(context.Background()); ps.OK || ps.Error == "" {
		t.Fatalf("dead root primed: %+v", ps)
	}
}
