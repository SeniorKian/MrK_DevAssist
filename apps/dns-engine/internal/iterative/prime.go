package iterative

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// PrimeInterval is how often the root set is re-primed (RFC 8109 §3).
const PrimeInterval = 24 * time.Hour

// PrimeStatus is reported in GET /v1/status resolution.root_priming.
type PrimeStatus struct {
	OK               bool      `json:"ok"`
	At               time.Time `json:"at"`
	ServersReachable int       `json:"servers_reachable"`
	Error            string    `json:"error,omitempty"`
	Done             bool      `json:"-"`
}

// PrimeStatus returns the last priming result.
func (r *Resolver) PrimeStatus() PrimeStatus {
	r.primeMu.Lock()
	defer r.primeMu.Unlock()
	return r.prime
}

// Prime asks the hint servers for ". NS" (RFC 8109), replaces the root set
// with the answer's servers and glue, then probes every root address.
func (r *Resolver) Prime(ctx context.Context) PrimeStatus {
	st := r.newState(context.Background())
	st.cfg = r.cfg.Load()
	st.tr = nil
	cfg := st.cfg
	hints := r.hints()
	usable := hints[:0:0]
	for _, h := range hints {
		if h.Addr.Is4() && cfg.UseV4 || h.Addr.Is6() && cfg.UseV6 {
			usable = append(usable, h)
		}
	}
	res := PrimeStatus{At: r.now().UTC(), Done: true}
	order := rand.Perm(len(usable))
	var roots []Server
	err := errors.New("no usable root hint for the configured IP version")
	for i, n := range order {
		if i >= 3 {
			break
		}
		h := usable[n]
		st.queries = 0
		resp, e := r.send(ctx, st, ".", cand{name: h.Name, addr: h.Addr}, ".", dns.TypeNS)
		if e != nil {
			err = e
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			err = errors.New("priming answer " + dns.RcodeToString[resp.Rcode])
			continue
		}
		roots = primeSet(resp, hints)
		if len(roots) == 0 {
			err = errors.New("priming answer has no root servers")
			continue
		}
		err = nil
		break
	}
	if err != nil {
		res.Error = err.Error()
		r.setPrime(res)
		return res
	}
	r.roots.Store(&roots)
	res.ServersReachable = r.probe(ctx, roots)
	res.OK = res.ServersReachable > 0
	if !res.OK {
		res.Error = "no root server answered the probe"
	}
	r.setPrime(res)
	return res
}

func (r *Resolver) setPrime(p PrimeStatus) {
	r.primeMu.Lock()
	r.prime = p
	r.primeMu.Unlock()
}

// primeSet builds the root set from a priming answer: the NS names of "."
// with their addresses from the additional section, falling back to the hint
// addresses of the same name.
func primeSet(resp *dns.Msg, hints []Server) []Server {
	var names []string
	seen := map[string]bool{}
	for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Ns...) {
		if ns, ok := rr.(*dns.NS); ok && ns.Hdr.Name == "." {
			n := strings.ToLower(ns.Ns)
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	addrs := map[string][]netip.Addr{}
	for _, rr := range resp.Extra {
		n := strings.ToLower(rr.Header().Name)
		if !seen[n] {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
				addrs[n] = append(addrs[n], a)
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				addrs[n] = append(addrs[n], a)
			}
		}
	}
	for _, h := range hints {
		if seen[h.Name] && len(addrs[h.Name]) == 0 {
			addrs[h.Name+"\x00hint"] = append(addrs[h.Name+"\x00hint"], h.Addr)
		}
	}
	var out []Server
	for _, n := range names {
		l := addrs[n]
		if len(l) == 0 {
			l = addrs[n+"\x00hint"]
		}
		for _, a := range l {
			out = append(out, Server{Name: n, Addr: a})
		}
	}
	return out
}

// probe sends ". SOA" to one address of every root name and counts answers.
func (r *Resolver) probe(ctx context.Context, roots []Server) int {
	cfg := r.cfg.Load()
	byName := map[string]Server{}
	for _, s := range roots {
		if _, ok := byName[s.Name]; ok {
			continue
		}
		if s.Addr.Is4() && cfg.UseV4 || s.Addr.Is6() && cfg.UseV6 {
			byName[s.Name] = s
		}
	}
	var n atomic.Int32
	var wg sync.WaitGroup
	for _, s := range byName {
		wg.Add(1)
		go func(s Server) {
			defer wg.Done()
			st := r.newState(context.Background())
			st.tr = nil
			resp, err := r.send(ctx, st, ".", cand{name: s.Name, addr: s.Addr}, ".", dns.TypeSOA)
			if err == nil && resp.Rcode == dns.RcodeSuccess {
				n.Add(1)
			}
		}(s)
	}
	wg.Wait()
	return int(n.Load())
}
