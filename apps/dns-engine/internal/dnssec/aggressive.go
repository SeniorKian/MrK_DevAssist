package dnssec

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Aggressive use of DNSSEC-validated cache (RFC 8198), NSEC only: validated
// NXDOMAIN proofs are kept per zone and later queries for names they cover
// are answered without asking.

const (
	maxNSECZones   = 2000
	maxNSECPerZone = 512
)

type nsecItem struct {
	rr     *dns.NSEC
	sigs   []dns.RR
	expire time.Time
}

type nsecZone struct {
	soa    []dns.RR // SOA + its RRSIG
	expire time.Time
	items  map[string]*nsecItem // owner -> item
}

type nsecCache struct {
	mu    sync.Mutex
	zones map[string]*nsecZone
}

func newNSECCache() *nsecCache { return &nsecCache{zones: map[string]*nsecZone{}} }

func (c *nsecCache) flush() {
	c.mu.Lock()
	c.zones = map[string]*nsecZone{}
	c.mu.Unlock()
}

// learn stores the NSEC records and SOA of a validated (secure) NXDOMAIN.
func (c *nsecCache) learn(msg *dns.Msg, now time.Time) {
	var soa []dns.RR
	zone := ""
	var negTTL uint32
	for _, rr := range msg.Ns {
		if s, ok := rr.(*dns.SOA); ok {
			zone = lower(s.Hdr.Name)
			negTTL = s.Hdr.Ttl
			if s.Minttl < negTTL {
				negTTL = s.Minttl
			}
			soa = append(soa, rr)
		}
	}
	if zone == "" {
		return
	}
	for _, rr := range msg.Ns {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeSOA {
			soa = append(soa, rr)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	z := c.zones[zone]
	if z == nil {
		if len(c.zones) >= maxNSECZones {
			for k := range c.zones { // random eviction keeps this O(1)
				delete(c.zones, k)
				break
			}
		}
		z = &nsecZone{items: map[string]*nsecItem{}}
		c.zones[zone] = z
	}
	z.soa = soa
	z.expire = now.Add(time.Duration(negTTL) * time.Second)
	for _, rr := range msg.Ns {
		n, ok := rr.(*dns.NSEC)
		if !ok || !dns.IsSubDomain(zone, lower(n.Hdr.Name)) {
			continue
		}
		ttl := n.Hdr.Ttl
		if negTTL < ttl {
			ttl = negTTL
		}
		it := &nsecItem{rr: n, expire: now.Add(time.Duration(ttl) * time.Second)}
		for _, x := range msg.Ns {
			if sig, ok := x.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeNSEC && strings.EqualFold(sig.Hdr.Name, n.Hdr.Name) {
				it.sigs = append(it.sigs, x)
			}
		}
		if len(z.items) >= maxNSECPerZone {
			for k := range z.items {
				delete(z.items, k)
				break
			}
		}
		z.items[lower(n.Hdr.Name)] = it
	}
}

// Synthesize returns a secure NXDOMAIN for qname from cached NSEC proofs, or
// nil. The returned TTLs are the remaining lifetimes.
func (v *Validator) Synthesize(qname string, qtype uint16) *dns.Msg {
	if !v.cfg.Load().Aggressive || v.NTAFor(qname) {
		return nil
	}
	c := v.nsec
	now := v.now()
	qname = lower(qname)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.zones) == 0 {
		return nil
	}
	for n := qname; ; n = parentOf(n) {
		z := c.zones[n]
		if z != nil && now.Before(z.expire) {
			var live []*dns.NSEC
			byOwner := map[string]*nsecItem{}
			for k, it := range z.items {
				if now.Before(it.expire) {
					live = append(live, it.rr)
					byOwner[k] = it
				} else {
					delete(z.items, k)
				}
			}
			if nxNSEC(live, qname) != proofOK {
				return nil
			}
			cov := nsecCovering(live, qname)
			ce := nsecCloser(cov, qname)
			wild := "*." + ce
			if ce == "." {
				wild = "*."
			}
			wcov := nsecCovering(live, wild)
			m := new(dns.Msg)
			m.SetQuestion(qname, qtype)
			m.Response = true
			m.Rcode = dns.RcodeNameError
			left := uint32(z.expire.Sub(now) / time.Second)
			add := func(rrs []dns.RR) {
				for _, rr := range rrs {
					cp := dns.Copy(rr)
					if cp.Header().Ttl > left {
						cp.Header().Ttl = left
					}
					m.Ns = append(m.Ns, cp)
				}
			}
			add(z.soa)
			for _, n := range []*dns.NSEC{cov, wcov} {
				it := byOwner[lower(n.Hdr.Name)]
				if n == wcov && wcov == cov {
					break
				}
				add(append([]dns.RR{it.rr}, it.sigs...))
			}
			return m
		}
		if n == "." {
			return nil
		}
	}
}
