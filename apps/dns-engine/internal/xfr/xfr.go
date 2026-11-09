// Package xfr implements zone transfers (RFC 5936 AXFR, RFC 1995 IXFR):
// the secondary side (SOA check, fetch, IXFR application with fallback to
// AXFR) and the helpers of the primary side (message chunking, IXFR diff).
package xfr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Limits.
const (
	// MaxMessage is the largest transfer message (TCP, 2-byte length).
	MaxMessage = 65535
	// ChunkBytes is the uncompressed RR budget of one outgoing message.
	ChunkBytes = 16 << 10
	// MaxRRs bounds an incoming zone.
	MaxRRs = 400_000
	// MaxBytes bounds the RR data of an incoming transfer.
	MaxBytes = 256 << 20
	// Timeout of a whole incoming transfer.
	Timeout = 5 * time.Minute
)

// Signer adds TSIG to outgoing requests and verifies responses.
type Signer struct {
	Key       string            // FQDN key name ("" = unsigned)
	Algorithm string            // wire algorithm name
	Secrets   map[string]string // FQDN -> secret
}

func (s *Signer) apply(m *dns.Msg) {
	if s != nil && s.Key != "" {
		m.SetTsig(s.Key, s.Algorithm, 300, time.Now().Unix())
	}
}

func (s *Signer) secrets() map[string]string {
	if s == nil || s.Key == "" {
		return nil
	}
	return s.Secrets
}

// NormalizeAddr returns ip:port (default port 53) or false.
func NormalizeAddr(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String(), ap.Port() != 0
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return netip.AddrPortFrom(a.Unmap(), 53).String(), true
	}
	return "", false
}

// QuerySOA asks addr for zone's SOA (UDP, TCP on truncation).
func QuerySOA(ctx context.Context, addr, zone string, sg *Signer) (*dns.SOA, error) {
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeSOA)
	m.RecursionDesired = false
	sg.apply(m)
	timeout := 3 * time.Second
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < timeout {
		timeout = time.Until(dl)
	}
	c := &dns.Client{Net: "udp", Timeout: timeout, TsigSecret: sg.secrets()}
	r, _, err := c.ExchangeContext(ctx, m, addr)
	if err == nil && r.Truncated {
		c.Net = "tcp"
		sg.apply(m)
		r, _, err = c.ExchangeContext(ctx, m, addr)
	}
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("SOA query: %s", dns.RcodeToString[r.Rcode])
	}
	if !r.Authoritative {
		return nil, errors.New("SOA query: answer is not authoritative")
	}
	for _, rr := range r.Answer {
		if s, ok := rr.(*dns.SOA); ok && strings.EqualFold(s.Hdr.Name, zone) {
			return s, nil
		}
	}
	return nil, errors.New("SOA query: no SOA in the answer")
}

// Result of a fetch.
type Result struct {
	SOA         *dns.SOA
	RRs         []dns.RR // complete zone without SOA
	Incremental bool     // applied as IXFR
	UpToDate    bool
}

// Fetch transfers zone from addr. With cur (the current zone: SOA + data)
// it asks for IXFR and applies the differences; without, AXFR.
func Fetch(ctx context.Context, addr, zone string, cur *dns.SOA, data []dns.RR, sg *Signer) (Result, error) {
	m := new(dns.Msg)
	if cur != nil {
		m.SetIxfr(zone, cur.Serial, cur.Ns, cur.Mbox)
	} else {
		m.SetAxfr(zone)
	}
	sg.apply(m)
	d := net.Dialer{Timeout: 5 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, err
	}
	defer nc.Close()
	dl := time.Now().Add(Timeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		dl = cdl
	}
	_ = nc.SetDeadline(dl)
	stop := context.AfterFunc(ctx, func() { nc.Close() })
	defer stop()
	t := &dns.Transfer{Conn: &dns.Conn{Conn: nc}, TsigSecret: sg.secrets(), ReadTimeout: 30 * time.Second}
	ch, err := t.In(m, addr)
	if err != nil {
		return Result{}, err
	}
	var all []dns.RR
	bytes := 0
	var ferr error
	for env := range ch {
		if env.Error != nil {
			ferr = env.Error
			continue
		}
		if ferr != nil {
			continue
		}
		for _, rr := range env.RR {
			bytes += dns.Len(rr)
		}
		all = append(all, env.RR...)
		if len(all) > MaxRRs || bytes > MaxBytes {
			ferr = errors.New("transfer exceeds the size limit")
			nc.Close()
		}
	}
	if ferr != nil {
		return Result{}, ferr
	}
	return Parse(zone, all, cur, data)
}

// Parse interprets the RRs of an AXFR or IXFR response.
func Parse(zone string, all []dns.RR, cur *dns.SOA, data []dns.RR) (Result, error) {
	if len(all) == 0 {
		return Result{}, errors.New("empty transfer")
	}
	first, ok := all[0].(*dns.SOA)
	if !ok || !strings.EqualFold(first.Hdr.Name, zone) {
		return Result{}, errors.New("transfer does not start with the zone SOA")
	}
	for _, rr := range all {
		h := rr.Header()
		if h.Class != dns.ClassINET {
			return Result{}, fmt.Errorf("record %s has class %d", h.Name, h.Class)
		}
		if !dns.IsSubDomain(zone, strings.ToLower(h.Name)) {
			return Result{}, fmt.Errorf("record %s is outside the zone", h.Name)
		}
	}
	if len(all) == 1 {
		if cur != nil && !serialLess(cur.Serial, first.Serial) {
			return Result{SOA: first, RRs: data, UpToDate: true}, nil
		}
		return Result{}, errors.New("transfer has only a SOA")
	}
	if _, isSOA := all[1].(*dns.SOA); isSOA && cur != nil && len(all) > 2 {
		return applyIXFR(zone, all, cur, data)
	}
	// AXFR form: SOA data… SOA
	last, ok := all[len(all)-1].(*dns.SOA)
	if !ok || last.Serial != first.Serial {
		return Result{}, errors.New("transfer does not end with the zone SOA")
	}
	var rrs []dns.RR
	for _, rr := range all[1 : len(all)-1] {
		if rr.Header().Rrtype == dns.TypeSOA {
			return Result{}, errors.New("unexpected SOA inside the transfer")
		}
		rrs = append(rrs, rr)
	}
	return Result{SOA: first, RRs: Dedup(rrs)}, nil
}

// Key identifies an RR for set operations (lower-case owner, full rdata).
func Key(rr dns.RR) string {
	c := dns.Copy(rr)
	c.Header().Name = strings.ToLower(c.Header().Name)
	c.Header().Ttl = 0
	return strings.ToLower(c.String())
}

// Dedup removes duplicate RRs keeping the first.
func Dedup(rrs []dns.RR) []dns.RR {
	seen := make(map[string]bool, len(rrs))
	out := rrs[:0:0]
	for _, rr := range rrs {
		k := Key(rr)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, rr)
	}
	return out
}

func applyIXFR(zone string, all []dns.RR, cur *dns.SOA, data []dns.RR) (Result, error) {
	final := all[0].(*dns.SOA)
	set := make(map[string]dns.RR, len(data))
	var order []string
	for _, rr := range data {
		k := Key(rr)
		if _, ok := set[k]; !ok {
			order = append(order, k)
		}
		set[k] = rr
	}
	i := 1
	serial := cur.Serial
	for {
		if i >= len(all) {
			return Result{}, errors.New("IXFR ends before the final SOA")
		}
		from, ok := all[i].(*dns.SOA)
		if !ok {
			return Result{}, errors.New("IXFR: expected SOA of a deletion sequence")
		}
		if from.Serial == final.Serial && i == len(all)-1 {
			break // closing SOA
		}
		if from.Serial != serial {
			return Result{}, fmt.Errorf("IXFR: sequence from serial %d, have %d", from.Serial, serial)
		}
		i++
		for ; i < len(all); i++ {
			if _, ok := all[i].(*dns.SOA); ok {
				break
			}
			k := Key(all[i])
			if _, ok := set[k]; !ok {
				return Result{}, errors.New("IXFR deletes a record that does not exist")
			}
			delete(set, k)
		}
		if i >= len(all) {
			return Result{}, errors.New("IXFR: missing addition SOA")
		}
		to := all[i].(*dns.SOA)
		i++
		for ; i < len(all); i++ {
			if _, ok := all[i].(*dns.SOA); ok {
				break
			}
			k := Key(all[i])
			if _, ok := set[k]; !ok {
				order = append(order, k)
			}
			set[k] = all[i]
		}
		serial = to.Serial
	}
	if serial != final.Serial {
		return Result{}, fmt.Errorf("IXFR ends at serial %d, expected %d", serial, final.Serial)
	}
	out := make([]dns.RR, 0, len(set))
	for _, k := range order {
		if rr, ok := set[k]; ok {
			out = append(out, rr)
			delete(set, k)
		}
	}
	return Result{SOA: final, RRs: out, Incremental: true}, nil
}

func serialLess(s1, s2 uint32) bool {
	return s1 != s2 && ((s1 < s2 && s2-s1 < 1<<31) || (s1 > s2 && s1-s2 > 1<<31))
}

// SerialLess implements RFC 1982 s1 < s2.
func SerialLess(s1, s2 uint32) bool { return serialLess(s1, s2) }

// Diff returns the RRs to delete and add to turn old into cur.
func Diff(old, cur []dns.RR) (del, add []dns.RR) {
	om := map[string]dns.RR{}
	for _, rr := range old {
		om[Key(rr)] = rr
	}
	cm := map[string]bool{}
	for _, rr := range cur {
		k := Key(rr)
		cm[k] = true
		if _, ok := om[k]; !ok {
			add = append(add, rr)
		}
	}
	for _, rr := range old {
		if !cm[Key(rr)] {
			del = append(del, rr)
		}
	}
	sort.SliceStable(del, func(i, j int) bool { return del[i].Header().Name < del[j].Header().Name })
	return del, add
}

// Chunk splits rrs into message-sized groups (ChunkBytes uncompressed each).
func Chunk(rrs []dns.RR) [][]dns.RR {
	var out [][]dns.RR
	var cur []dns.RR
	size := 0
	for _, rr := range rrs {
		l := dns.Len(rr)
		if len(cur) > 0 && size+l > ChunkBytes {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, rr)
		size += l
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}
