package engine

import (
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/querylog"
	"mrk/dns-engine/internal/tsig"
	"mrk/dns-engine/internal/zone"
)

// RFC 2136 dynamic update (docs/41 §2.4).

func updateAllowed(cfg *zone.UpdateConfig, client netip.Addr, v tsig.Verdict) bool {
	if cfg == nil || !cfg.Enabled {
		return false
	}
	if len(cfg.Allow) > 0 {
		l, err := acl.Compile(cfg.Allow)
		if err != nil || !l.Allowed(client) {
			return false
		}
	}
	keyOK := v.OK && (cfg.TSIGKey == "" || strings.EqualFold(v.Key, dns.Fqdn(cfg.TSIGKey)))
	if cfg.RequireTSIG {
		return keyOK
	}
	return !v.Signed || keyOK
}

func (e *Engine) handleUpdate(pkt []byte, req *dns.Msg, client netip.Addr, proto Proto) []byte {
	start := time.Now()
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer, resp.Ns, resp.Extra = nil, nil, nil
	finish := func(rcode int, v tsig.Verdict) []byte {
		resp.Rcode = rcode
		b, _ := e.packSigned(resp, v, "", false)
		src := querylog.SrcAuthoritative
		if rcode == dns.RcodeRefused || rcode == dns.RcodeNotAuth {
			src = querylog.SrcRefused
		}
		e.recordMsg(req, client, proto, start, rcode, src, len(b), 0, "")
		return b
	}
	if len(req.Question) != 1 || req.Question[0].Qtype != dns.TypeSOA || req.Question[0].Qclass != dns.ClassINET {
		return finish(dns.RcodeFormatError, tsig.Verdict{})
	}
	v := e.d5.tsig.Check(pkt, req)
	if v.Signed && !v.OK {
		return tsig.ErrorResponse(resp, req, v)
	}
	name := strings.ToLower(req.Question[0].Name)
	z := e.zoneDoc(name)
	switch {
	case z == nil || z.Type == zone.TypeForwarder:
		return finish(dns.RcodeNotAuth, v)
	case z.Type == zone.TypeSecondary:
		return finish(dns.RcodeRefused, v) // read-only copy (no update forwarding)
	case !updateAllowed(z.Update, client, v):
		return finish(dns.RcodeRefused, v)
	}
	actor := "update:" + client.String()
	if v.OK {
		actor = "update:" + zone.Display(v.Key)
	}
	rcode := dns.RcodeServerFailure
	_ = e.WithActor(actor, func() error {
		rcode = e.applyUpdate(name, req)
		return nil
	})
	return finish(rcode, v)
}

// applyUpdate checks prerequisites and applies the update atomically.
func (e *Engine) applyUpdate(fq string, req *dns.Msg) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	old := e.zones[fq]
	if old == nil || old.Type != zone.TypePrimary {
		return dns.RcodeNotAuth
	}
	inZone := func(n string) bool { return dns.IsSubDomain(fq, strings.ToLower(n)) }
	rel := func(n string) string { return zone.RelativeName(strings.ToLower(n), fq) }
	// index of enabled records: owner -> type -> indexes
	idx := func(recs []zone.Record) map[string]map[string][]int {
		m := map[string]map[string][]int{}
		for i, r := range recs {
			if r.Disabled || r.View != "" {
				continue
			}
			if m[r.Name] == nil {
				m[r.Name] = map[string][]int{}
			}
			m[r.Name][r.Type] = append(m[r.Name][r.Type], i)
		}
		return m
	}
	cur := idx(old.Records)
	inUse := func(owner string) bool { return owner == "@" || len(cur[owner]) > 0 }
	typeName := func(t uint16) string { return dns.TypeToString[t] }

	// prerequisites (RFC 2136 §3.2)
	valueSets := map[string][]zone.Record{}
	for _, rr := range req.Answer {
		h := rr.Header()
		if h.Ttl != 0 {
			return dns.RcodeFormatError
		}
		if !inZone(h.Name) {
			return dns.RcodeNotZone
		}
		owner := rel(h.Name)
		switch h.Class {
		case dns.ClassANY:
			if h.Rdlength != 0 {
				return dns.RcodeFormatError
			}
			if h.Rrtype == dns.TypeANY {
				if !inUse(owner) {
					return dns.RcodeNameError
				}
			} else if !rrsetExists(old, cur, owner, h.Rrtype) {
				return dns.RcodeNXRrset
			}
		case dns.ClassNONE:
			if h.Rdlength != 0 {
				return dns.RcodeFormatError
			}
			if h.Rrtype == dns.TypeANY {
				if inUse(owner) {
					return dns.RcodeYXDomain
				}
			} else if rrsetExists(old, cur, owner, h.Rrtype) {
				return dns.RcodeYXRrset
			}
		case dns.ClassINET:
			r, err := zone.FromRR(rr, fq)
			if err != nil {
				return dns.RcodeNXRrset // a type we do not hold cannot exist
			}
			k := owner + "|" + r.Type
			valueSets[k] = append(valueSets[k], r)
		default:
			return dns.RcodeFormatError
		}
	}
	for k, want := range valueSets {
		owner, t, _ := strings.Cut(k, "|")
		have := cur[owner][t]
		if len(have) != len(want) {
			return dns.RcodeNXRrset
		}
		for _, w := range want {
			found := false
			for _, i := range have {
				if string(old.Records[i].Data) == string(w.Data) {
					found = true
				}
			}
			if !found {
				return dns.RcodeNXRrset
			}
		}
	}

	// prescan (RFC 2136 §3.4.1)
	type op struct {
		class uint16
		rtype uint16
		owner string
		rec   zone.Record
	}
	var ops []op
	for _, rr := range req.Ns {
		h := rr.Header()
		if !inZone(h.Name) {
			return dns.RcodeNotZone
		}
		switch h.Rrtype {
		case dns.TypeAXFR, dns.TypeIXFR, dns.TypeMAILA, dns.TypeMAILB, dns.TypeOPT, dns.TypeTSIG:
			return dns.RcodeFormatError
		}
		o := op{class: h.Class, rtype: h.Rrtype, owner: rel(h.Name)}
		switch h.Class {
		case dns.ClassINET:
			if h.Rrtype == dns.TypeANY {
				return dns.RcodeFormatError
			}
			if h.Rrtype == dns.TypeSOA {
				continue // the engine manages the SOA
			}
			r, err := zone.FromRR(rr, fq)
			if err != nil {
				return dns.RcodeRefused // record type not supported by the zone model
			}
			if r.TTL > zone.MaxTTL {
				r.TTL = zone.MaxTTL
			}
			o.rec = r
		case dns.ClassANY:
			if h.Ttl != 0 || h.Rdlength != 0 {
				return dns.RcodeFormatError
			}
		case dns.ClassNONE:
			if h.Ttl != 0 || h.Rrtype == dns.TypeANY {
				return dns.RcodeFormatError
			}
			if h.Rrtype == dns.TypeSOA {
				continue
			}
			r, err := zone.FromRR(rr, fq)
			if err != nil {
				continue // deleting a record we cannot hold is a no-op
			}
			o.rec = r
		default:
			return dns.RcodeFormatError
		}
		ops = append(ops, o)
	}

	// apply (RFC 2136 §3.4.2)
	z := old.Clone()
	z.Serial = old.Serial
	recs := append([]zone.Record(nil), z.Records...)
	changed := false
	remove := func(keep func(r *zone.Record) bool) {
		out := recs[:0:0]
		for i := range recs {
			if keep(&recs[i]) {
				out = append(out, recs[i])
			} else {
				changed = true
			}
		}
		recs = out
	}
	for _, o := range ops {
		switch o.class {
		case dns.ClassINET:
			r := o.rec
			hasCNAME, hasOther := false, false
			dup := -1
			for i := range recs {
				if recs[i].Name != r.Name || recs[i].Disabled || recs[i].View != "" {
					continue
				}
				if recs[i].Type == "CNAME" {
					hasCNAME = true
				} else {
					hasOther = true
				}
				if recs[i].Type == r.Type && string(recs[i].Data) == string(r.Data) {
					dup = i
				}
			}
			if r.Type == "CNAME" && hasOther || r.Type != "CNAME" && hasCNAME {
				continue // RFC 2136 §3.4.2.2: CNAME exclusivity, ignore
			}
			if r.Type == "CNAME" && hasCNAME {
				remove(func(x *zone.Record) bool { return !(x.Name == r.Name && x.Type == "CNAME") })
			}
			if dup >= 0 && r.Type != "CNAME" {
				if recs[dup].TTL != r.TTL {
					recs[dup].TTL = r.TTL
					zone.SyncRRsetTTL(recs, dup)
					changed = true
				}
				continue
			}
			r.Comment = "dynamic update"
			recs = append(recs, r)
			zone.SyncRRsetTTL(recs, len(recs)-1)
			changed = true
		case dns.ClassANY:
			t := typeName(o.rtype)
			remove(func(x *zone.Record) bool {
				if x.Name != o.owner || x.View != "" {
					return true
				}
				if o.owner == "@" && (x.Type == "NS" || x.Type == "SOA") {
					return true // apex SOA/NS are never removed this way
				}
				return o.rtype != dns.TypeANY && x.Type != t
			})
		case dns.ClassNONE:
			r := o.rec
			if r.Name == "@" && r.Type == "NS" {
				n := 0
				for i := range recs {
					if recs[i].Name == "@" && recs[i].Type == "NS" && !recs[i].Disabled {
						n++
					}
				}
				if n <= 1 {
					continue // the last apex NS stays
				}
			}
			remove(func(x *zone.Record) bool {
				return x.View != "" || !(x.Name == r.Name && x.Type == r.Type && string(x.Data) == string(r.Data))
			})
		}
	}
	if !changed {
		return dns.RcodeSuccess
	}
	z.Records = recs
	if l := zone.ValidateRecords(z.Name, z.Records); len(l) > 0 {
		return dns.RcodeRefused
	}
	if err := e.commitZoneLocked(old, z, "update"); err != nil {
		e.log.Warn("dynamic update failed", "zone", fq, "err", err)
		return dns.RcodeServerFailure
	}
	return dns.RcodeSuccess
}

func rrsetExists(_ *zone.Zone, cur map[string]map[string][]int, owner string, t uint16) bool {
	if t == dns.TypeSOA {
		return owner == "@"
	}
	return len(cur[owner][dns.TypeToString[t]]) > 0
}
