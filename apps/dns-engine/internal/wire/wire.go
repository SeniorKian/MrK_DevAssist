// Package wire contains allocation-free helpers for the DNS hot path: a strict
// minimal parser for ordinary queries and pre-packed response templates whose
// ID, question casing and TTLs are patched in place when served from cache.
//
// Anything the fast parser does not fully understand is rejected (ok=false) so
// the caller falls back to the full miekg/dns decoder, which then produces the
// correct FORMERR/NOTIMP/BADVERS behaviour.
package wire

import (
	"encoding/binary"
	"errors"
)

// Header flag bits (RFC 1035 §4.1.1).
const (
	FlagQR = 1 << 15
	FlagAA = 1 << 10
	FlagTC = 1 << 9
	FlagRD = 1 << 8
	FlagRA = 1 << 7
	FlagAD = 1 << 5
	FlagCD = 1 << 4

	opcodeMask = 0x7800
	rcodeMask  = 0x000f

	TypeOPT  = 41
	ClassIN  = 1
	HeaderSz = 12
	// MaxKey is the largest cache key: 255 octets of name + 2 of type.
	MaxKey = 257
)

// Query is the result of ParseQuery. Key aliases the caller's buffer.
type Query struct {
	ID       uint16
	Flags    uint16
	QNameLen int // wire length of QNAME including the root label
	QType    uint16
	QClass   uint16
	HasEDNS  bool
	UDPSize  uint16
	DO       bool
	Key      []byte // lower-cased QNAME wire + QTYPE (big endian)
}

// QName returns the raw (case preserved) QNAME bytes of pkt.
func (q *Query) QName(pkt []byte) []byte { return pkt[HeaderSz : HeaderSz+q.QNameLen] }

// RD reports whether recursion was desired.
func (q *Query) RD() bool { return q.Flags&FlagRD != 0 }

// CD reports the checking-disabled bit.
func (q *Query) CD() bool { return q.Flags&FlagCD != 0 }

// ParseQuery parses a standard query with exactly one question and at most one
// OPT record. keyBuf must have capacity >= MaxKey. It never allocates.
func ParseQuery(pkt []byte, keyBuf []byte) (q Query, ok bool) {
	if len(pkt) < HeaderSz+5 {
		return q, false
	}
	q.ID = binary.BigEndian.Uint16(pkt[0:])
	q.Flags = binary.BigEndian.Uint16(pkt[2:])
	if q.Flags&FlagQR != 0 || q.Flags&opcodeMask != 0 || q.Flags&FlagTC != 0 {
		return q, false
	}
	qd := binary.BigEndian.Uint16(pkt[4:])
	an := binary.BigEndian.Uint16(pkt[6:])
	ns := binary.BigEndian.Uint16(pkt[8:])
	ar := binary.BigEndian.Uint16(pkt[10:])
	if qd != 1 || an != 0 || ns != 0 || ar > 1 {
		return q, false
	}
	key := keyBuf[:0]
	off := HeaderSz
	for {
		if off >= len(pkt) {
			return q, false
		}
		l := int(pkt[off])
		if l == 0 {
			key = append(key, 0)
			off++
			break
		}
		if l > 63 { // compression pointers or extended labels are not valid here
			return q, false
		}
		if off+1+l > len(pkt) || len(key)+1+l+1 > 255 {
			return q, false
		}
		key = append(key, byte(l))
		for _, c := range pkt[off+1 : off+1+l] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			key = append(key, c)
		}
		off += 1 + l
	}
	q.QNameLen = off - HeaderSz
	if off+4 > len(pkt) {
		return q, false
	}
	q.QType = binary.BigEndian.Uint16(pkt[off:])
	q.QClass = binary.BigEndian.Uint16(pkt[off+2:])
	off += 4
	if q.QClass != ClassIN {
		return q, false
	}
	if ar == 1 {
		// OPT: root owner, type 41, class=udp size, ttl=ext-rcode|version|flags, rdlen, rdata
		if off+11 > len(pkt) || pkt[off] != 0 {
			return q, false
		}
		if binary.BigEndian.Uint16(pkt[off+1:]) != TypeOPT {
			return q, false
		}
		q.HasEDNS = true
		q.UDPSize = binary.BigEndian.Uint16(pkt[off+3:])
		if pkt[off+5] != 0 || pkt[off+6] != 0 { // ext rcode / version 0 only
			return q, false
		}
		q.DO = pkt[off+7]&0x80 != 0
		rdlen := int(binary.BigEndian.Uint16(pkt[off+9:]))
		off += 11
		// validate option framing
		end := off + rdlen
		if end > len(pkt) {
			return q, false
		}
		for o := off; o < end; {
			if o+4 > end {
				return q, false
			}
			ol := int(binary.BigEndian.Uint16(pkt[o+2:]))
			o += 4 + ol
			if o > end {
				return q, false
			}
		}
		off = end
	}
	if off != len(pkt) {
		return q, false
	}
	key = append(key, byte(q.QType>>8), byte(q.QType))
	q.Key = key
	return q, true
}

// AppendKey appends the cache key for an already lower-cased-or-not wire name.
func AppendKey(dst []byte, nameWire []byte, qtype uint16) []byte {
	for _, c := range nameWire {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return append(dst, byte(qtype>>8), byte(qtype))
}

// ErrMalformed is returned for responses that cannot be walked.
var ErrMalformed = errors.New("wire: malformed message")

// skipName returns the offset after a (possibly compressed) name at off.
func skipName(msg []byte, off int) (int, error) {
	for hops := 0; hops < 128; hops++ {
		if off >= len(msg) {
			return 0, ErrMalformed
		}
		c := int(msg[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				return off + 1, nil
			}
			off += 1 + c
		case 0xC0:
			if off+2 > len(msg) {
				return 0, ErrMalformed
			}
			return off + 2, nil
		default:
			return 0, ErrMalformed
		}
	}
	return 0, ErrMalformed
}

// Template is a packed response kept in the cache. The question is stored as
// packed (owner case of the first resolver query); Render patches it per client.
type Template struct {
	Wire       []byte
	QNameLen   int
	TTLOffsets []uint16
	TTLs       []uint32
	MinTTL     uint32 // smallest TTL in the message (0 if no records)
	Rcode      int
	Records    int
	// Sec is the DNSSEC status of the cached answer (docs/40 §2.2).
	Sec SecInfo
	// DNSSEC is the variant with RRSIG/NSEC/NSEC3 records for DO=1 clients
	// (nil when the answer carries none); the template itself is stripped.
	DNSSEC *Template
}

// SecInfo is the validation result stored with a cached answer.
type SecInfo struct {
	State  uint8 // dnssec.State
	EDE    uint16
	HasEDE bool
	Reason string
	Text   string
}

// NewTemplate walks a packed response (which must not contain an OPT record)
// and records TTL offsets. The ID is zeroed.
func NewTemplate(packed []byte) (*Template, error) {
	if len(packed) < HeaderSz || len(packed) > 0xffff {
		return nil, ErrMalformed
	}
	t := &Template{Wire: packed}
	binary.BigEndian.PutUint16(t.Wire[0:], 0)
	flags := binary.BigEndian.Uint16(packed[2:])
	t.Rcode = int(flags & rcodeMask)
	qd := int(binary.BigEndian.Uint16(packed[4:]))
	if qd != 1 {
		return nil, ErrMalformed
	}
	rrs := int(binary.BigEndian.Uint16(packed[6:])) + int(binary.BigEndian.Uint16(packed[8:])) + int(binary.BigEndian.Uint16(packed[10:]))
	off, err := skipName(packed, HeaderSz)
	if err != nil {
		return nil, err
	}
	// The question name must not be compressed (it is the first name).
	if packed[off-1] != 0 {
		return nil, ErrMalformed
	}
	t.QNameLen = off - HeaderSz
	off += 4
	if off > len(packed) {
		return nil, ErrMalformed
	}
	t.MinTTL = ^uint32(0)
	for i := 0; i < rrs; i++ {
		off, err = skipName(packed, off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(packed) {
			return nil, ErrMalformed
		}
		if binary.BigEndian.Uint16(packed[off:]) == TypeOPT {
			return nil, ErrMalformed
		}
		ttlOff := off + 4
		ttl := binary.BigEndian.Uint32(packed[ttlOff:])
		if ttl > 0x7fffffff { // RFC 2181 §8
			ttl = 0
		}
		t.TTLOffsets = append(t.TTLOffsets, uint16(ttlOff))
		t.TTLs = append(t.TTLs, ttl)
		if ttl < t.MinTTL {
			t.MinTTL = ttl
		}
		rdlen := int(binary.BigEndian.Uint16(packed[off+8:]))
		off += 10 + rdlen
		if off > len(packed) {
			return nil, ErrMalformed
		}
	}
	if off != len(packed) {
		return nil, ErrMalformed
	}
	if rrs == 0 {
		t.MinTTL = 0
	}
	t.Records = rrs
	return t, nil
}

// ClampTTLs rewrites every TTL into [min,max] and returns the new minimum.
func (t *Template) ClampTTLs(minTTL, maxTTL uint32) {
	t.MinTTL = ^uint32(0)
	for i := range t.TTLs {
		v := t.TTLs[i]
		if v < minTTL {
			v = minTTL
		}
		if maxTTL > 0 && v > maxTTL {
			v = maxTTL
		}
		t.TTLs[i] = v
		binary.BigEndian.PutUint32(t.Wire[t.TTLOffsets[i]:], v)
		if v < t.MinTTL {
			t.MinTTL = v
		}
	}
	if len(t.TTLs) == 0 {
		t.MinTTL = 0
	}
}

// RenderOpts controls Render.
type RenderOpts struct {
	ID       uint16
	ReqFlags uint16 // request header flags (RD and CD are copied)
	QName    []byte // client's QNAME bytes (same length as template), nil = keep
	QType    uint16 // 0 = keep
	Elapsed  uint32 // seconds since insert; TTLs are decremented
	StaleTTL uint32 // >0: serve stale with this TTL for every record
	EDNS     bool
	UDPSize  uint16 // advertised in OPT
	DO       bool
	AD       bool   // set the authenticated-data bit (secure answer, client asked with DO or AD)
	EDE      uint16 // >0: add an Extended DNS Error option (RFC 8914) with this info code
	MaxSize  int    // 0 = no limit; over it a TC=1 header+question response is produced
}

// Render appends the patched response to dst[:0] and returns it.
func (t *Template) Render(dst []byte, o *RenderOpts) []byte {
	out := append(dst[:0], t.Wire...)
	binary.BigEndian.PutUint16(out[0:], o.ID)
	flags := binary.BigEndian.Uint16(out[2:])
	flags &^= FlagAA | FlagTC | FlagRD | FlagCD | FlagAD
	flags |= FlagQR | FlagRA | (o.ReqFlags & (FlagRD | FlagCD))
	if o.AD {
		flags |= FlagAD
	}
	binary.BigEndian.PutUint16(out[2:], flags)
	if o.QName != nil && len(o.QName) == t.QNameLen {
		copy(out[HeaderSz:], o.QName)
	}
	if o.QType != 0 {
		binary.BigEndian.PutUint16(out[HeaderSz+t.QNameLen:], o.QType)
	}
	for i, off := range t.TTLOffsets {
		var v uint32
		if o.StaleTTL > 0 {
			v = o.StaleTTL
		} else if t.TTLs[i] > o.Elapsed {
			v = t.TTLs[i] - o.Elapsed
		}
		binary.BigEndian.PutUint32(out[off:], v)
	}
	if o.MaxSize > 0 {
		extra := 0
		if o.EDNS {
			extra = 11
		}
		if len(out)+extra > o.MaxSize {
			out = out[:HeaderSz+t.QNameLen+4]
			binary.BigEndian.PutUint16(out[2:], flags|FlagTC)
			binary.BigEndian.PutUint16(out[6:], 0)
			binary.BigEndian.PutUint16(out[8:], 0)
			binary.BigEndian.PutUint16(out[10:], 0)
			if o.EDNS {
				out = appendOPT(out, o.UDPSize, o.DO, 0)
			}
			return out
		}
	}
	if o.EDNS {
		out = appendOPT(out, o.UDPSize, o.DO, o.EDE)
	}
	return out
}

func appendOPT(out []byte, size uint16, do bool, ede uint16) []byte {
	ar := binary.BigEndian.Uint16(out[10:])
	binary.BigEndian.PutUint16(out[10:], ar+1)
	var fl byte
	if do {
		fl = 0x80
	}
	rdlen := 0
	if ede > 0 {
		rdlen = 6
	}
	out = append(out, 0, 0, TypeOPT, byte(size>>8), byte(size), 0, 0, fl, 0, 0, byte(rdlen))
	if ede > 0 {
		out = append(out, 0, 15, 0, 2, byte(ede>>8), byte(ede))
	}
	return out
}

// Size returns the approximate memory cost of the template.
func (t *Template) Size() int {
	n := cap(t.Wire) + 6*cap(t.TTLs) + 96 + len(t.Sec.Reason) + len(t.Sec.Text)
	if t.DNSSEC != nil {
		n += t.DNSSEC.Size()
	}
	return n
}

// ErrorResponse appends to dst[:0] a header+question response to a query
// parsed by ParseQuery, with the given rcode (no records). ra sets RA.
func ErrorResponse(dst, pkt []byte, q *Query, rcode int, ra bool, udpSize uint16) []byte {
	end := HeaderSz + q.QNameLen + 4
	out := append(dst[:0], pkt[:end]...)
	flags := FlagQR | (q.Flags & (FlagRD | FlagCD)) | uint16(rcode&0xf)
	if ra {
		flags |= FlagRA
	}
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[6:], 0)
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	if q.HasEDNS {
		out = appendOPT(out, udpSize, q.DO, 0)
	}
	return out
}

// ErrorResponseEDE is ErrorResponse with an RFC 8914 extended error code in
// the OPT record (when the query had EDNS).
func ErrorResponseEDE(dst, pkt []byte, q *Query, rcode int, ra bool, udpSize, ede uint16) []byte {
	out := ErrorResponse(dst, pkt, q, rcode, ra, udpSize)
	if q.HasEDNS {
		out = out[:HeaderSz+q.QNameLen+4]
		binary.BigEndian.PutUint16(out[10:], 0)
		out = appendOPT(out, udpSize, q.DO, ede)
	}
	return out
}

// TruncatedResponse is like ErrorResponse with NOERROR and TC=1 (RRL slip).
func TruncatedResponse(dst, pkt []byte, q *Query, udpSize uint16) []byte {
	out := ErrorResponse(dst, pkt, q, 0, true, udpSize)
	binary.BigEndian.PutUint16(out[2:], binary.BigEndian.Uint16(out[2:])|FlagTC)
	return out
}

// ClientUDPSize returns the response size limit for a UDP client.
func ClientUDPSize(q *Query, serverMax int) int {
	if !q.HasEDNS || q.UDPSize < 512 {
		return 512
	}
	if int(q.UDPSize) < serverMax {
		return int(q.UDPSize)
	}
	return serverMax
}

// HasSuffixKey walks label boundaries of a wire name (lower-cased, ending in
// the root label) and reports whether any suffix is in set.
func HasSuffix(name []byte, set map[string]struct{}) bool {
	for off := 0; off < len(name); {
		if _, ok := set[string(name[off:])]; ok {
			return true
		}
		l := int(name[off])
		if l == 0 {
			break
		}
		off += 1 + l
	}
	return false
}
