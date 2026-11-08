package querylog

import (
	"encoding/binary"
	"errors"
	"strconv"
	"time"
)

// Row is one stored query-log row (after privacy and exclusions).
type Row struct {
	TS       int64  // unix microseconds
	Client   string // display form after privacy ("" with client_ip=none)
	Name     string // presentation form, lower case, no trailing dot ("." = root)
	Upstream string
	DurUS    uint32
	Size     uint16
	QType    uint16
	Rcode    uint8
	Source   uint8
	Proto    uint8
	Flags    uint8
}

// PresentName converts a lower-case wire name to presentation form without
// the trailing dot, escaping '.', '\\' and non-printable bytes as RFC 1035.
func PresentName(w []byte, buf []byte) []byte {
	buf = buf[:0]
	for off := 0; off < len(w); {
		l := int(w[off])
		if l == 0 || off+1+l > len(w) {
			break
		}
		if len(buf) > 0 {
			buf = append(buf, '.')
		}
		for _, c := range w[off+1 : off+1+l] {
			switch {
			case c == '.' || c == '\\' || c == '"' || c == '(' || c == ')' || c == ';' || c == '@' || c == '$':
				buf = append(buf, '\\', c)
			case c < 0x21 || c > 0x7e:
				buf = append(buf, '\\', '0'+c/100, '0'+c/10%10, '0'+c%10)
			default:
				buf = append(buf, c)
			}
		}
		off += 1 + l
	}
	if len(buf) == 0 {
		buf = append(buf, '.')
	}
	return buf
}

// block is a column-oriented set of rows with per-block dictionaries. It is
// both the in-memory active segment (builder maps set) and a decoded segment.
type block struct {
	names, clients, upstreams []string
	ts                        []int64
	client, name, upstream    []uint32 // upstream: 0 = none, else index+1
	qtype                     []uint16
	size                      []uint16
	dur                       []uint32
	rcode, source, proto      []uint8
	flags                     []uint8

	nameIdx, clientIdx, upIdx map[string]uint32 // builder only
	minTS, maxTS              int64
}

func newBuilder() *block {
	return &block{nameIdx: map[string]uint32{}, clientIdx: map[string]uint32{}, upIdx: map[string]uint32{}}
}

func (b *block) len() int { return len(b.ts) }

func intern(m map[string]uint32, list *[]string, s string) uint32 {
	if i, ok := m[s]; ok {
		return i
	}
	i := uint32(len(*list))
	*list = append(*list, s)
	m[s] = i
	return i
}

// add appends a row (builder only).
func (b *block) add(r *Row) {
	if len(b.ts) == 0 || r.TS < b.minTS {
		b.minTS = r.TS
	}
	if len(b.ts) == 0 || r.TS > b.maxTS {
		b.maxTS = r.TS
	}
	b.ts = append(b.ts, r.TS)
	b.client = append(b.client, intern(b.clientIdx, &b.clients, r.Client))
	b.name = append(b.name, intern(b.nameIdx, &b.names, r.Name))
	var u uint32
	if r.Upstream != "" {
		u = intern(b.upIdx, &b.upstreams, r.Upstream) + 1
	}
	b.upstream = append(b.upstream, u)
	b.qtype = append(b.qtype, r.QType)
	b.size = append(b.size, r.Size)
	b.dur = append(b.dur, r.DurUS)
	b.rcode = append(b.rcode, r.Rcode)
	b.source = append(b.source, r.Source)
	b.proto = append(b.proto, r.Proto)
	b.flags = append(b.flags, r.Flags)
}

// row materialises row i.
func (b *block) row(i int) Row {
	r := Row{TS: b.ts[i], Client: b.clients[b.client[i]], Name: b.names[b.name[i]], DurUS: b.dur[i], Size: b.size[i],
		QType: b.qtype[i], Rcode: b.rcode[i], Source: b.source[i], Proto: b.proto[i], Flags: b.flags[i]}
	if u := b.upstream[i]; u > 0 {
		r.Upstream = b.upstreams[u-1]
	}
	return r
}

// filterRows returns a new builder holding the rows for which keep is true.
func (b *block) filterRows(keep func(i int) bool) *block {
	nb := newBuilder()
	for i := 0; i < b.len(); i++ {
		if keep(i) {
			r := b.row(i)
			nb.add(&r)
		}
	}
	return nb
}

// Body format (before compression), all integers unsigned LEB128 unless noted:
//
//	version(1) nnames {len bytes}* nclients {len bytes}* nups {len bytes}*
//	nrows baseTS(zigzag) then columns of nrows each:
//	ts delta (zigzag, µs, from previous) | client idx | name idx | upstream idx
//	| qtype | size | dur µs | rcode(1) | source(1) | proto(1) | flags(1)
const bodyVersion = 1

// maxRows bounds rows per block (decoder sanity).
const maxRows = 1 << 22

func putUvarint(b []byte, v uint64) []byte { return binary.AppendUvarint(b, v) }

func putStrings(dst []byte, ss []string) []byte {
	dst = putUvarint(dst, uint64(len(ss)))
	for _, s := range ss {
		dst = putUvarint(dst, uint64(len(s)))
		dst = append(dst, s...)
	}
	return dst
}

// encode serialises rows [from,to) with dictionaries local to that range.
func (b *block) encode(dst []byte, from, to int) []byte {
	// remap dictionaries to the referenced subset (identity for the full range)
	full := from == 0 && to == b.len()
	names, clients, ups := b.names, b.clients, b.upstreams
	nm, cm, um := []uint32(nil), []uint32(nil), []uint32(nil)
	if !full {
		remap := func(idx []uint32, dict []string, offset uint32) ([]string, []uint32) {
			m := make([]uint32, len(dict)+1)
			for i := range m {
				m[i] = ^uint32(0)
			}
			var out []string
			for _, v := range idx[from:to] {
				if offset == 1 && v == 0 {
					continue
				}
				d := v - offset
				if m[d] == ^uint32(0) {
					m[d] = uint32(len(out))
					out = append(out, dict[d])
				}
			}
			return out, m
		}
		names, nm = remap(b.name, b.names, 0)
		clients, cm = remap(b.client, b.clients, 0)
		ups, um = remap(b.upstream, b.upstreams, 1)
	}
	dst = append(dst, bodyVersion)
	dst = putStrings(dst, names)
	dst = putStrings(dst, clients)
	dst = putStrings(dst, ups)
	n := to - from
	dst = putUvarint(dst, uint64(n))
	var base int64
	if n > 0 {
		base = b.ts[from]
	}
	dst = binary.AppendVarint(dst, base)
	prev := base
	for _, t := range b.ts[from:to] {
		dst = binary.AppendVarint(dst, t-prev)
		prev = t
	}
	for _, v := range b.client[from:to] {
		if cm != nil {
			v = cm[v]
		}
		dst = putUvarint(dst, uint64(v))
	}
	for _, v := range b.name[from:to] {
		if nm != nil {
			v = nm[v]
		}
		dst = putUvarint(dst, uint64(v))
	}
	for _, v := range b.upstream[from:to] {
		if um != nil && v > 0 {
			v = um[v-1] + 1
		}
		dst = putUvarint(dst, uint64(v))
	}
	for _, v := range b.qtype[from:to] {
		dst = putUvarint(dst, uint64(v))
	}
	for _, v := range b.size[from:to] {
		dst = putUvarint(dst, uint64(v))
	}
	for _, v := range b.dur[from:to] {
		dst = putUvarint(dst, uint64(v))
	}
	dst = append(dst, b.rcode[from:to]...)
	dst = append(dst, b.source[from:to]...)
	dst = append(dst, b.proto[from:to]...)
	dst = append(dst, b.flags[from:to]...)
	return dst
}

var errCorrupt = errors.New("querylog: corrupt block")

type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b[r.off:])
	if n <= 0 {
		r.err = errCorrupt
		return 0
	}
	r.off += n
	return v
}

func (r *reader) varint() int64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Varint(r.b[r.off:])
	if n <= 0 {
		r.err = errCorrupt
		return 0
	}
	r.off += n
	return v
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.off+n > len(r.b) || r.off+n < r.off {
		r.err = errCorrupt
		return nil
	}
	s := r.b[r.off : r.off+n]
	r.off += n
	return s
}

func (r *reader) strings() []string {
	n := r.uvarint()
	if n > uint64(len(r.b)-r.off) { // each string needs at least one byte
		r.err = errCorrupt
		return nil
	}
	out := make([]string, 0, n)
	for i := uint64(0); i < n && r.err == nil; i++ {
		l := r.uvarint()
		if l > 1<<16 {
			r.err = errCorrupt
			return nil
		}
		out = append(out, string(r.bytes(int(l))))
	}
	return out
}

// decodeBlock parses an encoded body with full bounds checking.
func decodeBlock(data []byte) (*block, error) {
	r := &reader{b: data}
	if v := r.bytes(1); r.err != nil || v[0] != bodyVersion {
		return nil, errCorrupt
	}
	b := &block{}
	b.names = r.strings()
	b.clients = r.strings()
	b.upstreams = r.strings()
	n64 := r.uvarint()
	if r.err != nil || n64 > maxRows || n64 > uint64(len(data)) {
		return nil, errCorrupt
	}
	n := int(n64)
	b.ts = make([]int64, n)
	t := r.varint()
	for i := 0; i < n; i++ {
		t += r.varint()
		b.ts[i] = t
		if i == 0 || t < b.minTS {
			b.minTS = t
		}
		if i == 0 || t > b.maxTS {
			b.maxTS = t
		}
	}
	idx := func(limit int, offset int) []uint32 {
		out := make([]uint32, n)
		for i := range out {
			v := r.uvarint()
			if v >= uint64(limit+offset) {
				r.err = errCorrupt
				return out
			}
			out[i] = uint32(v)
		}
		return out
	}
	b.client = idx(len(b.clients), 0)
	b.name = idx(len(b.names), 0)
	b.upstream = idx(len(b.upstreams), 1)
	b.qtype = make([]uint16, n)
	for i := range b.qtype {
		v := r.uvarint()
		if v > 0xffff {
			r.err = errCorrupt
		}
		b.qtype[i] = uint16(v)
	}
	b.size = make([]uint16, n)
	for i := range b.size {
		v := r.uvarint()
		if v > 0xffff {
			r.err = errCorrupt
		}
		b.size[i] = uint16(v)
	}
	b.dur = make([]uint32, n)
	for i := range b.dur {
		v := r.uvarint()
		if v > 0xffffffff {
			r.err = errCorrupt
		}
		b.dur[i] = uint32(v)
	}
	b.rcode = append([]uint8(nil), r.bytes(n)...)
	b.source = append([]uint8(nil), r.bytes(n)...)
	b.proto = append([]uint8(nil), r.bytes(n)...)
	b.flags = append([]uint8(nil), r.bytes(n)...)
	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(data) {
		return nil, errCorrupt
	}
	for i := 0; i < n; i++ {
		if b.source[i] >= SrcCount || b.proto[i] >= ProtoCount {
			return nil, errCorrupt
		}
	}
	return b, nil
}

// TSString renders a row timestamp (µs) as RFC 3339 with milliseconds.
func TSString(us int64) string {
	return time.UnixMicro(us).UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

func itoa(v int) string { return strconv.Itoa(v) }
