package querylog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"

	"mrk/dns-engine/internal/store"
)

// Segment file layout:
//
//	"MRKQLOG1" | bodyLen u32 | bodyCRC u32 (crc32c of the compressed body) | zstd(body)
//	| index | indexLen u32 | indexCRC u32 | "MRKQEND1"
//
// The index holds the time range, row count, per-rcode/source counts and two
// Bloom filters (name suffixes + labels, clients) so searches skip segments
// without reading the body. Files are written to a temp file, fsynced and
// renamed: a segment is either complete or absent.
var (
	segMagic = []byte("MRKQLOG1")
	endMagic = []byte("MRKQEND1")
	crcTab   = crc32.MakeTable(crc32.Castagnoli)
)

const (
	trailerLen = 16
	headLen    = 16
	// maxBody caps a decompressed body (decoder memory bound).
	maxBody = 256 << 20
)

type segMeta struct {
	Seq     uint64
	Path    string
	Size    int64
	Rows    int
	MinTS   int64
	MaxTS   int64
	Rcodes  [16]uint32
	Sources [SrcCount]uint32
	names   *bloom
	clients *bloom
}

func segPath(dir string, seq uint64) string { return filepath.Join(dir, fmt.Sprintf("%016d.seg", seq)) }

var (
	encFast, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1),
		zstd.WithLowerEncoderMem(true))
	encSeg, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1),
		zstd.WithLowerEncoderMem(true))
	dec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(2), zstd.WithDecoderMaxMemory(maxBody),
		zstd.WithDecoderMaxWindow(32<<20), zstd.WithDecoderLowmem(true))
)

func decompress(b []byte) ([]byte, error) {
	out, err := dec.DecodeAll(b, nil)
	if err != nil {
		return nil, errCorrupt
	}
	if len(out) > maxBody {
		return nil, errCorrupt
	}
	return out, nil
}

func buildIndex(seq uint64, b *block) *segMeta {
	m := &segMeta{Seq: seq, Rows: b.len(), MinTS: b.minTS, MaxTS: b.maxTS}
	for i := 0; i < b.len(); i++ {
		m.Rcodes[b.rcode[i]&15]++
		m.Sources[b.source[i]%SrcCount]++
	}
	keys := 0
	for _, n := range b.names {
		nameKeys(n, func(string) { keys++ })
	}
	m.names = newBloom(keys)
	for _, n := range b.names {
		nameKeys(n, m.names.add)
	}
	m.clients = newBloom(len(b.clients))
	for _, c := range b.clients {
		m.clients.add(c)
	}
	return m
}

func (m *segMeta) marshalIndex() []byte {
	var d []byte
	d = append(d, 2)
	d = binary.AppendUvarint(d, m.Seq)
	d = binary.AppendUvarint(d, uint64(m.Rows))
	d = binary.AppendVarint(d, m.MinTS)
	d = binary.AppendVarint(d, m.MaxTS)
	for _, c := range m.Rcodes {
		d = binary.AppendUvarint(d, uint64(c))
	}
	d = binary.AppendUvarint(d, uint64(len(m.Sources)))
	for _, c := range m.Sources {
		d = binary.AppendUvarint(d, uint64(c))
	}
	d = m.names.marshal(d)
	d = m.clients.marshal(d)
	return d
}

func parseIndex(d []byte) (*segMeta, error) {
	r := &reader{b: d}
	v := r.bytes(1)
	if r.err != nil || v[0] != 1 && v[0] != 2 {
		return nil, errCorrupt
	}
	version := v[0]
	m := &segMeta{}
	m.Seq = r.uvarint()
	rows := r.uvarint()
	if rows > maxRows {
		return nil, errCorrupt
	}
	m.Rows = int(rows)
	m.MinTS = r.varint()
	m.MaxTS = r.varint()
	for i := range m.Rcodes {
		m.Rcodes[i] = uint32(r.uvarint())
	}
	nsrc := uint64(srcCountV1) // version 1 (D2/D3) indexed 8 sources
	if version >= 2 {
		nsrc = r.uvarint()
		if nsrc > 64 {
			return nil, errCorrupt
		}
	}
	for i := uint64(0); i < nsrc; i++ {
		c := uint32(r.uvarint())
		if i < uint64(len(m.Sources)) {
			m.Sources[i] = c
		}
	}
	m.names = readBloom(r)
	m.clients = readBloom(r)
	if r.err != nil || r.off != len(d) {
		return nil, errCorrupt
	}
	return m, nil
}

// marshalSegment renders a complete segment file.
func marshalSegment(seq uint64, b *block) ([]byte, *segMeta) {
	body := b.encode(make([]byte, 0, b.len()*12+1024), 0, b.len())
	comp := encSeg.EncodeAll(body, make([]byte, 0, len(body)/3+64))
	m := buildIndex(seq, b)
	idx := m.marshalIndex()
	out := make([]byte, 0, headLen+len(comp)+len(idx)+trailerLen)
	out = append(out, segMagic...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(comp)))
	out = binary.LittleEndian.AppendUint32(out, crc32.Checksum(comp, crcTab))
	out = append(out, comp...)
	out = append(out, idx...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(idx)))
	out = binary.LittleEndian.AppendUint32(out, crc32.Checksum(idx, crcTab))
	out = append(out, endMagic...)
	m.Size = int64(len(out))
	return out, m
}

// writeSegment atomically writes b as segment seq in dir.
func writeSegment(dir string, seq uint64, b *block) (*segMeta, error) {
	data, m := marshalSegment(seq, b)
	m.Path = segPath(dir, seq)
	if err := store.WriteFileAtomic(m.Path, data, 0o640); err != nil {
		return nil, err
	}
	return m, nil
}

// parseSegment validates a whole segment file and decodes it.
func parseSegment(data []byte) (*segMeta, *block, error) {
	m, bodyOff, bodyLen, err := parseTrailer(data)
	if err != nil {
		return nil, nil, err
	}
	b, err := decodeBody(data[bodyOff : bodyOff+bodyLen])
	if err != nil {
		return nil, nil, err
	}
	if b.len() != m.Rows {
		return nil, nil, errCorrupt
	}
	return m, b, nil
}

func parseTrailer(data []byte) (*segMeta, int, int, error) {
	if len(data) < headLen+trailerLen || !bytes.Equal(data[:8], segMagic) || !bytes.Equal(data[len(data)-8:], endMagic) {
		return nil, 0, 0, errCorrupt
	}
	bodyLen := int(binary.LittleEndian.Uint32(data[8:]))
	idxLen := int(binary.LittleEndian.Uint32(data[len(data)-16:]))
	if bodyLen < 0 || idxLen < 0 || headLen+bodyLen+idxLen+trailerLen != len(data) {
		return nil, 0, 0, errCorrupt
	}
	idx := data[headLen+bodyLen : headLen+bodyLen+idxLen]
	if crc32.Checksum(idx, crcTab) != binary.LittleEndian.Uint32(data[len(data)-12:]) {
		return nil, 0, 0, errCorrupt
	}
	body := data[headLen : headLen+bodyLen]
	if crc32.Checksum(body, crcTab) != binary.LittleEndian.Uint32(data[12:]) {
		return nil, 0, 0, errCorrupt
	}
	m, err := parseIndex(idx)
	if err != nil {
		return nil, 0, 0, err
	}
	m.Size = int64(len(data))
	return m, headLen, bodyLen, nil
}

func decodeBody(comp []byte) (*block, error) {
	raw, err := decompress(comp)
	if err != nil {
		return nil, err
	}
	return decodeBlock(raw)
}

// readIndex reads only the trailer and index of a segment file.
func readIndex(path string) (*segMeta, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size < headLen+trailerLen {
		return nil, errCorrupt
	}
	var tr [trailerLen]byte
	if _, err := f.ReadAt(tr[:], size-trailerLen); err != nil {
		return nil, err
	}
	var head [headLen]byte
	if _, err := f.ReadAt(head[:], 0); err != nil {
		return nil, err
	}
	if !bytes.Equal(tr[8:], endMagic) || !bytes.Equal(head[:8], segMagic) {
		return nil, errCorrupt
	}
	idxLen := int64(binary.LittleEndian.Uint32(tr[0:]))
	bodyLen := int64(binary.LittleEndian.Uint32(head[8:]))
	if headLen+bodyLen+idxLen+trailerLen != size {
		return nil, errCorrupt
	}
	idx := make([]byte, idxLen)
	if _, err := f.ReadAt(idx, size-trailerLen-idxLen); err != nil && err != io.EOF {
		return nil, err
	}
	if crc32.Checksum(idx, crcTab) != binary.LittleEndian.Uint32(tr[4:]) {
		return nil, errCorrupt
	}
	m, err := parseIndex(idx)
	if err != nil {
		return nil, err
	}
	m.Size = size
	m.Path = path
	return m, nil
}

// readBlock reads and decodes the body of a segment.
func readBlock(m *segMeta) (*block, error) {
	data, err := os.ReadFile(m.Path)
	if err != nil {
		return nil, err
	}
	_, b, err := parseSegment(data)
	return b, err
}
