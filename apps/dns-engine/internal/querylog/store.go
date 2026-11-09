package querylog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Store defaults.
const (
	DefaultSegmentRows = 131072
	DefaultSegmentAge  = 5 * time.Minute
	walSyncInterval    = time.Second
	blockCacheSize     = 3
)

var walMagic = []byte("MRKQWAL1")

// Store holds finalized segments and the active (in-memory + WAL) segment.
//
// The active segment's rows are appended to active-<seq>.wal as compressed,
// checksummed batches; after a crash the valid prefix of the WAL is turned
// into segment <seq> on the next start (a WAL whose segment already exists is
// a leftover of a crash between rename and WAL removal and is discarded).
type Store struct {
	dir string
	now func() time.Time

	// SegmentRows and SegmentAge trigger finalisation of the active segment.
	SegmentRows int
	SegmentAge  time.Duration

	mu        sync.Mutex
	segs      []*segMeta // ascending Seq
	segBytes  int64
	active    *block
	activeSeq uint64
	activeAt  time.Time
	wal       *os.File
	walW      *bufio.Writer
	walMark   int
	walBytes  int64
	walDirty  bool
	lastSync  time.Time

	cacheMu sync.Mutex
	cache   map[uint64]*block
	order   []uint64
}

// OpenStore opens (creating) dir and recovers it.
func OpenStore(dir string, now func() time.Time) (*Store, []error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{dir: dir, now: now, SegmentRows: DefaultSegmentRows, SegmentAge: DefaultSegmentAge,
		cache: map[uint64]*block{}}
	var warns []error
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, []error{err}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{err}
	}
	var wals []uint64
	maxSeq := uint64(0)
	for _, de := range ents {
		n := de.Name()
		switch {
		case strings.HasPrefix(n, ".tmp-"):
			_ = os.Remove(filepath.Join(dir, n))
		case strings.HasSuffix(n, ".seg"):
			seq, err := strconv.ParseUint(strings.TrimSuffix(n, ".seg"), 10, 64)
			if err != nil {
				continue
			}
			m, err := readIndex(filepath.Join(dir, n))
			if err != nil || m.Seq != seq {
				warns = append(warns, fmt.Errorf("querylog: dropping unreadable segment %s: %v", n, err))
				_ = os.Rename(filepath.Join(dir, n), filepath.Join(dir, n+".bad"))
				continue
			}
			s.segs = append(s.segs, m)
			s.segBytes += m.Size
			maxSeq = max(maxSeq, seq)
		case strings.HasPrefix(n, "active-") && strings.HasSuffix(n, ".wal"):
			seq, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(n, "active-"), ".wal"), 10, 64)
			if err == nil {
				wals = append(wals, seq)
				maxSeq = max(maxSeq, seq)
			}
		}
	}
	sort.Slice(s.segs, func(i, j int) bool { return s.segs[i].Seq < s.segs[j].Seq })
	for _, seq := range wals {
		if err := s.recoverWAL(seq); err != nil {
			warns = append(warns, err)
		}
	}
	s.activeSeq = maxSeq + 1
	if err := s.startActiveLocked(); err != nil {
		return nil, append(warns, err)
	}
	return s, warns
}

func (s *Store) walPath(seq uint64) string {
	return filepath.Join(s.dir, fmt.Sprintf("active-%016d.wal", seq))
}

// recoverWAL turns the valid prefix of a WAL into a segment.
func (s *Store) recoverWAL(seq uint64) error {
	p := s.walPath(seq)
	defer os.Remove(p)
	for _, m := range s.segs {
		if m.Seq == seq {
			return nil // already finalized; the WAL is a leftover
		}
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	b, _ := ReadWAL(data)
	if b.len() == 0 {
		return nil
	}
	m, err := writeSegment(s.dir, seq, b)
	if err != nil {
		return fmt.Errorf("querylog: recover %s: %w", p, err)
	}
	s.segs = append(s.segs, m)
	sort.Slice(s.segs, func(i, j int) bool { return s.segs[i].Seq < s.segs[j].Seq })
	s.segBytes += m.Size
	return nil
}

// ReadWAL decodes the valid prefix of a WAL image; the bool reports whether
// the whole image was valid.
func ReadWAL(data []byte) (*block, bool) {
	b := newBuilder()
	if len(data) < len(walMagic) || !bytes.Equal(data[:len(walMagic)], walMagic) {
		return b, false
	}
	off := len(walMagic)
	for off < len(data) {
		if off+8 > len(data) {
			return b, false
		}
		n := int(binary.LittleEndian.Uint32(data[off:]))
		crc := binary.LittleEndian.Uint32(data[off+4:])
		if n <= 0 || n > maxBody || off+8+n > len(data) {
			return b, false
		}
		payload := data[off+8 : off+8+n]
		if crc32.Checksum(payload, crcTab) != crc {
			return b, false
		}
		blk, err := decodeBody(payload)
		if err != nil {
			return b, false
		}
		for i := 0; i < blk.len(); i++ {
			r := blk.row(i)
			b.add(&r)
		}
		off += 8 + n
	}
	return b, true
}

func (s *Store) startActiveLocked() error {
	s.active = newBuilder()
	s.activeAt = s.now()
	s.walMark = 0
	f, err := os.OpenFile(s.walPath(s.activeSeq), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		s.wal, s.walW = nil, nil
		return err
	}
	s.wal = f
	s.walW = bufio.NewWriterSize(f, 256<<10)
	_, _ = s.walW.Write(walMagic)
	s.walBytes = int64(len(walMagic))
	s.walDirty = true
	return nil
}

func (s *Store) closeWALLocked(remove bool) {
	if s.wal != nil {
		_ = s.walW.Flush()
		_ = s.wal.Close()
		if remove {
			_ = os.Remove(s.walPath(s.activeSeq))
		}
	}
	s.wal, s.walW = nil, nil
}

// Append adds rows to the active segment and its WAL; it finalizes the
// segment when it is full or old.
func (s *Store) Append(rows []Row) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range rows {
		s.active.add(&rows[i])
	}
	err := s.flushWALLocked()
	if s.active.len() >= s.SegmentRows {
		if ferr := s.finalizeLocked(); ferr != nil {
			err = ferr
		}
	}
	return err
}

func (s *Store) flushWALLocked() error {
	if s.walW == nil {
		if err := s.startWALOnlyLocked(); err != nil {
			return err
		}
	}
	if s.walMark < s.active.len() {
		body := s.active.encode(nil, s.walMark, s.active.len())
		comp := encFast.EncodeAll(body, nil)
		var h [8]byte
		binary.LittleEndian.PutUint32(h[0:], uint32(len(comp)))
		binary.LittleEndian.PutUint32(h[4:], crc32.Checksum(comp, crcTab))
		_, _ = s.walW.Write(h[:])
		_, _ = s.walW.Write(comp)
		s.walBytes += int64(8 + len(comp))
		s.walMark = s.active.len()
		s.walDirty = true
	}
	if err := s.walW.Flush(); err != nil {
		return err
	}
	return nil
}

// startWALOnlyLocked recreates the WAL of the current active segment with
// all its rows (after an I/O error or a delete).
func (s *Store) startWALOnlyLocked() error {
	s.closeWALLocked(false)
	f, err := os.OpenFile(s.walPath(s.activeSeq), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	s.wal = f
	s.walW = bufio.NewWriterSize(f, 256<<10)
	_, _ = s.walW.Write(walMagic)
	s.walBytes = int64(len(walMagic))
	s.walMark = 0
	return nil
}

// Sync fsyncs the WAL if it changed (call about once a second) and
// finalizes the active segment when it is older than SegmentAge.
func (s *Store) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.wal != nil && s.walDirty && s.now().Sub(s.lastSync) >= walSyncInterval {
		_ = s.walW.Flush()
		err = s.wal.Sync()
		s.walDirty = false
		s.lastSync = s.now()
	}
	if s.active.len() > 0 && s.now().Sub(s.activeAt) >= s.SegmentAge {
		if ferr := s.finalizeLocked(); ferr != nil {
			err = ferr
		}
	}
	return err
}

// Finalize writes the active segment now (tests, shutdown).
func (s *Store) Finalize() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active.len() == 0 {
		return nil
	}
	return s.finalizeLocked()
}

func (s *Store) finalizeLocked() error {
	if s.active.len() == 0 {
		s.activeAt = s.now()
		return nil
	}
	m, err := writeSegment(s.dir, s.activeSeq, s.active)
	if err != nil {
		// never grow without bound: the rows are lost, the WAL is reset
		s.closeWALLocked(true)
		s.activeSeq++
		_ = s.startActiveLocked()
		return err
	}
	s.segs = append(s.segs, m)
	s.segBytes += m.Size
	s.closeWALLocked(true)
	s.activeSeq++
	return s.startActiveLocked()
}

// Close flushes and finalizes the active segment.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.active.len() > 0 {
		m, werr := writeSegment(s.dir, s.activeSeq, s.active)
		if werr == nil {
			s.segs = append(s.segs, m)
			s.segBytes += m.Size
			s.closeWALLocked(true)
			s.active = newBuilder()
			return nil
		}
		err = werr
	}
	s.closeWALLocked(s.active.len() == 0)
	return err
}

// Retention deletes segments older than maxAge and the oldest segments while
// the total size exceeds maxBytes. It returns the number of deleted segments.
func (s *Store) Retention(maxAge time.Duration, maxBytes int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.now().Add(-maxAge).UnixMicro()
	n := 0
	for len(s.segs) > 0 {
		m := s.segs[0]
		if m.MaxTS >= cut && s.segBytes+s.walBytes <= maxBytes {
			break
		}
		s.removeSegLocked(0)
		n++
	}
	return n
}

func (s *Store) removeSegLocked(i int) {
	m := s.segs[i]
	_ = os.Remove(m.Path)
	s.segBytes -= m.Size
	s.segs = append(s.segs[:i], s.segs[i+1:]...)
	s.dropCache(m.Seq)
}

// Usage is the storage summary.
type Usage struct {
	Bytes    int64
	Segments int
	OldestTS int64 // µs, 0 when empty
	Rows     int
}

// Usage returns the current size and age of the log.
func (s *Store) Usage() Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := Usage{Bytes: s.segBytes + s.walBytes, Segments: len(s.segs), Rows: s.active.len()}
	for _, m := range s.segs {
		u.Rows += m.Rows
		if u.OldestTS == 0 || m.MinTS < u.OldestTS {
			u.OldestTS = m.MinTS
		}
	}
	if s.active.len() > 0 && (u.OldestTS == 0 || s.active.minTS < u.OldestTS) {
		u.OldestTS = s.active.minTS
	}
	return u
}

// Dir returns the directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) dropCache(seq uint64) {
	s.cacheMu.Lock()
	delete(s.cache, seq)
	s.cacheMu.Unlock()
}

func (s *Store) loadBlock(m *segMeta) (*block, error) {
	s.cacheMu.Lock()
	if b := s.cache[m.Seq]; b != nil {
		s.cacheMu.Unlock()
		return b, nil
	}
	s.cacheMu.Unlock()
	b, err := readBlock(m)
	if err != nil {
		return nil, err
	}
	s.cacheMu.Lock()
	if _, ok := s.cache[m.Seq]; !ok {
		s.cache[m.Seq] = b
		s.order = append(s.order, m.Seq)
		for len(s.order) > blockCacheSize {
			delete(s.cache, s.order[0])
			s.order = s.order[1:]
		}
	}
	s.cacheMu.Unlock()
	return b, nil
}

// DeleteResult is DELETE /v1/querylog.
type DeleteResult struct {
	DeletedSegments   int `json:"deleted_segments"`
	RewrittenSegments int `json:"rewritten_segments"`
	DeletedRows       int `json:"deleted_rows"`
}

// Delete removes rows matching client (nil = any) with ts < before (0 = any).
// Both nil/0 deletes everything. Segments are rewritten atomically.
func (s *Store) Delete(client *Filter, before int64) (DeleteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res DeleteResult
	if client == nil && before == 0 {
		for len(s.segs) > 0 {
			res.DeletedRows += s.segs[0].Rows
			s.removeSegLocked(0)
			res.DeletedSegments++
		}
		res.DeletedRows += s.active.len()
		s.active = newBuilder()
		return res, s.startWALOnlyLocked()
	}
	doomed := func(b *block, mt *matcher, i int) bool {
		if before > 0 && b.ts[i] >= before {
			return false
		}
		return mt == nil || mt.clientOK[b.client[i]]
	}
	compileFor := func(b *block) *matcher {
		if client == nil {
			return nil
		}
		mt := &matcher{f: client, clientOK: make([]bool, 0, len(b.clients))}
		for _, c := range b.clients {
			mt.clientOK = append(mt.clientOK, client.matchClient(c))
		}
		return mt
	}
	var firstErr error
	for i := 0; i < len(s.segs); i++ {
		m := s.segs[i]
		if before > 0 && m.MinTS >= before {
			continue
		}
		if client != nil && client.skipMeta(&segMeta{MinTS: m.MinTS, MaxTS: m.MaxTS, Rcodes: allOnes, Sources: allSrc,
			clients: m.clients}) {
			continue
		}
		if client == nil && m.MaxTS < before {
			res.DeletedRows += m.Rows
			s.removeSegLocked(i)
			i--
			res.DeletedSegments++
			continue
		}
		b, err := readBlock(m)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		mt := compileFor(b)
		nb := b.filterRows(func(j int) bool { return !doomed(b, mt, j) })
		removed := b.len() - nb.len()
		if removed == 0 {
			continue
		}
		res.DeletedRows += removed
		if nb.len() == 0 {
			s.removeSegLocked(i)
			i--
			res.DeletedSegments++
			continue
		}
		nm, err := writeSegment(s.dir, m.Seq, nb)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		s.segBytes += nm.Size - m.Size
		s.segs[i] = nm
		s.dropCache(m.Seq)
		res.RewrittenSegments++
	}
	if s.active.len() > 0 {
		mt := compileFor(s.active)
		a := s.active
		nb := a.filterRows(func(j int) bool { return !doomed(a, mt, j) })
		if removed := a.len() - nb.len(); removed > 0 {
			res.DeletedRows += removed
			s.active = nb
			if err := s.startWALOnlyLocked(); err == nil {
				_ = s.flushWALLocked()
			}
		}
	}
	return res, firstErr
}

var (
	allOnes = [16]uint32{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	allSrc  = [SrcCount]uint32{1, 1, 1, 1, 1, 1, 1, 1, 1}
)

// SearchResult is the outcome of one search page.
type SearchResult struct {
	Rows      []Row
	Next      *Cursor
	Scanned   int
	Truncated bool
}

// Search scans newest-first. budget bounds the scan time (0 = unbounded);
// when it runs out the result is Truncated and Next resumes the scan.
func (s *Store) Search(ctx context.Context, f *Filter, budget time.Duration) SearchResult {
	var res SearchResult
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	var deadline time.Time
	if budget > 0 {
		deadline = time.Now().Add(budget)
	}
	expired := func() bool {
		return (!deadline.IsZero() && time.Now().After(deadline)) || ctx.Err() != nil
	}
	// scan one block from start downwards; true when the page is complete
	scan := func(seq uint64, b *block, start int, mt *matcher) bool {
		res.Scanned++
		for i := start; i >= 0; i-- {
			if i&4095 == 0 && i != start && expired() {
				res.Truncated = true
				res.Next = &Cursor{Seq: seq, Row: i + 1}
				return true
			}
			if mt.match(b, i) {
				res.Rows = append(res.Rows, b.row(i))
				if len(res.Rows) >= limit {
					res.Next = &Cursor{Seq: seq, Row: i}
					return true
				}
			}
		}
		return false
	}
	startFor := func(seq uint64, n int) (int, bool) {
		if f.Cursor == nil {
			return n - 1, true
		}
		if seq > f.Cursor.Seq {
			return 0, false
		}
		if seq == f.Cursor.Seq {
			return min(f.Cursor.Row, n) - 1, true
		}
		return n - 1, true
	}
	s.mu.Lock()
	segs := append([]*segMeta(nil), s.segs...)
	if start, ok := startFor(s.activeSeq, s.active.len()); ok && start >= 0 && s.overlaps(f, s.active) {
		var mt matcher
		f.compile(s.active, &mt)
		if scan(s.activeSeq, s.active, start, &mt) {
			s.mu.Unlock()
			return res
		}
	}
	s.mu.Unlock()
	for i := len(segs) - 1; i >= 0; i-- {
		m := segs[i]
		start, ok := startFor(m.Seq, m.Rows)
		if !ok || start < 0 || f.skipMeta(m) {
			continue
		}
		if expired() {
			res.Truncated = true
			res.Next = &Cursor{Seq: m.Seq, Row: start + 1}
			return res
		}
		b, err := s.loadBlock(m)
		if err != nil {
			continue
		}
		var mt matcher
		f.compile(b, &mt)
		if scan(m.Seq, b, min(start, b.len()-1), &mt) {
			return res
		}
	}
	return res
}

func (s *Store) overlaps(f *Filter, b *block) bool {
	if b.len() == 0 {
		return false
	}
	return !(f.From > 0 && b.maxTS < f.From) && !(f.To > 0 && b.minTS > f.To)
}
