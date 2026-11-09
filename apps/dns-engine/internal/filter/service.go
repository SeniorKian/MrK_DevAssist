package filter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/store"
)

// Limits of docs/41 §3.1.
const (
	DefaultMaxListBytes = 50 << 20
	DefaultMaxTotal     = 2_000_000
	DefaultTimeout      = 60 * time.Second
	// retryAfterFailure is the delay before a failed list is tried again.
	retryAfterFailure = time.Hour
)

// Error codes of a list (status `error`).
const (
	ErrCodeDownload    = "download_failed"
	ErrCodeHTTP        = "http_status"
	ErrCodeTooLarge    = "too_large"
	ErrCodeTooMany     = "too_many_entries"
	ErrCodeEmpty       = "empty_list"
	ErrCodeMemory      = "memory_limit"
	ErrCodePressure    = "deferred_pressure"
	ErrCodeParse       = "parse_failed"
	ErrCodeStore       = "store_failed"
	ErrCodeNotYetFetch = ""
)

// Options configure a Service.
type Options struct {
	Dir          string       // cache directory of downloaded lists
	Client       *http.Client // default: HTTPS-only client
	Now          func() time.Time
	Log          *slog.Logger
	MaxListBytes int64
	MaxTotal     int
	Timeout      time.Duration
	// MemCheck refuses a build needing `need` more bytes (memory guard).
	MemCheck func(need int64) error
	// Busy reports server pressure (downloads and loads wait).
	Busy func() bool
	// OnFail is called when a list's error changes to a non-empty value.
	OnFail func(id, code, detail string)
}

type listState struct {
	cfg       config.FilterList
	bit       uint32
	loaded    bool // entries of cfg.URL/Format are in the matcher
	attempted bool // processed at least once (nextAt is meaningful)
	entries   int
	updatedAt time.Time // last successful download (or 304)
	nextAt    time.Time
	errCode   string
	errDetail string
	running   bool
	etag      string
	lastMod   string
}

type meta struct {
	URL          string    `json:"url"`
	Format       string    `json:"format"`
	UpdatedAt    time.Time `json:"updated_at"`
	Entries      int       `json:"entries"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
}

// Service owns the lists: it loads cached copies, downloads on schedule and
// publishes matchers without blocking queries.
type Service struct {
	opts Options
	cur  atomic.Pointer[Matcher]

	mu      sync.Mutex // guards cfg, lists, free bits
	cfg     config.Filtering
	lists   map[string]*listState
	order   []string
	allow   []string
	block   []string
	buildMu sync.Mutex // serialises matcher rebuilds

	kick    chan struct{}
	idle    chan struct{} // closed and replaced each time the loop goes idle
	working atomic.Int32
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// New starts a service (Configure must be called to load lists).
func New(opts Options) *Service {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.MaxListBytes <= 0 {
		opts.MaxListBytes = DefaultMaxListBytes
	}
	if opts.MaxTotal <= 0 {
		opts.MaxTotal = DefaultMaxTotal
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Client == nil {
		opts.Client = &http.Client{}
	}
	if opts.Client.CheckRedirect == nil {
		c := *opts.Client
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirect to a non-https URL")
			}
			return nil
		}
		opts.Client = &c
	}
	s := &Service{opts: opts, lists: map[string]*listState{}, kick: make(chan struct{}, 1), idle: make(chan struct{})}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.cur.Store(&Matcher{})
	s.wg.Add(1)
	go s.loop()
	return s
}

// Close stops downloads.
func (s *Service) Close() {
	s.cancel()
	s.wg.Wait()
}

// Matcher returns the current matcher (never nil).
func (s *Service) Matcher() *Matcher { return s.cur.Load() }

// BitOf returns the mask bit of a list id (0 = not configured/enabled).
func (s *Service) BitOf(id string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l := s.lists[id]; l != nil {
		return l.bit
	}
	return 0
}

// ListOfBit returns the list id of a single mask bit.
func (s *Service) ListOfBit(bit uint32) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, l := range s.lists {
		if l.bit == bit {
			return id
		}
	}
	return ""
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Configure applies the filtering section. Removed or disabled lists and the
// custom names are applied synchronously (O(entries)); new lists are loaded
// from the cache or downloaded in the background.
func (s *Service) Configure(f config.Filtering) {
	s.mu.Lock()
	var updates []Update
	want := map[string]config.FilterList{}
	s.order = s.order[:0]
	if f.Enabled {
		for _, fl := range f.Lists {
			if fl.Enabled {
				want[fl.ID] = fl
				s.order = append(s.order, fl.ID)
			}
		}
	}
	used := uint32(0)
	for id, l := range s.lists {
		n, ok := want[id]
		if !ok || n.URL != l.cfg.URL || n.Format != l.cfg.Format {
			if l.loaded {
				updates = append(updates, Update{Bit: l.bit})
			}
			delete(s.lists, id)
			continue
		}
		if n.UpdateHours != l.cfg.UpdateHours && l.loaded {
			l.nextAt = l.updatedAt.Add(time.Duration(n.UpdateHours) * time.Hour)
		}
		l.cfg = n
		used |= l.bit
	}
	added := false
	for _, id := range s.order {
		if _, ok := s.lists[id]; ok {
			continue
		}
		bit := uint32(0)
		for b := 0; b < 31; b++ {
			if used&(1<<b) == 0 {
				bit = 1 << b
				break
			}
		}
		used |= bit
		s.lists[id] = &listState{cfg: want[id], bit: bit}
		added = true
	}
	allow, block := []string{}, []string{}
	if f.Enabled {
		allow, block = f.Allow, f.Block
	}
	if !equalStrings(allow, s.allow) || !equalStrings(block, s.block) {
		s.allow, s.block = append([]string{}, allow...), append([]string{}, block...)
		updates = append(updates, Update{Bit: CustomBit, Parsed: &Parsed{Block: CustomKeys(block), Allow: CustomKeys(allow)}})
	}
	prune := len(f.Lists) != len(s.cfg.Lists)
	ids := map[string]bool{}
	for i, fl := range f.Lists {
		ids[fl.ID] = true
		if !prune && s.cfg.Lists[i].ID != fl.ID {
			prune = true
		}
	}
	s.cfg = f
	keep := used | CustomBit
	s.mu.Unlock()
	if len(updates) > 0 {
		s.buildMu.Lock()
		s.cur.Store(Rebuild(s.cur.Load(), keep, updates))
		s.buildMu.Unlock()
	}
	if prune {
		s.Prune(ids)
	}
	if added {
		s.poke()
	}
}

func (s *Service) poke() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// ListStatus is one list in GET /v1/filtering/status.
type ListStatus struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Enabled     bool    `json:"enabled"`
	Entries     int     `json:"entries"`
	UpdatedAt   *string `json:"updated_at"`
	NextUpdate  *string `json:"next_update_at"`
	Updating    bool    `json:"updating"`
	Error       string  `json:"error,omitempty"`
	ErrorDetail string  `json:"error_detail,omitempty"`
}

func ts(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	v := t.UTC().Format(time.RFC3339)
	return &v
}

// Status lists every configured list (disabled ones with zero entries).
func (s *Service) Status() []ListStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []ListStatus{}
	for _, fl := range s.cfg.Lists {
		st := ListStatus{ID: fl.ID, Name: fl.Name, Enabled: fl.Enabled && s.cfg.Enabled}
		if l := s.lists[fl.ID]; l != nil {
			st.Entries, st.UpdatedAt, st.Updating = l.entries, ts(l.updatedAt), l.running
			st.Error, st.ErrorDetail = l.errCode, l.errDetail
			if !l.nextAt.IsZero() {
				st.NextUpdate = ts(l.nextAt)
			}
		} else if m, ok := s.readMeta(fl.ID); ok && m.URL == fl.URL && m.Format == fl.Format {
			st.Entries, st.UpdatedAt = m.Entries, ts(m.UpdatedAt) // disabled: what the cached copy holds
		}
		out = append(out, st)
	}
	return out
}

// Refresh marks every enabled list due and waits (up to ctx) for the
// downloads to finish.
func (s *Service) Refresh(ctx context.Context) {
	s.mu.Lock()
	for _, l := range s.lists {
		l.nextAt = time.Time{}
		l.etag, l.lastMod = "", "" // a manual refresh always downloads
	}
	s.mu.Unlock()
	s.poke()
	s.WaitIdle(ctx)
}

// WaitIdle blocks until no list is due or being processed (or ctx ends).
func (s *Service) WaitIdle(ctx context.Context) {
	for {
		s.mu.Lock()
		ch := s.idle
		busy := s.working.Load() > 0 || len(s.dueLocked(s.opts.Now())) > 0
		s.mu.Unlock()
		if !busy {
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (s *Service) dueLocked(now time.Time) []*listState {
	var out []*listState
	for _, id := range s.order {
		l := s.lists[id]
		if l == nil || l.running {
			continue
		}
		if !l.attempted || !now.Before(l.nextAt) {
			out = append(out, l)
		}
	}
	return out
}

func (s *Service) loop() {
	defer s.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		s.runDue()
		s.mu.Lock()
		close(s.idle)
		s.idle = make(chan struct{})
		s.mu.Unlock()
		select {
		case <-s.ctx.Done():
			return
		case <-s.kick:
		case <-t.C:
		}
	}
}

// runDue processes due lists one at a time (bounded memory).
func (s *Service) runDue() {
	for s.ctx.Err() == nil {
		if s.opts.Busy != nil && s.opts.Busy() {
			s.mu.Lock()
			for _, l := range s.dueLocked(s.opts.Now()) {
				s.setErrLocked(l, ErrCodePressure, "server under pressure; retried when it recovers")
				l.nextAt = s.opts.Now().Add(time.Minute)
				l.attempted = true
			}
			s.mu.Unlock()
			return
		}
		s.mu.Lock()
		due := s.dueLocked(s.opts.Now())
		if len(due) == 0 {
			s.mu.Unlock()
			return
		}
		l := due[0]
		l.running = true
		cfg, bit, wasLoaded := l.cfg, l.bit, l.loaded
		etag, lastMod := l.etag, l.lastMod
		s.working.Add(1)
		s.mu.Unlock()

		res := s.process(cfg, bit, wasLoaded, etag, lastMod)

		s.mu.Lock()
		s.working.Add(-1)
		cur := s.lists[cfg.ID]
		if cur != l { // reconfigured meanwhile: the result was not applied
			s.mu.Unlock()
			continue
		}
		l.running = false
		l.attempted = true
		now := s.opts.Now()
		if res.code == "" {
			l.loaded = true
			if res.entries >= 0 {
				l.entries = res.entries
			}
			if !res.at.IsZero() {
				l.updatedAt = res.at
			}
			l.etag, l.lastMod = res.etag, res.lastMod
			l.nextAt = l.updatedAt.Add(time.Duration(cfg.UpdateHours) * time.Hour)
			if res.fromCache && !l.nextAt.After(now) {
				l.nextAt = now // cached copy is stale: download now
			}
			l.errCode, l.errDetail = "", ""
		} else {
			s.setErrLocked(l, res.code, res.detail)
			retry := retryAfterFailure
			if h := time.Duration(cfg.UpdateHours) * time.Hour; h < retry {
				retry = h
			}
			l.nextAt = now.Add(retry)
		}
		s.mu.Unlock()
	}
}

func (s *Service) setErrLocked(l *listState, code, detail string) {
	changed := l.errCode != code || l.errDetail != detail
	l.errCode, l.errDetail = code, detail
	if changed && code != "" && s.opts.OnFail != nil {
		go s.opts.OnFail(l.cfg.ID, code, detail)
	}
}

type result struct {
	code, detail  string
	entries       int // -1 = unchanged
	at            time.Time
	etag, lastMod string
	fromCache     bool
}

func (s *Service) listPath(id string) string { return filepath.Join(s.opts.Dir, id+".list") }
func (s *Service) metaPath(id string) string { return filepath.Join(s.opts.Dir, id+".json") }

func (s *Service) readMeta(id string) (meta, bool) {
	var m meta
	b, err := os.ReadFile(s.metaPath(id))
	if err != nil || json.Unmarshal(b, &m) != nil {
		return meta{}, false
	}
	return m, true
}

// budget is the entry budget for list id (total minus the other lists).
func (s *Service) budget(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	used := 0
	for oid, l := range s.lists {
		if oid != id && l.loaded {
			used += l.entries
		}
	}
	if b := s.opts.MaxTotal - used; b > 0 {
		return b
	}
	return 0
}

// process loads the cached copy (first time) or downloads the list.
func (s *Service) process(cfg config.FilterList, bit uint32, loaded bool, etag, lastMod string) result {
	if !loaded {
		if m, ok := s.readMeta(cfg.ID); ok && m.URL == cfg.URL && m.Format == cfg.Format {
			if r := s.apply(cfg, bit, s.listPath(cfg.ID)); r.code == "" {
				r.at, r.etag, r.lastMod, r.fromCache = m.UpdatedAt, m.ETag, m.LastModified, true
				return r
			}
		}
	}
	return s.download(cfg, bit, etag, lastMod, loaded)
}

// apply parses path and swaps the list's entries into the matcher.
func (s *Service) apply(cfg config.FilterList, bit uint32, path string) result {
	f, err := os.Open(path)
	if err != nil {
		return result{code: ErrCodeStore, detail: err.Error()}
	}
	defer f.Close()
	p, err := Parse(f, cfg.Format, s.budget(cfg.ID))
	switch {
	case errors.Is(err, ErrTooMany):
		return result{code: ErrCodeTooMany, detail: fmt.Sprintf("the lists may hold %d names in total", s.opts.MaxTotal)}
	case errors.Is(err, ErrEmpty):
		return result{code: ErrCodeEmpty, detail: "no usable entries in the " + cfg.Format + " format"}
	case err != nil:
		return result{code: ErrCodeParse, detail: err.Error()}
	}
	s.buildMu.Lock()
	defer s.buildMu.Unlock()
	cur := s.cur.Load()
	if s.opts.MemCheck != nil {
		need := int64(cur.block.len()+cur.allow.len()+p.Entries())*12 + 2*65537*4
		if err := s.opts.MemCheck(need); err != nil {
			return result{code: ErrCodeMemory, detail: err.Error()}
		}
	}
	s.mu.Lock()
	l := s.lists[cfg.ID]
	stillWanted := l != nil && l.bit == bit && l.cfg.URL == cfg.URL && l.cfg.Format == cfg.Format
	keep := CustomBit
	for _, o := range s.lists {
		keep |= o.bit
	}
	s.mu.Unlock()
	if !stillWanted {
		return result{code: "", entries: -1}
	}
	s.cur.Store(Rebuild(cur, keep, []Update{{Bit: bit, Parsed: p}}))
	return result{entries: p.Entries()}
}

func (s *Service) download(cfg config.FilterList, bit uint32, etag, lastMod string, loaded bool) result {
	ctx, cancel := context.WithTimeout(s.ctx, s.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.URL, nil)
	if err != nil {
		return result{code: ErrCodeDownload, detail: err.Error()}
	}
	req.Header.Set("User-Agent", "mrk-dns-filter/1")
	if loaded && etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if loaded && lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}
	resp, err := s.opts.Client.Do(req)
	if err != nil {
		return result{code: ErrCodeDownload, detail: err.Error()}
	}
	defer resp.Body.Close()
	now := s.opts.Now()
	if resp.StatusCode == http.StatusNotModified && loaded {
		m, _ := s.readMeta(cfg.ID)
		m.UpdatedAt = now
		_ = s.writeMeta(cfg.ID, m)
		return result{entries: -1, at: now, etag: etag, lastMod: lastMod}
	}
	if resp.StatusCode != http.StatusOK {
		return result{code: ErrCodeHTTP, detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	if resp.ContentLength > s.opts.MaxListBytes {
		return result{code: ErrCodeTooLarge, detail: fmt.Sprintf("larger than %d bytes", s.opts.MaxListBytes)}
	}
	if err := os.MkdirAll(s.opts.Dir, 0o750); err != nil {
		return result{code: ErrCodeStore, detail: err.Error()}
	}
	tmp, err := os.CreateTemp(s.opts.Dir, ".tmp-*")
	if err != nil {
		return result{code: ErrCodeStore, detail: err.Error()}
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, s.opts.MaxListBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return result{code: ErrCodeDownload, detail: err.Error()}
	}
	if n > s.opts.MaxListBytes {
		return result{code: ErrCodeTooLarge, detail: fmt.Sprintf("larger than %d bytes", s.opts.MaxListBytes)}
	}
	r := s.apply(cfg, bit, tmpName)
	if r.code != "" {
		return r // the previous version (if any) stays in the matcher
	}
	if err := os.Rename(tmpName, s.listPath(cfg.ID)); err != nil {
		s.opts.Log.Warn("filter list cache", "id", cfg.ID, "err", err)
	}
	r.at, r.etag, r.lastMod = now, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	m := meta{URL: cfg.URL, Format: cfg.Format, UpdatedAt: now, Entries: r.entries, ETag: r.etag, LastModified: r.lastMod}
	if err := s.writeMeta(cfg.ID, m); err != nil {
		s.opts.Log.Warn("filter list meta", "id", cfg.ID, "err", err)
	}
	return r
}

func (s *Service) writeMeta(id string, m meta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(s.metaPath(id), b, 0o640)
}

// Prune removes cached files of lists no longer configured.
func (s *Service) Prune(ids map[string]bool) {
	ents, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.opts.Log.Warn("filter list cache", "err", err)
		}
		return
	}
	for _, e := range ents {
		n := e.Name()
		ext := filepath.Ext(n)
		if ext != ".list" && ext != ".json" {
			continue
		}
		if !ids[n[:len(n)-len(ext)]] {
			_ = os.Remove(filepath.Join(s.opts.Dir, n))
		}
	}
}
