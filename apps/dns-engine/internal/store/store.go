// Package store persists engine state crash-safely: every file is written to
// a temporary file in the same directory, fsynced, renamed over the target and
// the directory fsynced, so a reader sees either the old or the new content.
// Each zone keeps the last HistoryLimit versions for rollback.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"mrk/dns-engine/internal/zone"
)

// HistoryLimit is the number of zone versions kept.
const HistoryLimit = 50

// Schema is the on-disk document version.
const Schema = 1

// Store is a directory of JSON documents. Methods are not synchronised; the
// engine serialises writers.
type Store struct {
	dir string
}

// Open creates the layout under dir and removes stale temporary files.
func Open(dir string) (*Store, error) {
	s := &Store{dir: dir}
	for _, d := range []string{dir, s.zonesDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasPrefix(d.Name(), ".tmp-") {
			_ = os.Remove(p)
		}
		return nil
	})
	return s, nil
}

// Dir returns the root directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) zonesDir() string { return filepath.Join(s.dir, "zones") }

// WriteFileAtomic writes data to path via temp file + fsync + rename.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return nil // some filesystems (and Windows) do not support directory fsync
	}
	return nil
}

// WriteJSON atomically writes v as JSON to rel (relative to the root).
func (s *Store) WriteJSON(rel string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(s.dir, rel), append(b, '\n'), 0o640)
}

// ReadJSON reads rel into v. It returns fs.ErrNotExist if missing.
func (s *Store) ReadJSON(rel string, v any) error {
	b, err := os.ReadFile(filepath.Join(s.dir, rel))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func zoneBase(name string) string { return zone.Display(name) }

func (s *Store) zonePath(name string) string {
	return filepath.Join(s.zonesDir(), zoneBase(name)+".json")
}

func (s *Store) historyDir(name string) string {
	return filepath.Join(s.zonesDir(), zoneBase(name)+".history")
}

// SaveZone writes the zone and appends it to its history.
func (s *Store) SaveZone(z *zone.Zone) error {
	b, err := json.Marshal(z)
	if err != nil {
		return err
	}
	hd := s.historyDir(z.Name)
	if err := os.MkdirAll(hd, 0o750); err != nil {
		return err
	}
	// history first: if we crash between the two writes, load recovers the
	// newest version from history.
	if err := WriteFileAtomic(filepath.Join(hd, fmt.Sprintf("%08d.json", z.Version)), b, 0o640); err != nil {
		return err
	}
	if err := WriteFileAtomic(s.zonePath(z.Name), b, 0o640); err != nil {
		return err
	}
	return s.pruneHistory(z.Name)
}

func (s *Store) versions(name string) ([]int, error) {
	ents, err := os.ReadDir(s.historyDir(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var vs []int
	for _, e := range ents {
		n := strings.TrimSuffix(e.Name(), ".json")
		if v, err := strconv.Atoi(n); err == nil && strings.HasSuffix(e.Name(), ".json") {
			vs = append(vs, v)
		}
	}
	sort.Ints(vs)
	return vs, nil
}

func (s *Store) pruneHistory(name string) error {
	vs, err := s.versions(name)
	if err != nil {
		return err
	}
	for len(vs) > HistoryLimit {
		_ = os.Remove(filepath.Join(s.historyDir(name), fmt.Sprintf("%08d.json", vs[0])))
		vs = vs[1:]
	}
	return nil
}

// DeleteZone removes a zone and its history.
func (s *Store) DeleteZone(name string) error {
	// history first, so a crash never leaves history that would resurrect the zone
	if err := os.RemoveAll(s.historyDir(name)); err != nil {
		return err
	}
	if err := os.Remove(s.zonePath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(s.zonesDir())
}

// HistoryEntry summarises one stored zone version.
type HistoryEntry struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	Records   int    `json:"records"`
	Actor     string `json:"actor"`
	Serial    uint32 `json:"serial"`
	Reason    string `json:"reason,omitempty"`
}

// History lists stored versions, newest first.
func (s *Store) History(name string) ([]HistoryEntry, error) {
	vs, err := s.versions(name)
	if err != nil {
		return nil, err
	}
	out := make([]HistoryEntry, 0, len(vs))
	for i := len(vs) - 1; i >= 0; i-- {
		z, err := s.LoadVersion(name, vs[i])
		if err != nil {
			continue
		}
		out = append(out, HistoryEntry{Version: z.Version, Serial: z.Serial, Actor: z.Actor,
			CreatedAt: z.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"), Records: len(z.Records), Reason: z.Reason})
	}
	return out, nil
}

// LoadVersion reads one history version.
func (s *Store) LoadVersion(name string, version int) (*zone.Zone, error) {
	var z zone.Zone
	b, err := os.ReadFile(filepath.Join(s.historyDir(name), fmt.Sprintf("%08d.json", version)))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &z); err != nil {
		return nil, err
	}
	return &z, nil
}

// LoadZones reads all zones. A corrupt or stale zone file is recovered from
// the newest readable history version; problems are returned as warnings.
func (s *Store) LoadZones() ([]*zone.Zone, []error) {
	ents, err := os.ReadDir(s.zonesDir())
	if err != nil {
		return nil, []error{err}
	}
	var (
		out  []*zone.Zone
		warn []error
		seen = map[string]bool{}
	)
	load := func(base string) {
		if seen[base] {
			return
		}
		seen[base] = true
		name := base + "."
		var z *zone.Zone
		var cur zone.Zone
		b, err := os.ReadFile(s.zonePath(name))
		if err == nil {
			if err = json.Unmarshal(b, &cur); err == nil {
				z = &cur
			}
		}
		vs, _ := s.versions(name)
		// prefer a newer history version (crash between history and main write)
		for i := len(vs) - 1; i >= 0; i-- {
			if z != nil && vs[i] <= z.Version {
				break
			}
			if hz, herr := s.LoadVersion(name, vs[i]); herr == nil {
				if z == nil {
					warn = append(warn, fmt.Errorf("zone %s: main file unreadable (%v); recovered version %d", base, err, hz.Version))
				}
				z = hz
				break
			}
		}
		if z == nil {
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				warn = append(warn, fmt.Errorf("zone %s: unreadable: %v", base, err))
			}
			return
		}
		out = append(out, z)
	}
	for _, e := range ents {
		n := e.Name()
		switch {
		case !e.IsDir() && strings.HasSuffix(n, ".json") && !strings.HasPrefix(n, "."):
			load(strings.TrimSuffix(n, ".json"))
		case e.IsDir() && strings.HasSuffix(n, ".history"):
			load(strings.TrimSuffix(n, ".history"))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, warn
}
