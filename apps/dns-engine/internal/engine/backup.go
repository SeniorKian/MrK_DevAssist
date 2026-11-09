package engine

// Backup and restore (docs/41 §4): GET /v1/backup is a tar.gz of the state
// files of the data directory (a generic walk with an allow-list, so files
// added by other parts of the engine are covered) with a versioned
// manifest; POST /v1/restore validates the whole archive first and then
// swaps the files atomically (journaled, rolled back on failure or after a
// crash) and reloads the engine in place.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mrk/dns-engine/internal/certs"
	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/mitigate"
	"mrk/dns-engine/internal/store"
	"mrk/dns-engine/internal/tokens"
	"mrk/dns-engine/internal/version"
	"mrk/dns-engine/internal/zone"
)

// Backup format.
const (
	BackupFormat  = "mrk-dns-backup"
	BackupVersion = 1
	// CodeRestoreInvalid is the 422 error of a rejected archive.
	CodeRestoreInvalid = "restore_invalid"
	// CodeBackupFailed is the 500 error of a backup that could not be built.
	CodeBackupFailed = "backup_failed"
	manifestName     = "manifest.json"
	// bounds of an archive
	maxBackupFile  = 256 << 20
	maxBackupTotal = 1 << 30
	maxBackupFiles = 200_000
	journalName    = ".restore-journal.json"
)

// BackupManifest is manifest.json.
type BackupManifest struct {
	Format        string       `json:"format"`
	Version       int          `json:"version"`
	EngineVersion string       `json:"engine_version"`
	CreatedAt     time.Time    `json:"created_at"`
	ConfigVersion int64        `json:"config_version"`
	Files         []BackupFile `json:"files"`
}

// BackupFile is one archived file.
type BackupFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// excludedDirs hold derived or bulky data that is rebuilt (logs, statistics,
// downloaded block lists, transferred secondary zones).
var excludedDirs = map[string]bool{"querylog": true, "stats": true, "filter-lists": true, "secondary": true}

// excludedFiles are re-fetched automatically (RFC 5011 trust anchors).
var excludedFiles = map[string]bool{"trust-anchors.json": true}

// backupIncluded reports whether rel (slash-separated, relative to the data
// directory) belongs in a backup: state documents (.json), certificates and
// keys (.pem, .key), outside the excluded directories and hidden files.
func backupIncluded(rel string) bool {
	if rel == "" || len(rel) > 512 || strings.ContainsAny(rel, "\\\x00") {
		return false
	}
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.HasPrefix(p, ".") {
			return false
		}
	}
	if excludedDirs[parts[0]] || excludedFiles[rel] {
		return false
	}
	switch path.Ext(rel) {
	case ".json", ".pem", ".key":
		return true
	}
	return false
}

// secretFile reports files written 0600 on restore.
func secretFile(rel string) bool {
	return strings.HasPrefix(rel, "tls/") || strings.HasSuffix(rel, ".key") || strings.Contains(rel, "tsig") ||
		strings.Contains(rel, "dnssec") || strings.Contains(rel, "token")
}

// RestoreHook lets another part of the engine validate and reload the files
// under Prefix it owns (e.g. TSIG or DNSSEC key stores).
type RestoreHook struct {
	Prefix   string
	Validate func(stageDir string) error
	Reload   func() error
}

// RegisterRestoreHook adds a hook (call before serving).
func (e *Engine) RegisterRestoreHook(h RestoreHook) {
	e.mu.Lock()
	e.pst.hooks = append(e.pst.hooks, h)
	e.mu.Unlock()
}

// coreReloaded are the prefixes Restore reloads itself.
var coreReloaded = []string{"settings.json", "overrides.json", "mitigations.json", "doh-tokens.json", "zones/", "tls/"}

func listBackupFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == dir {
				return err
			}
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			first := strings.SplitN(rel, "/", 2)[0]
			if excludedDirs[first] || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && backupIncluded(rel) {
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// Backup writes the archive to w. The files are copied under the state lock
// into a temporary archive (a consistent snapshot), then streamed.
func (e *Engine) Backup(w io.Writer) error {
	tmp, err := e.backupFile()
	if err != nil {
		e.log.Error("backup failed", "err", err)
		return &fielderr.Error{Code: CodeBackupFailed, Message: err.Error(), Status: 500}
	}
	defer os.Remove(tmp)
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func (e *Engine) backupFile() (string, error) {
	_ = e.mon.mit.Save()
	_ = e.enc.toks.Save()
	e.mu.Lock()
	defer e.mu.Unlock()
	dir := e.st.Dir()
	files, err := listBackupFiles(dir)
	if err != nil {
		return "", err
	}
	if len(files) > maxBackupFiles {
		return "", fmt.Errorf("backup: %d files exceed %d", len(files), maxBackupFiles)
	}
	man := BackupManifest{Format: BackupFormat, Version: BackupVersion, EngineVersion: version.String(),
		CreatedAt: time.Now().UTC().Truncate(time.Second), ConfigVersion: e.configVersion, Files: []BackupFile{}}
	var total int64
	for _, rel := range files {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		total += int64(len(b))
		if len(b) > maxBackupFile || total > maxBackupTotal {
			return "", fmt.Errorf("backup: data exceeds the archive limits")
		}
		sum := sha256.Sum256(b)
		man.Files = append(man.Files, BackupFile{Path: rel, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])})
	}
	out, err := os.CreateTemp(dir, ".backup-*.tar.gz")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			out.Close()
			os.Remove(out.Name())
		}
	}()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	mb, _ := json.MarshalIndent(man, "", " ")
	put := func(name string, b []byte) error {
		h := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: man.CreatedAt, Typeflag: tar.TypeReg,
			Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := put(manifestName, mb); err != nil {
		return "", err
	}
	for _, f := range man.Files {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil {
			return "", err
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != f.SHA256 {
			return "", fmt.Errorf("backup: %s changed during the backup", f.Path) // never under the lock
		}
		if err := put(f.Path, b); err != nil {
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	ok = true
	return out.Name(), nil
}

// RestoreResult is POST /v1/restore.
type RestoreResult struct {
	Restored        bool     `json:"restored"`
	Files           int      `json:"files"`
	ConfigVersion   int64    `json:"config_version"`
	BackupCreatedAt string   `json:"backup_created_at"`
	RestartRequired bool     `json:"restart_required"`
	RestartFor      []string `json:"restart_for,omitempty"`
}

func restoreInvalid(field, reason string, params ...any) error {
	return fielderr.Single(CodeRestoreInvalid, "the backup archive is invalid", field, reason, params...)
}

// Restore validates the archive read from r completely, then replaces the
// state files and reloads the engine. Nothing changes when it fails.
func (e *Engine) Restore(r io.Reader) (RestoreResult, error) {
	dir := e.st.Dir()
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	stage := filepath.Join(dir, ".restore-"+hex.EncodeToString(rnd[:]))
	newDir := filepath.Join(stage, "new")
	if err := os.MkdirAll(newDir, 0o700); err != nil {
		return RestoreResult{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stage)
		}
	}()
	man, err := extractBackup(r, newDir)
	if err != nil {
		return RestoreResult{}, err
	}
	if err := e.validateStage(newDir); err != nil {
		return RestoreResult{}, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	for _, h := range e.pst.hooks {
		if h.Validate != nil {
			if err := h.Validate(newDir); err != nil {
				return RestoreResult{}, restoreInvalid(h.Prefix, "invalid", "detail", err.Error())
			}
		}
	}
	restored := map[string]bool{}
	for _, f := range man.Files {
		restored[f.Path] = true
	}
	current, err := listBackupFiles(dir)
	if err != nil {
		return RestoreResult{}, err
	}
	changed := map[string]bool{}
	for _, rel := range current {
		changed[rel] = true
	}
	for rel := range restored {
		changed[rel] = true
	}
	if err := swapIn(dir, stage, current, man.Files); err != nil {
		return RestoreResult{}, err
	}
	prevVersion := e.configVersion
	if err := e.reloadLocked(prevVersion); err != nil {
		// the validated archive did not load: put the previous state back
		e.log.Error("restore: reload failed; rolling back", "err", err)
		if rerr := rollbackSwap(dir, stage); rerr != nil {
			e.log.Error("restore: rollback failed", "err", rerr)
		}
		if rerr := e.reloadLocked(prevVersion); rerr != nil {
			e.log.Error("restore: reload after rollback failed", "err", rerr)
		}
		return RestoreResult{}, err
	}
	_ = os.Remove(filepath.Join(dir, journalName))
	res := RestoreResult{Restored: true, Files: len(man.Files), ConfigVersion: e.configVersion,
		BackupCreatedAt: man.CreatedAt.UTC().Format(time.RFC3339)}
	need := map[string]bool{}
	for rel := range changed {
		if handled(rel, coreReloaded) {
			continue
		}
		hooked := false
		for _, h := range e.pst.hooks {
			if strings.HasPrefix(rel, h.Prefix) {
				hooked = true
			}
		}
		if !hooked {
			need[strings.SplitN(rel, "/", 2)[0]] = true
		}
	}
	for k := range need {
		res.RestartFor = append(res.RestartFor, k)
	}
	sort.Strings(res.RestartFor)
	res.RestartRequired = len(res.RestartFor) > 0
	for _, h := range e.pst.hooks {
		if h.Reload != nil {
			if err := h.Reload(); err != nil {
				e.log.Error("restore: hook reload failed", "prefix", h.Prefix, "err", err)
				res.RestartRequired = true
				res.RestartFor = append(res.RestartFor, h.Prefix)
			}
		}
	}
	e.log.Info("restore: state replaced", "files", res.Files, "config_version", res.ConfigVersion,
		"restart_required", res.RestartRequired)
	return res, nil
}

func handled(rel string, prefixes []string) bool {
	for _, p := range prefixes {
		if rel == p || strings.HasSuffix(p, "/") && strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

// extractBackup unpacks a validated archive into dir and checks it against
// its manifest.
func extractBackup(r io.Reader, dir string) (*BackupManifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, restoreInvalid("archive", "not_gzip")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var man *BackupManifest
	type got struct {
		size int64
		sum  string
	}
	files := map[string]got{}
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, restoreInvalid("archive", "corrupt", "detail", err.Error())
		}
		if n > maxBackupFiles {
			return nil, restoreInvalid("archive", "too_many_files", "max", maxBackupFiles)
		}
		name := h.Name
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return nil, restoreInvalid(name, "not_a_regular_file")
		}
		if h.Size < 0 || h.Size > maxBackupFile {
			return nil, restoreInvalid(name, "too_large", "max", maxBackupFile)
		}
		total += h.Size
		if total > maxBackupTotal {
			return nil, restoreInvalid("archive", "too_large", "max", maxBackupTotal)
		}
		if name == manifestName {
			if man != nil {
				return nil, restoreInvalid(name, "duplicate")
			}
			b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
			if err != nil {
				return nil, restoreInvalid("archive", "corrupt", "detail", err.Error())
			}
			man = &BackupManifest{}
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(man); err != nil {
				return nil, restoreInvalid(name, "invalid_json", "detail", err.Error())
			}
			continue
		}
		if path.Clean(name) != name || path.IsAbs(name) || !backupIncluded(name) {
			return nil, restoreInvalid(name, "path_not_allowed")
		}
		if _, dup := files[name]; dup {
			return nil, restoreInvalid(name, "duplicate")
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		hs := sha256.New()
		sz, err := io.Copy(io.MultiWriter(f, hs), io.LimitReader(tr, maxBackupFile+1))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, restoreInvalid("archive", "corrupt", "detail", err.Error())
		}
		files[name] = got{size: sz, sum: hex.EncodeToString(hs.Sum(nil))}
	}
	if man == nil {
		return nil, restoreInvalid(manifestName, "required")
	}
	if man.Format != BackupFormat {
		return nil, restoreInvalid(manifestName+".format", "invalid_choice", "choices", []string{BackupFormat})
	}
	if man.Version < 1 || man.Version > BackupVersion {
		return nil, restoreInvalid(manifestName+".version", "unsupported_version", "max", BackupVersion)
	}
	if len(man.Files) != len(files) {
		return nil, restoreInvalid(manifestName+".files", "mismatch", "archive", len(files), "manifest", len(man.Files))
	}
	for i, f := range man.Files {
		g, ok := files[f.Path]
		if !ok {
			return nil, restoreInvalid(fmt.Sprintf("%s.files[%d]", manifestName, i), "missing_file", "path", f.Path)
		}
		if g.size != f.Size || g.sum != strings.ToLower(f.SHA256) {
			return nil, restoreInvalid(fmt.Sprintf("%s.files[%d]", manifestName, i), "checksum_mismatch", "path", f.Path)
		}
	}
	return man, nil
}

// validateStage checks every state file of the staged archive with the same
// code that loads it.
func (e *Engine) validateStage(dir string) error {
	var sd settingsDoc
	b, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil {
		return restoreInvalid("settings.json", "required")
	}
	if err := json.Unmarshal(b, &sd); err != nil {
		return restoreInvalid("settings.json", "invalid_json", "detail", err.Error())
	}
	merged := config.Defaults(e.opts.DefaultListen)
	mergeSettings(&merged, sd.Settings)
	if l := merged.Validate(); len(l) > 0 {
		var out fielderr.List
		out.Prefixed("settings.json", l)
		return out.Err(CodeRestoreInvalid, "the backup settings are invalid")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "overrides.json")); err == nil {
		var od overridesDoc
		if err := json.Unmarshal(b, &od); err != nil {
			return restoreInvalid("overrides.json", "invalid_json", "detail", err.Error())
		}
		if len(od.Items) > MaxOverrides {
			return restoreInvalid("overrides.json", "too_many", "max", MaxOverrides)
		}
		for i, o := range od.Items {
			if _, err := overrideRR(o); err != nil {
				return restoreInvalid(fmt.Sprintf("overrides.json.items[%d]", i), "invalid_override")
			}
		}
		if err := checkOverrideSet(od.Items); err != nil {
			return restoreInvalid("overrides.json", "invalid", "detail", err.Error())
		}
	}
	st, err := store.Open(dir)
	if err != nil {
		return err
	}
	zs, warns := st.LoadZones()
	if len(warns) > 0 {
		return restoreInvalid("zones", "unreadable", "detail", warns[0].Error())
	}
	if len(zs) > MaxZones {
		return restoreInvalid("zones", "too_many", "max", MaxZones)
	}
	for _, z := range zs {
		f := "zones/" + zone.Display(z.Name) + ".json"
		if _, ok := zone.NormalizeZoneName(z.Name); !ok {
			return restoreInvalid(f, "invalid_zone_name")
		}
		if z.Type == zone.TypePrimary {
			if l := zone.ValidateRecords(z.Name, z.Records); len(l) > 0 {
				return restoreInvalid(f, "invalid_records", "detail", l.Err(CodeRecordInvalid, "invalid").Error())
			}
		}
		if _, err := zone.Compile(z); err != nil {
			return restoreInvalid(f, "invalid_zone", "detail", err.Error())
		}
	}
	if _, err := mitigate.Open(filepath.Join(dir, "mitigations.json"), nil); err != nil {
		return restoreInvalid("mitigations.json", "invalid", "detail", err.Error())
	}
	if _, err := tokens.Open(st, nil); err != nil {
		return restoreInvalid("doh-tokens.json", "invalid", "detail", err.Error())
	}
	if _, err := certs.Open(dir, nil); err != nil {
		return restoreInvalid("tls", "invalid", "detail", err.Error())
	}
	// every other document must at least be JSON
	files, err := listBackupFiles(dir)
	if err != nil {
		return err
	}
	for _, rel := range files {
		if !strings.HasSuffix(rel, ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if !json.Valid(b) {
			return restoreInvalid(rel, "invalid_json")
		}
	}
	return nil
}

// journal records the swap phase so an interrupted restore is rolled back.
type journal struct {
	Stage string `json:"stage"`
	Phase string `json:"phase"` // moving_old | moving_new
}

func writeJournal(dir string, j journal) error {
	b, _ := json.Marshal(j)
	return store.WriteFileAtomic(filepath.Join(dir, journalName), b, 0o600)
}

func moveFile(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
		return err
	}
	return os.Rename(from, to)
}

// swapIn moves the current files to stage/old and the staged ones in place.
func swapIn(dir, stage string, current []string, files []BackupFile) error {
	oldDir := filepath.Join(stage, "old")
	if err := writeJournal(dir, journal{Stage: filepath.Base(stage), Phase: "moving_old"}); err != nil {
		return err
	}
	for _, rel := range current {
		if err := moveFile(filepath.Join(dir, filepath.FromSlash(rel)), filepath.Join(oldDir, filepath.FromSlash(rel))); err != nil {
			_ = rollbackSwap(dir, stage)
			return err
		}
	}
	if err := writeJournal(dir, journal{Stage: filepath.Base(stage), Phase: "moving_new"}); err != nil {
		_ = rollbackSwap(dir, stage)
		return err
	}
	for _, f := range files {
		src := filepath.Join(stage, "new", filepath.FromSlash(f.Path))
		dst := filepath.Join(dir, filepath.FromSlash(f.Path))
		if !secretFile(f.Path) {
			_ = os.Chmod(src, 0o640)
		}
		if err := moveFile(src, dst); err != nil {
			_ = rollbackSwap(dir, stage)
			return err
		}
	}
	_ = os.Remove(filepath.Join(dir, journalName))
	return nil
}

// rollbackSwap restores stage/old: in phase moving_new every included file
// in dir came from the archive and is removed first.
func rollbackSwap(dir, stage string) error {
	var j journal
	if b, err := os.ReadFile(filepath.Join(dir, journalName)); err == nil {
		_ = json.Unmarshal(b, &j)
	} else {
		j.Phase = "moving_new" // called after the swap completed (reload failed)
	}
	if j.Phase == "moving_new" {
		cur, _ := listBackupFiles(dir)
		for _, rel := range cur {
			_ = os.Remove(filepath.Join(dir, filepath.FromSlash(rel)))
		}
	}
	oldDir := filepath.Join(stage, "old")
	old, err := listBackupFiles(oldDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var first error
	for _, rel := range old {
		if err := moveFile(filepath.Join(oldDir, filepath.FromSlash(rel)), filepath.Join(dir, filepath.FromSlash(rel))); err != nil && first == nil {
			first = err
		}
	}
	_ = os.Remove(filepath.Join(dir, journalName))
	return first
}

// recoverRestore finishes an interrupted restore at start-up: the previous
// state is put back, then stale staging directories are removed.
func recoverRestore(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, journalName))
	if err == nil {
		var j journal
		if json.Unmarshal(b, &j) == nil && strings.HasPrefix(j.Stage, ".restore-") && !strings.ContainsAny(j.Stage, "/\\") {
			if err := rollbackSwap(dir, filepath.Join(dir, j.Stage)); err != nil {
				return fmt.Errorf("roll back the interrupted restore: %w", err)
			}
		} else {
			_ = os.Remove(filepath.Join(dir, journalName))
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, en := range ents {
		n := en.Name()
		if en.IsDir() && strings.HasPrefix(n, ".restore-") || !en.IsDir() && strings.HasPrefix(n, ".backup-") {
			_ = os.RemoveAll(filepath.Join(dir, n))
		}
	}
	return nil
}

// reloadLocked re-reads settings, overrides, zones, mitigations, DoH tokens
// and the certificate from disk and publishes them (e.mu held). The config
// version always moves forward so a panel holding an old version conflicts.
func (e *Engine) reloadLocked(prevVersion int64) error {
	var sd settingsDoc
	if err := e.st.ReadJSON("settings.json", &sd); err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	merged := config.Defaults(e.opts.DefaultListen)
	mergeSettings(&merged, sd.Settings)
	if l := merged.Validate(); len(l) > 0 {
		return l.Err(CodeSettingsInvalid, "restored settings are invalid")
	}
	var od overridesDoc
	if err := e.st.ReadJSON("overrides.json", &od); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read overrides: %w", err)
	}
	zs, warns := e.st.LoadZones()
	if len(warns) > 0 {
		return fmt.Errorf("load zones: %v", warns[0])
	}
	// the DNSSEC keys on disk may have been replaced: never sign with (or,
	// on an algorithm mismatch, overwrite them with) stale cached keys
	e.resetDNSSECCacheLocked()
	zones := map[string]*zone.Zone{}
	compiled := map[string]*zone.Compiled{}
	for _, z := range zs {
		c, err := e.compileZone(z)
		if err != nil {
			return fmt.Errorf("zone %s: %w", z.Name, err)
		}
		zones[z.Name], compiled[z.Name] = z, c
	}
	prev := e.settings
	e.settings = merged
	e.configVersion = max(prevVersion, sd.ConfigVersion) + 1
	e.overrides = od.Items
	e.zones, e.compiled = zones, compiled
	if err := e.st.WriteJSON("settings.json", settingsDoc{Schema: store.Schema, ConfigVersion: e.configVersion,
		Settings: e.settings}); err != nil {
		return err
	}
	if err := e.rebuildLocked(); err != nil {
		return err
	}
	e.applyMonitorSettings(e.settings)
	e.Cache.Flush("")
	e.flushGroupCaches("")
	if d4FlushNeeded(prev, e.settings) {
		e.flushD4()
	}
	if err := e.mon.mit.Reload(); err != nil {
		return fmt.Errorf("mitigations: %w", err)
	}
	if err := e.enc.toks.Reload(); err != nil {
		return fmt.Errorf("tokens: %w", err)
	}
	if err := e.enc.certs.Reload(); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	if h := e.listenerHook.Load(); h != nil {
		go (*h)(e.settings.Clone())
	}
	return nil
}
