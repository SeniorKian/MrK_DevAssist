// Package admin serves the engine's management API (docs/37 §2): HTTP+JSON
// over a unix socket (0660), bearer-token authentication (token file 0640,
// constant-time compare), 4 MiB body cap, strict JSON decoding and the
// {error:{code,message,fields?}} envelope.
package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/engine"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/store"
	"mrk/dns-engine/internal/zone"
)

// MaxBody is the request body cap.
const MaxBody = 4 << 20

// StatusFunc returns listener status from the DNS server.
type StatusFunc func() []engine.ListenerStatus

// API is the HTTP handler.
type API struct {
	e         *engine.Engine
	listeners StatusFunc
	token     []byte
	log       *slog.Logger
	mux       *http.ServeMux
	stop      context.Context // cancelled when Serve stops (ends live streams)
}

// New builds the API.
func New(e *engine.Engine, listeners StatusFunc, token string, log *slog.Logger) *API {
	a := &API{e: e, listeners: listeners, token: []byte(token), log: log, mux: http.NewServeMux()}
	a.routes()
	return a
}

// EnsureToken reads the token at path or creates a new random one (0640).
func EnsureToken(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		t := strings.TrimSpace(string(b))
		if len(t) >= 32 {
			return t, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	t := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	if err := store.WriteFileAtomic(path, []byte(t+"\n"), 0o640); err != nil {
		return "", err
	}
	return t, nil
}

// ListenUnix binds path (removing a stale socket) with mode 0660.
func ListenUnix(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, 200*time.Millisecond); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s is in use by another process", path)
		}
		_ = os.Remove(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	old := syscall.Umask(0o117) // socket is created 0660 from the start
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve runs the HTTP server on ln until ctx is done.
func (a *API) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: a, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	a.stop = ctx
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// ServeHTTP authenticates, caps the body and dispatches.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path != "/v1/health" {
		h := r.Header.Get("Authorization")
		tok, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(tok)), a.token) != 1 {
			writeErr(w, &fielderr.Error{Code: "unauthorized", Message: "missing or invalid bearer token", Status: 401})
			return
		}
	}
	if r.ContentLength > MaxBody {
		writeErr(w, &fielderr.Error{Code: "body_too_large", Message: "request body exceeds 4 MiB", Status: 413})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	if r.Method == http.MethodGet || r.URL.Path == "/v1/resolve" {
		a.mux.ServeHTTP(w, r)
		return
	}
	// changes are attributed to the panel user named by X-MRK-Actor (zone history "actor")
	_ = a.e.WithActor(actorFrom(r), func() error { a.mux.ServeHTTP(w, r); return nil })
}

func actorFrom(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("X-MRK-Actor"))
	if v == "" || len(v) > 128 {
		return "api"
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return "api"
		}
	}
	return v
}

var statusByCode = map[string]int{
	engine.CodeConfigConflict: 409, engine.CodeSettingsInvalid: 422, engine.CodeZoneExists: 409,
	engine.CodeZoneNotFound: 404, engine.CodeInvalidZoneName: 422, engine.CodeZoneInvalid: 422,
	engine.CodeZoneTypeMismatch: 409, engine.CodeRecordNotFound: 404, engine.CodeRecordInvalid: 422,
	engine.CodeCNAMEConflict: 409, engine.CodeOverrideNotFound: 404, engine.CodeOverrideInvalid: 422,
	engine.CodeVersionNotFound: 404, engine.CodeImportInvalid: 422, engine.CodeInvalidRequest: 400,
	engine.CodeTooMany: 409, "not_found": 404, "method_not_allowed": 405,
	"mitigation_invalid": 422, "mitigation_not_found": 404, "too_many_streams": 429, "querylog_disabled": 409,
	"query_invalid": 422,
}

type errBody struct {
	Code    string        `json:"code"`
	Message string        `json:"message"`
	Fields  fielderr.List `json:"fields,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var fe *fielderr.Error
	if !errors.As(err, &fe) {
		writeJSON(w, 500, map[string]any{"error": errBody{Code: "internal", Message: "internal error"}})
		return
	}
	st := fe.Status
	if st == 0 {
		st = statusByCode[fe.Code]
	}
	if st == 0 {
		st = 400
	}
	writeJSON(w, st, map[string]any{"error": errBody{Code: fe.Code, Message: fe.Message, Fields: fe.Fields}})
}

// decode strictly decodes the body into v.
func decode(r *http.Request, v any) error {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return &fielderr.Error{Code: "body_too_large", Message: "request body exceeds 4 MiB", Status: 413}
		}
		return fielderr.New(engine.CodeInvalidRequest, "cannot read body")
	}
	if len(bytes.TrimSpace(b)) == 0 {
		b = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var l fielderr.List
		msg := err.Error()
		var te *json.UnmarshalTypeError
		switch {
		case errors.As(err, &te):
			l.Add(te.Field, "invalid_type", "expected", te.Type.String())
		case strings.HasPrefix(msg, "json: unknown field "):
			l.Add(strings.Trim(strings.TrimPrefix(msg, "json: unknown field "), `"`), "unknown_field")
		default:
			l.Add("", "invalid_json", "detail", msg)
		}
		return &fielderr.Error{Code: engine.CodeInvalidRequest, Message: "invalid JSON body", Fields: l}
	}
	if dec.More() {
		return fielderr.New(engine.CodeInvalidRequest, "trailing data after JSON body")
	}
	return nil
}

func (a *API) handle(pattern string, h func(w http.ResponseWriter, r *http.Request) error) {
	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			var fe *fielderr.Error
			if !errors.As(err, &fe) {
				a.log.Error("admin request failed", "method", r.Method, "path", r.URL.Path, "err", err)
			}
			writeErr(w, err)
		}
	})
}

type settingsView struct {
	config.Settings
	ConfigVersion int64 `json:"config_version"`
}

type settingsBody struct {
	config.Settings
	ConfigVersion *int64 `json:"config_version"`
}

type items[T any] struct {
	Items []T `json:"items"`
}

func (a *API) routes() {
	a.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, fielderr.New("not_found", "no such endpoint"))
	})
	a.handle("GET /v1/health", func(w http.ResponseWriter, r *http.Request) error {
		ls := a.listeners()
		ok := false
		for _, l := range ls {
			ok = ok || l.OK
		}
		st := 200
		if !ok {
			st = 503
		}
		writeJSON(w, st, map[string]any{"ok": ok, "listeners": ls})
		return nil
	})
	a.handle("GET /v1/status", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, a.e.Status(a.listeners()))
		return nil
	})
	a.handle("GET /v1/metrics", func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		a.e.WritePrometheus(w)
		return nil
	})
	a.handle("GET /v1/settings", func(w http.ResponseWriter, r *http.Request) error {
		s, v := a.e.Settings()
		writeJSON(w, 200, settingsView{s, v})
		return nil
	})
	a.handle("PUT /v1/settings", func(w http.ResponseWriter, r *http.Request) error {
		cur, _ := a.e.Settings()
		body := settingsBody{Settings: cur}
		// decoded onto the current settings: a provided list replaces the current one,
		// an omitted key keeps its current value
		if err := decode(r, &body); err != nil {
			return err
		}
		if body.ConfigVersion == nil {
			return fielderr.Single(engine.CodeSettingsInvalid, "config_version is required", "config_version", "required")
		}
		s, v, err := a.e.PutSettings(body.Settings, *body.ConfigVersion)
		if err != nil {
			return err
		}
		writeJSON(w, 200, settingsView{s, v})
		return nil
	})

	// zones
	a.handle("GET /v1/zones", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, items[engine.ZoneSummary]{a.e.Zones()})
		return nil
	})
	a.handle("POST /v1/zones", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Name       string   `json:"name"`
			Type       string   `json:"type"`
			Forwarders []string `json:"forwarders"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.Type == "" {
			b.Type = zone.TypePrimary
		}
		d, err := a.e.CreateZone(b.Name, b.Type, b.Forwarders)
		if err != nil {
			return err
		}
		writeJSON(w, 201, d)
		return nil
	})
	a.handle("GET /v1/zones/{zone}", func(w http.ResponseWriter, r *http.Request) error {
		d, err := a.e.Zone(r.PathValue("zone"))
		if err != nil {
			return err
		}
		writeJSON(w, 200, d)
		return nil
	})
	a.handle("PATCH /v1/zones/{zone}", func(w http.ResponseWriter, r *http.Request) error {
		var p engine.ZonePatch
		if err := decode(r, &p); err != nil {
			return err
		}
		d, err := a.e.PatchZone(r.PathValue("zone"), p)
		if err != nil {
			return err
		}
		writeJSON(w, 200, d)
		return nil
	})
	a.handle("DELETE /v1/zones/{zone}", func(w http.ResponseWriter, r *http.Request) error {
		if err := a.e.DeleteZone(r.PathValue("zone")); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	})
	a.handle("GET /v1/zones/{zone}/export", func(w http.ResponseWriter, r *http.Request) error {
		t, err := a.e.Export(r.PathValue("zone"))
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "text/dns; charset=utf-8")
		_, _ = io.WriteString(w, t)
		return nil
	})
	a.handle("POST /v1/zones/{zone}/import", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Text    string `json:"text"`
			Replace bool   `json:"replace"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		res, err := a.e.Import(r.PathValue("zone"), b.Text, b.Replace)
		if err != nil {
			return err
		}
		writeJSON(w, 200, res)
		return nil
	})
	a.handle("GET /v1/zones/{zone}/history", func(w http.ResponseWriter, r *http.Request) error {
		h, err := a.e.History(r.PathValue("zone"))
		if err != nil {
			return err
		}
		if h == nil {
			h = []store.HistoryEntry{}
		}
		writeJSON(w, 200, items[store.HistoryEntry]{h})
		return nil
	})
	a.handle("POST /v1/zones/{zone}/rollback", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Version json.RawMessage `json:"version"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		// the panel may send the version as a number or a string
		v, err := strconv.Atoi(strings.Trim(strings.TrimSpace(string(b.Version)), `"`))
		if err != nil || v < 1 {
			return fielderr.Single(engine.CodeInvalidRequest, "version is required", "version", "required")
		}
		d, err := a.e.Rollback(r.PathValue("zone"), v)
		if err != nil {
			return err
		}
		writeJSON(w, 200, d)
		return nil
	})

	// records
	a.handle("GET /v1/zones/{zone}/records", func(w http.ResponseWriter, r *http.Request) error {
		rs, err := a.e.Records(r.PathValue("zone"))
		if err != nil {
			return err
		}
		writeJSON(w, 200, items[zone.Record]{rs})
		return nil
	})
	a.handle("POST /v1/zones/{zone}/records", func(w http.ResponseWriter, r *http.Request) error {
		var in zone.RecordInput
		if err := decode(r, &in); err != nil {
			return err
		}
		rec, err := a.e.CreateRecord(r.PathValue("zone"), in)
		if err != nil {
			return err
		}
		writeJSON(w, 201, rec)
		return nil
	})
	a.handle("PUT /v1/zones/{zone}/records/{id}", func(w http.ResponseWriter, r *http.Request) error {
		var in zone.RecordInput
		if err := decode(r, &in); err != nil {
			return err
		}
		rec, err := a.e.UpdateRecord(r.PathValue("zone"), r.PathValue("id"), in)
		if err != nil {
			return err
		}
		writeJSON(w, 200, rec)
		return nil
	})
	a.handle("DELETE /v1/zones/{zone}/records/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if err := a.e.DeleteRecord(r.PathValue("zone"), r.PathValue("id")); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	})

	// overrides
	a.handle("GET /v1/overrides", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, items[engine.Override]{a.e.Overrides()})
		return nil
	})
	a.handle("POST /v1/overrides", func(w http.ResponseWriter, r *http.Request) error {
		var in engine.OverrideInput
		if err := decode(r, &in); err != nil {
			return err
		}
		o, err := a.e.CreateOverride(in)
		if err != nil {
			return err
		}
		writeJSON(w, 201, o)
		return nil
	})
	a.handle("PUT /v1/overrides/{id}", func(w http.ResponseWriter, r *http.Request) error {
		var in engine.OverrideInput
		if err := decode(r, &in); err != nil {
			return err
		}
		o, err := a.e.UpdateOverride(r.PathValue("id"), in)
		if err != nil {
			return err
		}
		writeJSON(w, 200, o)
		return nil
	})
	a.handle("DELETE /v1/overrides/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if err := a.e.DeleteOverride(r.PathValue("id")); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	})

	// tools
	a.handle("POST /v1/resolve", func(w http.ResponseWriter, r *http.Request) error {
		var b engine.ResolveRequest
		if err := decode(r, &b); err != nil {
			return err
		}
		s, _ := a.e.Settings()
		timeout := time.Duration(s.Resolution.ResolveTimeoutMS)*time.Millisecond + 2*time.Second
		if b.Trace {
			timeout += 4 * time.Second // the validator's DS/DNSKEY lookups are traced uncached too
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		res, err := a.e.ResolveWith(ctx, b)
		if err != nil {
			return err
		}
		writeJSON(w, 200, res)
		return nil
	})
	a.handle("POST /v1/cache/flush", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Name string `json:"name"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		n, err := a.e.FlushCache(b.Name)
		if err != nil {
			return err
		}
		writeJSON(w, 200, map[string]any{"flushed": n})
		return nil
	})
	a.monitorRoutes()
	a.d4Routes()
	a.encryptedRoutes()
}
