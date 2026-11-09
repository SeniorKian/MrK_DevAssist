package admin

// Routes of the policy engine (docs/41 §3–§4): filtering status/refresh/
// check and services, backup and restore (zone views: PATCH /v1/zones/{zone}).

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/engine"
)

// MaxRestoreBody caps POST /v1/restore (a backup archive).
const MaxRestoreBody = 1 << 30

// refreshWait bounds how long POST /v1/filtering/refresh waits for the
// downloads (they continue in the background; the response shows
// `updating`).
const refreshWait = 25 * time.Second

func init() {
	statusByCode[engine.CodeRestoreInvalid] = 422
}

func (a *API) policyRoutes() {
	a.handle("GET /v1/filtering/status", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, a.e.FilteringStatus())
		return nil
	})
	a.handle("POST /v1/filtering/refresh", func(w http.ResponseWriter, r *http.Request) error {
		var b struct{}
		if err := decode(r, &b); err != nil {
			return err
		}
		writeJSON(w, 200, a.e.RefreshFiltering(r.Context(), refreshWait))
		return nil
	})
	a.handle("POST /v1/filtering/check", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Name     string `json:"name"`
			Client   string `json:"client"`
			ClientIP string `json:"client_ip"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.Client == "" {
			b.Client = b.ClientIP
		}
		res, err := a.e.CheckFilter(b.Name, b.Client)
		if err != nil {
			return err
		}
		writeJSON(w, 200, res)
		return nil
	})
	a.handle("GET /v1/filtering/services", func(w http.ResponseWriter, r *http.Request) error {
		type svc struct {
			ID      string   `json:"id"`
			Domains []string `json:"domains"`
		}
		out := []svc{}
		for _, id := range config.ServiceIDs() {
			out = append(out, svc{ID: id, Domains: config.BlockedServices[id]})
		}
		writeJSON(w, 200, items[svc]{out})
		return nil
	})

	a.handle("GET /v1/backup", func(w http.ResponseWriter, r *http.Request) error {
		// the archive is built first (errors are still JSON), then streamed
		pr, pw := io.Pipe()
		errc := make(chan error, 1)
		go func() {
			err := a.e.Backup(pw)
			pw.CloseWithError(err)
			errc <- err
		}()
		var first [1]byte
		n, err := io.ReadFull(pr, first[:])
		if err != nil && n == 0 {
			<-errc
			pr.Close()
			return err
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="mrk-dns-backup-%s.tar.gz"`,
			time.Now().UTC().Format("20060102-150405")))
		w.WriteHeader(200)
		_, _ = w.Write(first[:n])
		_, _ = io.Copy(w, pr)
		pr.Close()
		<-errc
		return nil
	})
	a.handle("POST /v1/restore", func(w http.ResponseWriter, r *http.Request) error {
		// one pass: entries are unpacked and checked against the manifest as they arrive
		res, err := a.e.Restore(r.Body)
		if err != nil {
			return err
		}
		writeJSON(w, 200, res)
		return nil
	})
}
