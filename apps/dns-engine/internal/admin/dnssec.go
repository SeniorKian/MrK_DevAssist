package admin

import (
	"net/http"
)

// d4Routes registers the DNSSEC endpoints (docs/40 §3).
func (a *API) d4Routes() {
	a.handle("GET /v1/dnssec", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, a.e.DNSSEC())
		return nil
	})
	a.handle("POST /v1/dnssec/refresh", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, a.e.RefreshTrustAnchors())
		return nil
	})
}
