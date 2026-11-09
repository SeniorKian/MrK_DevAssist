package admin

import (
	"net/http"

	"mrk/dns-engine/internal/certs"
	"mrk/dns-engine/internal/engine"
	"mrk/dns-engine/internal/tokens"
)

func init() {
	statusByCode[certs.CodeInvalid] = 422
	statusByCode[engine.CodeCertificateRequired] = 422
	statusByCode[engine.CodeCertificateInUse] = 409
	statusByCode[tokens.CodeNotFound] = 404
	statusByCode[tokens.CodeInvalid] = 422
}

// encryptedRoutes registers the TLS certificate and DoH token endpoints
// (docs/40 §3). The private key is never returned.
func (a *API) encryptedRoutes() {
	a.handle("GET /v1/tls", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, a.e.TLS())
		return nil
	})
	a.handle("PUT /v1/tls", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		v, err := a.e.PutTLS(b.CertPEM, b.KeyPEM)
		if err != nil {
			return err
		}
		writeJSON(w, 200, v)
		return nil
	})
	a.handle("POST /v1/tls/self-signed", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Names []string `json:"names"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		v, err := a.e.SelfSignedTLS(b.Names)
		if err != nil {
			return err
		}
		writeJSON(w, 200, v)
		return nil
	})
	a.handle("DELETE /v1/tls", func(w http.ResponseWriter, r *http.Request) error {
		if err := a.e.DeleteTLS(); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	})

	a.handle("GET /v1/doh/tokens", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, items[tokens.View]{a.e.Tokens()})
		return nil
	})
	a.handle("POST /v1/doh/tokens", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Name string `json:"name"`
			QPS  *int   `json:"qps"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		t, err := a.e.CreateToken(b.Name, b.QPS)
		if err != nil {
			return err
		}
		writeJSON(w, 201, t)
		return nil
	})
	a.handle("PATCH /v1/doh/tokens/{id}", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Name *string `json:"name"`
			QPS  *int    `json:"qps"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		v, err := a.e.PatchToken(r.PathValue("id"), b.Name, b.QPS)
		if err != nil {
			return err
		}
		writeJSON(w, 200, v)
		return nil
	})
	a.handle("DELETE /v1/doh/tokens/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if err := a.e.DeleteToken(r.PathValue("id")); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	})
}
