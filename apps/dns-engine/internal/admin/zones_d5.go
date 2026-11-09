package admin

import (
	"context"
	"net/http"
	"time"

	"mrk/dns-engine/internal/engine"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/tsig"
)

// docs/41 §2 routes: TSIG keys, secondary refresh, DNSSEC status/rollover.

func init() {
	for code, st := range map[string]int{
		engine.CodeZoneReadOnly: 409, engine.CodeTSIGInvalid: 422, engine.CodeTSIGExists: 409,
		engine.CodeTSIGNotFound: 404, engine.CodeTSIGInUse: 409, engine.CodeRolloverInProgress: 409,
		engine.CodeDNSSECDisabled: 409,
	} {
		statusByCode[code] = st
	}
}

func (a *API) createSecondary(w http.ResponseWriter, name, typ string, forwarders []string, in engine.ZoneCreateD5) error {
	if typ != "secondary" {
		var l fielderr.List
		for f, set := range map[string]bool{"primaries": len(in.Primaries) > 0, "tsig_key": in.TSIGKey != "",
			"notify_allow": len(in.NotifyAllow) > 0} {
			if set {
				l.Add(f, "not_allowed")
			}
		}
		return l.Err(engine.CodeZoneInvalid, "only secondary zones have primaries")
	}
	if len(forwarders) > 0 {
		return fielderr.Single(engine.CodeZoneInvalid, "secondary zones have no forwarders", "forwarders", "not_allowed")
	}
	d, err := a.e.CreateSecondary(name, in)
	if err != nil {
		return err
	}
	writeJSON(w, 201, d)
	return nil
}

func (a *API) zonesD5Routes() {
	a.handle("GET /v1/tsig", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, items[tsig.View]{a.e.TSIGKeys()})
		return nil
	})
	a.handle("POST /v1/tsig", func(w http.ResponseWriter, r *http.Request) error {
		var in engine.TSIGInput
		if err := decode(r, &in); err != nil {
			return err
		}
		k, err := a.e.CreateTSIG(in)
		if err != nil {
			return err
		}
		writeJSON(w, 201, k)
		return nil
	})
	a.handle("DELETE /v1/tsig/{name}", func(w http.ResponseWriter, r *http.Request) error {
		if err := a.e.DeleteTSIG(r.PathValue("name")); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	})
	a.handle("POST /v1/zones/{zone}/refresh", func(w http.ResponseWriter, r *http.Request) error {
		if err := decode(r, &struct{}{}); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
		defer cancel()
		st, err := a.e.RefreshZone(ctx, r.PathValue("zone"))
		if err != nil {
			return err
		}
		writeJSON(w, 200, map[string]any{"secondary": st})
		return nil
	})
	a.handle("GET /v1/zones/{zone}/dnssec", func(w http.ResponseWriter, r *http.Request) error {
		v, err := a.e.ZoneDNSSEC(r.PathValue("zone"))
		if err != nil {
			return err
		}
		writeJSON(w, 200, v)
		return nil
	})
	a.handle("POST /v1/zones/{zone}/dnssec/rollover", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Role string `json:"role"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		v, err := a.e.RolloverDNSSEC(r.PathValue("zone"), b.Role)
		if err != nil {
			return err
		}
		writeJSON(w, 200, v)
		return nil
	})
}
