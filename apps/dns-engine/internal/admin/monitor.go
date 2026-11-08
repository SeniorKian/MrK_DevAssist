package admin

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"math"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"mrk/dns-engine/internal/engine"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/mitigate"
	"mrk/dns-engine/internal/querylog"
)

// Query-log API limits (docs/38 §3).
const (
	searchBudget    = 2 * time.Second
	exportMaxRows   = 1_000_000
	streamHeartbeat = 15 * time.Second
)

type searchResponse struct {
	Items           []querylog.Item `json:"items"`
	NextCursor      *string         `json:"next_cursor"`
	ScannedSegments int             `json:"scanned_segments"`
	Truncated       bool            `json:"truncated"`
}

type streamEntry struct {
	Type string `json:"type"`
	querylog.Item
}

// flexTime accepts unix milliseconds (number or numeric string) or RFC 3339.
type flexTime struct {
	set bool
	us  int64
}

func (f *flexTime) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		return nil
	}
	s = strings.Trim(s, `"`)
	if s == "" {
		return nil
	}
	us, ok := querylog.ParseTime(s)
	if !ok {
		return &json.UnmarshalTypeError{Value: "time", Type: reflect.TypeOf(int64(0)), Field: "before"}
	}
	f.set, f.us = true, us
	return nil
}

func (a *API) monitorRoutes() {
	ql := func() *querylog.Logger { return a.e.QueryLog() }

	a.handle("GET /v1/querylog", func(w http.ResponseWriter, r *http.Request) error {
		f, err := querylog.ParseFilter(r.URL.Query())
		if err != nil {
			return err
		}
		a.e.FlushMonitor()
		res := ql().Search(r.Context(), f, searchBudget)
		out := searchResponse{Items: make([]querylog.Item, 0, len(res.Rows)), ScannedSegments: res.Scanned, Truncated: res.Truncated}
		for i := range res.Rows {
			out.Items = append(out.Items, querylog.View(&res.Rows[i]))
		}
		if res.Next != nil {
			s := res.Next.String()
			out.NextCursor = &s
		}
		writeJSON(w, 200, out)
		return nil
	})
	a.handle("GET /v1/querylog/status", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, ql().Status())
		return nil
	})
	a.handle("DELETE /v1/querylog", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Client string   `json:"client"`
			Before flexTime `json:"before"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		var l fielderr.List
		if b.Client != "" {
			if _, err := querylog.ParseFilter(map[string][]string{"client": {b.Client}}); err != nil {
				l.Add("client", "invalid_client")
			}
		}
		if err := l.Err(engine.CodeInvalidRequest, "invalid delete request"); err != nil {
			return err
		}
		a.e.FlushMonitor()
		res, err := ql().Delete(strings.TrimSpace(b.Client), b.Before.us)
		if err != nil {
			a.log.Warn("query log delete incomplete", "err", err)
		}
		a.log.Info("query log deleted", "actor", actorFrom(r), "client", b.Client, "before", b.Before.us,
			"rows", res.DeletedRows)
		writeJSON(w, 200, res)
		return nil
	})
	a.handle("GET /v1/querylog/stream", a.stream)
	a.handle("GET /v1/querylog/export", a.export)

	a.handle("GET /v1/stats", func(w http.ResponseWriter, r *http.Request) error {
		rg := r.URL.Query().Get("range")
		if rg == "" {
			rg = "1h"
		}
		a.e.FlushMonitor()
		res, ok := a.e.Stats(rg)
		if !ok {
			return fielderr.Single(engine.CodeInvalidRequest, "invalid range", "range", "invalid_choice",
				"choices", []string{"1h", "6h", "24h", "7d", "30d", "1y"})
		}
		writeJSON(w, 200, res)
		return nil
	})
	a.handle("GET /v1/pressure", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, a.e.Pressure())
		return nil
	})
	a.handle("POST /v1/host-metrics", func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			CPU    *float64        `json:"cpu_percent"`
			Mem    *float64        `json:"memory_percent"`
			Load1  float64         `json:"load1"`
			TS     json.RawMessage `json:"ts"`
			Source string          `json:"source"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		var l fielderr.List
		if b.CPU == nil || *b.CPU < 0 || *b.CPU > 100 || math.IsNaN(*b.CPU) {
			l.Add("cpu_percent", "out_of_range", "min", 0, "max", 100)
		}
		if b.Mem == nil || *b.Mem < 0 || *b.Mem > 100 || math.IsNaN(*b.Mem) {
			l.Add("memory_percent", "out_of_range", "min", 0, "max", 100)
		}
		ts, ok := parseHostTS(b.TS)
		if !ok {
			l.Add("ts", "invalid_time")
		}
		if err := l.Err(engine.CodeInvalidRequest, "invalid host metrics"); err != nil {
			return err
		}
		accepted := a.e.HostMetrics(*b.CPU, *b.Mem, b.Load1, ts)
		writeJSON(w, 200, map[string]any{"accepted": accepted})
		return nil
	})
	a.handle("GET /v1/mitigations", func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, items[mitigate.Item]{a.e.Mitigations()})
		return nil
	})
	a.handle("POST /v1/mitigations", func(w http.ResponseWriter, r *http.Request) error {
		var in mitigate.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		it, err := a.e.CreateMitigation(in)
		if err != nil {
			return err
		}
		a.log.Info("mitigation created", "actor", actorFrom(r), "id", it.ID, "kind", it.Kind, "match", it.Match, "action", it.Action)
		writeJSON(w, 201, it)
		return nil
	})
	a.handle("DELETE /v1/mitigations/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if err := a.e.DeleteMitigation(r.PathValue("id")); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	})
	a.handle("GET /v1/events", func(w http.ResponseWriter, r *http.Request) error {
		q := r.URL.Query()
		var after int64
		if s := q.Get("after"); s != "" {
			v, err := strconv.ParseInt(s, 10, 64)
			if err != nil || v < 0 {
				return fielderr.Single(engine.CodeInvalidRequest, "invalid after", "after", "invalid_number")
			}
			after = v
		}
		limit := 1000
		if s := q.Get("limit"); s != "" {
			v, err := strconv.Atoi(s)
			if err != nil || v < 1 || v > 1000 {
				return fielderr.Single(engine.CodeInvalidRequest, "invalid limit", "limit", "out_of_range", "min", 1, "max", 1000)
			}
			limit = v
		}
		evs, next := a.e.Events(after, limit)
		writeJSON(w, 200, map[string]any{"items": evs, "next": next})
		return nil
	})
}

func parseHostTS(raw json.RawMessage) (time.Time, bool) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" || s == "null" {
		return time.Time{}, true // now
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f > 1e11 { // milliseconds
			return time.UnixMilli(int64(f)), true
		}
		return time.Unix(int64(f), int64((f-math.Floor(f))*1e9)), true
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func (a *API) stopCtx() context.Context {
	if a.stop != nil {
		return a.stop
	}
	return context.Background()
}

// stream serves GET /v1/querylog/stream as NDJSON.
func (a *API) stream(w http.ResponseWriter, r *http.Request) error {
	f, err := querylog.ParseFilter(r.URL.Query())
	if err != nil {
		return err
	}
	ql := a.e.QueryLog()
	if st := ql.Status(); !st.Enabled || st.Mode == "off" {
		return &fielderr.Error{Code: "querylog_disabled", Message: "the query log is turned off", Status: 409}
	}
	sub, err := ql.Subscribe(f)
	if err != nil {
		return &fielderr.Error{Code: "too_many_streams", Message: err.Error(), Status: 429}
	}
	defer sub.Close()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	bw := bufio.NewWriterSize(w, 16<<10)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	flush := func() bool {
		if bw.Flush() != nil {
			return false
		}
		return rc.Flush() == nil
	}
	maxEPS := ql.StreamMaxEPS()
	_ = enc.Encode(map[string]any{"type": "hello", "max_eps": maxEPS, "mode_effective": ql.ModeEffective()})
	if !flush() {
		return nil
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastWrite := time.Now()
	tokens := float64(maxEPS)
	lastFill := time.Now()
	var skipped uint64
	stop := a.stopCtx()
	for {
		select {
		case <-r.Context().Done():
			return nil
		case <-stop.Done():
			return nil
		case <-tick.C:
			skipped += sub.TakeSkipped()
			wrote := false
			if skipped > 0 {
				_ = enc.Encode(map[string]any{"type": "sampled", "skipped": skipped})
				skipped, wrote = 0, true
			}
			if time.Since(lastWrite) >= streamHeartbeat {
				_ = enc.Encode(map[string]string{"type": "ping"})
				wrote = true
			}
			if wrote {
				if !flush() {
					return nil
				}
				lastWrite = time.Now()
			}
		case row := <-sub.C:
			now := time.Now()
			tokens = math.Min(float64(maxEPS), tokens+now.Sub(lastFill).Seconds()*float64(maxEPS))
			lastFill = now
			if tokens < 1 {
				skipped++
				continue
			}
			tokens--
			_ = enc.Encode(streamEntry{Type: "entry", Item: querylog.View(&row)})
			// batch what is already queued before flushing
			if len(sub.C) == 0 || bw.Buffered() > 8<<10 {
				if !flush() {
					return nil
				}
				lastWrite = now
			}
		}
	}
}

// export serves GET /v1/querylog/export (ndjson or csv, at most 1M rows).
func (a *API) export(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "ndjson"
	}
	if format != "ndjson" && format != "csv" {
		return fielderr.Single(querylog.CodeQueryInvalid, "invalid format", "format", "invalid_choice", "choices", []string{"ndjson", "csv"})
	}
	maxRows := exportMaxRows // export: limit is the row cap (1..1,000,000)
	if s := q.Get("limit"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 || v > exportMaxRows {
			return fielderr.Single(querylog.CodeQueryInvalid, "invalid limit", "limit", "out_of_range", "min", 1, "max", exportMaxRows)
		}
		maxRows = v
	}
	q.Del("limit")
	q.Del("format")
	f, err := querylog.ParseFilter(q)
	if err != nil {
		return err
	}
	f.Limit = 1000
	a.e.FlushMonitor()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	stamp := time.Now().UTC().Format("20060102-150405")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="dns-log-`+stamp+`.csv"`)
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="dns-log-`+stamp+`.ndjson"`)
	}
	w.WriteHeader(200)
	bw := bufio.NewWriterSize(w, 64<<10)
	defer bw.Flush()
	cw := csv.NewWriter(bw)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	if format == "csv" {
		_ = cw.Write(querylog.CSVHeader)
	}
	ql := a.e.QueryLog()
	n := 0
	stop := a.stopCtx()
	for n < maxRows {
		if r.Context().Err() != nil || stop.Err() != nil {
			return nil
		}
		f.Limit = min(1000, maxRows-n)
		res := ql.Search(r.Context(), f, 0)
		for i := range res.Rows {
			it := querylog.View(&res.Rows[i])
			if format == "csv" {
				_ = cw.Write(it.CSV())
			} else {
				_ = enc.Encode(it)
			}
		}
		n += len(res.Rows)
		if format == "csv" {
			cw.Flush()
		}
		if res.Next == nil {
			break
		}
		f.Cursor = res.Next
	}
	return nil
}
