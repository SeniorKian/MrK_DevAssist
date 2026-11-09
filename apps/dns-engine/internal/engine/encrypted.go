package engine

// D4 part B (docs/40 §2.3, §2.4, §3): incoming encrypted DNS — the
// transports (DoT, DoH, DoQ), their admission (encrypted.allow, DoH tokens),
// the TLS certificate store, DoH tokens and the related status and events.

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/certs"
	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/events"
	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/metrics"
	"mrk/dns-engine/internal/tokens"
)

// Encrypted transports.
const (
	DoT Proto = iota + 10
	DoH
	DoQ
)

// Encrypted reports whether p is DoT, DoH or DoQ.
func (p Proto) Encrypted() bool { return p == DoT || p == DoH || p == DoQ }

// Error codes of the encrypted endpoints (docs/40 §3).
const (
	CodeCertificateRequired = "certificate_required"
	CodeCertificateInUse    = "certificate_in_use"
)

// encPolicy is the part of the policy snapshot used by encrypted transports.
type encPolicy struct {
	allow *acl.List // nil = query_allow / recursion.allow
}

// encState is the engine-lifetime state of part B.
type encState struct {
	certs *certs.Store
	toks  *tokens.Store
	conns atomic.Pointer[func() EncryptedConns]

	mu          sync.Mutex
	warnedFP    string // fingerprint the thresholds below belong to
	warnedLevel int    // smallest expiring threshold already reported (0 = none)
	expiredFP   string
}

type tokenKey struct{}

func withToken(ctx context.Context, t *tokens.Token) context.Context {
	return context.WithValue(ctx, tokenKey{}, t)
}

func tokenFrom(ctx context.Context) *tokens.Token {
	t, _ := ctx.Value(tokenKey{}).(*tokens.Token)
	return t
}

// admit is the query ACL for proto (encrypted.allow replaces query_allow).
func (p *policy) admit(client netip.Addr, proto Proto) bool {
	if proto.Encrypted() && p.enc.allow != nil {
		return p.enc.allow.Allowed(client)
	}
	return p.queryACL.Allowed(client)
}

// recACLFor is the recursion ACL for proto; trusted = a valid DoH token.
func (p *policy) recACLFor(client netip.Addr, proto Proto, trusted bool) bool {
	switch {
	case trusted:
		return true
	case proto.Encrypted() && p.enc.allow != nil:
		return p.enc.allow.Allowed(client)
	}
	return p.recACL.Allowed(client)
}

func (p *policy) recursionFor(client netip.Addr, proto Proto, trusted bool) bool {
	return p.s.Recursion.Enabled && p.recACLFor(client, proto, trusted)
}

func (e *Engine) configureEncryptedLocked(p *policy) error {
	if a := p.s.Encrypted.Allow; a != nil {
		l, err := acl.Compile(*a)
		if err != nil {
			return err
		}
		p.enc.allow = l
	}
	return nil
}

func (e *Engine) openEncrypted() error {
	cs, err := certs.Open(e.opts.DataDir, e.opts.Now)
	if err != nil {
		return err
	}
	ts, err := tokens.Open(e.st, e.opts.Now)
	if err != nil {
		return err
	}
	e.enc.certs, e.enc.toks = cs, ts
	e.wg.Add(1)
	go e.encLoop()
	return nil
}

func (e *Engine) closeEncrypted() {
	if e.enc.toks != nil {
		if err := e.enc.toks.Save(); err != nil {
			e.log.Warn("save DoH token usage", "err", err)
		}
	}
}

func (e *Engine) encLoop() {
	defer e.wg.Done()
	first := time.NewTimer(5 * time.Second)
	defer first.Stop()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-e.bg.Done():
			return
		case <-first.C:
			e.CheckCertificate()
		case <-t.C:
			n++
			if n%60 == 0 {
				e.CheckCertificate()
			}
			if err := e.enc.toks.Save(); err != nil {
				e.log.Warn("save DoH token usage", "err", err)
			}
		}
	}
}

// expiringLevels are the days_left thresholds of tls.certificate_expiring.
var expiringLevels = []int{14, 7, 3, 1}

// CheckCertificate renews a due self-signed certificate and emits the
// expiry events (run hourly; exported for tests).
func (e *Engine) CheckCertificate() {
	cs := e.enc.certs
	if renewed, err := cs.RenewIfDue(); err != nil {
		e.log.Warn("self-signed certificate renewal failed", "err", err)
	} else if renewed {
		e.log.Info("self-signed certificate renewed", "fingerprint", cs.Fingerprint())
	}
	leaf, _ := cs.Leaf()
	if leaf == nil {
		return
	}
	fp := cs.Fingerprint()
	now := e.opts.Now()
	st := &e.enc
	st.mu.Lock()
	defer st.mu.Unlock()
	if !now.Before(leaf.NotAfter) {
		if st.expiredFP != fp {
			st.expiredFP = fp
			e.mon.ev.Emit(events.TLSCertificateExpired, events.Error, map[string]any{
				"not_after": leaf.NotAfter.UTC().Format(time.RFC3339), "fingerprint_sha256": fp})
		}
		return
	}
	days := int(leaf.NotAfter.Sub(now) / (24 * time.Hour))
	if st.warnedFP != fp {
		st.warnedFP, st.warnedLevel = fp, 0
	}
	level := 0
	for _, l := range expiringLevels {
		if days < l {
			level = l
		}
	}
	if level > 0 && (st.warnedLevel == 0 || level < st.warnedLevel) {
		st.warnedLevel = level
		e.mon.ev.Emit(events.TLSCertificateExpiring, events.Warning, map[string]any{"days_left": days,
			"not_after": leaf.NotAfter.UTC().Format(time.RFC3339), "fingerprint_sha256": fp})
	}
}

// checkEncryptedLocked rejects settings that enable a TLS listener without a
// usable certificate (e.mu held).
func (e *Engine) checkEncryptedLocked(next config.Settings) error {
	x, prev := next.Encrypted, e.settings.Encrypted
	cs := e.enc.certs
	var l fielderr.List
	need := func(field string, on, was bool) {
		if on && (!cs.Present() || !was && !cs.Valid()) {
			l.Add(field, CodeCertificateRequired)
		}
	}
	need("encrypted.dot.enabled", x.DoT.Enabled, prev.DoT.Enabled)
	need("encrypted.doq.enabled", x.DoQ.Enabled, prev.DoQ.Enabled)
	need("encrypted.doh.enabled", x.DoH.Enabled && x.DoH.TLS, prev.DoH.Enabled && prev.DoH.TLS)
	return l.Err(CodeCertificateRequired, "a valid TLS certificate is required (PUT /v1/tls or POST /v1/tls/self-signed)")
}

// ---------------------------------------------------------------- query path

// SlowToken answers a DoH query authenticated by tok: it is admitted from any
// address (encrypted.allow / query_allow / recursion.allow do not apply) and
// limited by the token's qps instead of the per-client limit. The query log
// keeps the token id in the upstream slot (t:<id>).
func (e *Engine) SlowToken(ctx context.Context, pkt []byte, client netip.Addr, proto Proto, tok *tokens.Token) []byte {
	return e.slow(withToken(ctx, tok), pkt, client, proto, false, tok)
}

// tokenLimited answers a token query over its qps (REFUSED, logged rate_limited).
func (e *Engine) tokenLimited(p *policy, req *dns.Msg, client netip.Addr, proto Proto, tok *tokens.Token, start time.Time) []byte {
	e.M.Drop(metrics.DropClientLimit)
	return e.finish(p, req, refused(req), client, proto, answerMeta{src: metrics.SrcRateLimited, upstream: tok.Tag()}, start)
}

// Certificates exposes the certificate store to the listeners (GetCertificate).
func (e *Engine) Certificates() *certs.Store { return e.enc.certs }

// LookupToken returns the DoH token matching secret, or nil.
func (e *Engine) LookupToken(secret string) *tokens.Token { return e.enc.toks.Lookup(secret) }

// ---------------------------------------------------------------- admin

// TLS returns the certificate view.
func (e *Engine) TLS() certs.View { return e.enc.certs.View() }

// PutTLS stores an uploaded certificate chain and key.
func (e *Engine) PutTLS(certPEM, keyPEM string) (certs.View, error) {
	v, err := e.enc.certs.Put(certPEM, keyPEM)
	if err == nil {
		e.resetCertWarnings()
	}
	return v, err
}

// SelfSignedTLS creates a self-signed certificate.
func (e *Engine) SelfSignedTLS(names []string) (certs.View, error) {
	v, err := e.enc.certs.SelfSigned(names)
	if err == nil {
		e.resetCertWarnings()
	}
	return v, err
}

func (e *Engine) resetCertWarnings() {
	e.enc.mu.Lock()
	e.enc.warnedFP, e.enc.warnedLevel = "", 0
	e.enc.mu.Unlock()
}

// DeleteTLS removes the certificate unless a TLS listener is enabled.
func (e *Engine) DeleteTLS() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.settings.Encrypted.NeedsCertificate() {
		return fielderr.New(CodeCertificateInUse, "disable DoT, DoQ and DoH with TLS before deleting the certificate")
	}
	return e.enc.certs.Delete()
}

// Tokens lists DoH tokens.
func (e *Engine) Tokens() []tokens.View { return e.enc.toks.List() }

// CreateToken adds a DoH token (the secret is returned only here).
func (e *Engine) CreateToken(name string, qps *int) (tokens.Created, error) {
	return e.enc.toks.Create(name, qps)
}

// PatchToken changes a token's name or qps.
func (e *Engine) PatchToken(id string, name *string, qps *int) (tokens.View, error) {
	return e.enc.toks.Patch(id, name, qps)
}

// DeleteToken removes a token.
func (e *Engine) DeleteToken(id string) error { return e.enc.toks.Delete(id) }

// ---------------------------------------------------------------- status

// EncryptedConns are the open connections per encrypted transport.
type EncryptedConns struct {
	DoT int64 `json:"dot"`
	DoH int64 `json:"doh"`
	DoQ int64 `json:"doq"`
}

// CertificateStatus is status.encrypted.certificate.
type CertificateStatus struct {
	Present    bool    `json:"present"`
	NotAfter   *string `json:"not_after,omitempty"`
	SelfSigned *bool   `json:"self_signed,omitempty"`
	DaysLeft   *int    `json:"days_left,omitempty"`
}

// EncryptedStatus is status.encrypted (docs/40 §3).
type EncryptedStatus struct {
	Connections EncryptedConns    `json:"connections"`
	Certificate CertificateStatus `json:"certificate"`
}

// SetEncryptedConns registers the server's connection counter.
func (e *Engine) SetEncryptedConns(f func() EncryptedConns) { e.enc.conns.Store(&f) }

func (e *Engine) encryptedStatus() EncryptedStatus {
	var st EncryptedStatus
	if f := e.enc.conns.Load(); f != nil {
		st.Connections = (*f)()
	}
	leaf, src := e.enc.certs.Leaf()
	if leaf != nil {
		na := leaf.NotAfter.UTC().Format(time.RFC3339)
		ss := src == certs.SourceSelfSigned
		days := int(leaf.NotAfter.Sub(e.opts.Now()) / (24 * time.Hour))
		if days < 0 {
			days = 0
		}
		st.Certificate = CertificateStatus{Present: true, NotAfter: &na, SelfSigned: &ss, DaysLeft: &days}
	}
	return st
}

func (e *Engine) encGauges() []metrics.Gauge {
	var g []metrics.Gauge
	if f := e.enc.conns.Load(); f != nil {
		c := (*f)()
		for _, x := range []struct {
			p string
			n int64
		}{{"dot", c.DoT}, {"doh", c.DoH}, {"doq", c.DoQ}} {
			g = append(g, metrics.Gauge{Name: "mrk_dns_encrypted_connections", Help: "Open encrypted DNS connections.",
				Labels: fmt.Sprintf("proto=%q", x.p), Value: float64(x.n)})
		}
	}
	if leaf, _ := e.enc.certs.Leaf(); leaf != nil {
		g = append(g, metrics.Gauge{Name: "mrk_dns_tls_certificate_expiry_seconds", Help: "Seconds until the TLS certificate expires.",
			Value: leaf.NotAfter.Sub(e.opts.Now()).Seconds()})
	}
	return g
}
