// Package resolver forwards queries to upstream resolvers over UDP, TCP, DoT
// (RFC 7858), DoH (RFC 8484) and DoQ (RFC 9250) with health checks, EWMA latency tracking,
// fastest/parallel/in_order strategies, bounded in-flight exchanges and
// single-flight coalescing.
package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/metrics"
)

// Errors.
var (
	ErrOverloaded = errors.New("resolver: too many upstream exchanges in flight")
	ErrNoUpstream = errors.New("resolver: no upstream configured")
	ErrMismatch   = errors.New("resolver: response does not match query")
)

// MaxMsg is the largest upstream response accepted.
const MaxMsg = 65535

// EDNSSize is advertised to upstreams (DNS flag day 2020).
const EDNSSize = 1232

// TestRootCAs, when set (tests only), replaces the system roots for DoT/DoH.
var TestRootCAs *x509.CertPool

func tlsConfig(name string) *tls.Config {
	return &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, RootCAs: TestRootCAs}
}

// Bootstrap resolves a DoH host name to IPs without using the system resolver.
type Bootstrap func(ctx context.Context, host string) ([]string, error)

// Upstream is one forwarder with its transport and health state.
type Upstream struct {
	ID      string
	Raw     string
	Addr    config.UpstreamAddr
	Enabled bool

	ewmaUS   atomic.Uint64 // float64 bits, microseconds
	fails    atomic.Int32
	healthy  atomic.Bool
	lastUsed atomic.Int64
	lastErr  atomic.Value // string

	pool chan net.Conn // TCP/DoT idle connections

	httpc     *http.Client
	boot      Bootstrap
	bootMu    sync.Mutex
	bootAddrs []string
	bootExp   time.Time

	doqc doqClient // DoQ connection

	m *metrics.Upstream
}

// NewUpstream parses raw and prepares transports.
func NewUpstream(id, raw string, enabled bool, boot Bootstrap, m *metrics.Metrics) (*Upstream, error) {
	a, err := config.ParseUpstream(raw)
	if err != nil {
		return nil, err
	}
	u := &Upstream{ID: id, Raw: raw, Addr: a, Enabled: enabled, boot: boot}
	if m != nil {
		u.m = m.Upstream(id)
	} else {
		u.m = &metrics.Upstream{}
	}
	u.healthy.Store(true)
	u.setEWMA(50_000) // optimistic 50 ms prior
	switch a.Proto {
	case config.ProtoTCP, config.ProtoDoT:
		u.pool = make(chan net.Conn, 8)
	case config.ProtoDoH:
		tr := &http.Transport{
			Proxy:                  nil,
			DialContext:            u.dohDial,
			TLSClientConfig:        tlsConfig(a.ServerName),
			ForceAttemptHTTP2:      true,
			MaxIdleConns:           8,
			MaxIdleConnsPerHost:    8,
			IdleConnTimeout:        90 * time.Second,
			TLSHandshakeTimeout:    3 * time.Second,
			ResponseHeaderTimeout:  4 * time.Second,
			MaxResponseHeaderBytes: 16 << 10,
		}
		u.httpc = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	return u, nil
}

// Close releases pooled connections.
func (u *Upstream) Close() {
	if u.pool != nil {
		for {
			select {
			case c := <-u.pool:
				c.Close()
			default:
				goto done
			}
		}
	}
done:
	if u.Addr.Proto == config.ProtoDoQ {
		u.closeDoQ()
	}
	if u.httpc != nil {
		u.httpc.CloseIdleConnections()
	}
}

func (u *Upstream) setEWMA(us float64) { u.ewmaUS.Store(math.Float64bits(us)) }

// RTT returns the smoothed round-trip time.
func (u *Upstream) RTT() time.Duration {
	return time.Duration(math.Float64frombits(u.ewmaUS.Load())) * time.Microsecond
}

// Healthy reports the current health.
func (u *Upstream) Healthy() bool { return u.healthy.Load() }

// LastError returns the last exchange error text.
func (u *Upstream) LastError() string {
	if v, ok := u.lastErr.Load().(string); ok {
		return v
	}
	return ""
}

// CopyStateFrom keeps health/RTT across a settings reload.
func (u *Upstream) CopyStateFrom(o *Upstream) {
	u.ewmaUS.Store(o.ewmaUS.Load())
	u.fails.Store(o.fails.Load())
	u.healthy.Store(o.healthy.Load())
}

const failThreshold = 3

func (u *Upstream) observe(rtt time.Duration, err error) {
	u.lastUsed.Store(time.Now().UnixNano())
	old := math.Float64frombits(u.ewmaUS.Load())
	if err != nil {
		u.m.Errors.Add(1)
		u.lastErr.Store(err.Error())
		// penalise: double the estimate (bounded) so others are preferred
		u.setEWMA(math.Min(math.Max(old*2, 500_000), 5_000_000))
		if u.fails.Add(1) >= failThreshold {
			u.healthy.Store(false)
		}
		return
	}
	us := float64(rtt.Microseconds())
	u.setEWMA(0.7*old + 0.3*us)
	u.fails.Store(0)
	u.healthy.Store(true)
}

// Exchange sends q and returns a validated response.
func (u *Upstream) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, time.Duration, error) {
	u.m.Queries.Add(1)
	start := time.Now()
	var (
		r   *dns.Msg
		err error
	)
	switch u.Addr.Proto {
	case config.ProtoUDP:
		r, err = u.udp(ctx, q)
		if err == nil && r.Truncated {
			r, err = u.stream(ctx, q, false)
		}
	case config.ProtoTCP:
		r, err = u.stream(ctx, q, false)
	case config.ProtoDoT:
		r, err = u.stream(ctx, q, true)
	case config.ProtoDoH:
		r, err = u.doh(ctx, q)
	case config.ProtoDoQ:
		r, err = u.doq(ctx, q)
	default:
		err = fmt.Errorf("unknown protocol")
	}
	rtt := time.Since(start)
	if err == nil {
		err = validate(q, r)
	}
	if err != nil && errors.Is(err, context.DeadlineExceeded) {
		u.m.Timeouts.Add(1)
	}
	u.observe(rtt, err)
	if err != nil {
		return nil, rtt, err
	}
	return r, rtt, nil
}

func validate(q, r *dns.Msg) error {
	if r == nil || !r.Response || r.Id != q.Id || len(r.Question) != 1 {
		return ErrMismatch
	}
	a, b := q.Question[0], r.Question[0]
	if a.Qtype != b.Qtype || a.Qclass != b.Qclass || !strings.EqualFold(a.Name, b.Name) {
		return ErrMismatch
	}
	return nil
}

func deadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(2 * time.Second)
}

func (u *Upstream) udp(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	pkt, err := q.Pack()
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	// a fresh socket per query gives a random source port (RFC 5452)
	c, err := d.DialContext(ctx, "udp", u.Addr.Addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(deadline(ctx))
	if _, err := c.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil, context.DeadlineExceeded
			}
			return nil, err
		}
		if n < 12 || binary.BigEndian.Uint16(buf) != q.Id {
			continue // ignore spoofed or stale datagrams
		}
		r := new(dns.Msg)
		if err := r.Unpack(buf[:n]); err != nil {
			continue
		}
		if validate(q, r) != nil {
			continue
		}
		return r, nil
	}
}

func (u *Upstream) dialStream(ctx context.Context, tlsOn bool) (net.Conn, error) {
	d := net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	if !tlsOn {
		return d.DialContext(ctx, "tcp", u.Addr.Addr)
	}
	td := tls.Dialer{NetDialer: &d, Config: tlsConfig(u.Addr.ServerName)}
	return td.DialContext(ctx, "tcp", u.Addr.Addr)
}

func (u *Upstream) stream(ctx context.Context, q *dns.Msg, tlsOn bool) (*dns.Msg, error) {
	pkt, err := q.Pack()
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		var c net.Conn
		pooled := false
		if u.pool != nil {
			select {
			case c = <-u.pool:
				pooled = true
			default:
			}
		}
		if c == nil {
			c, err = u.dialStream(ctx, tlsOn)
			if err != nil {
				return nil, err
			}
		}
		r, err := exchangeStream(c, pkt, q.Id, deadline(ctx))
		if err != nil {
			c.Close()
			if pooled && ctx.Err() == nil {
				continue // idle connection was closed by the server; retry on a fresh one
			}
			return nil, err
		}
		if u.pool != nil {
			select {
			case u.pool <- c:
			default:
				c.Close()
			}
		} else {
			c.Close()
		}
		return r, nil
	}
	return nil, errors.New("resolver: stream exchange failed")
}

func exchangeStream(c net.Conn, pkt []byte, id uint16, dl time.Time) (*dns.Msg, error) {
	_ = c.SetDeadline(dl)
	out := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(out, uint16(len(pkt)))
	copy(out[2:], pkt)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	var lb [2]byte
	for {
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < 12 {
			return nil, ErrMismatch
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c, buf); err != nil {
			return nil, err
		}
		if binary.BigEndian.Uint16(buf) != id {
			continue
		}
		r := new(dns.Msg)
		if err := r.Unpack(buf); err != nil {
			return nil, err
		}
		_ = c.SetDeadline(time.Time{})
		return r, nil
	}
}

func (u *Upstream) dohAddrs(ctx context.Context) ([]string, error) {
	if u.Addr.Addr != "" {
		return []string{u.Addr.Addr}, nil
	}
	if len(u.Addr.Bootstrap) > 0 {
		return u.Addr.Bootstrap, nil
	}
	u.bootMu.Lock()
	defer u.bootMu.Unlock()
	if len(u.bootAddrs) > 0 && time.Now().Before(u.bootExp) {
		return u.bootAddrs, nil
	}
	host := u.Addr.ServerName
	port := "443"
	if pu := strings.SplitN(strings.TrimPrefix(u.Addr.URL, "https://"), "/", 2)[0]; strings.Contains(pu, ":") {
		if _, p, err := net.SplitHostPort(pu); err == nil {
			port = p
		}
	}
	var ips []string
	var err error
	if u.boot != nil {
		ips, err = u.boot(ctx, host)
	}
	if len(ips) == 0 {
		var addrs []string
		addrs, err = net.DefaultResolver.LookupHost(ctx, host)
		ips = addrs
	}
	if len(ips) == 0 {
		if err == nil {
			err = fmt.Errorf("bootstrap: no address for %s", host)
		}
		return nil, err
	}
	u.bootAddrs = u.bootAddrs[:0]
	for _, ip := range ips {
		u.bootAddrs = append(u.bootAddrs, net.JoinHostPort(ip, port))
	}
	u.bootExp = time.Now().Add(10 * time.Minute)
	return u.bootAddrs, nil
}

func (u *Upstream) dohDial(ctx context.Context, network, _ string) (net.Conn, error) {
	addrs, err := u.dohAddrs(ctx)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	var last error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, network, a)
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

func (u *Upstream) doh(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	id := q.Id
	q.Id = 0 // RFC 8484 §4.1: use ID 0 for cache friendliness
	pkt, err := q.Pack()
	q.Id = id
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.Addr.URL, bytes.NewReader(pkt))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("doh: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxMsg+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxMsg {
		return nil, fmt.Errorf("doh: response too large")
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, err
	}
	r.Id = id
	return r, nil
}

// NewQuery builds an upstream query with a random ID, RD and EDNS0.
func NewQuery(name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	q.SetEdns0(EDNSSize, false)
	return q
}
