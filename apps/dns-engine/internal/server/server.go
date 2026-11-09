// Package server runs the DNS listeners: several SO_REUSEPORT UDP sockets per
// address (one reader per CPU, cache hits answered inline), TCP with a global
// connection cap, idle timeout and RFC 7766 pipelining, a bounded pool for
// slow-path work, live reconciliation when settings change, and graceful
// shutdown.
package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"mrk/dns-engine/internal/acl"
	"mrk/dns-engine/internal/config"
	"mrk/dns-engine/internal/engine"
	"mrk/dns-engine/internal/events"
	"mrk/dns-engine/internal/metrics"
)

// MaxSlow bounds concurrent slow-path goroutines (upstream waits included).
const MaxSlow = 8192

// perConnInflight bounds pipelined queries per TCP connection.
const perConnInflight = 16

type key struct {
	addr  string
	proto string
}

type listener struct {
	key   key
	ok    bool
	err   string
	udp   []*net.UDPConn
	tcp   net.Listener
	since time.Time
	// encrypted listeners (encrypted.go)
	sig    string // parameters fixed at start (a change restarts the listener)
	bound  string // bound address
	http   *http.Server
	quic   *quic.Listener
	qconns sync.Map // *quic.Conn -> struct{}
}

// Server owns the listeners.
type Server struct {
	e   *engine.Engine
	log *slog.Logger

	mu        sync.Mutex
	listeners map[key]*listener
	settings  atomic.Pointer[config.Settings]
	closed    bool

	slow     chan struct{}
	wg       sync.WaitGroup // slow-path and connection goroutines
	readers  sync.WaitGroup
	tcpConns atomic.Int64
	conns    sync.Map // net.Conn -> struct{}
	enc      encConns
	trusted  atomic.Pointer[acl.List] // encrypted.doh.trusted_proxies

	ctx    context.Context
	cancel context.CancelFunc
	// Sockets per UDP address (default GOMAXPROCS, max 16).
	Sockets int
}

// New creates a server bound to e.
func New(e *engine.Engine, log *slog.Logger) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	n := runtime.GOMAXPROCS(0)
	if n > 16 {
		n = 16
	}
	if !reusePortSupported {
		n = 1
	}
	s := &Server{e: e, log: log, listeners: map[key]*listener{}, slow: make(chan struct{}, MaxSlow),
		ctx: ctx, cancel: cancel, Sockets: n}
	s.enc.perClient = map[netip.Addr]int{}
	e.SetEncryptedConns(s.EncryptedConns)
	return s
}

// Apply reconciles listeners with s: new ones start before removed ones stop,
// unchanged sockets keep serving (no dropped queries on reload).
func (s *Server) Apply(st config.Settings) {
	cp := st.Clone()
	s.settings.Store(&cp)
	s.setTrusted(cp)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	want := map[key]bool{}
	for _, l := range st.Listen {
		if l.UDP {
			want[key{l.Address, "udp"}] = true
		}
		if l.TCP {
			want[key{l.Address, "tcp"}] = true
		}
	}
	wantEncrypted(want, st)
	for k := range want {
		l := s.listeners[k]
		if l != nil && l.ok && l.sig != encSig(k.proto, &cp) {
			s.stopListener(l) // DoH/DoQ parameters changed
			l = nil
		}
		if l == nil || !l.ok {
			s.startLocked(k)
		}
	}
	for k, l := range s.listeners {
		if !want[k] {
			s.stopListener(l)
			delete(s.listeners, k)
		}
	}
}

// RetryFailed re-attempts listeners that could not bind (e.g. docker0 not up yet).
func (s *Server) RetryFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	for k, l := range s.listeners {
		if !l.ok {
			s.startLocked(k)
		}
	}
}

// Run retries failed listeners every interval until Shutdown.
func (s *Server) Run(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.RetryFailed()
		}
	}
}

func (s *Server) startLocked(k key) {
	l := &listener{key: k, since: time.Now()}
	var err error
	switch {
	case k.proto == "udp":
		err = s.startUDP(l)
	case isEncrypted(k.proto):
		err = s.startEncrypted(l)
	default:
		err = s.startTCP(l)
	}
	if err != nil {
		l.ok, l.err = false, err.Error()
		if old := s.listeners[k]; old == nil || old.err != l.err {
			s.log.Warn("listener failed", "address", k.addr, "proto", k.proto, "err", err)
			s.e.EventRing().Emit(events.ListenerFailed, events.Error,
				map[string]any{"address": k.addr, "proto": k.proto, "error": l.err})
		}
	} else {
		l.ok = true
		s.log.Info("listening", "address", k.addr, "proto", k.proto, "sockets", len(l.udp))
	}
	s.listeners[k] = l
}

func (s *Server) stopListener(l *listener) {
	for _, c := range l.udp {
		c.Close()
	}
	if l.tcp != nil {
		l.tcp.Close()
	}
	if l.http != nil {
		l.http.Close()
	}
	if l.quic != nil {
		l.quic.Close()
		l.qconns.Range(func(k, _ any) bool { _ = k.(*quic.Conn).CloseWithError(doqNoError, ""); return true })
	}
	s.log.Info("listener stopped", "address", l.key.addr, "proto", l.key.proto)
}

// Status lists listeners in address order.
func (s *Server) Status() []engine.ListenerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]engine.ListenerStatus, 0, len(s.listeners))
	for _, l := range s.listeners {
		out = append(out, engine.ListenerStatus{Address: l.key.addr, Proto: l.key.proto, OK: l.ok, Error: l.err})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].Proto > out[j].Proto
	})
	return out
}

// Addr returns the bound address of the first healthy listener of proto
// (useful with port 0 in tests).
func (s *Server) Addr(proto string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.listeners {
		if !l.ok || l.key.proto != proto {
			continue
		}
		if l.bound != "" {
			return l.bound
		}
		if proto == "udp" && len(l.udp) > 0 {
			return l.udp[0].LocalAddr().String()
		}
		if proto == "tcp" && l.tcp != nil {
			return l.tcp.Addr().String()
		}
	}
	return ""
}

func (s *Server) startUDP(l *listener) error {
	ap, err := netip.ParseAddrPort(l.key.addr)
	if err != nil {
		return err
	}
	network := "udp4"
	if ap.Addr().Is6() && !ap.Addr().Is4In6() {
		network = "udp6"
	}
	wildcard := ap.Addr().IsUnspecified()
	lc := net.ListenConfig{Control: control}
	addr := l.key.addr
	n := s.Sockets
	for i := 0; i < n; i++ {
		pc, err := lc.ListenPacket(s.ctx, network, addr)
		if err != nil {
			for _, c := range l.udp {
				c.Close()
			}
			l.udp = nil
			return err
		}
		c := pc.(*net.UDPConn)
		if i == 0 && ap.Port() == 0 {
			addr = c.LocalAddr().String() // tests: all sockets share the chosen port
		}
		_ = c.SetReadBuffer(4 << 20)
		_ = c.SetWriteBuffer(4 << 20)
		if wildcard {
			if err := enablePktInfo(c, network == "udp6"); err != nil {
				c.Close()
				return fmt.Errorf("pktinfo: %w", err)
			}
		}
		l.udp = append(l.udp, c)
	}
	for _, c := range l.udp {
		s.readers.Add(1)
		go s.udpLoop(c, wildcard)
	}
	return nil
}

func (s *Server) udpLoop(c *net.UDPConn, wildcard bool) {
	defer s.readers.Done()
	buf := make([]byte, 65535)
	var oob []byte
	if wildcard {
		oob = make([]byte, 256)
	}
	sc := engine.NewScratch()
	m := s.e.M
	for {
		n, oobn, _, from, err := c.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		client := from.Addr().Unmap()
		var roob []byte
		if wildcard {
			roob = replyOOB(oob[:oobn])
		}
		resp, v := s.e.Fast(buf[:n], client, engine.UDP, sc)
		switch v {
		case engine.Reply:
			_, _, _ = c.WriteMsgUDPAddrPort(resp, roob, from)
		case engine.DropIt:
		default:
			select {
			case s.slow <- struct{}{}:
			default:
				m.Drop(metrics.DropOverload)
				continue
			}
			pkt := append([]byte(nil), buf[:n]...)
			checked := v == engine.Slow
			s.wg.Add(1)
			go func() {
				defer func() { <-s.slow; s.wg.Done() }()
				ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
				out := s.e.Slow(ctx, pkt, client, engine.UDP, checked)
				cancel()
				if out != nil {
					_, _, _ = c.WriteMsgUDPAddrPort(out, roob, from)
				}
			}()
		}
	}
}

func (s *Server) startTCP(l *listener) error {
	lc := net.ListenConfig{KeepAlive: -1}
	ln, err := lc.Listen(s.ctx, "tcp", l.key.addr)
	if err != nil {
		return err
	}
	l.tcp = ln
	s.readers.Add(1)
	go s.acceptLoop(ln)
	return nil
}

func (s *Server) current() *config.Settings {
	if p := s.settings.Load(); p != nil {
		return p
	}
	d := config.Defaults("")
	return &d
}

func (s *Server) acceptLoop(ln net.Listener) {
	defer s.readers.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond) // e.g. EMFILE: back off instead of spinning
			continue
		}
		limit := int64(s.current().Limits.MaxTCPConnections)
		if s.tcpConns.Add(1) > limit {
			s.tcpConns.Add(-1)
			s.e.M.Drop(metrics.DropTCPLimit)
			c.Close()
			continue
		}
		s.e.M.TCPConns.Add(1)
		s.wg.Add(1)
		go s.serveTCP(c)
	}
}

func (s *Server) serveTCP(c net.Conn) {
	s.conns.Store(c, struct{}{})
	defer func() {
		s.conns.Delete(c)
		c.Close()
		s.tcpConns.Add(-1)
		s.e.M.TCPConns.Add(-1)
		s.wg.Done()
	}()
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	client := ap.Addr().Unmap()
	idle := time.Duration(s.current().Limits.TCPIdleTimeoutMS) * time.Millisecond
	var wmu sync.Mutex
	write := func(b []byte) bool {
		wmu.Lock()
		defer wmu.Unlock()
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		frame := make([]byte, 2+len(b))
		binary.BigEndian.PutUint16(frame, uint16(len(b)))
		copy(frame[2:], b)
		_, err := c.Write(frame)
		return err == nil
	}
	sem := make(chan struct{}, perConnInflight)
	var inner sync.WaitGroup
	defer inner.Wait()
	sc := engine.NewScratch()
	var lb [2]byte
	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < 12 {
			s.e.M.Drop(metrics.DropMalformed)
			return
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(c, pkt); err != nil {
			return
		}
		if engine.IsTransfer(pkt) { // AXFR/IXFR stream several messages (docs/41 §2.2)
			inner.Wait() // keep answers in order around the transfer
			if !s.e.ServeTransfer(pkt, client, write) {
				return
			}
			continue
		}
		resp, v := s.e.Fast(pkt, client, engine.TCP, sc)
		switch v {
		case engine.Reply:
			if !write(resp) {
				return
			}
			continue
		case engine.DropIt:
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-s.ctx.Done():
			return
		}
		select {
		case s.slow <- struct{}{}:
		default:
			<-sem
			s.e.M.Drop(metrics.DropOverload)
			continue
		}
		checked := v == engine.Slow
		inner.Add(1)
		go func() {
			defer func() { <-s.slow; <-sem; inner.Done() }()
			ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			out := s.e.Slow(ctx, pkt, client, engine.TCP, checked)
			cancel()
			if out != nil {
				write(out)
			}
		}()
	}
}

// Shutdown stops listeners, lets in-flight queries finish until ctx expires,
// then closes remaining TCP connections.
func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	s.closed = true
	for k, l := range s.listeners {
		s.stopListener(l)
		delete(s.listeners, k)
	}
	s.mu.Unlock()
	s.readers.Wait()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	// idle TCP connections would otherwise wait for their idle timeout
	s.conns.Range(func(k, _ any) bool {
		_ = k.(net.Conn).SetReadDeadline(time.Now())
		return true
	})
	select {
	case <-done:
	case <-ctx.Done():
		s.conns.Range(func(k, _ any) bool { k.(net.Conn).Close(); return true })
	}
	s.cancel()
}
