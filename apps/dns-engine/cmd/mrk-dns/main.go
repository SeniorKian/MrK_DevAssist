// Command mrk-dns is the MRK DNS engine.
//
//	mrk-dns serve     run the server (env: MRK_DNS_DATA_DIR, MRK_DNS_ADMIN_SOCKET,
//	                  MRK_DNS_ADMIN_TOKEN_FILE, MRK_DNS_LISTEN, MRK_DNS_GOMEMLIMIT, MRK_DNS_LOG_LEVEL)
//	mrk-dns health    exit 0 when the admin socket and a DNS listener answer (Docker healthcheck)
//	mrk-dns version   print the version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"mrk/dns-engine/internal/admin"
	"mrk/dns-engine/internal/engine"
	"mrk/dns-engine/internal/querylog"
	"mrk/dns-engine/internal/server"
	"mrk/dns-engine/internal/version"
)

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func socketPath() string { return env("MRK_DNS_ADMIN_SOCKET", "/run/mrk-dns/admin.sock") }

func tokenPath() string {
	return env("MRK_DNS_ADMIN_TOKEN_FILE", filepath.Join(filepath.Dir(socketPath()), "admin.token"))
}

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		os.Exit(serve())
	case "health":
		os.Exit(health())
	case "version", "--version", "-v":
		fmt.Println("mrk-dns", version.String())
	default:
		fmt.Fprintln(os.Stderr, "usage: mrk-dns [serve|health|version]")
		os.Exit(2)
	}
}

func logger() *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(env("MRK_DNS_LOG_LEVEL", "info")) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// parseBytes accepts 512MiB, 400MB, 450m, 1g or a plain byte count.
func parseBytes(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	mult := int64(1)
	for _, u := range []struct {
		suf string
		m   int64
	}{{"gib", 1 << 30}, {"mib", 1 << 20}, {"kib", 1 << 10}, {"gb", 1e9}, {"mb", 1e6}, {"kb", 1e3}, {"g", 1 << 30}, {"m", 1 << 20}, {"k", 1 << 10}, {"b", 1}} {
		if strings.HasSuffix(s, u.suf) {
			s, mult = strings.TrimSuffix(s, u.suf), u.m
			break
		}
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(n * float64(mult)), nil
}

// memoryLimit applies MRK_DNS_GOMEMLIMIT, else 85% of the cgroup limit.
func memoryLimit(log *slog.Logger) {
	if os.Getenv("GOMEMLIMIT") != "" {
		return // the runtime already applied it
	}
	if v := os.Getenv("MRK_DNS_GOMEMLIMIT"); v != "" {
		n, err := parseBytes(v)
		if err != nil {
			log.Warn("ignoring MRK_DNS_GOMEMLIMIT", "err", err)
		} else {
			debug.SetMemoryLimit(n)
			log.Info("memory limit", "bytes", n, "source", "MRK_DNS_GOMEMLIMIT")
			return
		}
	}
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 {
			debug.SetMemoryLimit(n * 85 / 100)
			log.Info("memory limit", "bytes", n*85/100, "source", "cgroup")
		}
	}
}

func serve() int {
	log := logger()
	syscall.Umask(0o027)
	dropped, uid, gid, err := dropPrivileges()
	if err != nil {
		log.Error("cannot drop privileges; refusing to run as root", "err", err)
		return 1
	}
	bind := raiseBindCapability()
	if dropped {
		log.Info("privileges dropped", "uid", uid, "gid", gid, "net_bind_service", bind)
	} else if !bind {
		log.Warn("running unprivileged without CAP_NET_BIND_SERVICE: ports below 1024 cannot be bound "+
			"(start as root with cap_add NET_BIND_SERVICE, SETUID, SETGID; see docs/37 §0.2)", "uid", uid, "gid", gid)
	} else {
		log.Info("bind capability", "uid", uid, "gid", gid, "net_bind_service", true)
	}
	memoryLimit(log)
	e, err := engine.Open(engine.Options{DataDir: env("MRK_DNS_DATA_DIR", "/var/lib/mrk-dns"),
		DefaultListen: os.Getenv("MRK_DNS_LISTEN"), Logger: log})
	if err != nil {
		log.Error("cannot start engine", "err", err)
		return 1
	}
	srv := server.New(e, log)
	e.SetListenerHook(srv.Apply)
	st, _ := e.Settings()
	srv.Apply(st)
	go srv.Run(10 * time.Second)

	token, err := admin.EnsureToken(tokenPath())
	if err != nil {
		log.Error("cannot create admin token", "err", err)
		return 1
	}
	ln, err := admin.ListenUnix(socketPath())
	if err != nil {
		log.Error("cannot open admin socket", "err", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	api := admin.New(e, srv.Status, token, log)
	errc := make(chan error, 1)
	go func() { errc <- api.Serve(ctx, ln) }()
	log.Info("mrk-dns started", "version", version.String(), "admin_socket", socketPath())
	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil {
			log.Error("admin API stopped", "err", err)
		}
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	srv.Shutdown(sctx)
	cancel()
	<-errc
	_ = os.Remove(socketPath())
	e.Close()
	log.Info("stopped")
	return 0
}

func health() int {
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath())
		}}}
	resp, err := c.Get("http://mrk-dns/v1/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "admin socket:", err)
		return 1
	}
	defer resp.Body.Close()
	var h struct {
		OK        bool                    `json:"ok"`
		Listeners []engine.ListenerStatus `json:"listeners"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil || !h.OK {
		fmt.Fprintln(os.Stderr, "no healthy listener")
		return 1
	}
	for _, l := range h.Listeners {
		if !l.OK || l.Proto != "udp" {
			continue
		}
		ap, err := netip.ParseAddrPort(l.Address)
		if err != nil {
			continue
		}
		if ap.Addr().IsUnspecified() {
			lo := netip.MustParseAddr("127.0.0.1")
			if ap.Addr().Is6() {
				lo = netip.IPv6Loopback()
			}
			ap = netip.AddrPortFrom(lo, ap.Port())
		}
		m := new(dns.Msg)
		m.SetQuestion(querylog.HealthProbeName+".", dns.TypeA)
		dc := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
		if r, _, err := dc.Exchange(m, ap.String()); err == nil && r != nil {
			return 0 // any response (even REFUSED) proves the listener answers
		} else if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			fmt.Fprintln(os.Stderr, "dns query:", err)
		}
	}
	fmt.Fprintln(os.Stderr, "no DNS listener answered")
	return 1
}
