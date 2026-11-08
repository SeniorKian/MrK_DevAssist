// Command mrk-dnsbench is a small UDP DNS load generator.
//
//	mrk-dnsbench -server 127.0.0.1:53 -c 64 -window 32 -d 10s -names example.com,example.org -type A [-qps 50000]
//	mrk-dnsbench -random victim.example ...   random 12-character label under a parent (water torture)
//
// Each worker owns one UDP socket and keeps up to -window queries in flight
// (open loop when -qps is set, closed loop otherwise). It reports achieved
// QPS, latency percentiles, rcodes, timeouts and errors.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const bucketUS = 10     // histogram resolution
const buckets = 100_000 // 10 µs * 100k = 1 s

type hist struct {
	b   [buckets + 1]uint32
	max time.Duration
	n   uint64
}

func (h *hist) add(d time.Duration) {
	i := int(d.Microseconds() / bucketUS)
	if i < 0 {
		i = 0
	}
	if i > buckets {
		i = buckets
	}
	h.b[i]++
	h.n++
	if d > h.max {
		h.max = d
	}
}

func (h *hist) merge(o *hist) {
	for i := range h.b {
		h.b[i] += o.b[i]
	}
	h.n += o.n
	if o.max > h.max {
		h.max = o.max
	}
}

func (h *hist) pct(p float64) time.Duration {
	if h.n == 0 {
		return 0
	}
	target := uint64(float64(h.n)*p + 0.5)
	if target == 0 {
		target = 1
	}
	var c uint64
	for i, v := range h.b {
		c += uint64(v)
		if c >= target {
			return time.Duration((i+1)*bucketUS) * time.Microsecond
		}
	}
	return h.max
}

type query struct{ pkt []byte }

const randLabelPlaceholder = "aaaaaaaaaaaa"

var randomLabel bool

const alnum = "abcdefghijklmnopqrstuvwxyz0123456789"

type worker struct {
	conn     *net.UDPConn
	mu       sync.Mutex
	inflight map[uint16]int64
	hist     hist
	rcodes   [24]uint64
	sent     uint64
	recv     uint64
	timeouts uint64
	errs     uint64
	trunc    uint64
}

func main() {
	server := flag.String("server", "127.0.0.1:53", "DNS server host:port")
	conc := flag.Int("c", 32, "workers (UDP sockets)")
	window := flag.Int("window", 16, "max in-flight queries per worker")
	dur := flag.Duration("d", 10*time.Second, "duration")
	qps := flag.Int("qps", 0, "target total QPS (0 = as fast as possible)")
	names := flag.String("names", "example.com", "comma separated names")
	file := flag.String("file", "", "file with 'name [type]' per line")
	qtype := flag.String("type", "A", "query type")
	timeout := flag.Duration("timeout", 2*time.Second, "per-query timeout")
	jsonOut := flag.Bool("json", false, "print a JSON summary")
	edns := flag.Bool("edns", true, "add EDNS0 (1232)")
	random := flag.String("random", "", "query <random 12 chars>.<parent> (random-subdomain load)")
	flag.Parse()

	if *random != "" {
		*names, *file = randLabelPlaceholder+"."+strings.TrimSuffix(*random, "."), ""
		randomLabel = true
	}
	qs, err := buildQueries(*names, *file, *qtype, *edns)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	raddr, err := net.ResolveUDPAddr("udp", *server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ws := make([]*worker, *conc)
	for i := range ws {
		c, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = c.SetReadBuffer(4 << 20)
		ws[i] = &worker{conn: c, inflight: make(map[uint16]int64, *window)}
	}
	var stop atomic.Bool
	done := make(chan struct{})
	var wg sync.WaitGroup
	start := time.Now()
	perWorker := 0.0
	if *qps > 0 {
		perWorker = float64(*qps) / float64(*conc)
	}
	for _, w := range ws {
		wg.Add(2)
		slots := make(chan struct{}, *window)
		go func(w *worker) { defer wg.Done(); w.receive(slots, &stop, *timeout) }(w)
		go func(w *worker) { defer wg.Done(); w.send(qs, slots, done, &stop, perWorker) }(w)
	}
	time.Sleep(*dur)
	stop.Store(true)
	close(done)
	elapsed := time.Since(start)
	time.Sleep(*timeout / 2)
	for _, w := range ws {
		w.conn.Close()
	}
	wg.Wait()
	report(ws, elapsed, *jsonOut)
}

func buildQueries(names, file, qtype string, edns bool) ([]query, error) {
	t, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		return nil, fmt.Errorf("unknown type %q", qtype)
	}
	type nq struct {
		n string
		t uint16
	}
	var list []nq
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) == 0 || strings.HasPrefix(fs[0], "#") {
				continue
			}
			tt := t
			if len(fs) > 1 {
				if v, ok := dns.StringToType[strings.ToUpper(fs[1])]; ok {
					tt = v
				}
			}
			list = append(list, nq{fs[0], tt})
		}
	} else {
		for _, n := range strings.Split(names, ",") {
			if n = strings.TrimSpace(n); n != "" {
				list = append(list, nq{n, t})
			}
		}
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no names")
	}
	out := make([]query, 0, len(list))
	for _, x := range list {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(x.n), x.t)
		m.RecursionDesired = true
		if edns {
			m.SetEdns0(1232, false)
		}
		b, err := m.Pack()
		if err != nil {
			return nil, err
		}
		out = append(out, query{b})
	}
	return out, nil
}

func (w *worker) send(qs []query, slots chan struct{}, done <-chan struct{}, stop *atomic.Bool, rate float64) {
	buf := make([]byte, 512)
	var id uint16 = uint16(rand.IntN(65536))
	next := time.Now()
	var interval time.Duration
	if rate > 0 {
		interval = time.Duration(float64(time.Second) / rate)
	}
	for !stop.Load() {
		select {
		case slots <- struct{}{}:
		case <-done:
			return
		}
		if stop.Load() {
			return
		}
		if interval > 0 {
			next = next.Add(interval)
			if d := time.Until(next); d > time.Millisecond {
				time.Sleep(d)
			}
		}
		q := qs[rand.IntN(len(qs))]
		pkt := append(buf[:0], q.pkt...)
		w.mu.Lock()
		for {
			id++
			if _, busy := w.inflight[id]; !busy {
				break
			}
		}
		binary.BigEndian.PutUint16(pkt, id)
		if randomLabel { // the first label starts at offset 13 (after the header and its length byte)
			for i := 13; i < 13+len(randLabelPlaceholder); i++ {
				pkt[i] = alnum[rand.IntN(len(alnum))]
			}
		}
		w.inflight[id] = time.Now().UnixNano()
		w.sent++
		w.mu.Unlock()
		if _, err := w.conn.Write(pkt); err != nil {
			w.mu.Lock()
			delete(w.inflight, id)
			w.errs++
			w.mu.Unlock()
			<-slots
		}
	}
}

func (w *worker) receive(slots chan struct{}, stop *atomic.Bool, timeout time.Duration) {
	buf := make([]byte, 65535)
	lastSweep := time.Now()
	for {
		_ = w.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, err := w.conn.Read(buf)
		now := time.Now()
		if err == nil && n >= 12 {
			id := binary.BigEndian.Uint16(buf)
			w.mu.Lock()
			t0, ok := w.inflight[id]
			if ok {
				delete(w.inflight, id)
				w.recv++
				lat := time.Duration(time.Now().UnixNano() - t0)
				if lat < 0 {
					lat = 0
				}
				w.hist.add(lat)
				w.rcodes[buf[3]&0x0f]++
				if buf[2]&0x02 != 0 {
					w.trunc++
				}
			}
			w.mu.Unlock()
			if ok {
				<-slots
			}
		} else if err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				return // closed
			}
		}
		if now.Sub(lastSweep) > 50*time.Millisecond {
			lastSweep = now
			cut := now.Add(-timeout).UnixNano()
			w.mu.Lock()
			for id, t0 := range w.inflight {
				if t0 < cut {
					delete(w.inflight, id)
					w.timeouts++
					<-slots
				}
			}
			w.mu.Unlock()
		}
	}
}

func report(ws []*worker, elapsed time.Duration, asJSON bool) {
	var h hist
	var sent, recv, to, errs, trunc uint64
	var rc [24]uint64
	for _, w := range ws {
		w.mu.Lock()
		h.merge(&w.hist)
		sent += w.sent
		recv += w.recv
		to += w.timeouts + uint64(len(w.inflight))
		errs += w.errs
		trunc += w.trunc
		for i := range rc {
			rc[i] += w.rcodes[i]
		}
		w.mu.Unlock()
	}
	rcodes := map[string]uint64{}
	for i, v := range rc {
		if v > 0 {
			rcodes[dns.RcodeToString[i]] = v
		}
	}
	sum := map[string]any{
		"duration_s": elapsed.Seconds(), "sent": sent, "received": recv, "timeouts": to, "errors": errs,
		"truncated": trunc, "qps": float64(recv) / elapsed.Seconds(), "rcodes": rcodes,
		"latency_ms": map[string]float64{"p50": ms(h.pct(0.5)), "p90": ms(h.pct(0.9)), "p99": ms(h.pct(0.99)),
			"p999": ms(h.pct(0.999)), "max": ms(h.max)},
	}
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(sum)
		return
	}
	keys := make([]string, 0, len(rcodes))
	for k := range rcodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("duration   %.2fs\nsent       %d\nreceived   %d\ntimeouts   %d\nerrors     %d\ntruncated  %d\n",
		elapsed.Seconds(), sent, recv, to, errs, trunc)
	fmt.Printf("qps        %.0f\n", float64(recv)/elapsed.Seconds())
	fmt.Printf("latency    p50 %.3fms  p90 %.3fms  p99 %.3fms  p99.9 %.3fms  max %.3fms\n",
		ms(h.pct(0.5)), ms(h.pct(0.9)), ms(h.pct(0.99)), ms(h.pct(0.999)), ms(h.max))
	for _, k := range keys {
		fmt.Printf("rcode      %-10s %d\n", k, rcodes[k])
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
