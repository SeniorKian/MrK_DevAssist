package querylog

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestSearchLatencyLarge stores MRK_QL_BENCH_ROWS rows (e.g. 5000000) with a
// realistic shape and reports search latencies. It is skipped by default:
//
//	MRK_QL_BENCH_ROWS=5000000 go test -run TestSearchLatencyLarge -v ./internal/querylog
func TestSearchLatencyLarge(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("MRK_QL_BENCH_ROWS"))
	if n <= 0 {
		t.Skip("set MRK_QL_BENCH_ROWS")
	}
	dir := filepath.Join(t.TempDir(), "ql")
	if d := os.Getenv("MRK_QL_BENCH_DIR"); d != "" {
		dir = d
	}
	base := time.Now().Add(-24 * time.Hour)
	st, warns := OpenStore(dir, time.Now)
	if len(warns) > 0 {
		t.Fatal(warns)
	}
	r := rand.New(rand.NewPCG(7, 9))
	z := rand.NewZipf(r, 1.1, 1, 50000)
	srcs := []uint8{SrcCache, SrcCache, SrcCache, SrcUpstream, SrcAuthoritative}
	rows := make([]Row, 0, 10000)
	t0 := time.Now()
	step := 24 * time.Hour / time.Duration(n)
	for i := 0; i < n; i++ {
		d := z.Uint64()
		rc := uint8(0)
		if r.IntN(20) == 0 {
			rc = 3
		}
		row := Row{TS: base.Add(time.Duration(i) * step).UnixMicro(), Client: fmt.Sprintf("10.%d.%d.%d", r.IntN(4), r.IntN(16), r.IntN(250)),
			Name: fmt.Sprintf("host%d.domain%d.example", d%7, d), QType: 1, Rcode: rc, Source: srcs[r.IntN(len(srcs))],
			DurUS: uint32(50 + r.IntN(5000)), Size: uint16(60 + r.IntN(200))}
		if i == n/3 {
			row.Name, row.Client = "needle.rare.example", "192.0.2.99"
		}
		rows = append(rows, row)
		if len(rows) == cap(rows) {
			if err := st.Append(rows); err != nil {
				t.Fatal(err)
			}
			rows = rows[:0]
		}
	}
	st.Append(rows)
	st.Finalize()
	write := time.Since(t0)
	u := st.Usage()
	t.Logf("stored %d rows in %v (%.0f rows/s), %d segments, %.1f MiB, %.2f bytes/row",
		u.Rows, write.Round(time.Millisecond), float64(n)/write.Seconds(), u.Segments, float64(u.Bytes)/(1<<20), float64(u.Bytes)/float64(u.Rows))
	st.Close()
	// reopen: index loading time
	t1 := time.Now()
	st, _ = OpenStore(dir, time.Now)
	t.Logf("reopen (read %d indexes) %v", len(st.segs), time.Since(t1).Round(time.Millisecond))
	defer st.Close()
	mid := base.Add(12 * time.Hour)
	queries := []string{
		"limit=100",
		"rcode=NXDOMAIN&limit=100",
		"name=*.domain3.example&limit=100",
		"name=*.rare.example&limit=100",
		"client=192.0.2.99&limit=100",
		"client=10.1.0.0/16&limit=100",
		fmt.Sprintf("from=%d&to=%d&limit=1000", mid.UnixMilli(), mid.Add(time.Minute).UnixMilli()),
		"name=zzz-not-there&limit=100",
		"min_ms=5.04&limit=1000",
	}
	for _, q := range queries {
		v, _ := url.ParseQuery(q)
		f, err := ParseFilter(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, cold := range []bool{true, false} {
			if cold {
				st.cacheMu.Lock()
				clear(st.cache)
				st.order = nil
				st.cacheMu.Unlock()
			}
			t2 := time.Now()
			res := st.Search(context.Background(), &f, 2*time.Second)
			label := "warm"
			if cold {
				label = "cold"
			}
			t.Logf("%-55s %s %8v rows=%d scanned=%d truncated=%v", q, label, time.Since(t2).Round(100*time.Microsecond),
				len(res.Rows), res.Scanned, res.Truncated)
		}
	}
}
