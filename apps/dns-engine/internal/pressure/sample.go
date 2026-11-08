package pressure

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"time"
)

// Sampler measures the engine's own CPU and memory use.
//
// CPU: cgroup v2 cpu.stat usage_usec against the cpu.max quota (or the CPU
// count without a quota); without cgroup v2 the process CPU time
// (getrusage) against GOMAXPROCS.
// Memory: Go runtime memory (total minus released) against GOMEMLIMIT; when
// no limit is set, cgroup memory.current against memory.max.
type Sampler struct {
	Root     string // cgroup root, default /sys/fs/cgroup
	now      func() time.Time
	lastUse  float64 // µs
	lastAt   time.Time
	procCPU  func() (float64, bool) // µs of process CPU time
	memLimit func() int64
	goMem    func() uint64
}

// NewSampler returns a sampler for the current process.
func NewSampler() *Sampler {
	return &Sampler{Root: "/sys/fs/cgroup", now: time.Now, procCPU: processCPU, memLimit: func() int64 { return debug.SetMemoryLimit(-1) },
		goMem: goMemory}
}

var memSamples = []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}

func goMemory() uint64 {
	s := make([]metrics.Sample, len(memSamples))
	copy(s, memSamples)
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 || s[1].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return s[0].Value.Uint64() - s[1].Value.Uint64()
}

func readInt(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n, err == nil
}

// cgroupUsage returns cpu.stat usage_usec.
func (s *Sampler) cgroupUsage() (float64, bool) {
	b, err := os.ReadFile(filepath.Join(s.Root, "cpu.stat"))
	if err != nil {
		return 0, false
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[0] == "usage_usec" {
			v, err := strconv.ParseFloat(f[1], 64)
			return v, err == nil
		}
	}
	return 0, false
}

// CPUs returns the CPU allowance (cpu.max quota/period, else CPU count).
func (s *Sampler) CPUs() float64 {
	if b, err := os.ReadFile(filepath.Join(s.Root, "cpu.max")); err == nil {
		f := strings.Fields(string(b))
		if len(f) == 2 && f[0] != "max" {
			q, err1 := strconv.ParseFloat(f[0], 64)
			p, err2 := strconv.ParseFloat(f[1], 64)
			if err1 == nil && err2 == nil && q > 0 && p > 0 {
				return q / p
			}
		}
	}
	return float64(runtime.NumCPU())
}

// Sample returns CPU and memory percentages. The first call primes the CPU
// counter and returns 0 for CPU.
func (s *Sampler) Sample() (cpu, mem float64) {
	now := s.now()
	use, ok := s.cgroupUsage()
	cpus := s.CPUs()
	if !ok {
		use, ok = s.procCPU()
		cpus = float64(runtime.GOMAXPROCS(0))
	}
	if ok && !s.lastAt.IsZero() {
		el := now.Sub(s.lastAt).Seconds() * 1e6
		if el > 0 && cpus > 0 {
			cpu = math.Max(0, math.Min(100, (use-s.lastUse)/(el*cpus)*100))
		}
	}
	if ok {
		s.lastUse, s.lastAt = use, now
	}
	lim := s.memLimit()
	if lim > 0 && lim < math.MaxInt64 {
		mem = float64(s.goMem()) / float64(lim) * 100
	} else if cur, ok1 := readInt(filepath.Join(s.Root, "memory.current")); ok1 {
		if mx, ok2 := readInt(filepath.Join(s.Root, "memory.max")); ok2 && mx > 0 {
			mem = float64(cur) / float64(mx) * 100
		}
	}
	return round1(cpu), round1(math.Min(mem, 100))
}
