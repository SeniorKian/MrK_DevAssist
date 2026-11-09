package pressure

import (
	"fmt"
	"math"
	"runtime/debug"
)

// MemoryUse returns the Go runtime memory in use and the soft limit
// (GOMEMLIMIT; math.MaxInt64 = none).
func MemoryUse() (used uint64, limit int64) { return goMemory(), debug.SetMemoryLimit(-1) }

// HeadroomPercent is the share of the memory limit a large allocation (a
// block list build) may bring the process to.
const HeadroomPercent = 80

// CheckHeadroom refuses an allocation of need bytes that would take the
// process above HeadroomPercent of its memory limit. Without a limit it
// always succeeds (the cgroup is then the only bound and the pressure
// controller still sheds load).
func CheckHeadroom(need int64) error {
	used, limit := MemoryUse()
	if limit <= 0 || limit == math.MaxInt64 {
		return nil
	}
	if float64(used)+float64(need) > float64(limit)*HeadroomPercent/100 {
		return fmt.Errorf("needs %d MiB more; %d of %d MiB in use (limit %d%%)", need>>20, used>>20, limit>>20, HeadroomPercent)
	}
	return nil
}
