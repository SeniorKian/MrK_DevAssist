//go:build unix

package pressure

import "golang.org/x/sys/unix"

func processCPU() (float64, bool) {
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	us := float64(ru.Utime.Sec+ru.Stime.Sec)*1e6 + float64(ru.Utime.Usec+ru.Stime.Usec)
	return us, true
}
