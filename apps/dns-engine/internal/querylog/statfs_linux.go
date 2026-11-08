//go:build linux

package querylog

import "golang.org/x/sys/unix"

// DiskFree returns the percentage of the filesystem holding path that is
// available to unprivileged users.
func DiskFree(path string) (float64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	if st.Blocks == 0 {
		return 100, nil
	}
	return float64(st.Bavail) * 100 / float64(st.Blocks), nil
}
