//go:build !linux

package querylog

// DiskFree is not implemented outside Linux: the guard never triggers.
func DiskFree(string) (float64, error) { return 100, nil }
