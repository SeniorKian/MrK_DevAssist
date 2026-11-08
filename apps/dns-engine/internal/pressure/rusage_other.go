//go:build !unix

package pressure

func processCPU() (float64, bool) { return 0, false }
