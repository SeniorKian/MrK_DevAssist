//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Privilege model (docs/37 §0.2). Docker gives a non-root user no permitted
// capabilities, and with no-new-privileges the kernel ignores file
// capabilities on execve (e.g. behind `init: true`), so a non-root start can
// never bind port 53. The mrk-dns service therefore starts as uid 0 with only
// NET_BIND_SERVICE, SETUID and SETGID, and dropPrivileges, before anything
// else, switches every OS thread to MRK_DNS_RUN_AS (default 10001:10001)
// keeping exactly CAP_NET_BIND_SERVICE (permitted+effective, nothing
// inheritable or ambient). SETUID/SETGID are gone afterwards and cannot come
// back (no-new-privileges), so a compromise yields an unprivileged process
// that can only bind low ports. Listener rebinds after the drop keep working.

func capBit(c int) (idx int, bit uint32) { return c / 32, uint32(1) << (uint(c) % 32) }

// setCapsAllThreads sets permitted=effective={caps}, inheritable={} on every thread.
func setCapsAllThreads(caps ...int) error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	for _, c := range caps {
		i, b := capBit(c)
		data[i].Permitted |= b
		data[i].Effective |= b
	}
	_, _, errno := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func prctlAllThreads(option, arg uintptr) error {
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, option, arg, 0); errno != 0 {
		return errno
	}
	return nil
}

// dropPrivileges switches a root start to the run-as user keeping only
// CAP_NET_BIND_SERVICE. It is a no-op (returning dropped=false) when not root.
func dropPrivileges() (dropped bool, uid, gid int, err error) {
	if os.Geteuid() != 0 {
		return false, os.Geteuid(), os.Getegid(), nil
	}
	uid, gid, err = parseRunAs(os.Getenv("MRK_DNS_RUN_AS"))
	if err != nil {
		return false, 0, 0, err
	}
	if err := prctlAllThreads(unix.PR_SET_KEEPCAPS, 1); err != nil {
		return false, 0, 0, fmt.Errorf("PR_SET_KEEPCAPS: %w", err)
	}
	// syscall.Set* apply to every OS thread of the process (Go >= 1.16).
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return false, 0, 0, fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setresgid(gid, gid, gid); err != nil {
		return false, 0, 0, fmt.Errorf("setresgid: %w", err)
	}
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		return false, 0, 0, fmt.Errorf("setresuid: %w", err)
	}
	if err := setCapsAllThreads(unix.CAP_NET_BIND_SERVICE); err != nil {
		return false, 0, 0, fmt.Errorf("capset: %w", err)
	}
	if err := prctlAllThreads(unix.PR_SET_KEEPCAPS, 0); err != nil {
		return false, 0, 0, fmt.Errorf("clear PR_SET_KEEPCAPS: %w", err)
	}
	_ = prctlAllThreads(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL)
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return false, 0, 0, fmt.Errorf("still root after the privilege drop")
	}
	return true, uid, gid, nil
}

// raiseBindCapability makes CAP_NET_BIND_SERVICE effective when it is in the
// permitted set (non-root start) and reports whether it is effective.
func raiseBindCapability() bool {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	i, b := capBit(unix.CAP_NET_BIND_SERVICE)
	if data[i].Permitted&b == 0 {
		return false
	}
	if data[i].Effective&b != 0 {
		return true
	}
	return setCapsAllThreads(unix.CAP_NET_BIND_SERVICE) == nil
}
