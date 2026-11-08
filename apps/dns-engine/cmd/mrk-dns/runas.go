package main

import (
	"fmt"
	"strconv"
	"strings"
)

// MRK_DNS_RUN_AS: the unprivileged uid:gid a root start drops to.
const defaultRunAs = "10001:10001"

func parseRunAs(s string) (int, int, error) {
	if strings.TrimSpace(s) == "" {
		s = defaultRunAs
	}
	u, g, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, 0, fmt.Errorf("MRK_DNS_RUN_AS must be uid:gid, got %q", s)
	}
	uid, err1 := strconv.Atoi(u)
	gid, err2 := strconv.Atoi(g)
	if err1 != nil || err2 != nil || uid <= 0 || gid <= 0 || uid > 1<<31-2 || gid > 1<<31-2 {
		return 0, 0, fmt.Errorf("MRK_DNS_RUN_AS must be a non-root numeric uid:gid, got %q", s)
	}
	return uid, gid, nil
}
