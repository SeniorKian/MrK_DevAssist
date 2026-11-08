//go:build !linux

package server

import (
	"net"
	"syscall"
)

const reusePortSupported = false

func control(network, address string, c syscall.RawConn) error { return nil }

func enablePktInfo(c *net.UDPConn, v6 bool) error { return nil }

func replyOOB(oob []byte) []byte { return nil }
