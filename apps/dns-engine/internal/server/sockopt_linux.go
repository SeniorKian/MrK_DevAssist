//go:build linux

package server

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePort lets several sockets bind the same address; the kernel spreads
// datagrams across them (one reader per CPU).
const reusePortSupported = true

func control(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

// enablePktInfo asks the kernel for the destination address of each datagram
// so replies on a wildcard socket leave from the address the client used.
func enablePktInfo(c *net.UDPConn, v6 bool) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		if v6 {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
		} else {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// replyOOB converts received control data into the control data for the reply.
func replyOOB(oob []byte) []byte {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_PKTINFO && len(m.Data) >= 12:
			var info unix.Inet4Pktinfo
			copy(info.Spec_dst[:], m.Data[8:12]) // header destination address
			return unix.PktInfo4(&info)
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_PKTINFO && len(m.Data) >= 20:
			var info unix.Inet6Pktinfo
			copy(info.Addr[:], m.Data[0:16])
			a := netip.AddrFrom16(info.Addr)
			if a.IsLinkLocalUnicast() {
				info.Ifindex = binary.NativeEndian.Uint32(m.Data[16:20])
			}
			return unix.PktInfo6(&info)
		}
	}
	return nil
}
