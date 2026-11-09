package iterative

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// Transport sends one query to one authoritative server.
type Transport interface {
	// Exchange sends m to server (UDP, or TCP when tcp is set) and returns
	// the first response whose ID matches. Question matching is the caller's.
	Exchange(ctx context.Context, server netip.AddrPort, m *dns.Msg, tcp bool) (*dns.Msg, error)
}

// ErrTimeout is returned when a server does not answer in time.
var ErrTimeout = errors.New("iterative: timeout")

// NetTransport is the real network transport: a fresh UDP socket per query
// (random source port chosen by the OS, RFC 5452) and one TCP connection per
// query.
type NetTransport struct{}

func dl(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(2 * time.Second)
}

// Exchange implements Transport.
func (NetTransport) Exchange(ctx context.Context, server netip.AddrPort, m *dns.Msg, tcp bool) (*dns.Msg, error) {
	pkt, err := m.Pack()
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	if !tcp {
		c, err := d.DialContext(ctx, "udp", server.String())
		if err != nil {
			return nil, err
		}
		defer c.Close()
		_ = c.SetDeadline(dl(ctx))
		if _, err := c.Write(pkt); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		for {
			n, err := c.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					return nil, ErrTimeout
				}
				return nil, err
			}
			if n < 12 || binary.BigEndian.Uint16(buf) != m.Id {
				continue // spoofed or late datagram
			}
			r := new(dns.Msg)
			if err := r.Unpack(buf[:n]); err != nil {
				if r.Truncated {
					return r, nil
				}
				continue
			}
			return r, nil
		}
	}
	c, err := d.DialContext(ctx, "tcp", server.String())
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, ErrTimeout
		}
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(dl(ctx))
	out := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(out, uint16(len(pkt)))
	copy(out[2:], pkt)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, ErrTimeout
		}
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(buf); err != nil {
		return nil, err
	}
	if r.Id != m.Id {
		return nil, errors.New("iterative: id mismatch")
	}
	return r, nil
}
