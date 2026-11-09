package resolver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// DoQ (RFC 9250) client: one QUIC connection per upstream, reused; one
// bidirectional stream per query, message ID 0, 2-octet length prefix.

const (
	doqNoError       = 0x0
	doqInternalError = 0x1
)

type doqClient struct {
	mu   sync.Mutex
	conn *quic.Conn
}

func (u *Upstream) doqConn(ctx context.Context) (*quic.Conn, error) {
	u.doqc.mu.Lock()
	defer u.doqc.mu.Unlock()
	if c := u.doqc.conn; c != nil && c.Context().Err() == nil {
		return c, nil
	}
	tc := tlsConfig(u.Addr.ServerName)
	tc.NextProtos = []string{"doq"}
	tc.MinVersion = tls.VersionTLS13
	c, err := quic.DialAddr(ctx, u.Addr.Addr, tc, &quic.Config{HandshakeIdleTimeout: 3 * time.Second,
		MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 0})
	if err != nil {
		return nil, err
	}
	u.doqc.conn = c
	return c, nil
}

func (u *Upstream) dropDoQ(c *quic.Conn) {
	u.doqc.mu.Lock()
	if u.doqc.conn == c {
		u.doqc.conn = nil
	}
	u.doqc.mu.Unlock()
	_ = c.CloseWithError(doqNoError, "")
}

func (u *Upstream) closeDoQ() {
	u.doqc.mu.Lock()
	c := u.doqc.conn
	u.doqc.conn = nil
	u.doqc.mu.Unlock()
	if c != nil {
		_ = c.CloseWithError(doqNoError, "")
	}
}

func (u *Upstream) doq(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	id := q.Id
	q.Id = 0 // RFC 9250 §4.2.1
	pkt, err := q.Pack()
	q.Id = id
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(frame, uint16(len(pkt)))
	copy(frame[2:], pkt)
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		c, err := u.doqConn(ctx)
		if err != nil {
			return nil, err
		}
		r, err := doqExchange(ctx, c, frame)
		if err == nil {
			r.Id = id
			return r, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
		u.dropDoQ(c) // stale connection (idle timeout, server restart): retry on a fresh one
	}
	return nil, last
}

func doqExchange(ctx context.Context, c *quic.Conn, frame []byte) (*dns.Msg, error) {
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	_ = s.SetDeadline(deadline(ctx))
	if _, err := s.Write(frame); err != nil {
		s.CancelRead(doqInternalError)
		return nil, err
	}
	_ = s.Close() // FIN: the query is complete
	var lb [2]byte
	if _, err := io.ReadFull(s, lb[:]); err != nil {
		s.CancelRead(doqInternalError)
		return nil, timeoutErr(err)
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n < 12 {
		s.CancelRead(doqInternalError)
		return nil, ErrMismatch
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(s, buf); err != nil {
		s.CancelRead(doqInternalError)
		return nil, timeoutErr(err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(buf); err != nil {
		return nil, fmt.Errorf("doq: %w", err)
	}
	return r, nil
}

func timeoutErr(err error) error {
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}
