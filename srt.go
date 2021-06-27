package srt

import (
	"io"
	"net"
	"sync"

	"github.com/nikandfor/errors"
	"github.com/nikandfor/srt/wire"
	"github.com/nikandfor/tlog"
	"github.com/nikandfor/tlog/low"
)

type (
	Conn struct {
		net.Conn

		p    net.PacketConn
		addr net.Addr

		localid  uint32
		remoteid uint32

		epoch int64

		mu sync.Mutex

		s queue
		r queue

		readnotify chan struct{}
	}
)

var ErrShortBuffer = io.ErrShortBuffer

var errWait = errors.New("wait")

const mtuHeaders = 6 * 4 // 2 * 4 udp + 4 * 4 srt data header

func (c *Conn) LocalAddr() net.Addr {
	return c.p.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *Conn) Write(p []byte) (n int, err error) {
	// TODO
	tlog.Printw("write")
	return
}

func (c *Conn) Read(p []byte) (n int, err error) {
again:
	n, err = c.r.read(p)
	tlog.Printw("read", "n", n, "err", err)
	if err == errWait {
		<-c.readnotify

		goto again
	}

	return
}

func (c *Conn) recv(p wire.Packet, addr net.Addr, ts int64) (err error) {
	if p.Control() {
		return c.recvControl(p, addr, ts)
	}

	dp := wire.DataPacket(p)

	c.r.insert(dp)

	select {
	case c.readnotify <- struct{}{}:
	default:
	}

	err = c.lightAck()
	if err != nil {
		return errors.Wrap(err, "send ack")
	}

	return
}

func (c *Conn) recvControl(p wire.Packet, addr net.Addr, ts int64) (err error) {
	tp, _ := p.ControlType()

	switch tp {
	case wire.ShutdownType:
		c.r.insert(nil)

		select {
		case c.readnotify <- struct{}{}:
		default:
		}
	default:
		tlog.Printw("control", "tp", tp)
	}

	return
}

func (c *Conn) lightAck() (err error) {
	p := make(wire.Ack, wire.Ack{}.MinSize())

	n := c.r.ack()

	defer func() {
		tlog.Printw("ack", "ack", tlog.Hex(n), "err", err)
	}()

	p.SetAckNum(n + 1)

	wire.Packet(p).SetControlType(wire.AckType, 0)

	return c.sendControl(wire.Packet(p))
}

func (c *Conn) sendControl(p wire.Packet) (err error) {
	p.SetTimestamp(low.Monotonic() - c.epoch)
	p.SetSocketID(c.remoteid)

	_, err = c.p.WriteTo(p, c.addr)

	return errors.Wrap(err, "write")
}

func (c *Conn) Close() (err error) {
	p := make(wire.Packet, wire.Packet{}.MinSize())

	p.SetControlType(wire.ShutdownType, 0)

	err = c.sendControl(p)
	if err != nil {
		return errors.Wrap(err, "send shutdown packet")
	}

	return nil
}
