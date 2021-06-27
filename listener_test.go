package srt

import (
	"net"
	"testing"

	"github.com/nikandfor/errors"
	"github.com/nikandfor/tlog"
	"github.com/nikandfor/tlog/low"
	"github.com/stretchr/testify/assert"

	"github.com/nikandfor/srt/wire"
)

type (
	testPacketConn struct {
		net.PacketConn

		r  []testPacket
		ri int

		w []testPacket

		exp map[string]testChecker
	}

	testChecker func(p testPacket) (match bool, n int, err error)

	testPacket struct {
		p    wire.Packet
		addr net.Addr
	}
)

func TestListenerAccept(t *testing.T) {
	tlog.DefaultLogger = tlog.NewTestLogger(t, "raw", nil)

	var pc testPacketConn

	l := newListener(&pc)

	l.Encryption = wire.NoEncryption

	pc.r = []testPacket{
		{p: []byte{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x26, 0x88, 0x47, 0x89, 0x00, 0x00, 0x05, 0xdc,
			0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x9e, 0x7d, 0x6d, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}, addr: testAddr("a")},
		{p: []byte{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc1, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x26, 0x88, 0x47, 0x89, 0x00, 0x00, 0x05, 0xdc,
			0x00, 0x00, 0x20, 0x00, 0xff, 0xff, 0xff, 0xff, 0x20, 0x9e, 0x7d, 0x6d, 0x9d, 0x89, 0x51, 0x86,
			0x01, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x04, 0x03, 0x00, 0x00, 0x00, 0xe4, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x06, 0x00, 0x01, 0x65, 0x6c, 0x69, 0x66,
		}, addr: testAddr("a")},
	}

	phase := 1

	pc.exp = map[string]testChecker{
		"handshake": func(tp testPacket) (ok bool, n int, err error) {
			if !tp.p.Handshake() {
				err = errors.New("not a handshake")
				return
			}

			assert.EqualValues(t, 0x209e7d6d, tp.p.SocketID())

			h := wire.Handshake(tp.p)

			assert.EqualValues(t, 5, h.Version())
			assert.EqualValues(t, l.Encryption, h.Encryption())

			if phase == 1 {
				assert.EqualValues(t, wire.Induction, h.Type())
				assert.EqualValues(t, wire.Magic, h.Extensions())

				phase++
			} else {
				assert.EqualValues(t, wire.Conclusion, h.Type())
				assert.EqualValues(t, 5, h.Extensions())
			}

			assert.EqualValues(t, calcCookie(testAddr("a"), low.Monotonic()), h.Cookie())

			return true, len(tp.p), nil
		},
	}

	err := l.readPacket()
	assert.NoError(t, err)

	err = l.readPacket()
	assert.NoError(t, err)
}

func (c *testPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.ri == len(c.r) {
		return 0, nil, errors.New("no more packets")
	}

	q := c.r[c.ri]
	c.ri++

	n = copy(p, q.p)
	addr = q.addr

	return
}

func (c *testPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.w = append(c.w, testPacket{
		p:    p,
		addr: addr,
	})

	if c.exp == nil {
		return len(p), nil
	}

	var ok bool
	for _, f := range c.exp {
		ok, n, err = f(c.w[len(c.w)-1])
		if ok {
			break
		}
	}

	if !ok {
		return 0, errors.New("no matches")
	}

	return n, err
}
