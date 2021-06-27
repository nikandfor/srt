package srt

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/nikandfor/errors"
	"github.com/nikandfor/tlog"
	"github.com/nikandfor/tlog/low"
)

type (
	Conn struct {
		p    net.PacketConn
		addr net.Addr

		localID  uint32
		remoteID uint32
		epoch    int64 // monotonic nanoseconds

		MaxTransmissonUnit int
		MaxFlowWindow      int

		BufferLatency time.Duration

		mu sync.Mutex

		seq uint32
		msg uint32

		sendq queue
		recvq queue

		// end of mu

		stream bool

		stopc chan struct{}
	}

	queue struct {
		first *msg
		last  *msg
	}

	msg struct {
		ts uint32

		seq uint32
		msg uint32

		size int

		flags byte

		data []byte

		buf []byte

		next *msg
	}
)

const controlPacket = 0x80

// Control Types.
const (
	handshake = iota
	keepAlive
	ack
	nak
	congestionWarning
	shutdown
	ackack
	dropReq
	peerError

	userDefined = 0x7fff
)

// data flags
const (
	flagPPFirst = 0b0000_0001
	flagPPLast  = 0b0000_0010
	flagO       = 0b0000_0100
	flagKKMask  = 0b0001_1000
	flagR       = 0b0010_0000
)

// Encryption schemes.
const (
	noEncryption = iota
	aes128
	aes192
	aes256
)

// handshake ext filed
const (
	hsReq = 1 << iota
	kmReq
	config
)

// Handshake type.
const (
	waveHand  = 0
	induction = 1

	done       = 0xfffffffd
	agreement  = 0xfffffffe
	conclusion = 0xffffffff
)

const headerSize = 0x10

var zeros = make([]byte, 16*4)

func NewConn(p net.PacketConn, addr net.Addr) (c *Conn) {
	return &Conn{
		p:    p,
		addr: addr,

		MaxTransmissonUnit: 1500,
		MaxFlowWindow:      0x2000,

		stopc: make(chan struct{}),
	}
}

func (c *Conn) Connect() (err error) {
	c.seq = uint32(rand.Int31())

	b := c.encodeInduction(nil)

	_, err = send(tlog.Span{Logger: tlog.DefaultLogger}, c.p, b, c.addr)
	if err != nil {
		return errors.Wrap(err, "write induction")
	}

	// first phase response
	buf := make([]byte, 2000)

	n, addr, err := c.p.ReadFrom(buf)
	if err != nil {
		return errors.Wrap(err, "read packet")
	}

	ts := low.Monotonic()

	tlog.Printf("packet from %v\n%s", addr, hex.Dump(buf[:n]))

	_ = ts

	go func() {
		for {
			err := c.run()

			select {
			case <-c.stopc:
				return
			default:
			}

			tlog.Printw("run", "err", err)
		}
	}()

	return nil
}

func (c *Conn) Close() (err error) {
	// send close to the peer

	close(c.stopc)

	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	return c.p.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *Conn) SetDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *Conn) run() (err error) {
	for {
		buf := make([]byte, 2000)

		n, addr, err := c.p.ReadFrom(buf)
		if err != nil {
			return errors.Wrap(err, "read packet")
		}

		ts := low.Monotonic()

		tlog.Printf("packet from %v\n%s", addr, hex.Dump(buf[:n]))

		err = c.recv(buf[:n], addr, ts)
		if err != nil {
			return errors.Wrap(err, "recv")
		}
	}
}

func (c *Conn) encodeInduction(b []byte) []byte {
	i := len(b)
	b = append(b, zeros[:16*4]...)

	b = append(b[i:], handshakeHeader...)
	i += len(handshakeHeader)

	binary.BigEndian.PutUint32(b[i:], 0) // ts
	i += 4

	// dst socket id
	i += 4

	binary.BigEndian.PutUint32(b[i:], 4) // version
	i += 4

	// encryption
	i += 2

	binary.BigEndian.PutUint16(b[i:], kmReq) // extension
	i += 2

	binary.BigEndian.PutUint32(b[i:], c.seq)
	i += 4

	binary.BigEndian.PutUint32(b[i:], uint32(c.MaxTransmissonUnit))
	i += 4

	binary.BigEndian.PutUint32(b[i:], uint32(c.MaxFlowWindow))
	i += 4

	binary.BigEndian.PutUint32(b[i:], induction)
	i += 4

	binary.BigEndian.PutUint32(b[i:], c.localID)
	i += 4

	// cookie
	i += 4

	// our ip
	i += 16

	return b[:i]
}

func (c *Conn) Write(p []byte) (n int, err error) {
	size := calcSize(c.MaxTransmissonUnit, len(p))

	defer c.mu.Unlock()
	c.mu.Lock()

	m := &msg{
		ts:    uint32((low.Monotonic() - c.epoch) / 1000), // ns to us
		seq:   c.seq,
		msg:   c.msg,
		size:  size,
		flags: flagO,
		data:  p,
	}

	c.seq += uint32(n)
	c.msg++

	c.sendq.Push(m)

	n, err = c.send(m, m.seq)
	if err != nil {
		return n, errors.Wrap(err, "send")
	}

	return n, nil
}

func (c *Conn) send(m *msg, seq uint32) (n int, err error) {
	var nn int

	for i := 0; i < m.size; i++ {
		m.buf = c.encodeData(m.buf[:0], m, i)

		nn, err = send(tlog.Span{Logger: tlog.DefaultLogger}, c.p, m.buf, c.addr)
		n += nn
		if err != nil {
			return
		}
	}

	m.flags |= flagR

	return
}

func (c *Conn) encodeData(b []byte, m *msg, i int) []byte {
	mtu := c.MaxTransmissonUnit - headerSize

	// data part
	st := i * mtu
	end := (i + 1) * mtu
	if end > len(m.data) {
		end = len(m.data)
	}

	i = len(b) // i reused
	b = append(b, zeros[:0x20]...)

	binary.BigEndian.PutUint32(b[i:], (m.seq+uint32(i))&0x7fff_ffff)
	i += 4

	binary.BigEndian.PutUint32(b[i:], m.msg&0x7_ffff)

	{ // flags
		ff := m.flags

		if i == 0 {
			ff |= flagPPFirst
		}

		if i == m.size-1 {
			ff |= flagPPLast
		}

		b[i] = ff
	}

	i += 4

	binary.BigEndian.PutUint32(b[i:], m.ts)
	i += 4

	binary.BigEndian.PutUint32(b[i:], c.remoteID)
	i += 4

	b = append(b, m.data[st:end]...)

	return b
}

func (c *Conn) Read(p []byte) (n int, err error) {
	return 0, nil
}

func (c *Conn) recv(b []byte, addr net.Addr, ts int64) (err error) {
	if len(b) < 0x10 {
		return errors.New("short packet")
	}

	if b[0]&controlPacket == controlPacket {
		return c.recvControl(b, addr, ts)
	}

	return nil
}

func (c *Conn) recvControl(b []byte, addr net.Addr, ts int64) (err error) {
	tp := binary.BigEndian.Uint16(b) & 0x7fff

	switch tp {
	case keepAlive:
	case shutdown:
		// mark somehow
	}

	return nil
}

func (q *queue) Push(m *msg) {
	if q.last == nil {
		q.first = m
		q.last = m
	} else {
		q.last.next = m
		q.last = m
	}
}

func (q *queue) Pop() (m *msg) {
	if q.first == nil {
		return nil
	}

	m = q.first
	q.first = m.next

	return
}

func (q *queue) Peek() (m *msg) {
	return q.first
}

func calcSize(mtu, l int) int {
	mtu -= headerSize
	return (l + mtu - 1) / mtu
}
