package srt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"time"
	"unsafe"

	"github.com/nikandfor/errors"
	"github.com/nikandfor/tlog"
	"github.com/nikandfor/tlog/low"
)

type (
	Listener struct {
		p net.PacketConn

		socks map[uint32]*Conn

		acceptc chan *Conn

		stopc chan struct{}
	}
)

var _ net.Listener = &Listener{}

var handshakeHeader []byte

func init() {
	handshakeHeader = make([]byte, 8)
	handshakeHeader[0] = controlPacket
}

func NewListener(p net.PacketConn) (l *Listener) {
	l = &Listener{
		p:       p,
		socks:   make(map[uint32]*Conn),
		acceptc: make(chan *Conn, 16),
		stopc:   make(chan struct{}),
	}

	go func() {
		for {
			err := l.run()

			select {
			case <-l.stopc:
				return
			default:
			}

			tlog.Printw("run", "err", err)
		}
	}()

	return l
}

func (l *Listener) Addr() net.Addr {
	return l.p.LocalAddr()
}

func (l *Listener) Close() (err error) {
	close(l.stopc)

	return nil
}

func (l *Listener) Accept() (c net.Conn, err error) {
	select {
	case c = <-l.acceptc:
	case <-l.stopc:
		err = errors.New("stopped")
	}

	return c, err
}

func (l *Listener) Connect(addr net.Addr) (c *Conn, err error) {
	c = NewConn(l.p, addr)
	err = c.Connect()

	return c, err
}

func (l *Listener) run() error {
	for {
		buf := make([]byte, 2000)

		n, addr, err := l.p.ReadFrom(buf)
		if err != nil {
			return errors.Wrap(err, "read packet")
		}

		ts := low.Monotonic()

		tlog.Printf("packet from %v\n%s", addr, hex.Dump(buf[:n]))

		sid, err := l.sockID(buf[:n])
		if err != nil {
			return errors.Wrap(err, "sockid")
		}

		if sid == 0 {
			err = l.accept(buf[:n], addr, ts)
			if err != nil {
				return errors.Wrap(err, "accept")
			}

			continue
		}

		s := l.socks[sid]
		if s == nil {
			return errors.Wrap(err, "unknown socket id: %x", sid)
		}

		err = s.recv(buf[:n], addr, ts)
		if err != nil {
			return errors.Wrap(err, "socket: recv")
		}
	}

	return nil
}

func (l *Listener) accept(b []byte, addr net.Addr, ts int64) (err error) {
	b, sid, err := l.respondInduct(b, addr, ts)
	if err != nil {
		return errors.Wrap(err, "parse induction")
	}

	_, err = send(tlog.Span{Logger: tlog.DefaultLogger}, l.p, b, addr)
	if err != nil {
		return errors.Wrap(err, "send induction resp")
	}

	if sid == 0 {
		return nil
	}

	c := NewConn(l.p, addr)

	select {
	case l.acceptc <- c:
	default:
		return errors.Wrap(err, "accept queue is full")
	}

	l.socks[sid] = c

	return nil
}

func (l *Listener) respondInduct(b []byte, addr net.Addr, ts int64) (_ []byte, sid uint32, err error) {
	if len(b) < 16*4 || !bytes.Equal(b[:8], handshakeHeader) {
		err = errors.New("not a handshake packet")
		return
	}

	var ver uint32

	defer func() {
		if err == nil {
			return
		}

		err = errors.Wrap(err, "ver %x", ver)
	}()

	// ts
	// socket id is already checked

	i := headerSize

	ver = binary.BigEndian.Uint32(b[i:])
	binary.BigEndian.PutUint32(b[i:], 5)
	i += 4

	{
		enc := binary.BigEndian.Uint16(b[i:])
		if enc != noEncryption {
			err = errors.New("bad encryption")
			return
		}

		// TODO: advertise encryption

		i += 2
	}

	ext := binary.BigEndian.Uint16(b[i:])
	binary.BigEndian.PutUint16(b[i:], 0x4A17) // magic code
	i += 2

	//	seq := binary.BigEndian.Uint32(b[i:])
	i += 4

	//	mtu := binary.BigEndian.Uint32(b[i:])
	i += 4

	//	mfw := binary.BigEndian.Uint32(b[i:])
	i += 4

	ht := binary.BigEndian.Uint32(b[i:])
	//	binary.BigEndian.PutUint32(b[i:], induction)
	i += 4

	{
		sid = binary.BigEndian.Uint32(b[i:])

		copy(b[0xc:0x10], b[i:])

		binary.BigEndian.PutUint32(b[i:], sid) // TODO: random our socker id?

		i += 4
	}

	cookie := binary.BigEndian.Uint32(b[i:])
	ccookie := calcCookie(addr, ts)

	tlog.Printw("calc cookie", "cookie", tlog.Hex(ccookie), "got_cookie", tlog.Hex(cookie), "addr", addr, "ts_min", ts/int64(time.Minute))

	switch {
	case ver == 4 && ht == induction:
		if ext != kmReq {
			err = errors.New("bad kmreq")
			return
		}

		if cookie != 0 {
			err = errors.New("non-zero cookie")
			return
		}

		binary.BigEndian.PutUint32(b[i:], ccookie)

		sid = 0 // it's returned and non-zero means second step
	case ver == 5 && ht == conclusion:
		if cookie != ccookie {
			err = errors.New("bad cookie")
			return
		}

		if sid == 0 {
			err = errors.New("zero socket id")
			return
		}

		binary.BigEndian.PutUint32(b[i:], 0)
	default:
		err = errors.New("bad handshake type")
		return
	}

	i += 4 // cookie

	// source ip
	i += 16

	// extension
	for i < len(b) {
		if i+4 > len(b) {
			err = errors.New("bad ext")
			return
		}

		exttp := binary.BigEndian.Uint16(b[i:])
		i += 2
		extlen := binary.BigEndian.Uint16(b[i:])
		i += 2

		if i+4*int(extlen) > len(b) {
			err = errors.New("bad ext len: %x+%x > %x", i, 4*int(extlen), len(b))
			return
		}

		st := i

		//	tlog.Printw("ext", "ext", tlog.Hex(exttp), "len", tlog.Hex(extlen), "st", tlog.Hex(st), "end", tlog.Hex(st+4*int(extlen)), "buf", tlog.Hex(len(b)))

		switch exttp {
		case 1: // handshake req
			i -= 4

			binary.BigEndian.PutUint16(b[i:], 2) // resp
			i += 2

			i += 2 // len

			//	copy(b[i:], libver)
			i += 4
		case 6: // congestion config
			tlog.Printw("congestion alg", "alg", string(b[i:i+4*int(extlen)]))
		}

		i = st + 4*int(extlen)
	}

	return b, sid, nil
}

func (l *Listener) sockID(p []byte) (id uint32, err error) {
	if len(p) < 0x10 {
		return 0, errors.Wrap(err, "short msg")
	}

	id = binary.BigEndian.Uint32(p[0xc:])

	return
}

func send(tr tlog.Span, p net.PacketConn, b []byte, addr net.Addr) (n int, err error) {
	n, err = p.WriteTo(b, addr)

	tlog.Printf("packet to  %v err %v\n%s", addr, err, hex.Dump(b))

	return
}

func calcCookie(a net.Addr, ts int64) (c uint32) {
	ts /= int64(time.Minute)

	var h uintptr

	h = low.StrHash(a.String(), h)
	h = low.MemHash64(unsafe.Pointer(&ts), h)

	return uint32(h)
}
