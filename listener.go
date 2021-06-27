package srt

import (
	"context"
	"encoding/hex"
	"math/rand"
	"net"
	"time"
	"unsafe"

	"github.com/nikandfor/errors"
	"github.com/nikandfor/srt/wire"
	"github.com/nikandfor/tlog"
	"github.com/nikandfor/tlog/low"
)

type (
	Listener struct {
		p net.PacketConn

		Encryption int

		MaxTransmissonUnit int
		MaxFlowWindow      int

		//	mu sync.Mutex

		socks map[sockkey]*Conn
		conng map[uint32]*connreq

		rand *rand.Rand

		// end of mu

		acceptc chan *Conn

		stopc chan struct{}
	}

	sockkey struct {
		ip   [16]byte
		port uint16
		sid  uint32
	}

	sender struct {
		net.PacketConn
	}

	conndata struct {
		tp uint32

		lid uint32
		rid uint32

		lseq uint32
		rseq uint32
	}

	connreq struct {
		id   uint32
		errc chan error
		c    *Conn
	}

	testAddr string
)

func newListener(p net.PacketConn) (l *Listener) {
	return &Listener{
		p: p,

		MaxTransmissonUnit: 1500,
		MaxFlowWindow:      0x2000,

		socks:   make(map[sockkey]*Conn),
		conng:   make(map[uint32]*connreq),
		rand:    rand.New(rand.NewSource(time.Now().UnixNano())),
		acceptc: make(chan *Conn, 2),
		stopc:   make(chan struct{}),
	}
}

func New(p net.PacketConn) (l *Listener) {
	l = newListener(p)

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

	return
}

func (l *Listener) Connect(ctx context.Context, addr net.Addr) (_ *Conn, err error) {
	req := connreq{
		id:   uint32(l.rand.Int31()),
		errc: make(chan error, 1),
	}

	l.conng[req.id] = &req

	defer func() {
		delete(l.conng, req.id)
	}()

	tlog.Printw("connect as", "streamid", tlog.Hex(req.id))

	p := l.newHandshake(wire.Induction, req.id)

	_, err = l.WriteTo(p, addr)
	if err != nil {
		return nil, err
	}

	select {
	case err = <-req.errc:
	case <-ctx.Done():
		err = ctx.Err()
	}

	if err != nil {
		return nil, err
	}

	return req.c, nil
}

func (l *Listener) run() (err error) {
	for {
		err = l.readPacket()
		if err != nil {
			return err
		}
	}
}

func (l *Listener) readPacket() (err error) {
	buf := make(wire.Packet, 2000)

	n, addr, err := l.p.ReadFrom(buf)
	if err != nil {
		return errors.Wrap(err, "read packet")
	}

	buf = buf[:n]

	ts := low.Monotonic()

	if tlog.If("raw") {
		tlog.Printf("packet from %v\n%s", addr, hex.Dump(buf))
	}

	if n < buf.MinSize() {
		return errors.New("short packet")
	}

	sid := buf.SocketID()

	if buf.Handshake() {
		err = l.handleHandshake(wire.Handshake(buf), addr, ts)

		return errors.Wrap(err, "handshake")
	}

	c := l.socks[key(addr, sid)]

	if c == nil {
		return errors.New("no socket")
	}

	err = c.recv(buf[:n], addr, ts)
	if err != nil {
		return errors.Wrap(err, "recv: sid %x", sid)
	}

	return nil
}

func (l *Listener) handleHandshake(p wire.Handshake, addr net.Addr, ts int64) (err error) {
	dstid := wire.Packet(p).SocketID()

	var d conndata
	p, d, err = l.parseHandshake(p, addr, ts)

	req, reqok := l.conng[d.lid]
	if reqok {
		defer func() {
			if err != nil {
				req.errc <- err
			}
		}()
	}

	if err != nil {
		return errors.Wrap(err, "parse")
	}

	tlog.Printw("handshake", "tp_conclusion", d.tp == wire.Conclusion, "local_sid", tlog.Hex(dstid))

	if d.tp != wire.Conclusion || dstid == 0 {
		_, err = l.WriteTo(p, addr)
		if err != nil {
			return errors.Wrap(err, "send resp")
		}
	}

	if d.tp != wire.Conclusion {
		return nil
	}

	c := &Conn{
		p:        sender{PacketConn: l.p},
		addr:     addr,
		localid:  d.lid,
		remoteid: d.rid,

		epoch: ts,

		readnotify: make(chan struct{}, 1),
	}

	c.s.seq = d.lseq
	c.r.seq = d.rseq

	if reqok {
		req.c = c
		req.errc <- nil

		return nil
	}

	err = l.accepted(c, addr)
	if err != nil {
		return errors.Wrap(err, "accept")
	}

	return nil
}

func (l *Listener) accepted(c *Conn, addr net.Addr) (err error) {
	select {
	case l.acceptc <- c:
	default:
		panic("stop")
		return errors.New("full buffer")
	}

	l.socks[key(addr, c.localid)] = c

	return nil
}

func (l *Listener) newHandshake(tp int, id uint32) (p wire.Handshake) {
	p = make(wire.Handshake, wire.Handshake{}.MinSize()) // first req

	wire.Packet(p).SetControlType(wire.HandshakeType, 0)

	if tp == wire.Induction {
		p.SetVersion(4)
		p.SetExtensions(2)
	} else {
		p.SetVersion(5)
	}

	p.SetMaxTransmissionUnit(uint32(l.MaxTransmissonUnit))
	p.SetMaxFlowWindow(uint32(l.MaxFlowWindow))

	p.SetType(uint32(tp))

	p.SetSocketID(id)

	return p
}

func (l *Listener) parseHandshake(p wire.Handshake, addr net.Addr, ts int64) (_ wire.Handshake, d conndata, err error) {
	err = l.checkHandshake(p, addr, ts)
	if err != nil {
		return nil, d, errors.Wrap(err, "check packet")
	}

	ver := p.Version()

	defer func() {
		if err != nil {
			err = errors.Wrap(err, "%x", ver)
		}
	}()

	dst := wire.Packet(p).SocketID()

	d.tp = p.Type()
	cookie := p.Cookie()

	wire.Packet(p).SetSocketID(p.SocketID())

	p, err = l.procExts(p, &d)
	if err != nil {
		return nil, d, errors.Wrap(err, "extensions")
	}

	switch {
	case ver == 4 && d.tp == wire.Induction: // first resp
		if p.Extensions() != 2 {
			return nil, d, errors.New("bad extension")
		}

		p.SetExtensions(wire.Magic)

		if cookie != 0 {
			return nil, d, errors.New("bad cookie")
		}

		cookie = calcCookie(addr, ts)
		p.SetCookie(cookie)
		p.SetSocketID(0)
	case ver == 5 && d.tp == wire.Induction: // second req
		p.SetType(wire.Conclusion)

		p.SetSocketID(dst)

		ext := make(wire.Ext, wire.HandshakeExt{}.Size())

		ext.SetHeader(1, wire.HandshakeExt{}.Size())
		wire.HandshakeExt(ext).SetVersion(1, 4, 0)
		wire.HandshakeExt(ext).SetFlags(0)

		p = append(p, ext...)

		p = append(p, []byte{0x00, 0x06, 0x00, 0x01, 'e', 'l', 'i', 'f'}...)
	case ver == 5 && d.tp == wire.Conclusion: // second resp
		if cookie == 0 {
			return nil, d, errors.New("bad cookie")
		}

		d.lid = uint32(l.rand.Int31())
		d.rid = p.SocketID()

		d.lseq = uint32(l.rand.Int31())
		d.rseq = p.Seq() - 1

		p.SetSeq(d.lseq)
		p.SetSocketID(d.lid)
	default:
		return nil, d, errors.New("bad handshake")
	}

	p.SetVersion(5)
	p.SetEncryption(uint16(l.Encryption))

	p.SetMaxTransmissionUnit(uint32(l.MaxTransmissonUnit))
	p.SetMaxFlowWindow(uint32(l.MaxFlowWindow))

	return p, d, nil
}

func (l *Listener) procExts(p wire.Handshake, d *conndata) (_ wire.Handshake, err error) {
	for st := p.ExtStart(); st < len(p); {
		tp, _, next := p.Ext(st)

		switch tp {
		case 1: // handshake request
			p[st+1] = 2 // resp
		case 6: // congestion
		}

		if next == -1 {
			return nil, errors.New("bad extension: %x at %x", tp, st)
		}

		st = next
	}

	return p, nil
}

func (l *Listener) checkHandshake(p wire.Handshake, addr net.Addr, ts int64) (err error) {
	if len(p) < p.MinSize() {
		return errors.New("too short")
	}

	enc := p.Encryption()
	if enc != wire.NoEncryption {
		return errors.New("bad encryption")
	}

	return nil
}

func (l *Listener) Accept() (c net.Conn, err error) {
	select {
	case c = <-l.acceptc:
	case <-l.stopc:
		return nil, errors.New("stopped")
	}

	return
}

func (l *Listener) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = l.p.WriteTo(p, addr)

	if tlog.If("raw") {
		tlog.Printf("packet to   %v\n%s", addr, hex.Dump(p))
	}

	return
}

func calcCookie(a net.Addr, ts int64) (c uint32) {
	ts /= int64(time.Minute)

	var h uintptr

	h = low.StrHash(a.String(), h)
	h = low.MemHash64(unsafe.Pointer(&ts), h)

	return uint32(h)
}

func key(addr net.Addr, sid uint32) (k sockkey) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		copy(k.ip[:], a.IP.To16())
		k.port = uint16(a.Port)
	case testAddr:
	default:
		panic(addr)
	}

	k.sid = sid

	return
}

func (a testAddr) Network() string { return "testing" }
func (a testAddr) String() string  { return string(a) }

func (s sender) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = s.PacketConn.WriteTo(p, addr)

	if tlog.If("raw") {
		tlog.Printf("packet to   %v => %v %v\n%s", addr, n, err, hex.Dump(p))
	}

	return
}
