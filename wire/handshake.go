package wire

import (
	"encoding/binary"
	"time"
)

type (
	Handshake Packet

	Ext []byte

	HandshakeExt []byte
)

const handshakeSize = headerSize + 12*4

const (
	Wavehand  = 0
	Induction = 1

	Done       = 0xfffffffd
	Agreement  = 0xfffffffe
	Conclusion = 0xffffffff
)

// Encryption schemes.
const (
	NoEncryption = iota
	AES128
	AES192
	AES256
)

// Magic extension field value for SRT protocol.
const Magic = 0x4a17

func (p Handshake) MinSize() int {
	return handshakeSize
}

func (p Handshake) Version() uint32 {
	return binary.BigEndian.Uint32(p[headerSize:])
}

func (p Handshake) Encryption() uint16 {
	return binary.BigEndian.Uint16(p[headerSize+4:])
}

func (p Handshake) Extensions() uint16 {
	return binary.BigEndian.Uint16(p[headerSize+6:])
}

func (p Handshake) Seq() uint32 {
	return binary.BigEndian.Uint32(p[headerSize+8:])
}

func (p Handshake) MaxTransmissonUnit() int {
	return int(binary.BigEndian.Uint32(p[headerSize+12:]))
}

func (p Handshake) MaxFlowWindow() int {
	return int(binary.BigEndian.Uint32(p[headerSize+16:]))
}

func (p Handshake) Type() uint32 {
	return binary.BigEndian.Uint32(p[headerSize+20:])
}

func (p Handshake) SocketID() uint32 {
	return binary.BigEndian.Uint32(p[headerSize+24:])
}

func (p Handshake) Cookie() uint32 {
	return binary.BigEndian.Uint32(p[headerSize+28:])
}

func (p Handshake) ExtStart() int {
	return handshakeSize
}

func (p Handshake) Ext(st int) (tp uint16, data []byte, next int) {
	tp = binary.BigEndian.Uint16(p[st:])
	l := binary.BigEndian.Uint16(p[st+2:])

	next = st + 4 + 4*int(l)

	if next > len(p) {
		next = -1
		return
	}

	data = p[st:next]

	return
}

func (p Handshake) SetVersion(v uint32) {
	binary.BigEndian.PutUint32(p[headerSize:], v)
}

func (p Handshake) SetEncryption(enc uint16) {
	binary.BigEndian.PutUint16(p[headerSize+4:], enc)
}

func (p Handshake) SetExtensions(ext uint16) {
	binary.BigEndian.PutUint16(p[headerSize+6:], ext)
}

func (p Handshake) SetSeq(seq uint32) {
	binary.BigEndian.PutUint32(p[headerSize+8:], seq)
}

func (p Handshake) SetMaxTransmissionUnit(x uint32) {
	binary.BigEndian.PutUint32(p[headerSize+12:], x)
}

func (p Handshake) SetMaxFlowWindow(x uint32) {
	binary.BigEndian.PutUint32(p[headerSize+16:], x)
}

func (p Handshake) SetType(x uint32) {
	binary.BigEndian.PutUint32(p[headerSize+20:], x)
}

func (p Handshake) SetSocketID(c uint32) {
	binary.BigEndian.PutUint32(p[headerSize+24:], c)
}

func (p Handshake) SetCookie(c uint32) {
	binary.BigEndian.PutUint32(p[headerSize+28:], c)
}

func (p Ext) SetHeader(tp, size int) {
	binary.BigEndian.PutUint32(p, uint32(tp<<16)|uint32(uint16(size/4-1)))
}

func (p HandshakeExt) Size() int { return 16 }

func (p HandshakeExt) SetVersion(major, minor, patch int) {
	binary.BigEndian.PutUint32(p[4:], uint32(major<<16)|uint32(uint16(minor<<8))|uint32(uint16(patch)))
}

func (p HandshakeExt) SetFlags(f uint32) {
	binary.BigEndian.PutUint32(p[8:], f)
}

func (p HandshakeExt) SetTSBPDDelays(recv, send int64) {
	binary.BigEndian.PutUint16(p[12:], uint16(recv/int64(time.Millisecond)))
	binary.BigEndian.PutUint16(p[14:], uint16(send/int64(time.Millisecond)))
}

func MakeCongestionControlExt(s string) (e []byte) {
	e = make([]byte, 4+len(s))
	e[1] = 6

	binary.BigEndian.PutUint16(e[2:], uint16(len(s)/4))

	copy(e[4:], s)

	return e
}
