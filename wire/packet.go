package wire

import (
	"bytes"
	"encoding/binary"
)

type (
	Packet []byte
)

const (
	headerSize = 16
)

const controlPacket = 0x80

const (
	HandshakeType = iota
	KeepAliveType
	AckType
	NakType
	CongestionWarningType
	ShutdownType
	AckAckType
	DropReqType
	PeerErrorType
	UserDefinedType
)

var handshakeHeader = [8]byte{controlPacket}

func (p Packet) MinSize() int {
	return headerSize
}

func (p Packet) Control() bool {
	return p[0]&controlPacket != 0
}

func (p Packet) ControlType() (tp, sub uint16) {
	tp = binary.BigEndian.Uint16(p) & 0x7fff
	sub = binary.BigEndian.Uint16(p[2:])
	return
}

func (p Packet) Handshake() bool {
	return bytes.Equal(p[:len(handshakeHeader)], handshakeHeader[:])
}

func (p Packet) TypeSpecific() uint32 {
	return binary.BigEndian.Uint32(p[4:])
}

func (p Packet) Timestamp() int64 {
	return int64(binary.BigEndian.Uint32(p[8:]) * 1000)
}

func (p Packet) SocketID() uint32 {
	return binary.BigEndian.Uint32(p[12:])
}

func (p Packet) SetControl() {
	p[0] |= controlPacket
}

func (p Packet) SetControlType(tp, sub uint16) {
	p[0] = controlPacket | byte(tp<<1>>9)
	p[1] = byte(tp)

	p[2] = byte(sub >> 8)
	p[3] = byte(sub)
}

func (p Packet) SetTypeSpecific(v uint32) {
	binary.BigEndian.PutUint32(p[4:], v)
}

func (p Packet) SetTimestamp(ts int64) {
	binary.BigEndian.PutUint32(p[8:], uint32(ts/1000))
}

func (p Packet) SetSocketID(id uint32) {
	binary.BigEndian.PutUint32(p[12:], id)
}
