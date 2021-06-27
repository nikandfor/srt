package wire

import "encoding/binary"

type (
	Ack []byte
)

func (p Ack) MinSize() int {
	return headerSize + 4
}

func (p Ack) AckNum() uint32 {
	return binary.BigEndian.Uint32(p[4:])
}

func (p Ack) SetAckNum(n uint32) {
	binary.BigEndian.PutUint32(p[headerSize:], n)
}
