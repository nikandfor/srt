package wire

import "encoding/binary"

type (
	DataPacket Packet
)

func (p DataPacket) Seq() uint32 {
	// can ignore F bit since it is = 0 in data packet
	return binary.BigEndian.Uint32(p)
}

func (p DataPacket) Msg() uint32 {
	return binary.BigEndian.Uint32(p[4:]) & 0x3ff_ffff
}

func (p DataPacket) First() bool {
	return p[4]&0b1000_0000 != 0
}

func (p DataPacket) Last() bool {
	return p[4]&0b0100_0000 != 0
}

func (p DataPacket) Single() bool {
	return p[4]&0b1100_0000 != 0
}

func (p DataPacket) Ordered() bool {
	return p[4]&0b0010_0000 != 0
}

func (p DataPacket) Encrypted() bool {
	return p[4]&0b0001_1000 != 0
}

func (p DataPacket) EncOdd() bool {
	return p[4]&0b0001_0000 != 0
}

func (p DataPacket) Retransmitted() bool {
	return p[4]&0b0000_0100 != 0
}

func (p DataPacket) Data() []byte {
	return p[16:]
}

func (p DataPacket) SetSeq(seq uint32) {
	binary.BigEndian.PutUint32(p, seq&0x7fff_ffff)
}

func (p DataPacket) SetFirst(f bool) {
	if f {
		p[4] |= 0b1000_0000
	} else {
		p[4] &^= 0b1000_0000
	}
}

func (p DataPacket) SetLast(f bool) {
	if f {
		p[4] |= 0b0100_0000
	} else {
		p[4] &^= 0b0100_0000
	}
}

func (p DataPacket) SetSingle(f bool) {
	if f {
		p[4] |= 0b1100_0000
	} else {
		p[4] &^= 0b1100_0000
	}
}

func (p DataPacket) SetOrdered(f bool) {
	if f {
		p[4] |= 0b0010_0000
	} else {
		p[4] &^= 0b0010_0000
	}
}

func (p DataPacket) SetEncryption(en, odd bool) {
	p[4] &^= 0b0001_1000

	if !en {
		return
	}

	if odd {
		p[4] |= 0b0001_0000
	} else {
		p[4] |= 0b0000_1000
	}
}

func (p DataPacket) SetRetransmitted(f bool) {
	if f {
		p[4] |= 0b0000_0100
	} else {
		p[4] &^= 0b0000_0100
	}
}
