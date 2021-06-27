package srt

import (
	"context"
	"net"

	"github.com/nikandfor/errors"
)

type (
	Dialer struct {
		net.Dialer

		Version    int
		Encryption int
		//	Extension  int

		MaxTransmissonUnit int
		MaxFlowWindow      int
	}
)

func Dial(netw, addr string) (*Conn, error) {
	var d Dialer

	return d.DialContext(context.Background(), netw, addr)
}

func NewDialer() *Dialer {
	return &Dialer{
		Version:            5,
		MaxTransmissonUnit: 1500,
		MaxFlowWindow:      100,
	}
}

func (d *Dialer) DialContext(ctx context.Context, netw, addr string) (c *Conn, err error) {
	conn, err := d.Dialer.Dial(netw, addr)
	if err != nil {
		return nil, errors.Wrap(err, "net dial")
	}

	p, ok := conn.(net.PacketConn)
	if !ok {
		_ = conn.Close()

		return nil, errors.New("not a packet connection")
	}

	c = &Conn{
		p: p,
	}

	return c, nil
}
