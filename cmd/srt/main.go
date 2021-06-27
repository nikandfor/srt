package main

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/nikandfor/cli"
	"github.com/nikandfor/errors"
	"github.com/nikandfor/srt"
	"github.com/nikandfor/tlog"
	"github.com/nikandfor/tlog/ext/tlflag"
)

var (
	version = "dev"
	commit  = "HEAD"
	date    = ""

//	labels = tlog.Labels{"service=srt", "_execmd5", "version=" + version, "commit=" + commit}
)

func main() {
	cli.App = cli.Command{
		Name:   "srt tool",
		Before: before,
		Flags: []*cli.Flag{
			//	cli.NewFlag("labels", strings.Join(labels, ","), "labels"),
			cli.NewFlag("log", "stderr+dm", "log destination"),
			cli.NewFlag("v", "", "log verbosity"),
			cli.NewFlag("debug", "", "debug http address"),
			cli.HelpFlag,
			cli.FlagfileFlag,
		},
		Commands: []*cli.Command{{
			Name: "file",
			Commands: []*cli.Command{{
				Name:   "send",
				Action: filesend,
				Flags: []*cli.Flag{
					cli.NewFlag("addr", "localhost:8090", "addr"),
					cli.NewFlag("file", "go.mod", "file name"),
				},
			}, {
				Name:   "recv",
				Action: filerecv,
				Flags: []*cli.Flag{
					cli.NewFlag("addr", "localhost:8090", "addr"),
					cli.NewFlag("file", "/dev/tty", "file name"),
				},
			}},
		}, {
			Name:   "proxy",
			Action: proxy,
			Flags: []*cli.Flag{
				cli.NewFlag("addr", ":8099", "addr"),
				cli.NewFlag("dst-addr", ":8090", "addr"),
			},
		}},
	}

	cli.RunAndExit(os.Args)
}

func before(c *cli.Command) (err error) {
	w, err := tlflag.OpenWriter(c.String("log"))
	if err != nil {
		return errors.Wrap(err, "open log")
	}

	tlog.DefaultLogger = tlog.New(w)

	tlog.SetFilter(c.String("v"))

	//	ls := tlog.FillLabelsWithDefaults(strings.Split(c.String("labels"), ",")...)
	//	tlog.SetLabels(ls)

	if q := c.String("debug"); q != "" {
		l, err := net.Listen("tcp", q)
		if err != nil {
			return errors.Wrap(err, "listen debug")
		}

		tlog.Printw("listen debug", "addr", l.Addr())

		go func() {
			err := http.Serve(l, nil)
			if err != nil {
				tlog.Printw("serve debug", "err", err, "", tlog.Fatal)
				os.Exit(1)
			}
		}()
	}

	return nil
}

func filerecv(c *cli.Command) (err error) {
	p, err := net.ListenPacket("udp", c.String("addr"))
	if err != nil {
		return errors.Wrap(err, "listen udp")
	}

	defer func() {
		e := p.Close()
		if err == nil {
			err = errors.Wrap(e, "close udp")
		}
	}()

	l := srt.New(p)
	defer func() {
		e := l.Close()
		if err == nil {
			err = errors.Wrap(e, "close listener")
		}
	}()

	tlog.Printw("listening", "addr", l.Addr())

	s, err := l.Accept()
	if err != nil {
		return errors.Wrap(err, "accept")
	}

	defer func() {
		e := s.Close()
		if err == nil {
			err = errors.Wrap(e, "close")
		}
	}()

	tlog.Printw("accepted", "addr", s.RemoteAddr())

	buf := make([]byte, 2000)

	for {
		n, err := s.Read(buf)
		if err != nil {
			return errors.Wrap(err, "read")
		}

		_ = n
	}

	return nil
}

func filesend(c *cli.Command) (err error) {
	addr, err := net.ResolveUDPAddr("udp", c.String("addr"))
	if err != nil {
		return errors.Wrap(err, "resolve addr")
	}

	f, err := os.Open(c.String("file"))
	if err != nil {
		return errors.Wrap(err, "open file")
	}
	defer func() {
		e := f.Close()
		if err == nil {
			err = errors.Wrap(e, "close file")
		}
	}()

	p, err := net.ListenPacket("udp", "")
	if err != nil {
		return errors.Wrap(err, "dial udp")
	}

	defer func() {
		e := p.Close()
		if err == nil {
			err = errors.Wrap(e, "close udp")
		}
	}()

	l := srt.New(p)

	tlog.Printw("connecting", "addr", addr)

	s, err := l.Connect(context.Background(), addr)
	if err != nil {
		return errors.Wrap(err, "connect")
	}

	tlog.Printw("connected", "addr", s.RemoteAddr())

	defer func() {
		e := s.Close()
		if err == nil {
			err = errors.Wrap(e, "close")
		}
	}()

	buf := make([]byte, 10_000)

	for {
		n, err := f.Read(buf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.Wrap(err, "read file")
		}

		_, err = s.Write(buf[:n])
		if err != nil {
			return errors.Wrap(err, "write")
		}
	}

	return nil
}

func proxy(c *cli.Command) (err error) {
	dst, err := net.ResolveUDPAddr("udp", c.String("dst-addr"))
	if err != nil {
		return errors.Wrap(err, "resolve dst")
	}

	p, err := net.ListenPacket("udp", c.String("addr"))
	if err != nil {
		return errors.Wrap(err, "listen udp")
	}

	tlog.Printw("proxy listening", "addr", p.LocalAddr(), "dst", dst)

	defer func() {
		e := p.Close()
		if err == nil {
			err = errors.Wrap(e, "close udp")
		}
	}()

	var clAddr net.Addr

	buf := make([]byte, 2000)
	for {
		n, addr, err := p.ReadFrom(buf)
		if err != nil {
			return errors.Wrap(err, "read")
		}

		if clAddr == nil {
			clAddr = addr
		}

		var to net.Addr
		var dir string

		if clAddr.String() == addr.String() {
			to = dst
			dir = "<--"
		} else {
			to = clAddr
			dir = "-->"
		}

		tlog.Printf("packet %v %s %v\n%s", to, dir, addr, hex.Dump(buf[:n]))

		_, err = p.WriteTo(buf[:n], to)
		if err != nil {
			return errors.Wrap(err, "write: %v", dst)
		}
	}
}
