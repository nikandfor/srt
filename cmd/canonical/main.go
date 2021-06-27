package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/haivision/srtgo"
	"github.com/nikandfor/cli"
	"github.com/nikandfor/errors"
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
		Name:   "canonical srt test tool",
		Before: before,
		After:  after,
		Flags: []*cli.Flag{
			cli.NewFlag("addr", ":8090", "addr"),

			//	cli.NewFlag("labels", strings.Join(labels, ","), "labels"),
			cli.NewFlag("log", "stderr+dm", "log destination"),
			cli.NewFlag("v", "", "log verbosity"),
			cli.NewFlag("debug", "", "debug http address"),
			cli.HelpFlag,
			cli.FlagfileFlag,
		},
		Commands: []*cli.Command{{
			Name: "file",
			Flags: []*cli.Flag{
				cli.NewFlag("file", "tmpfile", "file name"),
			},
			Commands: []*cli.Command{{
				Name:   "send",
				Action: filesend,
			}, {
				Name:   "recv",
				Action: filerecv,
			}},
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

	srtgo.InitSRT()

	srtgo.SrtSetLogHandler(func(lvl srtgo.SrtLogLevel, file string, line int, area, msg string) {
		msg = strings.TrimSpace(msg)

		tlog.Printw(msg, "area", area, "lvl", lvl)
	})

	srtgo.SrtSetLogLevel(srtgo.SrtLogLevelDebug)

	return nil
}

func after(c *cli.Command) (err error) {
	srtgo.CleanupSRT()

	return nil
}

func filesend(c *cli.Command) (err error) {
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

	host, sport, err := net.SplitHostPort(c.String("addr"))
	if err != nil {
		return errors.Wrap(err, "parse addr")
	}

	if host == "" {
		host = "0.0.0.0"
	}

	port, err := strconv.Atoi(sport)
	if err != nil {
		return errors.Wrap(err, "parse port")
	}

	s := srtgo.NewSrtSocket(host, uint16(port), map[string]string{
		"transtype": "file",
	})

	defer s.Close()

	err = s.Connect()
	if err != nil {
		return errors.Wrap(err, "connect")
	}

	buf := make([]byte, 10_000)

	for {
		n, err := f.Read(buf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.Wrap(err, "read file")
		}

		_, err = s.Write(buf[:n], 10000)
		if err != nil {
			return errors.Wrap(err, "write")
		}
	}

	return nil
}

func filerecv(c *cli.Command) (err error) {
	host, sport, err := net.SplitHostPort(c.String("addr"))
	if err != nil {
		return errors.Wrap(err, "parse addr")
	}

	if host == "" {
		host = "0.0.0.0"
	}

	port, err := strconv.Atoi(sport)
	if err != nil {
		return errors.Wrap(err, "parse port")
	}

	l := srtgo.NewSrtSocket(host, uint16(port), map[string]string{
		"transtype": "file",
	})

	defer l.Close()

	tlog.Printw("listening", "addr", c.String("addr"))

	err = l.Listen(1)
	if err != nil {
		return errors.Wrap(err, "listen")
	}

	s, addr, err := l.Accept()
	defer s.Close()
	if err != nil {
		return errors.Wrap(err, "accept")
	}

	err = serveFileRecvConn(c, s, addr)
	if err != nil {
		return errors.Wrap(err, "conn")
	}

	return nil
}

func serveFileRecvConn(c *cli.Command, s *srtgo.SrtSocket, addr *net.UDPAddr) (err error) {
	tr := tlog.Start("accept_conn", "addr", addr)
	defer func() {
		tr.Finish("err", err)
	}()

	f, err := os.Create(c.String("file"))
	if err != nil {
		return errors.Wrap(err, "create file")
	}
	defer func() {
		e := f.Close()
		if err == nil {
			err = errors.Wrap(e, "close file")
		}
	}()

	w := bufio.NewWriter(f)
	defer func() {
		e := w.Flush()
		if err == nil {
			err = errors.Wrap(e, "flush")
		}
	}()

	buf := make([]byte, 2000)
	for {
		n, err := s.Read(buf, 10000)
		if err != nil {
			return errors.Wrap(err, "read")
		}

		tlog.Printw("read", "data", buf[:n])

		if n == 0 {
			break
		}

		_, err = w.Write(buf[:n])
		if err != nil {
			return errors.Wrap(err, "write file")
		}
	}

	return nil
}
