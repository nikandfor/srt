package srt

import (
	"io"
	"sort"

	"github.com/nikandfor/srt/wire"
	"github.com/nikandfor/tlog"
)

type (
	queue struct {
		seq uint32 // prev

		q []wire.DataPacket
	}
)

func (q *queue) insert(p wire.DataPacket) {
	q.q = append(q.q, p)

	if p == nil {
		return
	}

	sort.Slice(q.q, func(i, j int) bool {
		return q.q[i].Seq() < q.q[j].Seq()
	})
}

func (q *queue) ack() (a uint32) {
	a = q.seq

	for _, p := range q.q {
		if a+1 != p.Seq() {
			break
		}

		a++
	}

	return a
}

func (q *queue) read(p []byte) (n int, err error) {
	if len(q.q) == 0 {
		return 0, errWait
	}

	if q.q[0] == nil {
		return 0, io.EOF
	}

	tlog.Printw("queue.read", "seq", tlog.Hex(q.seq), "qlen", len(q.q), "0.seq", tlog.Hex(q.q[0].Seq()), "0.first", q.q[0].First())

	if q.seq+1 != q.q[0].Seq() || !q.q[0].First() {
		return 0, errWait
	}

	seq := q.seq
	msg := q.q[0].Msg()

	end := -1
	for i := 0; i < len(q.q); i++ {
		if seq+1 != q.q[i].Seq() {
			return 0, errWait
		}

		if msg != q.q[i].Msg() {
			break
		}

		if q.q[i].Last() {
			end = i
		}

		seq++
	}

	if end == -1 {
		return 0, errWait
	}

	end++

	for i := 0; i < end; i++ {
		m := copy(p[n:], q.q[i].Data())
		n += m

		if m < len(q.q[i].Data()) {
			return n, ErrShortBuffer
		}
	}

	copy(q.q, q.q[end:])

	q.q = q.q[:len(q.q)-end]

	q.seq += uint32(end)

	return
}
