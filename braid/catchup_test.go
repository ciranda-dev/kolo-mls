package braid

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// archive has n encrypt data and keeps the message on pins alone.
func (w *world) archive(n *node, data string) []byte {
	w.t.Helper()
	msg, err := n.m.Encrypt([]byte(data), nil)
	if err != nil {
		w.t.Fatalf("%s Encrypt: %v", n.name, err)
	}
	if err := w.pins.Put(w.ctx, settle.ArchiveKey(w.gid, n.m.Epoch(), msg), msg); err != nil {
		w.t.Fatal(err)
	}
	return msg
}

// away takes a member offline, has every other live device send k messages
// in one epoch and commits; it returns the member, the epoch and the count.
func awayForEpoch(w *world, l *memLog, k int) (*node, uint64, int) {
	away := w.memberNodes()[0]
	away.online = false
	want := 0
	for _, n := range w.live() {
		for i := range k {
			w.send(n, fmt.Sprintf("%s %d", n.name, i))
			want++
		}
	}
	e := w.admins()[0].m.Epoch()
	w.commit(w.admins()[0], kolomls.CommitOptions{}, l.settle)
	away.online = true
	return away, e, want
}

// checkOrder checks that rs holds want messages and that each sender's come
// in the order it sent them.
func checkOrder(t *testing.T, rs []*kolomls.Result, want int) {
	t.Helper()
	if len(rs) != want {
		t.Fatalf("read %d of %d archived messages", len(rs), want)
	}
	next := map[uint32]int{}
	for _, r := range rs {
		var name string
		var i int
		if _, err := fmt.Sscanf(string(r.Application), "%s %d", &name, &i); err != nil || i != next[r.Sender] {
			t.Fatalf("leaf %d: %q after %d messages", r.Sender, r.Application, next[r.Sender])
		}
		next[r.Sender]++
	}
}

// TestCatchUpOrder: a member away for an epoch reads every archived message
// of each sender, in the order sent, however many a sender sent: the keys
// sort by hash, and a receiver keeps only a window of generations per sender.
func TestCatchUpOrder(t *testing.T) {
	for _, k := range []int{1, 5, 6, 20, 200} {
		w, l := memGroup(t, 3)
		away, e, want := awayForEpoch(w, l, k)
		rs, err := away.m.CatchUp(w.ctx, w.pins)
		if err != nil {
			t.Fatalf("%d per sender: %v", k, err)
		}
		checkOrder(t, rs, want)
		if away.m.Epoch() != e+1 {
			t.Fatalf("epoch %d", away.m.Epoch())
		}
		w.check()
	}
}

// TestCatchUpOrderLargeGroup: the same in a group of 1,024 leaves.
func TestCatchUpOrderLargeGroup(t *testing.T) {
	if testing.Short() {
		t.Skip("1,024 leaves")
	}
	w, l := memGroup(t, 3)
	var kps [][]byte
	for len(kps) < 1020 {
		d := w.device("leaf", nil)
		kps = append(kps, d.dev.KeyPackage(t, d.st))
	}
	w.commit(w.admins()[0], kolomls.CommitOptions{Add: kps}, l.settle)
	away, _, want := awayForEpoch(w, l, 20)
	rs, err := away.m.CatchUp(w.ctx, w.pins)
	if err != nil {
		t.Fatal(err)
	}
	checkOrder(t, rs, want)
}

// TestCatchUpAlreadyRead: archived messages the member read live are not
// reported, and the rest of the epoch is read.
func TestCatchUpAlreadyRead(t *testing.T) {
	w, l := memGroup(t, 2)
	away := w.memberNodes()[0]
	for _, n := range w.live() {
		for i := range 10 {
			w.send(n, fmt.Sprintf("%s %d", n.name, i))
		}
	}
	away.online = false
	for _, n := range w.live() {
		for i := 10; i < 20; i++ {
			w.send(n, fmt.Sprintf("%s %d", n.name, i))
		}
	}
	w.commit(w.admins()[0], kolomls.CommitOptions{}, l.settle)
	away.online = true
	rs, err := away.m.CatchUp(w.ctx, w.pins)
	if err != nil || len(rs) != 20 {
		t.Fatalf("%d read: %v", len(rs), err)
	}
}

// TestCatchUpReportsUnreadable: every archived value that is not read is
// counted in ErrCatchUp, the readable ones are read and the epoch applied;
// handshakes are not counted.
func TestCatchUpReportsUnreadable(t *testing.T) {
	w, l := memGroup(t, 2)
	away := w.memberNodes()[0]
	away.online = false
	var msgs [][]byte
	for _, n := range w.live() {
		for i := range 3 {
			msgs = append(msgs, w.send(n, fmt.Sprintf("%s %d", n.name, i)))
		}
	}
	e := w.admins()[0].m.Epoch()
	// A message that is not archived, so no valid twin is read first.
	twin, err := w.admins()[0].m.Encrypt([]byte("unarchived"), nil)
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func(*message.PrivateMessage)) []byte {
		m, err := message.UnmarshalMLSMessage(twin)
		if err != nil {
			t.Fatal(err)
		}
		f(m.Private)
		b, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	unreadable := [][]byte{
		[]byte("not an MLS message"),
		edit(func(p *message.PrivateMessage) { p.Ciphertext[len(p.Ciphertext)-1] ^= 1 }),
		edit(func(p *message.PrivateMessage) { p.EncryptedSenderData[0] ^= 1 }),
		edit(func(p *message.PrivateMessage) { p.Epoch++ }),
		edit(func(p *message.PrivateMessage) { p.GroupID = append([]byte{9}, p.GroupID...) }),
	}
	handshake := edit(func(p *message.PrivateMessage) { p.ContentType = message.ContentProposal })
	for _, b := range append(unreadable, handshake) {
		if err := w.pins.Put(w.ctx, settle.ArchiveKey(w.gid, e, b), b); err != nil {
			t.Fatal(err)
		}
	}
	w.commit(w.admins()[0], kolomls.CommitOptions{}, l.settle)
	away.online = true
	rs, err := away.m.CatchUp(w.ctx, w.pins)
	if !errors.Is(err, settle.ErrCatchUp) || !strings.Contains(err.Error(), fmt.Sprintf("%d archived messages", len(unreadable))) {
		t.Fatalf("%v", err)
	}
	if len(rs) != len(msgs) || away.m.Epoch() != e+1 {
		t.Fatalf("%d of %d read, epoch %d", len(rs), len(msgs), away.m.Epoch())
	}
}

// pagePins records the size of every List and calls sample with its start
// key at each List and at every sampleEvery-th Get; with ignore set it lists
// from the start whatever the start key.
type pagePins struct {
	settle.Pins
	lists  []int
	ignore bool
	sample func(after string)
	gets   int
}

const sampleEvery = 4000

func (p *pagePins) Get(ctx context.Context, k string, max int) ([]byte, error) {
	if p.gets++; p.sample != nil && p.gets%sampleEvery == 0 {
		p.sample("get")
	}
	return p.Pins.Get(ctx, k, max)
}

func (p *pagePins) List(ctx context.Context, prefix, after string, max int) ([]string, error) {
	p.lists = append(p.lists, max)
	if p.sample != nil {
		p.sample(after)
	}
	if p.ignore {
		after = ""
	}
	return p.Pins.List(ctx, prefix, after, max)
}

// TestCatchUpPages: an epoch with more messages than a pass holds is read in
// passes of that size, none skipped.
func TestCatchUpPages(t *testing.T) {
	w, l := memGroup(t, 3)
	away, e, want := awayForEpoch(w, l, 20)
	const n = 7
	limit := n * ((len(settle.ArchivePrefix(w.gid, e)) + 64 + 16 + 2*40) * 5 / 4)
	o := w.memberOptions(away)
	o.MaxCatchUpBytes = limit
	away.m.Close()
	var err error
	if away.m, err = settle.OpenMember(away.st, w.gid, w.config(away), o); err != nil {
		t.Fatal(err)
	}
	p := &pagePins{Pins: w.pins}
	rs, err := away.m.CatchUp(w.ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	checkOrder(t, rs, want)
	for _, m := range p.lists {
		if m != n {
			t.Fatalf("page of %d keys, want %d", m, n)
		}
	}
	if len(p.lists) < 2*(want/n) {
		t.Fatalf("%d lists for %d messages", len(p.lists), want)
	}
}

// TestCatchUpListingLoops: pins that list the same keys again, instead of
// the ones after the last, end the read with ErrCatchUp and the epoch is
// still applied.
func TestCatchUpListingLoops(t *testing.T) {
	w, l := memGroup(t, 2)
	away, e, _ := awayForEpoch(w, l, 3)
	rs, err := away.m.CatchUp(w.ctx, &pagePins{Pins: w.pins, ignore: true})
	if !errors.Is(err, settle.ErrCatchUp) || len(rs) != 0 || away.m.Epoch() != e+1 {
		t.Fatalf("%d read, epoch %d: %v", len(rs), away.m.Epoch(), err)
	}
}

// TestCatchUpLargeEpoch: 200,000 messages archived in one epoch are read in
// full with the default bound, and what a pass holds on the heap, measured as
// the live bytes after a collection, at every page and every few thousand
// reads, against the live bytes before the pass, stays within MaxCatchUpBytes.
// The Results returned are not counted. -short skips it; run it with
// go test -run TestCatchUpLargeEpoch -v ./braid
func TestCatchUpLargeEpoch(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("200,000 messages")
	}
	const total = 200000
	w, l := memGroup(t, 2)
	away := w.memberNodes()[0]
	away.online = false
	senders := w.live()
	for i := range total {
		w.archive(senders[i%len(senders)], fmt.Sprintf("%d", i))
	}
	e := w.admins()[0].m.Epoch()
	w.commit(w.admins()[0], kolomls.CommitOptions{}, l.settle)
	away.online = true

	defer debug.SetGCPercent(debug.SetGCPercent(10))
	live := func() int64 {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return int64(ms.HeapAlloc)
	}
	var base, held int64
	p := &pagePins{Pins: w.pins, sample: func(after string) {
		if after == "" {
			base = live()
		} else {
			held = max(held, live()-base)
		}
	}}
	rs, err := away.m.CatchUp(w.ctx, p)
	if err != nil || len(rs) != total || away.m.Epoch() != e+1 {
		t.Fatalf("%d of %d read at epoch %d: %v", len(rs), total, away.m.Epoch(), err)
	}
	t.Logf("%d messages, %d lists; a pass held up to %d bytes on the heap, bound %d", total, len(p.lists), held, settle.DefaultMaxCatchUpBytes)
	if held > settle.DefaultMaxCatchUpBytes {
		t.Fatalf("a pass held %d bytes, more than the %d bound", held, settle.DefaultMaxCatchUpBytes)
	}
}
