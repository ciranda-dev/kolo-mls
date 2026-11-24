package braid

import (
	"testing"

	kolomls "github.com/ciranda-dev/kolo-mls"
)

// memGroup builds a group of one admin and n members over a memLog.
func memGroup(t testing.TB, n int) (*world, *memLog) {
	w := newWorld(t)
	l := newLog(1)
	founder := w.device("admin", nil)
	w.create(founder, &memOrder{l: l, me: founder.dev.Key()})
	var joiners []*node
	for i := range n {
		joiners = append(joiners, w.device("member"+string(rune('a'+i)), nil))
	}
	w.join(founder, l.settle, joiners...)
	return w, l
}

func TestBasicFlow(t *testing.T) {
	w, l := memGroup(t, 3)
	for _, n := range w.live() {
		w.send(n, "hello from "+n.name)
	}
	victim := w.nodes[3]
	thief := w.steal(victim)
	admin := w.nodes[0]
	e := admin.m.Epoch()
	if _, err := admin.admin.Commit(w.ctx, kolomls.CommitOptions{Remove: []uint32{victim.m.OwnLeaf()}}); err != nil {
		t.Fatal(err)
	}
	w.pump(e+1, l.settle, 50)
	if !victim.m.Removed() {
		t.Fatal("victim not removed")
	}
	w.check()
	for _, n := range w.live() {
		w.send(n, "after the removal")
	}
	if got := w.decryptsNothing(thief); got != len(w.live()) {
		t.Fatalf("tried %d later messages", got)
	}
}
