package kolomls

import (
	"bytes"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// TestStagedExtensions: a member that a Commit removes still sees the
// GroupContext extensions the Commit sets.
func TestStagedExtensions(t *testing.T) {
	w := newWorld(t, 3)
	exts := []tls.Extension{{Type: message.ExtExternalSenders, Data: []byte{0}}}
	msg := commitBy(t, w, 0, CommitOptions{Remove: []uint32{2}, SetExtensions: true, Extensions: exts})
	r, err := w.members[2].g.Process(msg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Commit.Discard()
	got := r.Commit.Extensions()
	if !r.Commit.RemovesSelf() || r.Commit.GroupContext() != nil || len(got) != 1 || got[0].Type != message.ExtExternalSenders {
		t.Fatalf("extensions %+v", got)
	}
	got[0].Data[0] = 9
	if r.Commit.Extensions()[0].Data[0] != 0 {
		t.Fatal("Extensions shares its bytes")
	}
}

// TestPendingLeaves: the leaves a pending Commit adds or replaces, also once
// it is read back from the Store.
func TestPendingLeaves(t *testing.T) {
	w := newWorld(t, 2)
	g := w.members[0].g
	if g.PendingLeaves() != nil {
		t.Fatal("leaves without a pending Commit")
	}
	j := newClient(t)
	if _, err := g.Commit(CommitOptions{Add: [][]byte{j.keyPackage(t)}}); err != nil {
		t.Fatal(err)
	}
	check := func(g *Group) {
		t.Helper()
		ls := g.PendingLeaves()
		// The committer's own leaf (its path) and the added one.
		if len(ls) != 2 || !bytes.Equal(ls[1].Credential.Identity, j.id) {
			t.Fatalf("%d leaves", len(ls))
		}
	}
	check(g)
	g.Close()
	again, err := Open(w.members[0].st, g.GroupID(), w.cfg)
	if err != nil {
		t.Fatal(err)
	}
	check(again)
}
