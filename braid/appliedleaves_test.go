package braid

import (
	"bytes"
	"testing"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// hasDevice reports whether a leaf in ls names device and carries its signature key.
func hasDevice(t *testing.T, ls []*kolomls.LeafNode, device [32]byte) bool {
	t.Helper()
	for _, l := range ls {
		c, err := cred.Decode(l.Credential)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(c.Device(), device[:]) && len(l.SignatureKey) == 32 {
			return true
		}
	}
	return false
}

// TestAppliedLeaves: a device added and removed while a member is away is
// never in that member's tree, yet the member reads its credential in OnEpoch;
// the members that were live read it right after ApplySettled.
func TestAppliedLeaves(t *testing.T) {
	w, l := memGroup(t, 2)
	admin, other, away := w.admins()[0], w.memberNodes()[1], w.memberNodes()[0]
	away.online = false
	away.m.Close()

	var seen [][]*kolomls.LeafNode
	o := w.memberOptions(away)
	o.OnEpoch = func(m *settle.Member) error {
		seen = append(seen, m.AppliedLeaves())
		return nil
	}
	m, err := settle.OpenMember(away.st, w.gid, w.config(away), o)
	if err != nil {
		t.Fatal(err)
	}
	away.m = m

	x := w.device("x", nil)
	w.join(admin, l.settle, x)
	for _, n := range []*node{admin, other} {
		if !hasDevice(t, n.m.AppliedLeaves(), x.dev.Key()) {
			t.Fatalf("%s: the added device is not in AppliedLeaves", n.name)
		}
	}
	if x.m.AppliedLeaves() != nil {
		t.Fatal("a joiner has applied no Commit")
	}
	w.commit(admin, kolomls.CommitOptions{Remove: []uint32{x.m.OwnLeaf()}}, l.settle)
	if hasDevice(t, admin.m.AppliedLeaves(), x.dev.Key()) {
		t.Fatal("the removal Commit adds the removed device")
	}

	away.online = true
	if _, err := away.m.CatchUp(w.ctx, w.pins); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || !hasDevice(t, seen[0], x.dev.Key()) || hasDevice(t, seen[1], x.dev.Key()) {
		t.Fatalf("OnEpoch saw %d epochs", len(seen))
	}
	for _, leaf := range away.m.Tree().Members() {
		if hasDevice(t, []*kolomls.LeafNode{away.m.Tree().Leaf(leaf)}, x.dev.Key()) {
			t.Fatal("the removed device is still in the tree")
		}
	}
	got := away.m.AppliedLeaves()
	if len(got) == 0 {
		t.Fatal("no leaves")
	}
	got[0].SignatureKey[0] ^= 1
	if bytes.Equal(got[0].SignatureKey, away.m.AppliedLeaves()[0].SignatureKey) {
		t.Fatal("AppliedLeaves shares its bytes")
	}
}
