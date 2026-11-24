package braid

import (
	"os"
	"slices"
	"strconv"
	"testing"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// treeEpochs returns the epochs whose encrypted tree pins hold.
func (w *world) treeEpochs() []uint64 {
	w.t.Helper()
	prefix := settle.TreeKey(w.gid, 0)
	prefix = prefix[:len(prefix)-1]
	keys, err := w.pins.List(w.ctx, prefix, "", 0)
	if err != nil {
		w.t.Fatal(err)
	}
	var out []uint64
	for _, k := range keys {
		e, err := strconv.ParseUint(k[len(prefix):], 10, 64)
		if err != nil {
			w.t.Fatal(err)
		}
		out = append(out, e)
	}
	slices.Sort(out)
	return out
}

// welcomeOf has admin add a new device in a Commit and returns the device,
// its Welcome and the SettledCommit, without joining it.
func welcomeOf(w *world, l *memLog, admin *node, name string) (*node, []byte, []byte, uint64) {
	w.t.Helper()
	j := w.device(name, nil)
	e := admin.m.Epoch()
	welcome, err := admin.admin.Commit(w.ctx, kolomls.CommitOptions{Add: [][]byte{j.dev.KeyPackage(w.t, j.st)}})
	if err != nil {
		w.t.Fatal(err)
	}
	w.pump(e+1, l.settle, 200)
	return j, welcome, w.mustGet(settle.SettledKey(w.gid, e)), e
}

// joinLate joins j with a Welcome made epochs ago and catches up.
func joinLate(w *world, j *node, welcome, settled []byte) {
	w.t.Helper()
	m, err := settle.JoinMember(j.st, welcome, settled, func(gid []byte, epoch uint64, max int) ([]byte, error) {
		return w.pins.Get(w.ctx, settle.TreeKey(gid, epoch), max)
	}, kolomls.JoinOptions{Config: w.config(j)}, w.memberOptions(j))
	if err != nil {
		w.t.Fatalf("%s joining: %v", j.name, err)
	}
	j.m = m
	if _, err := m.CatchUp(w.ctx, w.pins); err != nil {
		w.t.Fatal(err)
	}
	w.nodes = append(w.nodes, j)
}

// treeRetention runs epochs epochs after two Welcomes were made and not
// used, in a group of four admins and leaves leaves.
func treeRetention(t *testing.T, leaves, epochs int) {
	w, l := fourAdmins(t, 1)
	admin := w.nodes[0]
	if leaves > 0 {
		var kps [][]byte
		for len(kps)+len(w.live()) < leaves-1 {
			d := w.device("leaf", nil)
			kps = append(kps, d.dev.KeyPackage(t, d.st))
		}
		e := admin.m.Epoch()
		w.commit(admin, kolomls.CommitOptions{Add: kps}, l.settle)
		if err := admin.admin.ReleaseWelcome(w.ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	j1, welcome1, settled1, e1 := welcomeOf(w, l, admin, "late1")
	for range epochs / 2 {
		w.commit(w.nodes[1], kolomls.CommitOptions{}, l.settle)
	}
	j2, welcome2, settled2, e2 := welcomeOf(w, l, w.nodes[2], "late2")
	for range epochs / 2 {
		w.commit(admin, kolomls.CommitOptions{}, l.settle)
	}
	latest := admin.m.Epoch()
	if got, want := w.treeEpochs(), []uint64{e1 + 1, e2 + 1, latest}; !slices.Equal(got, want) {
		t.Fatalf("trees of epochs %v on pins, want %v", got, want)
	}
	joinLate(w, j1, welcome1, settled1)
	joinLate(w, j2, welcome2, settled2)
	w.check()
	if err := admin.admin.ReleaseWelcome(w.ctx, e1); err != nil {
		t.Fatal(err)
	}
	if got, want := w.treeEpochs(), []uint64{e2 + 1, latest}; !slices.Equal(got, want) {
		t.Fatalf("after the first release: trees of epochs %v, want %v", got, want)
	}
	if err := w.nodes[2].admin.ReleaseWelcome(w.ctx, e2); err != nil {
		t.Fatal(err)
	}
	if got, want := w.treeEpochs(), []uint64{latest}; !slices.Equal(got, want) {
		t.Fatalf("after the second release: trees of epochs %v, want %v", got, want)
	}
	w.commit(admin, kolomls.CommitOptions{}, l.settle)
	if got, want := w.treeEpochs(), []uint64{latest + 1}; !slices.Equal(got, want) {
		t.Fatalf("after one more epoch: trees of epochs %v, want %v", got, want)
	}
}

// TestTreeRetention: pins hold the latest tree and the trees that unused
// Welcomes name, whichever admin made the Welcome or applied an epoch; a
// joiner of a Welcome made many epochs ago still joins, and its tree leaves
// when the Welcome is released.
func TestTreeRetention(t *testing.T) {
	treeRetention(t, 0, 100)
}

// TestTreeRetentionLarge runs the same at the number of leaves in
// KOLO_MLS_LEAVES, over 100 epochs: KOLO_MLS_LEAVES=30000 go test -run
// TestTreeRetentionLarge -timeout 1h -v ./braid
func TestTreeRetentionLarge(t *testing.T) {
	n, err := strconv.Atoi(os.Getenv("KOLO_MLS_LEAVES"))
	if err != nil || n < 1 || testing.Short() || raceEnabled {
		t.Skip("set KOLO_MLS_LEAVES")
	}
	treeRetention(t, n, 100)
}
