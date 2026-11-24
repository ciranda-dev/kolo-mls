package braid

import (
	"os"
	"testing"
	"time"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// TestMeasureKolo measures, for Kolo groups of n leaves with four admins, the size of a
// key-update Commit, a SettledCommit and the encrypted tree, and the time of a join and of
// applying a settled Commit. KOLO_MLS_LONG=1 adds 10,000 leaves.
func TestMeasureKolo(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("measurement")
	}
	sizes := []int{204, 1024}
	if os.Getenv("KOLO_MLS_LONG") == "1" {
		sizes = append(sizes, 10000)
	}
	for _, n := range sizes {
		w, l := fourAdmins(t, 1)
		a := w.nodes[0]
		var kps [][]byte
		for len(kps)+len(w.live()) < n-1 {
			d := w.device("leaf", nil)
			kps = append(kps, d.dev.KeyPackage(t, d.st))
		}
		w.commit(a, kolomls.CommitOptions{Add: kps}, l.settle)

		j := w.device("joiner", nil)
		kp := j.dev.KeyPackage(t, j.st)
		e := a.m.Epoch()
		welcome, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Add: [][]byte{kp}})
		if err != nil {
			t.Fatal(err)
		}
		addSize := len(a.m.Pending().Commit())
		w.pump(e+1, l.settle, 200)
		settled, _ := w.pins.Get(w.ctx, settle.SettledKey(w.gid, e), 0)
		sealed, _ := w.pins.Get(w.ctx, settle.TreeKey(w.gid, e+1), 0)
		start := time.Now()
		m, err := settle.JoinMember(j.st, welcome, settled, func(gid []byte, epoch uint64, max int) ([]byte, error) {
			return w.pins.Get(w.ctx, settle.TreeKey(gid, epoch), max)
		}, kolomls.JoinOptions{Config: w.config(j)}, w.memberOptions(j))
		join := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		j.m = m
		w.nodes = append(w.nodes, j)

		e = a.m.Epoch()
		if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
			t.Fatal(err)
		}
		commit := a.m.Pending().Commit()
		j.online = false
		w.pump(e+1, l.settle, 200)
		settled, _ = w.pins.Get(w.ctx, settle.SettledKey(w.gid, e), 0)
		start = time.Now()
		if _, err := j.m.ApplySettled(settled, commit); err != nil {
			t.Fatal(err)
		}
		apply := time.Since(start)
		j.online = true
		w.check()
		if j.m.Tree().Members() == nil || len(j.m.Tree().Members()) != n {
			t.Fatalf("%d leaves, want %d", len(j.m.Tree().Members()), n)
		}
		sc, err := settle.DecodeSettled(settled, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%d leaves, added in one Commit (the costliest tree for a path): key-update Commit %d B, one-Add Commit %d B, SettledCommit %d B (%d signatures), encrypted tree %d B, join %v, apply a settled Commit %v",
			n, len(commit), addSize, len(settled), len(sc.Shares), len(sealed), join.Round(time.Millisecond), apply.Round(time.Microsecond))
	}
}
