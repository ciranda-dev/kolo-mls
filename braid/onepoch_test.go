package braid

import (
	"bytes"
	"errors"
	"testing"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// awayThreeEpochs has a member miss three Commits and reopens it with the hook.
func awayThreeEpochs(t *testing.T, onEpoch func(*settle.Member) error) (*world, *node, uint64) {
	t.Helper()
	w, l := memGroup(t, 2)
	away := w.memberNodes()[0]
	away.online = false
	e := away.m.Epoch()
	for range 3 {
		w.commit(w.admins()[0], kolomls.CommitOptions{}, l.settle)
	}
	away.online = true
	away.m.Close()
	o := w.memberOptions(away)
	o.OnEpoch = onEpoch
	m, err := settle.OpenMember(away.st, w.gid, w.config(away), o)
	if err != nil {
		t.Fatal(err)
	}
	away.m = m
	return w, away, e
}

// TestCatchUpOnEpoch: the hook sees each of the three epochs CatchUp applies,
// and the key it exports differs in each and matches the key of a member that
// was in that epoch live.
func TestCatchUpOnEpoch(t *testing.T) {
	var epochs []uint64
	var keys [][]byte
	w, away, e := awayThreeEpochs(t, func(m *settle.Member) error {
		k, err := m.Export("test", nil, 32)
		epochs = append(epochs, m.Epoch())
		keys = append(keys, k)
		return err
	})
	if _, err := away.m.CatchUp(w.ctx, w.pins); err != nil {
		t.Fatal(err)
	}
	if len(epochs) != 3 || epochs[0] != e+1 || epochs[1] != e+2 || epochs[2] != e+3 {
		t.Fatalf("hook saw epochs %v after %d", epochs, e)
	}
	if bytes.Equal(keys[0], keys[1]) || bytes.Equal(keys[1], keys[2]) || bytes.Equal(keys[0], keys[2]) {
		t.Fatal("the three epochs exported the same key")
	}
	last, err := w.admins()[0].m.Export("test", nil, 32)
	if err != nil || !bytes.Equal(last, keys[2]) {
		t.Fatalf("last key differs from the admin's: %v", err)
	}
}

// TestCatchUpOnEpochError: an error of the hook stops CatchUp after that
// epoch and is returned wrapped; the next CatchUp goes on from there.
func TestCatchUpOnEpochError(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	w, away, e := awayThreeEpochs(t, func(*settle.Member) error {
		calls++
		if calls == 2 {
			return boom
		}
		return nil
	})
	_, err := away.m.CatchUp(w.ctx, w.pins)
	if !errors.Is(err, boom) || calls != 2 || away.m.Epoch() != e+2 {
		t.Fatalf("calls %d, epoch %d (from %d): %v", calls, away.m.Epoch(), e, err)
	}
	if _, err := away.m.CatchUp(w.ctx, w.pins); err != nil || calls != 3 || away.m.Epoch() != e+3 {
		t.Fatalf("calls %d, epoch %d: %v", calls, away.m.Epoch(), err)
	}
}
