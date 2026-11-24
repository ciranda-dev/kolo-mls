package secrettree

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
)

// FuzzOps runs arbitrary Next, Key and Clear sequences under arbitrary
// bounds: no panic, every outcome as the model says, every key as the
// oracle derives it, and the same transcript on a second run.
func FuzzOps(f *testing.F) {
	f.Add([]byte{3, 5, 10, 3, 0, 0, 5, 4, 0, 0, 3, 5, 0, 0, 1, 3, 1, 1, 9})
	f.Add([]byte{0, 0, 0, 3, 0, 0, 0x40, 0, 0, 1, 0})
	f.Add([]byte{6, 1, 1, 0, 2, 1, 0, 0, 2, 1, 0, 3, 2, 1, 0, 7, 0, 0, 0, 3, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if !bytes.Equal(run(t, b), run(t, b)) {
			t.Fatal("two runs differ")
		}
	})
}

// FuzzNew feeds arbitrary secrets, leaf counts and bounds to New: no panic,
// only ErrInvalidArgument, and an accepted tree serves its first and last leaf.
func FuzzNew(f *testing.F) {
	f.Add(make([]byte, 32), uint32(1), uint32(0), uint32(0))
	f.Add([]byte{}, uint32(0), uint32(1), uint32(1))
	f.Add(make([]byte, 33), uint32(1<<31), uint32(1<<31), uint32(7))
	f.Fuzz(func(t *testing.T, s []byte, n, d, tol uint32) {
		tr, err := New(s, n, Options{MaxForwardDistance: d, OutOfOrderTolerance: tol})
		if err != nil {
			if !errors.Is(err, errs.ErrInvalidArgument) {
				t.Fatalf("New: %v", err)
			}
			return
		}
		ls := []uint32{0, n}
		if n > 1 {
			ls = append(ls, n-1)
		}
		for _, l := range ls {
			_, _, err := tr.Key(l, Application, min(d, 3))
			if (err != nil) != (l == n) {
				t.Fatalf("Key(%d) of %d leaves: %v", l, n, err)
			}
		}
		if _, _, err := tr.Key(0, Handshake, ^uint32(0)); err == nil {
			t.Fatal("hostile generation accepted")
		}
		tr.Clear()
	})
}
