package settle

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
)

func FuzzRoles(f *testing.F) {
	f.Add((&Roles{Braid: key(9), Quorum: TwoThirds, Admins: keys(1, 2, 3), Settlers: keys(1, 3)}).Encode())
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRoles(b, Limits{MaxAdmins: 8, MaxSettlers: 4})
		if err != nil {
			if !errors.Is(err, ErrRoles) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		if !bytes.Equal(r.Encode(), b) || r.Q() > len(r.Settlers) || r.RejectQuorum() < 1 {
			t.Fatal("decode then encode differs, or a quorum out of range")
		}
	})
}

func FuzzSettled(f *testing.F) {
	s := &Settled{TBS: *testTBS(), Shares: []Share{{Signer: key(1)}, {Signer: key(2)}}}
	f.Add(s.Encode())
	f.Add(testTBS().Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := DecodeSettled(b, 4); err == nil {
			if !bytes.Equal(s.Encode(), b) {
				t.Fatal("SettledCommit decode then encode differs")
			}
		} else if !errors.Is(err, ErrNotSettled) {
			t.Fatalf("untyped error %v", err)
		}
		if tbs, err := DecodeTBS(b); err == nil {
			if !bytes.Equal(tbs.Encode(), b) {
				t.Fatal("TBS decode then encode differs")
			}
		} else if !errors.Is(err, ErrNotSettled) {
			t.Fatalf("untyped error %v", err)
		}
	})
}

func FuzzEnvelope(f *testing.F) {
	ad, _ := Envelope{}.Wrap(7, []byte("aad"))
	f.Add(ad, uint32(7))
	f.Fuzz(func(t *testing.T, b []byte, gen uint32) {
		aad, err := Envelope{}.Unwrap(gen, b)
		if err != nil {
			if !errors.Is(err, ErrEnvelope) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		again, _ := Envelope{}.Wrap(gen, aad)
		if !bytes.Equal(again, b) {
			t.Fatal("unwrap then wrap differs")
		}
	})
}

func FuzzRecords(f *testing.F) {
	r := &Roles{Braid: key(9), Quorum: Majority, Admins: keys(1), Settlers: keys(1)}
	f.Add(append(make([]byte, 40), r.Encode()...))
	f.Add([]byte{1})
	f.Add(make([]byte, 20))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := parseLast(b, Limits{}); err != nil && !errors.Is(err, errs.ErrMalformed) && !errors.Is(err, ErrRoles) {
			t.Fatalf("untyped error %v", err)
		}
	})
}

func FuzzOpenTree(f *testing.F) {
	export := func(label string, context []byte, n int) ([]byte, error) {
		return bytes.Repeat([]byte{byte(len(label))}, n), nil
	}
	sealed, _ := Seal(export, make([]byte, 32), 3, key(5), []byte("tree"))
	f.Add(sealed)
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := OpenTree(export, make([]byte, 32), 3, b); err != nil && !errors.Is(err, ErrSealedTree) {
			t.Fatalf("untyped error %v", err)
		}
	})
}
