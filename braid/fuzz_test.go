package braid

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/internal/kolotest"
	"github.com/ciranda-dev/kolo-mls/settle"
)

func FuzzEntries(f *testing.F) {
	gid := bytes.Repeat([]byte{1}, 32)
	for _, cert := range [][]byte{[]byte("cert"), kolotest.NewDevice(f, kolotest.Person(f), true).Cert.Encode(), nil} {
		f.Add(refBody(cert, gid, 3, [32]byte{2}))
		f.Add(voteBody(cert, gid, 3, [32]byte{2}, [32]byte{6}, true, 0))
		f.Add(sigBody(cert, &settle.TBS{GroupID: gid, Epoch: 3, RefPosition: 9}, make([]byte, 64)))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		e, ok, err := decodeEntry(b)
		if !ok {
			return
		}
		if err != nil {
			if !errors.Is(err, ErrEntry) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		if h := sha256.Sum256(e.cert); len(e.cert) == 0 || e.ref.Cert != h || e.vote.Cert != h || e.sig.Cert != h {
			t.Fatal("certificate missing or its hash differs")
		}
		var again []byte
		switch e.kind {
		case kindRef:
			again = refBody(e.cert, e.groupID, e.epoch, e.ref.Commit)
		case kindVote:
			again = voteBody(e.cert, e.groupID, e.epoch, e.vote.Commit, e.vote.ContextBefore, e.vote.Accept, e.vote.Reason)
		case kindSig:
			again = sigBody(e.cert, &e.sig.TBS, e.sig.Signature[:])
		}
		if !bytes.Equal(again, b) {
			t.Fatal("decode then encode differs")
		}
	})
}

func FuzzVoteRecord(f *testing.F) {
	f.Add(writeVotes(map[[32]byte]Vote{{1}: {Commit: [32]byte{1}, Accept: true}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		vs, err := readVotes(b)
		if err != nil {
			return
		}
		if len(vs)*34 != len(b) && len(vs) > len(b)/34 {
			t.Fatal("more votes than the record holds")
		}
	})
}

// FuzzCatchUpArchive adds an arbitrary value to the archive of the epoch a
// member was away for, under its own hash or not, and has the member catch
// up: no panic, only ErrCatchUp as an error, the epoch applied and every
// valid message read.
func FuzzCatchUpArchive(f *testing.F) {
	w, l := memGroup(f, 2)
	away := w.memberNodes()[0]
	away.online = false
	var valid [][]byte
	for _, n := range w.live() {
		valid = append(valid, w.send(n, "first"), w.send(n, "second"))
	}
	e := w.admins()[0].m.Epoch()
	w.commit(w.admins()[0], kolomls.CommitOptions{}, l.settle)
	saved := copyBackend(f, away.backend)
	for _, v := range valid {
		f.Add(v, true)
		f.Add(v[:len(v)-1], true)
		f.Add(v, false)
	}
	f.Add([]byte{}, true)
	f.Add([]byte("x"), false)
	f.Fuzz(func(t *testing.T, in []byte, matchKey bool) {
		pins := w.pins.clone()
		k := settle.ArchiveKey(w.gid, e, in)
		if !matchKey {
			h := sha256.Sum256(in)
			h[0] ^= 1
			k = settle.ArchivePrefix(w.gid, e) + hex.EncodeToString(h[:])
		}
		if err := pins.Put(w.ctx, k, in); err != nil {
			t.Fatal(err)
		}
		m, err := settle.OpenMember(backendStore(copyBackend(t, saved)), w.gid, w.config(away), w.memberOptions(away))
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		rs, err := m.CatchUp(w.ctx, pins)
		if err != nil && !errors.Is(err, settle.ErrCatchUp) {
			t.Fatalf("untyped error %v", err)
		}
		if m.Epoch() != e+1 || len(rs) != len(valid) {
			t.Fatalf("epoch %d, %d of %d read", m.Epoch(), len(rs), len(valid))
		}
	})
}
