package kolomls

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// typed reports whether err is one of the package's errors, as every refusal
// of untrusted input must be.
func typed(err error) bool {
	for _, e := range []error{errs.ErrMalformed, errs.ErrUnsupported, errs.ErrInvalidArgument, errs.ErrDecrypt,
		errs.ErrInvalidTree, errs.ErrInvalidCommit, errs.ErrWrongGroup, errs.ErrWrongEpoch, errs.ErrFutureEpoch,
		errs.ErrSignature, errs.ErrMembershipTag, errs.ErrConfirmationTag, errs.ErrInvalidLeaf, errs.ErrInvalidKeyPackage,
		errs.ErrInvalidProposal, errs.ErrInvalidWelcome, errs.ErrUnknownProposal, errs.ErrPSKNotFound,
		errs.ErrKeyPackageNotFound, errs.ErrCredential, errs.ErrPolicy, errs.ErrGroupExists, errs.ErrUnknownSender,
		errs.ErrReplay, errs.ErrTooOld, errs.ErrTooFarAhead, errs.ErrGenerationExhausted} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// FuzzProcess feeds arbitrary bytes and mutated valid messages to a member
// of a four-member group: no panic, a typed error, and no change on error.
func FuzzProcess(f *testing.F) {
	w := newWorld(f, 4)
	a := w.members[0].g
	f.Add(commitBy(f, w, 0, CommitOptions{}))
	f.Add(commitBy(f, w, 0, CommitOptions{Remove: []uint32{2}}))
	f.Add(commitBy(f, w, 0, CommitOptions{Add: [][]byte{newClient(f).keyPackage(f)}}))
	for _, p := range []func() ([]byte, error){
		func() ([]byte, error) { return a.ProposeRemove(3) },
		func() ([]byte, error) { return a.ProposeUpdate(nil) },
		func() ([]byte, error) {
			return a.ProposePSK(&schedule.PSKID{Type: schedule.PSKExternal, ID: []byte("x")})
		},
	} {
		msg, err := p()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(msg)
	}
	b := w.members[1].g
	saved, gid := cloneStore(b.st()), b.GroupID()
	f.Fuzz(func(t *testing.T, in []byte) {
		st := cloneStore(saved)
		g, err := Open(st, gid, w.cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer g.Close()
		ctx, auth, props := g.GroupContext(), epochAuth(g), len(g.props)
		r, err := g.Process(in)
		if err != nil {
			if !typed(err) {
				t.Fatalf("untyped error %v", err)
			}
			if !bytes.Equal(g.GroupContext(), ctx) || !bytes.Equal(epochAuth(g), auth) || len(g.props) != props {
				t.Fatal("a refused message changed the group")
			}
			return
		}
		if r.Commit != nil {
			if r.Commit.base != g.s {
				t.Fatal("staged Commit of another state")
			}
			r.Commit.Discard()
		}
	})
}

// cloneStore copies st with its values, which a MemStore zeroes when it
// replaces or deletes them.
func cloneStore(st *MemStore) *MemStore {
	c := NewMemStore()
	st.each(func(k, v []byte) { c.m[string(k)] = bytes.Clone(v) })
	return c
}

// FuzzUnprotectPrivate feeds mutated PrivateMessages (application data, a
// proposal, a Commit) to a member opened from its Store, whose secret tree
// is the stored one: no panic, a typed error, and a message refused before
// its signature verified changes nothing in the Store.
func FuzzUnprotectPrivate(f *testing.F) {
	w := newWorldWith(f, 4, privateConfig())
	a := w.members[0].g
	f.Add(w.encrypt(0, []byte("application data"), []byte("aad")))
	for _, p := range []func() ([]byte, error){
		func() ([]byte, error) { return a.ProposeRemove(3) },
		func() ([]byte, error) { return a.ProposeUpdate(nil) },
	} {
		msg, err := p()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(msg)
	}
	f.Add(commitBy(f, w, 0, CommitOptions{}))
	b := w.members[1].g
	saved, gid := cloneStore(b.st()), b.GroupID()
	f.Fuzz(func(t *testing.T, in []byte) {
		st := cloneStore(saved)
		g, err := Open(st, gid, w.cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer g.Close()
		before := snapshotStore(st)
		if _, err := g.Process(in); err != nil {
			if !typed(err) {
				t.Fatalf("untyped error %v", err)
			}
			for _, e := range []error{errs.ErrMalformed, errs.ErrDecrypt, errs.ErrUnknownSender, errs.ErrReplay, errs.ErrTooOld, errs.ErrTooFarAhead,
				errs.ErrGenerationExhausted, errs.ErrSignature, errs.ErrWrongGroup, errs.ErrWrongEpoch, errs.ErrFutureEpoch} {
				if errors.Is(err, e) && !sameStore(before, snapshotStore(st)) {
					t.Fatalf("refused with %v and changed the Store", err)
				}
			}
			return
		}
		storeMatches(t, g)
	})
}

// FuzzPeekSender feeds mutated PrivateMessages to PeekSender: no panic, a
// typed error, the Store unchanged, and a leaf that is a member.
func FuzzPeekSender(f *testing.F) {
	w := newWorldWith(f, 4, privateConfig())
	f.Add(w.encrypt(1, []byte("application data"), []byte("aad")))
	f.Add(w.encrypt(3, nil, nil))
	f.Add(commitBy(f, w, 0, CommitOptions{}))
	f.Add([]byte{})
	b := w.members[0].g
	saved, gid := cloneStore(b.st()), b.GroupID()
	f.Fuzz(func(t *testing.T, in []byte) {
		st := cloneStore(saved)
		g, err := Open(st, gid, w.cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer g.Close()
		before := snapshotStore(st)
		leaf, _, err := g.PeekSender(in)
		if !sameStore(before, snapshotStore(st)) {
			t.Fatal("PeekSender changed the Store")
		}
		if err != nil {
			if !typed(err) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		if g.Tree().Leaf(leaf) == nil {
			t.Fatalf("leaf %d is blank", leaf)
		}
	})
}

func FuzzJoin(f *testing.F) {
	w := newWorld(f, 3)
	j := newClient(f)
	pc := w.commit(0, CommitOptions{Add: [][]byte{j.keyPackage(f)}, RatchetTree: true})
	f.Add(pc.Welcome())
	saved := cloneStore(j.st)
	f.Fuzz(func(t *testing.T, in []byte) {
		_, err := Join(cloneStore(saved), in, nil, JoinOptions{Config: w.cfg})
		if err != nil && !typed(err) {
			t.Fatalf("untyped error %v", err)
		}
	})
}

// FuzzStoredState feeds arbitrary bytes to the decoders of stored records;
// the first byte picks the record.
func FuzzStoredState(f *testing.F) {
	w := newWorld(f, 3)
	g := w.members[0].g
	if _, err := g.ProposeRemove(2); err != nil {
		f.Fatal(err)
	}
	var b Batch
	if err := writeState(&b, nil, g.s, g.props); err != nil {
		f.Fatal(err)
	}
	if err := writeProps(&b, g.s.ctx.GroupID, nil, g.props); err != nil {
		f.Fatal(err)
	}
	gid := g.s.ctx.GroupID
	for _, kv := range b.Put {
		k := string(kv.Key)
		switch {
		case k == string(groupKey(gid, "meta")):
			f.Add(append([]byte{0}, kv.Value...))
		case bytes.HasPrefix(kv.Key, groupKey(gid, "prop/")):
			f.Add(append([]byte{1}, kv.Value...))
		case k == string(epochKey(gid, g.s.ctx.Epoch)):
			f.Add(append([]byte{4}, kv.Value...))
		case bytes.HasPrefix(kv.Key, groupKey(gid, "node/")):
			f.Add(append([]byte{5}, kv.Value...))
		case k == string(groupKey(gid, "index")):
			f.Add(append([]byte{6}, kv.Value...))
		}
	}
	rec, _ := (&keyPackageRecord{kp: mustKP(f, newClient(f)), initPriv: make([]byte, 32), encPriv: make([]byte, 32), sig: g.s.sig}).marshal()
	f.Add(append([]byte{2}, rec...))
	pc, err := g.Commit(CommitOptions{})
	if err != nil {
		f.Fatal(err)
	}
	p, _ := pc.marshal(g.s)
	f.Add(append([]byte{3}, p...))
	w.commit(1, CommitOptions{})
	if prev := w.members[0].g.prev; prev != nil {
		pb, _ := prev.marshal()
		f.Add(append([]byte{7}, pb...))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) == 0 {
			return
		}
		var err error
		switch in[0] % 8 {
		case 0:
			_, err = unmarshalMeta(in[1:])
		case 1:
			_, err = unmarshalCached([]byte{1}, in[1:])
		case 2:
			_, err = unmarshalKeyPackageRecord(in[1:])
		case 3:
			_, err = loadPending(g.s, in[1:])
		case 4:
			_, _, err = unmarshalEpoch(in[1:])
		case 5:
			err = tls.Decode(in[1:], func(r *tls.Reader) error {
				_, err := tree.ReadNode(r, uint64(len(in)))
				return err
			})
		case 6:
			_, err = unmarshalIndex(in[1:], 1<<20-1)
		case 7:
			_, err = unmarshalPast(in[1:])
		}
		if err != nil && !typed(err) {
			t.Fatalf("untyped error %v", err)
		}
	})
}

func mustKP(f *testing.F, c *client) *message.KeyPackage {
	k, err := decodeKeyPackage(c.keyPackage(f))
	if err != nil {
		f.Fatal(err)
	}
	return k
}
