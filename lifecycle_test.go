package kolomls

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// countStore counts the batches applied to a MemStore and fails them on
// demand: before writing, or after writing when late is set.
type countStore struct {
	*MemStore
	applies int
	fail    bool
	late    bool
}

var errDisk = errors.New("disk full")

func (s *countStore) Apply(b Batch) error {
	s.applies++
	if s.fail && !s.late {
		return errDisk
	}
	if err := s.MemStore.Apply(b); err != nil {
		return err
	}
	if s.fail {
		return errDisk
	}
	return nil
}

// reopen opens member c's group again from st after a failed write.
func reopen(t testing.TB, c *client, st Store, cfg Config) {
	t.Helper()
	g, err := Open(st, c.g.GroupID(), cfg)
	if err != nil {
		t.Fatalf("Open after a failed write: %v", err)
	}
	c.g = g
}

// Every change is exactly one Store batch. After a failed batch the Group
// refuses every call until the group is opened again, and the Store still
// holds the state of before.
func TestStoreAtomicity(t *testing.T) {
	w := newWorld(t, 3)
	a := w.members[0]
	cs := &countStore{MemStore: a.st}
	a.g.store = cs
	once := func(name string, op func() error) {
		t.Helper()
		ctx, auth, props, pending := a.g.GroupContext(), epochAuth(a.g), len(a.g.props), a.g.pending != nil
		cs.applies, cs.fail = 0, true
		if err := op(); !errors.Is(err, errs.ErrStore) || !errors.Is(err, errDisk) {
			t.Fatalf("%s with a failing Store: %v", name, err)
		}
		if cs.applies != 1 {
			t.Fatalf("%s: %d batches", name, cs.applies)
		}
		if a.g.err != nil {
			if _, err := a.g.Export("x", nil, 32); !errors.Is(err, errs.ErrStore) || cs.applies != 1 {
				t.Fatalf("%s: a Group with a failed write still works: %v", name, err)
			}
			reopen(t, a, cs, w.cfg)
		}
		if !bytes.Equal(a.g.GroupContext(), ctx) || !bytes.Equal(epochAuth(a.g), auth) || len(a.g.props) != props || (a.g.pending != nil) != pending {
			t.Fatalf("%s: the failure changed the stored group", name)
		}
		cs.applies, cs.fail = 0, false
		if err := op(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cs.applies != 1 {
			t.Fatalf("%s: %d batches, want 1", name, cs.applies)
		}
	}
	once("NewKeyPackage", func() error {
		_, err := NewKeyPackage(cs, KeyPackageOptions{Credential: tree.Credential{Type: tree.CredentialBasic}, SignatureKey: a.sig})
		return err
	})
	msg, err := w.members[1].g.ProposeRemove(2)
	if err != nil {
		t.Fatal(err)
	}
	once("Process", func() error { _, err := a.g.Process(msg); return err })
	once("Commit", func() error { _, err := a.g.Commit(CommitOptions{}); return err })
	once("DiscardPending", func() error { return a.g.DiscardPending() })
	if _, err := a.g.Commit(CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	once("ApplyPending", func() error { return a.g.ApplyPending() })
}

func TestStoreAtomicityApplyAndJoin(t *testing.T) {
	w := newWorld(t, 3)
	b := w.members[1]
	cs := &countStore{MemStore: b.st}
	b.g.store = cs
	msg := commitBy(t, w, 0, CommitOptions{})
	r, err := b.g.Process(msg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := b.g.GroupContext()
	cs.fail = true
	if err := b.g.Apply(r.Commit); !errors.Is(err, errs.ErrStore) || r.Commit.next != nil {
		t.Fatalf("Apply with a failing Store: %v", err)
	}
	cs.fail, cs.applies = false, 0
	reopen(t, b, cs, w.cfg)
	if !bytes.Equal(b.g.GroupContext(), ctx) {
		t.Fatal("a failed Apply changed the stored group")
	}
	if r, err = b.g.Process(msg); err != nil {
		t.Fatal(err)
	}
	if err := b.g.Apply(r.Commit); err != nil || cs.applies != 1 {
		t.Fatalf("Apply: %v, %d batches", err, cs.applies)
	}

	j := newClient(t)
	kp := j.keyPackage(t)
	pc, err := w.members[0].g.Commit(CommitOptions{Add: [][]byte{kp}, RatchetTree: true})
	if err != nil {
		t.Fatal(err)
	}
	js := &countStore{MemStore: j.st, fail: true}
	if _, err := Join(js, pc.Welcome(), nil, JoinOptions{Config: w.cfg}); !errors.Is(err, errs.ErrStore) {
		t.Fatalf("Join with a failing Store: %v", err)
	}
	js.fail, js.applies = false, 0
	if _, err := Join(js, pc.Welcome(), nil, JoinOptions{Config: w.cfg}); err != nil || js.applies != 1 {
		t.Fatalf("Join: %v, %d batches", err, js.applies)
	}
	c := newClient(t)
	o := CreateOptions{Config: w.cfg, KeyPackage: c.keyPackage(t)}
	cst := &countStore{MemStore: c.st, fail: true}
	if _, err := Create(cst, o); !errors.Is(err, errs.ErrStore) {
		t.Fatalf("Create with a failing Store: %v", err)
	}
	cst.fail, cst.applies = false, 0
	if _, err := Create(cst, o); err != nil || cst.applies != 1 {
		t.Fatalf("Create: %v, %d batches", err, cst.applies)
	}
}

func TestCloseAndDiscard(t *testing.T) {
	w := newWorld(t, 3)
	g := w.members[0].g
	if _, err := g.ProposeUpdate(nil); err != nil {
		t.Fatal(err)
	}
	pc, err := g.Commit(CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := g.Process(commitBy(t, w, 1, CommitOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, sig, next := g.props[0].leafPriv, g.s.sig, pc.next.secrets.Exporter
	exporter := g.s.secrets.Exporter
	g.Close()
	g.Close()
	if _, err := g.EpochAuthenticator(); !errors.Is(err, errs.ErrClosed) {
		t.Fatalf("EpochAuthenticator after Close: %v", err)
	}
	if _, err := g.RatchetTree(); !errors.Is(err, errs.ErrClosed) {
		t.Fatalf("RatchetTree after Close: %v", err)
	}
	if err := g.Apply(staged.Commit); !errors.Is(err, errs.ErrClosed) || staged.Commit.next != nil {
		t.Fatalf("Apply after Close: %v, or the staged secrets kept", err)
	}
	for name, b := range map[string][]byte{"exporter": exporter, "Update key": leafPriv, "signature key": sig, "pending secrets": next} {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("Close kept the %s", name)
		}
	}
	if _, err := g.Export("x", nil, 16); !errors.Is(err, errs.ErrClosed) {
		t.Fatalf("Export after Close: %v", err)
	}
	if _, err := g.Commit(CommitOptions{}); !errors.Is(err, errs.ErrClosed) {
		t.Fatalf("Commit after Close: %v", err)
	}
	if _, err := g.Process(commitBy(t, w, 1, CommitOptions{})); !errors.Is(err, errs.ErrClosed) {
		t.Fatalf("Process after Close: %v", err)
	}
	r, err := w.members[2].g.Process(commitBy(t, w, 1, CommitOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	secret := r.Commit.next.secrets.Exporter
	r.Commit.Discard()
	if !bytes.Equal(secret, make([]byte, len(secret))) || r.Commit.GroupContext() != nil {
		t.Fatal("Discard kept the staged secrets")
	}
	if err := w.members[2].g.Apply(r.Commit); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("Apply of a discarded Commit: %v", err)
	}
}

func TestArgumentAndStateRules(t *testing.T) {
	w := newWorld(t, 4)
	a := w.members[0].g
	t.Run("added and removed", func(t *testing.T) {
		msg := commitBy(t, w, 0, CommitOptions{Remove: []uint32{3, 2}, Add: [][]byte{newClient(t).keyPackage(t)}})
		r, err := w.members[1].g.Process(msg)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.Commit.Removed(); len(got) != 2 || got[0] != 2 || got[1] != 3 {
			t.Fatalf("Removed = %v", got)
		}
		if got := r.Commit.Added(); len(got) != 1 || got[0] != 2 {
			t.Fatalf("Added = %v", got)
		}
		r.Commit.Discard()
	})
	t.Run("NoPath with a new leaf or Adds", func(t *testing.T) {
		leaf := a.s.tree.Leaf(0).Clone()
		_, err := a.Commit(CommitOptions{NoPath: true, Leaf: leaf, PSKs: []*schedule.PSKID{pskID("x")}})
		wantErr(t, err, errs.ErrInvalidArgument, "a new leaf needs a path")
		_, err = a.Commit(CommitOptions{NoPath: true, Add: [][]byte{newClient(t).keyPackage(t)}})
		wantErr(t, err, errs.ErrInvalidArgument, "adds members carries a path")
	})
	t.Run("duplicate extensions", func(t *testing.T) {
		two := []tls.Extension{{Type: 9}, {Type: 9}}
		_, err := a.ProposeGroupContextExtensions(two)
		wantErr(t, err, errs.ErrInvalidArgument, "two extensions of type 0x0009")
		_, err = a.Commit(CommitOptions{SetExtensions: true, Extensions: two})
		wantErr(t, err, errs.ErrInvalidArgument, "two extensions")
		leaf := a.s.tree.Leaf(0).Clone()
		leaf.Extensions = two
		_, err = a.ProposeUpdate(leaf)
		wantErr(t, err, errs.ErrInvalidArgument, "two extensions")
		_, err = a.Commit(CommitOptions{Leaf: leaf})
		wantErr(t, err, errs.ErrInvalidArgument, "two extensions")
		_, err = NewKeyPackage(NewMemStore(), KeyPackageOptions{SignatureKey: w.members[0].sig, LeafExtensions: two})
		wantErr(t, err, errs.ErrInvalidArgument, "two extensions")
	})
	t.Run("nil arguments", func(t *testing.T) {
		_, err := a.ProposePSK(nil)
		wantErr(t, err, errs.ErrInvalidArgument, "no PSK id")
		_, err = a.Commit(CommitOptions{PSKs: []*schedule.PSKID{nil}})
		wantErr(t, err, errs.ErrInvalidArgument, "no PSK id")
		_, err = Create(NewMemStore(), CreateOptions{Config: w.cfg})
		wantErr(t, err, errs.ErrInvalidArgument, "no KeyPackage")
	})
	t.Run("MaxTreeBytes", func(t *testing.T) {
		j := newClient(t)
		pc := w.commit(0, CommitOptions{Add: [][]byte{j.keyPackage(t)}})
		tr, _ := a.RatchetTree()
		_, err := Join(cloneStore(j.st), pc.Welcome(), tr, JoinOptions{Config: w.cfg, MaxTreeBytes: len(tr) - 1})
		wantErr(t, err, errs.ErrInvalidTree, "above MaxTreeBytes")
		for _, limit := range []int{len(tr), -1} {
			if _, err := Join(cloneStore(j.st), pc.Welcome(), tr, JoinOptions{Config: w.cfg, MaxTreeBytes: limit}); err != nil {
				t.Fatalf("MaxTreeBytes %d: %v", limit, err)
			}
		}
		w.join(0, pc, []*client{j})
	})
	t.Run("PSKStore failure", func(t *testing.T) {
		cfg := w.cfg
		cfg.PSKs = pskFunc(func(*schedule.PSKID) ([]byte, error) { return nil, errDisk })
		_, err := cfg.pskValues(nil, []*schedule.PSKID{pskID("x")})
		if !errors.Is(err, errs.ErrStore) || errors.Is(err, errs.ErrPSKNotFound) {
			t.Fatalf("PSKStore I/O error: %v", err)
		}
		// The PSKStore hands over a copy, which the library zeroes after use.
		var handed []byte
		cfg.PSKs = pskFunc(func(*schedule.PSKID) ([]byte, error) {
			handed = bytes.Repeat([]byte{1}, 32)
			return handed, nil
		})
		w2 := newWorldWith(t, 2, cfg)
		if _, err := w2.members[0].g.Commit(CommitOptions{PSKs: []*schedule.PSKID{pskID("x")}}); err != nil {
			t.Fatal(err)
		}
		if strings.Trim(string(handed), "\x00") != "" {
			t.Fatal("a PSK value was not zeroed after use")
		}
	})
	t.Run("blank leaf in range", func(t *testing.T) {
		v := newWorld(t, 4)
		v.commit(0, CommitOptions{Remove: []uint32{1}})
		if v.members[0].g.s.tree.Leaves() != 4 {
			t.Fatal("leaf 1 is not inside the tree")
		}
		_, err := v.members[0].g.Commit(CommitOptions{Remove: []uint32{1}})
		wantErr(t, err, errs.ErrInvalidProposal, "Remove of blank leaf 1")
		_, err = v.members[2].g.Process(v.forge(0, byValue(removeP(1)), nil, nil))
		wantErr(t, err, errs.ErrInvalidProposal, "Remove of blank leaf 1")
	})
	t.Run("removed member checks the ciphertexts", func(t *testing.T) {
		v := newWorld(t, 4)
		msg := v.edit(0, commitBy(t, v, 0, CommitOptions{Remove: []uint32{3}}), func(c *message.FramedContent) {
			n := &c.Commit.Path.Nodes[0]
			n.Secrets = append(n.Secrets, n.Secrets[0])
		})
		g := v.members[3].g
		_, err := g.Process(msg)
		wantErr(t, err, errs.ErrInvalidCommit, "encrypted path secrets")
		if g.Removed() {
			t.Fatal("the member deleted its group")
		}
	})
	t.Run("policy sees the cache size", func(t *testing.T) {
		v := newWorld(t, 3)
		g := v.members[1].g
		g.cfg.Policy = cachePolicy{max: 1}
		for i, want := range []error{nil, errRefused} {
			msg, err := v.members[0].g.ProposeRemove(2 - uint32(i))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := g.Process(msg); !errors.Is(err, want) {
				t.Fatalf("proposal %d: %v", i, err)
			}
		}
	})
	t.Run("DeleteKeyPackage", func(t *testing.T) {
		c := newClient(t)
		kp := c.keyPackage(t)
		before := len(c.st.m)
		if err := DeleteKeyPackage(c.st, kp); err != nil || len(c.st.m) != before-1 {
			t.Fatalf("DeleteKeyPackage: %v, %d records left", err, len(c.st.m))
		}
	})
	t.Run("CachedProposals", func(t *testing.T) {
		v := newWorld(t, 3)
		g := v.members[0].g
		ref := v.propose(1, func(g *Group) ([]byte, error) { return g.ProposeRemove(2) })
		if _, err := g.ProposeUpdate(nil); err != nil {
			t.Fatal(err)
		}
		got := g.CachedProposals()
		if len(got) != 2 || !bytes.Equal(got[0], ref) {
			t.Fatalf("%d cached proposals at member 0", len(got))
		}
		if got := v.members[1].g.CachedProposals(); len(got) != 1 {
			t.Fatalf("%d cached proposals at member 1", len(got))
		}
	})
}

// cachePolicy refuses proposals once max are cached.
type cachePolicy struct {
	rfcPolicy
	max int
}

func (p cachePolicy) CheckProposal(v ProposalView) error {
	if v.Cached >= p.max {
		return errRefused
	}
	return nil
}

// TestPendingCommitRatchetTree: the committer reads the new tree from a pending
// Commit, also after the Group is opened again, and it is the tree the group
// has after ApplyPending (RFC 9420 section 12.4.3.3).
func TestPendingCommitRatchetTree(t *testing.T) {
	w := newWorld(t, 2)
	a, j := w.members[0], newClient(t)
	pc, err := a.g.Commit(CommitOptions{Add: [][]byte{j.keyPackage(t)}})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := pc.RatchetTree()
	if err != nil {
		t.Fatal(err)
	}
	a.g.Close()
	reopen(t, a, a.st, w.cfg)
	stored, err := a.g.Pending().RatchetTree()
	if err != nil || !bytes.Equal(stored, tr) {
		t.Fatalf("stored pending tree differs: %v", err)
	}
	if err := a.g.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	applied, err := a.g.RatchetTree()
	if err != nil || !bytes.Equal(applied, tr) {
		t.Fatalf("applied tree differs from the pending one: %v", err)
	}
	jg, err := Join(j.st, pc.Welcome(), tr, JoinOptions{Config: w.cfg})
	if err != nil {
		t.Fatal(err)
	}
	ea, _ := a.g.EpochAuthenticator()
	eb, _ := jg.EpochAuthenticator()
	if !bytes.Equal(ea, eb) {
		t.Fatal("epoch authenticators differ")
	}
}
