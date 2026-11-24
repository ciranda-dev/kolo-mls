package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

func TestOwnAndStaleCommits(t *testing.T) {
	w := newWorld(t, 3)
	a, b := w.members[0].g, w.members[1].g
	msg := commitBy(t, w, 0, CommitOptions{})
	_, err := a.Process(msg)
	wantErr(t, err, errs.ErrInvalidArgument, "ApplyPending")
	r, err := b.Process(msg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Commit.Committer() != 0 || r.Commit.RemovesSelf() || len(r.Commit.Added()) != 0 || len(r.Commit.Removed()) != 0 || r.Commit.GroupContext() == nil {
		t.Fatal("staged Commit accessors")
	}
	// Another Commit applied first makes the staged one stale.
	w.commit(2, CommitOptions{})
	wantErr(t, b.Apply(r.Commit), errs.ErrInvalidArgument, "staged for another state")
	wantErr(t, a.Apply(r.Commit), errs.ErrInvalidArgument, "staged for another state")
}

// createArgs are the parts of create, for tests that build a leaf by hand.
type createArgs struct {
	o    CreateOptions
	leaf *LeafNode
	enc  []byte
	sig  ed25519.PrivateKey
}

func (a createArgs) create(st Store) (*Group, error) {
	return create(st, a.o, a.leaf, a.enc, a.sig, nil)
}

func TestCreateErrors(t *testing.T) {
	c := newClient(t)
	rec := c.keyPackageRecord(t, c.keyPackage(t))
	base := createArgs{o: CreateOptions{Config: testConfig(), GroupID: []byte("g")}, leaf: rec.kp.LeafNode, enc: rec.encPriv, sig: rec.sig}
	for name, change := range map[string]func(a *createArgs){
		"other signature key":  func(a *createArgs) { _, a.sig, _ = ed25519.GenerateKey(nil) },
		"short signature key":  func(a *createArgs) { a.sig = a.sig[:10] },
		"other encryption key": func(a *createArgs) { a.enc = bytes.Repeat([]byte{1}, 32) },
	} {
		x := base
		change(&x)
		if _, err := x.create(NewMemStore()); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	for name, change := range map[string]func(o *CreateOptions){
		"no Authenticator": func(o *CreateOptions) { o.Authenticator = nil },
		"no Policy":        func(o *CreateOptions) { o.Policy = nil },
		"negative PSKs":    func(o *CreateOptions) { o.ResumptionPSKs = -1 },
	} {
		x := CreateOptions{Config: testConfig(), KeyPackage: newClient(t).keyPackage(t)}
		change(&x)
		if _, err := Create(NewMemStore(), x); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	x := base
	x.leaf = rec.kp.LeafNode.Clone()
	x.leaf.Source = tree.SourceUpdate
	if _, err := x.create(NewMemStore()); !errors.Is(err, errs.ErrInvalidLeaf) {
		t.Errorf("update leaf: %v", err)
	}
	st := NewMemStore()
	if _, err := base.create(st); err != nil {
		t.Fatal(err)
	}
	if _, err := base.create(st); !errors.Is(err, errs.ErrGroupExists) {
		t.Fatalf("second group with one id: %v", err)
	}
	if _, err := Open(st, []byte("other"), testConfig()); !errors.Is(err, errs.ErrNotFound) {
		t.Fatalf("Open of an unknown group: %v", err)
	}
	if _, err := Open(st, []byte("g"), Config{}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("Open without Authenticator: %v", err)
	}
	// A record that the meta record implies is missing: the stored state is
	// incomplete, not a group that does not exist.
	if err := st.Apply(Batch{Delete: [][]byte{epochKey([]byte("g"), 0)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(st, []byte("g"), testConfig()); !errors.Is(err, errs.ErrMalformed) || errors.Is(err, errs.ErrNotFound) {
		t.Fatalf("Open of an incomplete group: %v", err)
	}
	cfg := testConfig()
	cfg.MaxForwardDistance = secrettree.MaxBound + 1
	if _, err := Create(NewMemStore(), CreateOptions{Config: cfg, KeyPackage: newClient(t).keyPackage(t)}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("forward distance above the bound: %v", err)
	}
	cfg = testConfig()
	cfg.OutOfOrderTolerance = secrettree.MaxBound + 1
	gs := &getStore{MemStore: st}
	if _, err := Open(gs, []byte("g"), cfg); !errors.Is(err, errs.ErrInvalidArgument) || len(gs.gets) != 0 {
		t.Fatalf("tolerance above the bound: %v, %d Store reads", err, len(gs.gets))
	}
}

func TestNewKeyPackage(t *testing.T) {
	c := newClient(t)
	if _, err := NewKeyPackage(c.st, KeyPackageOptions{SignatureKey: c.sig[:5]}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("short key: %v", err)
	}
	if _, err := NewKeyPackage(c.st, KeyPackageOptions{SignatureKey: c.sig, Lifetime: -time.Hour}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("negative lifetime: %v", err)
	}
	now := time.Unix(1_000_000, 0)
	b, err := NewKeyPackage(c.st, KeyPackageOptions{Credential: tree.Credential{Type: tree.CredentialBasic}, SignatureKey: c.sig, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := decodeKeyPackage(b)
	l := kp.LeafNode
	if l.NotBefore != 1_000_000-3600 || l.NotAfter != 1_000_000+84*24*3600 {
		t.Fatalf("lifetime %d to %d", l.NotBefore, l.NotAfter)
	}
	cfg := testConfig()
	cfg.Now = func() time.Time { return now }
	if err := cfg.checkKeyPackage(kp, &defaultContext, EventKeyPackage, true); err != nil {
		t.Fatalf("a new KeyPackage is invalid: %v", err)
	}
	w := newWorld(t, 1)
	if _, err := decodeKeyPackage(commitBy(t, w, 0, CommitOptions{})); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("a Commit as a KeyPackage: %v", err)
	}
}

var defaultContext = schedule.GroupContext{CipherSuite: suite.ID, GroupID: []byte("g")}

// strictAuth refuses every successor credential.
type strictAuth struct{ testAuth }

func (strictAuth) Successor(prev, next tree.Credential) error { return errRefused }

// A leaf that replaces another with a new credential needs the
// Authenticator's consent (RFC 9420 section 5.3.1).
func TestSuccessor(t *testing.T) {
	w := newWorld(t, 3)
	a, b := w.members[0].g, w.members[1].g
	renamed := a.s.tree.Leaf(0).Clone()
	renamed.Credential.Identity = []byte("renamed")
	b.cfg.Authenticator = strictAuth{}
	msg, err := a.ProposeUpdate(renamed)
	if err != nil {
		t.Fatal(err)
	}
	refused(t, w, msg, errs.ErrCredential, "credential refused")
	refused(t, w, commitBy(t, w, 0, CommitOptions{Leaf: renamed}), errs.ErrCredential, "credential refused")
	// The same credential needs no consent.
	if _, err := b.Process(commitBy(t, w, 0, CommitOptions{})); err != nil {
		t.Fatal(err)
	}
	a.cfg.Authenticator = strictAuth{}
	if _, err := a.Commit(CommitOptions{Leaf: renamed}); !errors.Is(err, errs.ErrCredential) {
		t.Fatalf("committer with a refused successor: %v", err)
	}
	b.cfg.Authenticator = testAuth{}
	a.cfg.Authenticator = testAuth{}
	w.commit(0, CommitOptions{Leaf: renamed})
	w.check()
	if !bytes.Equal(w.members[1].g.s.tree.Leaf(0).Credential.Identity, []byte("renamed")) {
		t.Fatal("the new credential is not in the tree")
	}
}

// A Commit may drop an extension that the KeyPackage it adds lacks: the
// Add is checked against the new extensions (RFC 9420 section 12.3).
func TestExtensionsOfTheSameCommit(t *testing.T) {
	w := newWorld(t, 1)
	ext := []tls.Extension{{Type: 0xf00a}}
	supports := func(o *KeyPackageOptions) { o.Capabilities.Extensions = []uint16{0xf00a} }
	var joiners []*client
	var kps [][]byte
	for range 2 {
		c, kp := keyPackageFor(t, []byte{byte(len(kps))}, newClient(t).sig, supports)
		joiners, kps = append(joiners, c), append(kps, kp)
	}
	a := w.members[0].g
	leaf := a.s.tree.Leaf(0).Clone()
	leaf.Capabilities.Extensions = append(leaf.Capabilities.Extensions, 0xf00a)
	w.commit(0, CommitOptions{Leaf: leaf})
	pc := w.commit(0, CommitOptions{SetExtensions: true, Extensions: ext, Add: kps})
	w.join(0, pc, joiners)
	plain := newClient(t)
	pc = w.commit(1, CommitOptions{SetExtensions: true, Extensions: nil, Add: [][]byte{plain.keyPackage(t)}})
	w.join(1, pc, []*client{plain})
}

// TestBranch: a successor group carries a branch PSK of the old group's
// epoch in its first Commit, and its joiners need that PSK (RFC 9420
// section 11.3); a branch PSK is refused in any other Commit.
func TestBranch(t *testing.T) {
	old := newWorld(t, 3)
	id, v, err := old.members[0].g.BranchPSK()
	if err != nil {
		t.Fatal(err)
	}
	if id.Usage != schedule.UsageBranch || id.Epoch != old.members[0].g.Epoch() || len(id.Nonce) != 32 {
		t.Fatal("wrong branch PSK id")
	}
	cfg := testConfig()
	cfg.PSKs = pskFunc(func(p *schedule.PSKID) ([]byte, error) {
		if p.Usage == schedule.UsageBranch && bytes.Equal(p.GroupID, id.GroupID) && p.Epoch == id.Epoch {
			return bytes.Clone(v), nil
		}
		return nil, errs.ErrNotFound
	})
	w := newWorldWith(t, 1, cfg)
	if _, err := w.members[0].g.Commit(CommitOptions{PSKs: []*schedule.PSKID{{Type: schedule.PSKResumption, Usage: schedule.UsageBranch, GroupID: w.members[0].g.GroupID()}}}); !errors.Is(err, errs.ErrInvalidProposal) {
		t.Fatalf("branch PSK of the group itself: %v", err)
	}
	j := newClient(t)
	pc := w.commit(0, CommitOptions{Add: [][]byte{j.keyPackage(t)}, PSKs: []*schedule.PSKID{id}})
	joined := w.join(0, pc, []*client{j})
	if g := w.members[joined[0]].g; g.Epoch() != 1 {
		t.Fatalf("joined epoch %d", g.Epoch())
	}
	if _, err := w.members[0].g.Commit(CommitOptions{PSKs: []*schedule.PSKID{id}}); !errors.Is(err, errs.ErrInvalidProposal) {
		t.Fatalf("branch PSK after the first Commit: %v", err)
	}
}

// TestCreateFromKeyPackage: the creator's leaf is the KeyPackage's leaf and
// Create deletes the KeyPackage's private keys, as Join does.
func TestCreateFromKeyPackage(t *testing.T) {
	c := newClient(t)
	kp := c.keyPackage(t)
	rec := c.keyPackageRecord(t, kp)
	ref := mustRef(t, kp)
	g, err := Create(c.st, CreateOptions{Config: testConfig(), KeyPackage: kp})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(g.Tree().Leaf(0).Signature, rec.kp.LeafNode.Signature) {
		t.Fatal("leaf 0 is not the KeyPackage's leaf")
	}
	if _, err := c.st.Get(keyPackageKey(ref)); !errors.Is(err, errs.ErrNotFound) {
		t.Fatalf("KeyPackage record after Create: %v", err)
	}
	if _, err := Create(c.st, CreateOptions{Config: testConfig(), KeyPackage: kp}); !errors.Is(err, errs.ErrKeyPackageNotFound) {
		t.Fatalf("second Create from one KeyPackage: %v", err)
	}
}

func TestCreateNeedsOwnKeyPackage(t *testing.T) {
	c, other := newClient(t), newClient(t)
	kp := other.keyPackage(t)
	cfg := testConfig()
	if _, err := Create(c.st, CreateOptions{Config: cfg, KeyPackage: kp}); !errors.Is(err, errs.ErrKeyPackageNotFound) {
		t.Fatalf("KeyPackage of another Store: %v", err)
	}
	if _, err := Create(c.st, CreateOptions{Config: cfg}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("no KeyPackage: %v", err)
	}
	if _, err := Create(c.st, CreateOptions{Config: cfg, KeyPackage: kp[:len(kp)-1]}); !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("truncated KeyPackage: %v", err)
	}
	if _, err := other.st.Get(keyPackageKey(mustRef(t, kp))); err != nil {
		t.Fatalf("a refused Create deleted the KeyPackage: %v", err)
	}
}

// TestKeyPackageSeedsOneGroup: a KeyPackage used by Create is refused by a
// later Join, and one used by Join by a later Create (RFC 9420 section
// 16.8).
func TestKeyPackageSeedsOneGroup(t *testing.T) {
	welcome := func(kp []byte) ([]byte, []byte) {
		t.Helper()
		d := newClient(t)
		g, err := Create(d.st, CreateOptions{Config: testConfig(), KeyPackage: d.keyPackage(t)})
		if err != nil {
			t.Fatal(err)
		}
		pc, err := g.Commit(CommitOptions{Add: [][]byte{kp}})
		if err != nil {
			t.Fatal(err)
		}
		tree, err := pc.RatchetTree()
		if err != nil {
			t.Fatal(err)
		}
		return pc.Welcome(), tree
	}
	c := newClient(t)
	kp := c.keyPackage(t)
	w, tree := welcome(kp)
	if _, err := Create(c.st, CreateOptions{Config: testConfig(), KeyPackage: kp}); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(c.st, w, tree, JoinOptions{Config: testConfig()}); !errors.Is(err, errs.ErrKeyPackageNotFound) {
		t.Fatalf("Join with a KeyPackage used by Create: %v", err)
	}
	kp = c.keyPackage(t)
	w, tree = welcome(kp)
	if _, err := Join(c.st, w, tree, JoinOptions{Config: testConfig()}); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(c.st, CreateOptions{Config: testConfig(), KeyPackage: kp}); !errors.Is(err, errs.ErrKeyPackageNotFound) {
		t.Fatalf("Create with a KeyPackage used by Join: %v", err)
	}
}

func mustRef(t testing.TB, kp []byte) []byte {
	t.Helper()
	k, err := decodeKeyPackage(kp)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := k.Ref()
	if err != nil {
		t.Fatal(err)
	}
	return ref
}
