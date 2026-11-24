package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/framing"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// TestLifetimeBound: a key_package leaf whose lifetime equals the bound is
// accepted and one a second longer is refused (RFC 9420 section 7.2).
func TestLifetimeBound(t *testing.T) {
	c := testConfig()
	c.MaxLeafLifetime, c.Now = time.Hour, func() time.Time { return time.Unix(2000, 0) }
	for life, ok := range map[uint64]bool{3600: true, 3601: false} {
		n, ctx := leafFixture(t, func(n *tree.LeafNode) { n.NotBefore, n.NotAfter = 1000, 1000+life })
		if err := c.checkLeaf(n, leafRule{source: tree.SourceKeyPackage, sending: true}, ctx); (err == nil) != ok {
			t.Fatalf("lifetime %d s: %v", life, err)
		}
	}
}

// TestCommitterRefusals: the committer refuses what every receiver would:
// two Updates for one leaf, a resumption PSK of another group, a path leaf
// that breaks a leaf rule, a new leaf with another member's key, and a
// template whose key does not match.
func TestCommitterRefusals(t *testing.T) {
	w := newWorld(t, 3)
	a := w.members[0].g
	u1 := w.propose(1, func(g *Group) ([]byte, error) { return g.ProposeUpdate(nil) })
	u2 := w.propose(1, func(g *Group) ([]byte, error) { return g.ProposeUpdate(nil) })
	_, err := a.Commit(CommitOptions{References: [][]byte{u1, u2}})
	wantErr(t, err, errs.ErrInvalidCommit, "two Updates or Removes for leaf 1")

	other := &schedule.PSKID{Type: schedule.PSKResumption, Usage: schedule.UsageApplication, GroupID: []byte("another group"), Epoch: a.Epoch()}
	_, err = a.Commit(CommitOptions{PSKs: []*schedule.PSKID{other}})
	wantErr(t, err, errs.ErrPSKNotFound, "not found")

	own := a.s.tree.Leaf(0).Clone()
	own.Extensions = []tls.Extension{{Type: 0xf0aa}}
	_, err = a.Commit(CommitOptions{Leaf: own})
	wantErr(t, err, errs.ErrInvalidLeaf, "leaf extension 0xf0aa not in its capabilities")

	stolen := a.s.tree.Leaf(0).Clone()
	stolen.SignatureKey = w.members[1].sig.Public().(ed25519.PublicKey)
	_, err = a.Commit(CommitOptions{Leaf: stolen, SignatureKey: w.members[1].sig})
	wantErr(t, err, errs.ErrInvalidCommit, "signature key")
	_, err = a.Commit(CommitOptions{Leaf: stolen})
	wantErr(t, err, errs.ErrInvalidArgument, "does not match its private key")
	_, err = a.ProposeUpdate(stolen)
	wantErr(t, err, errs.ErrInvalidArgument, "keeps the signature key")
	if a.pending != nil {
		t.Fatal("a refused Commit is pending")
	}
}

// TestPastResumptionPSKs: ResumptionPSKs past epochs are kept, not more.
func TestPastResumptionPSKs(t *testing.T) {
	for _, keep := range []int{1, 2} {
		cfg := testConfig()
		cfg.ResumptionPSKs = keep
		w := newWorldWith(t, 2, cfg)
		for range 4 {
			w.commit(0, CommitOptions{})
		}
		a := w.members[0].g
		for back := 0; back <= keep+1; back++ {
			id := &schedule.PSKID{Type: schedule.PSKResumption, Usage: schedule.UsageApplication, GroupID: a.GroupID(), Epoch: a.Epoch() - uint64(back)}
			_, err := a.Commit(CommitOptions{PSKs: []*schedule.PSKID{id}})
			if back <= keep {
				if err != nil {
					t.Fatalf("keep %d: PSK of %d epochs back: %v", keep, back, err)
				}
				if err := a.DiscardPending(); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, errs.ErrPSKNotFound) {
				t.Fatalf("keep %d: PSK of %d epochs back: %v", keep, back, err)
			}
		}
	}
}

// welcomeFor returns a Welcome that adds a new client, the client and the
// public init key of its KeyPackage.
func welcomeFor(t *testing.T, w *world) (*client, []byte, *message.Welcome) {
	t.Helper()
	j := newClient(t)
	kp := j.keyPackage(t)
	k, err := decodeKeyPackage(kp)
	if err != nil {
		t.Fatal(err)
	}
	pc := w.commit(0, CommitOptions{Add: [][]byte{kp}, RatchetTree: true})
	m, err := message.UnmarshalMLSMessage(pc.Welcome())
	if err != nil {
		t.Fatal(err)
	}
	return j, k.InitKey, m.Welcome
}

func marshalWelcome(t *testing.T, wl *message.Welcome) []byte {
	t.Helper()
	b, err := (&message.MLSMessage{WireFormat: message.WireWelcome, Welcome: wl}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// getStore records the keys a Join reads.
type getStore struct {
	*MemStore
	gets []string
}

func (s *getStore) Get(key []byte) ([]byte, error) {
	s.gets = append(s.gets, string(key))
	return s.MemStore.Get(key)
}

// TestWelcomeRefusals: a Welcome of another suite, group secrets of a wrong
// size, and entries whose reference has another size, which are not looked
// up in the Store.
func TestWelcomeRefusals(t *testing.T) {
	w := newWorld(t, 2)
	j, initKey, wl := welcomeFor(t, w)
	other := *wl
	other.CipherSuite = 2
	_, err := Join(cloneStore(j.st), marshalWelcome(t, &other), nil, JoinOptions{Config: w.cfg})
	wantErr(t, err, errs.ErrUnsupported, "cipher suite 0x0002")

	for _, gs := range []*message.GroupSecrets{
		{JoinerSecret: make([]byte, 33)},
		{JoinerSecret: make([]byte, 32), HasPathSecret: true, PathSecret: make([]byte, 31)},
	} {
		gsb, err := gs.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		kem, ct, err := suite.EncryptWithLabel(initKey, "Welcome", wl.EncryptedGroupInfo, gsb)
		if err != nil {
			t.Fatal(err)
		}
		bad := *wl
		bad.Secrets = []message.EncryptedGroupSecrets{{NewMember: wl.Secrets[0].NewMember, Secrets: tree.HPKECiphertext{KEMOutput: kem, Ciphertext: ct}}}
		_, err = Join(cloneStore(j.st), marshalWelcome(t, &bad), nil, JoinOptions{Config: w.cfg})
		wantErr(t, err, errs.ErrInvalidWelcome, "joiner or path secret size")
	}

	long := bytes.Repeat([]byte{7}, 33)
	extra := *wl
	extra.Secrets = append([]message.EncryptedGroupSecrets{{NewMember: long, Secrets: wl.Secrets[0].Secrets}}, wl.Secrets...)
	gs := &getStore{MemStore: cloneStore(j.st)}
	if _, err := Join(gs, marshalWelcome(t, &extra), nil, JoinOptions{Config: w.cfg}); err != nil {
		t.Fatal(err)
	}
	for _, k := range gs.gets {
		if k == "kp/"+hex.EncodeToString(long) {
			t.Fatal("a reference of 33 bytes was looked up")
		}
	}
}

// refuseIdentity is an Authenticator that refuses one identity.
type refuseIdentity struct {
	testAuth
	id string
}

func (a refuseIdentity) Validate(c tree.Credential, key []byte, ev Event) error {
	if string(c.Identity) == a.id {
		return fmt.Errorf("identity %s refused", a.id)
	}
	return a.testAuth.Validate(c, key, ev)
}

// TestJoinTreeChecks runs the tree checks of a joiner (RFC 9420 section
// 12.4.3.1) on trees built by hand: a parent with no valid parent-hash
// link, a leaf the Authenticator refuses, and two leaves with one signature
// key. Each is refused by its own check.
func TestJoinTreeChecks(t *testing.T) {
	leaf := func(id string, sig ed25519.PrivateKey) *tree.LeafNode {
		_, kp := keyPackageFor(t, []byte(id), sig, nil)
		k, err := decodeKeyPackage(kp)
		if err != nil {
			t.Fatal(err)
		}
		return k.LeafNode
	}
	sigA, sigB := newClient(t).sig, newClient(t).sig
	_, parentKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	check := func(cfg Config, nodes map[uint64]tree.Node) error {
		tr, err := tree.FromNodes(3, nodes)
		if err != nil {
			t.Fatal(err)
		}
		th, err := tr.TreeHash()
		if err != nil {
			t.Fatal(err)
		}
		return cfg.checkJoinTree(tr, &schedule.GroupContext{CipherSuite: suite.ID, GroupID: []byte("g"), TreeHash: th})
	}
	a, b := leaf("a", sigA), leaf("b", sigB)
	if err := check(testConfig(), map[uint64]tree.Node{0: {Leaf: a}, 2: {Leaf: b}}); err != nil {
		t.Fatal(err)
	}
	err = check(testConfig(), map[uint64]tree.Node{0: {Leaf: a}, 1: {Parent: &tree.ParentNode{EncryptionKey: parentKey}}, 2: {Leaf: b}})
	wantErr(t, err, errs.ErrInvalidTree, "not parent-hash valid")
	cfg := testConfig()
	cfg.Authenticator = refuseIdentity{id: "b"}
	err = check(cfg, map[uint64]tree.Node{0: {Leaf: a}, 2: {Leaf: b}})
	wantErr(t, err, errs.ErrInvalidTree, "leaf 1")
	if !errors.Is(err, errs.ErrCredential) {
		t.Fatalf("refused credential: %v", err)
	}
	err = check(testConfig(), map[uint64]tree.Node{0: {Leaf: a}, 2: {Leaf: leaf("b", sigA)}})
	wantErr(t, err, errs.ErrInvalidTree, "signature key not unique")
	// A credential type that another member does not support: only the
	// member checks see it.
	_, kp := keyPackageFor(t, []byte("x"), newClient(t).sig, func(o *KeyPackageOptions) {
		o.Credential = tree.Credential{Type: tree.CredentialX509, Certificates: x509(t, []byte{1})}
		o.Capabilities.Credentials = []uint16{tree.CredentialBasic, tree.CredentialX509}
	})
	k, err := decodeKeyPackage(kp)
	if err != nil {
		t.Fatal(err)
	}
	cfg = testConfig()
	cfg.Authenticator = acceptAll{}
	err = check(cfg, map[uint64]tree.Node{0: {Leaf: a}, 2: {Leaf: k.LeafNode}})
	wantErr(t, err, errs.ErrInvalidTree, "does not support credential type 0x0002")
}

// acceptAll is an Authenticator that accepts every credential.
type acceptAll struct{ testAuth }

func (acceptAll) Validate(tree.Credential, []byte, Event) error { return nil }

// TestPathSecretAncestor: a Welcome's path secret must belong to a
// non-blank common ancestor of the joiner and the signer.
func TestPathSecretAncestor(t *testing.T) {
	c := newClient(t)
	rec := c.keyPackageRecord(t, c.keyPackage(t))
	_, kp := keyPackageFor(t, []byte("signer"), newClient(t).sig, nil)
	k, _ := decodeKeyPackage(kp)
	tr, err := tree.FromNodes(3, map[uint64]tree.Node{0: {Leaf: rec.kp.LeafNode}, 2: {Leaf: k.LeafNode}})
	if err != nil {
		t.Fatal(err)
	}
	gs := &message.GroupSecrets{JoinerSecret: make([]byte, 32), HasPathSecret: true, PathSecret: make([]byte, 32)}
	for _, signer := range []uint32{1, 0} {
		priv := &tree.Private{Leaf: 0, Keys: map[uint64][]byte{0: bytes.Clone(rec.encPriv)}}
		err := setPathSecrets(tr, priv, 0, signer, gs)
		wantErr(t, err, errs.ErrInvalidWelcome, "blank or missing common ancestor")
	}
	priv := &tree.Private{Leaf: 0, Keys: map[uint64][]byte{0: bytes.Clone(rec.encPriv)}}
	if err := setPathSecrets(tr, priv, 0, 1, &message.GroupSecrets{JoinerSecret: make([]byte, 32)}); err != nil {
		t.Fatalf("no path secret: %v", err)
	}
}

// TestIndexRecord: the stored index of non-blank nodes is refused when a run
// starts past the width, runs past it, or does not increase.
func TestIndexRecord(t *testing.T) {
	enc := func(runs ...[2]uint64) []byte {
		var w tls.Writer
		w.Vector(func(w *tls.Writer) {
			for _, r := range runs {
				w.U64(r[0])
				w.U64(r[1])
			}
		})
		b, _ := w.Bytes()
		return b
	}
	if xs, err := unmarshalIndex(enc([2]uint64{0, 3}, [2]uint64{4, 3}), 7); err != nil || len(xs) != 6 {
		t.Fatalf("valid runs: %v %v", xs, err)
	}
	for name, b := range map[string][]byte{
		"empty run":     enc([2]uint64{0, 0}),
		"start past":    enc([2]uint64{7, 1}),
		"run past":      enc([2]uint64{5, 3}),
		"overlap":       enc([2]uint64{0, 3}, [2]uint64{2, 1}),
		"not ascending": enc([2]uint64{4, 1}, [2]uint64{0, 1}),
	} {
		if _, err := unmarshalIndex(b, 7); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestStagedCommitAfterApply: a stale staged Commit is zeroed when refused,
// and discarding an applied one leaves the group's new state alone.
func TestStagedCommitAfterApply(t *testing.T) {
	w := newWorld(t, 3)
	b := w.members[1].g
	m0 := commitBy(t, w, 0, CommitOptions{})
	m2 := commitBy(t, w, 2, CommitOptions{})
	r0, err := b.Process(m0)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b.Process(m2)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(r2.Commit); err != nil {
		t.Fatal(err)
	}
	auth, exp := epochAuth(b), mustExport(t, b)
	r2.Commit.Discard()
	if !bytes.Equal(epochAuth(b), auth) || !bytes.Equal(mustExport(t, b), exp) {
		t.Fatal("discarding an applied Commit changed the group")
	}
	if err := b.Apply(r0.Commit); !errors.Is(err, errs.ErrInvalidArgument) || r0.Commit.next != nil {
		t.Fatalf("stale Commit: %v", err)
	}
	if _, err := b.Encrypt([]byte("still works"), nil); err != nil {
		t.Fatal(err)
	}
}

func mustExport(t *testing.T, g *Group) []byte {
	t.Helper()
	e, err := g.Export("t", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// keepStore keeps the value slices of every batch, which the library must
// zero once Apply returns (the Store contract).
type keepStore struct {
	*MemStore
	vals [][]byte
}

func (s *keepStore) Apply(b Batch) error {
	for _, kv := range b.Put {
		s.vals = append(s.vals, kv.Value)
	}
	return s.MemStore.Apply(b)
}

func TestBatchValuesZeroed(t *testing.T) {
	w := newWorldWith(t, 3, privateConfig())
	a, b := w.members[0], w.members[1]
	ka, kb := &keepStore{MemStore: a.st}, &keepStore{MemStore: b.st}
	a.g.store, b.g.store = ka, kb
	msg := w.encrypt(0, []byte("x"), nil)
	if _, err := b.g.Process(msg); err != nil {
		t.Fatal(err)
	}
	pc, err := a.g.Commit(CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.g.Process(pc.Commit())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.g.Apply(r.Commit); err != nil {
		t.Fatal(err)
	}
	if err := a.g.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	// A KeyPackage and a Join write secrets too.
	j := newClient(t)
	kj := &keepStore{MemStore: j.st}
	kp, err := NewKeyPackage(kj, KeyPackageOptions{Credential: tree.Credential{Type: tree.CredentialBasic, Identity: []byte("j")}, SignatureKey: j.sig})
	if err != nil {
		t.Fatal(err)
	}
	pc, err = a.g.Commit(CommitOptions{Add: [][]byte{kp}, RatchetTree: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Join(kj, pc.Welcome(), nil, JoinOptions{Config: w.cfg}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range append(append(ka.vals, kb.vals...), kj.vals...) {
		if strings.Trim(string(v), "\x00") != "" {
			t.Fatal("a batch value was not zeroed after Apply")
		}
		n += len(v)
	}
	if n == 0 {
		t.Fatal("no values written")
	}
}

// putStore records the keys of every put.
type putStore struct {
	*MemStore
	puts []string
}

func (s *putStore) Apply(b Batch) error {
	for _, kv := range b.Put {
		s.puts = append(s.puts, string(kv.Key))
	}
	return s.MemStore.Apply(b)
}

// TestCommitWritesChangedNodes: applying a Commit writes only the nodes it
// changed, here the committer's leaf and direct path.
func TestCommitWritesChangedNodes(t *testing.T) {
	w := newWorld(t, 8)
	b := w.members[5]
	ps := &putStore{MemStore: b.st}
	b.g.store = ps
	msg := commitBy(t, w, 0, CommitOptions{})
	r, err := b.g.Process(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.g.Apply(r.Commit); err != nil {
		t.Fatal(err)
	}
	var nodes []string
	for _, k := range ps.puts {
		if i := strings.Index(k, "/node/"); i >= 0 && !strings.Contains(k, "/epoch/") {
			nodes = append(nodes, k[i+len("/node/"):])
		}
	}
	if fmt.Sprint(nodes) != "[0 1 3 7]" && fmt.Sprint(nodes) != "[0 1 7 3]" {
		t.Fatalf("nodes written: %v, want the leaf 0 and its direct path 1, 3, 7", nodes)
	}
}

// TestJoinSkipsBlankPathNodes: the joiner's path secret chain skips the blank nodes of the
// committer's direct path (RFC 9420 section 12.4.3.1). With leaves 1 to 3 removed, the joiner
// at leaf 1 derives node 1, skips node 3 and derives node 7.
func TestJoinSkipsBlankPathNodes(t *testing.T) {
	w := newWorld(t, 8)
	w.commit(0, CommitOptions{Remove: []uint32{1, 2, 3}})
	got := w.add(0, 1)
	g := w.members[got[0]].g
	if got[0] != 1 || !g.s.tree.Node(3).Blank() || g.s.tree.Node(1).Blank() || g.s.tree.Node(7).Blank() {
		t.Fatalf("joiner at leaf %d; nodes 1, 3, 7 blank: %v %v %v", got[0], g.s.tree.Node(1).Blank(), g.s.tree.Node(3).Blank(), g.s.tree.Node(7).Blank())
	}
	if g.s.priv.Keys[7] == nil || g.s.priv.Keys[3] != nil {
		t.Fatal("joiner keys: want node 7 and not node 3")
	}
}

// TestLocalRefusalUsesNothing: a proposal of this member that the rules
// refuse uses no key and writes nothing (with PrivateMessage handshakes the
// next proposal takes generation 0).
func TestLocalRefusalUsesNothing(t *testing.T) {
	w := newWorldWith(t, 3, privateConfig())
	a := w.members[0]
	cs := &countStore{MemStore: a.st}
	a.g.store = cs
	if _, err := a.g.ProposeRemove(9); !errors.Is(err, errs.ErrInvalidProposal) || cs.applies != 0 {
		t.Fatalf("refused proposal: %v, %d batches", err, cs.applies)
	}
	a.g.cfg.Policy = refusePolicy{}
	if _, err := a.g.ProposeRemove(2); !errors.Is(err, errs.ErrPolicy) || cs.applies != 0 {
		t.Fatalf("proposal the Policy refuses: %v, %d batches", err, cs.applies)
	}
	a.g.cfg.Policy = rfcPolicy{}
	msg, err := a.g.ProposeRemove(2)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := message.UnmarshalMLSMessage(msg)
	b := w.members[1].g
	_, lk, err := framing.UnprotectPrivate(m.Private, b.s.secrets.SenderData, b.s.keys, func(uint32) bool { return true })
	if err != nil || lk.Generation() != 0 {
		t.Fatalf("first sent proposal: %v", err)
	}
	lk.Discard()
}

// mutatingPolicy changes everything a view gives it.
type mutatingPolicy struct{}

func (mutatingPolicy) CheckProposal(v ProposalView) error {
	v.SenderLeaf.SignatureKey[0] ^= 1
	v.Proposal.Removed = 7
	return nil
}

func (mutatingPolicy) CheckCommit(v CommitView) error {
	v.CommitterLeaf.SignatureKey[0] ^= 1
	v.Context.GroupID[0] ^= 1
	for _, l := range v.Tree.Members() {
		v.Tree.Leaf(l).EncryptionKey[0] ^= 1
	}
	return nil
}

func (mutatingPolicy) CheckJoin(v JoinView) error {
	v.Context.GroupID[0] ^= 1
	if l := v.Tree.Leaf(0); l != nil {
		l.SignatureKey[0] ^= 1
	}
	return nil
}

// mutatingAuth changes the signature key it is given.
type mutatingAuth struct{ testAuth }

func (mutatingAuth) Validate(c tree.Credential, key []byte, ev Event) error {
	key[0] ^= 1
	return nil
}

// TestViewsAreCopies: a Policy or Authenticator that changes what it is
// shown changes nothing in the group.
func TestViewsAreCopies(t *testing.T) {
	cfg := testConfig()
	cfg.Policy, cfg.Authenticator = mutatingPolicy{}, mutatingAuth{}
	w := newWorldWith(t, 3, cfg)
	ref := w.propose(1, func(g *Group) ([]byte, error) { return g.ProposeRemove(2) })
	w.commit(0, CommitOptions{References: [][]byte{ref}})
	w.check()
	if len(w.members) != 2 {
		t.Fatalf("%d members after the Remove", len(w.members))
	}
	if got := (TreeView{w.members[0].g.s.tree}).Members(); fmt.Sprint(got) != "[0 1]" {
		t.Fatalf("members %v", got)
	}
}

// TestConsumeZeroesOnError: a batch whose write is not attempted is zeroed
// all the same.
func TestConsumeZeroesOnError(t *testing.T) {
	w := newWorld(t, 2)
	g := w.members[0].g
	lk, err := g.s.keys.PeekNext(0, secrettree.Application)
	if err != nil {
		t.Fatal(err)
	}
	lk.Discard()
	v := bytes.Repeat([]byte{9}, 32)
	if err := g.consume(lk, Batch{Put: []KV{{Key: []byte("k"), Value: v}}}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("discarded lookup: %v", err)
	}
	if strings.Trim(string(v), "\x00") != "" {
		t.Fatal("batch value kept")
	}
}

// TestOpenPrunesKeys: a group stored with a wider out-of-order window and
// opened with a smaller one deletes the held keys outside it from the Store.
func TestOpenPrunesKeys(t *testing.T) {
	cfg := testConfig()
	cfg.OutOfOrderTolerance = 8
	w := newWorldWith(t, 2, cfg)
	var msgs [][]byte
	for range 7 {
		msgs = append(msgs, w.encrypt(0, []byte("x"), nil))
	}
	w.receive(1, 0, msgs[6], []byte("x"), nil)
	b := w.members[1]
	small := cfg
	small.OutOfOrderTolerance = 3
	reopen(t, b, b.st, small)
	storeMatches(t, b.g)
	if _, err := b.g.Process(msgs[3]); !errors.Is(err, errs.ErrTooOld) {
		t.Fatalf("generation outside the smaller window: %v", err)
	}
	w.cfg = small
	w.receive(1, 0, msgs[5], []byte("x"), nil)
}
