package settle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/kolotest"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// raw is one device of a group run on the core alone, with the Kolo Policy.
type raw struct {
	d    *kolotest.Device
	st   *kolomls.MemStore
	auth *cred.Authenticator
	p    *Policy
	cfg  kolomls.Config
	g    *kolomls.Group
}

func newRaw(t *testing.T) *raw {
	r := &raw{d: kolotest.NewDevice(t, kolotest.Person(t), true), st: kolomls.NewMemStore(), auth: &cred.Authenticator{Now: time.Now}, p: &Policy{}}
	r.cfg = NewConfig(r.auth, r.p, time.Now)
	return r
}

// rawGroup makes a group of n devices: the first one creates it as its only
// admin and settler and adds the others, settling its Commit alone.
func rawGroup(t *testing.T, n int) []*raw {
	t.Helper()
	founder := newRaw(t)
	roles, err := NewRoles(key(7), Majority, []ed25519.PublicKey{founder.d.ID.PublicKey()}, []ed25519.PublicKey{founder.d.ID.PublicKey()}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	exts, err := GroupExtensions(roles)
	if err != nil {
		t.Fatal(err)
	}
	if founder.g, err = kolomls.Create(founder.st, founder.d.CreateOptions(t, founder.st, founder.cfg, exts)); err != nil {
		t.Fatal(err)
	}
	out := []*raw{founder}
	var kps [][]byte
	for range n - 1 {
		j := newRaw(t)
		kps = append(kps, j.d.KeyPackage(t, j.st))
		out = append(out, j)
	}
	before := sha256.Sum256(founder.g.GroupContext())
	pc, err := founder.g.Commit(kolomls.CommitOptions{Add: kps})
	if err != nil {
		t.Fatal(err)
	}
	tbs := TBS{GroupID: founder.g.GroupID(), Epoch: founder.g.Epoch(), Commit: sha256.Sum256(pc.Commit()), ContextBefore: before, ContextAfter: sha256.Sum256(pc.GroupContext()), Braid: roles.Braid}
	sig, err := sign(founder.d.ID, &tbs)
	if err != nil {
		t.Fatal(err)
	}
	settled := &Settled{TBS: tbs, Shares: []Share{{Signer: founder.d.Key(), Signature: [64]byte(sig)}}}
	if err := founder.g.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	tr, err := founder.g.RatchetTree()
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range out[1:] {
		j.p.welcome = settled
		if j.g, err = kolomls.Join(j.st, pc.Welcome(), tr, kolomls.JoinOptions{Config: j.cfg}); err != nil {
			t.Fatal(err)
		}
		j.p.welcome = nil
	}
	return out
}

func wantRule(t *testing.T, name string, err error) {
	t.Helper()
	if !errors.Is(err, ErrRule) {
		t.Errorf("%s: %v", name, err)
	}
}

// TestPolicyProposals: only a member's own Remove is a proposal, at most one
// cached per member and fewer than the members, unless a Commit names it.
func TestPolicyProposals(t *testing.T) {
	rs := rawGroup(t, 3)
	a, m1, m2 := rs[0], rs[1], rs[2]
	_, err := m1.g.ProposeRemove(m2.g.OwnLeaf())
	wantRule(t, "Remove of another member", err)
	_, err = m1.g.ProposeUpdate(nil)
	wantRule(t, "Update", err)
	_, err = a.g.ProposeAdd(newRaw(t).d.KeyPackage(t, kolomls.NewMemStore()))
	wantRule(t, "Add", err)
	_, err = a.g.ProposeGroupContextExtensions(a.g.Extensions())
	wantRule(t, "GroupContextExtensions", err)
	_, err = a.g.ProposePSK(&schedule.PSKID{Type: schedule.PSKExternal, ID: []byte("k")})
	wantRule(t, "PSK", err)
	if _, err := m1.g.ProposeRemove(m1.g.OwnLeaf()); err != nil {
		t.Fatal(err)
	}
	_, err = m1.g.ProposeRemove(m1.g.OwnLeaf())
	wantRule(t, "a second own Remove", err)

	own := &message.Proposal{Type: message.ProposalRemove, Removed: 1}
	v := kolomls.ProposalView{Sender: 1, Proposal: own, Tree: a.g.Tree()}
	for name, c := range map[string]struct {
		v    kolomls.ProposalView
		want bool
	}{
		"first":             {v, true},
		"one cached":        {withCounts(v, 1, 1), false},
		"cache full":        {withCounts(v, 3, 0), false},
		"below the members": {withCounts(v, 2, 0), true},
		"other's Remove":    {kolomls.ProposalView{Sender: 2, Proposal: own, Tree: a.g.Tree()}, false},
	} {
		if err := a.p.CheckProposal(c.v); (err == nil) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func withCounts(v kolomls.ProposalView, cached, from int) kolomls.ProposalView {
	v.Cached, v.FromSender = cached, from
	return v
}

// TestPolicyCommitRefusals: what neither a member nor an admin may commit.
func TestPolicyCommitRefusals(t *testing.T) {
	rs := rawGroup(t, 3)
	a, m1, m2 := rs[0], rs[1], rs[2]
	roles, _ := RolesOf(a.g.Extensions(), Limits{})
	exts, _ := GroupExtensions(roles)
	_, err := a.g.Commit(kolomls.CommitOptions{Add: [][]byte{newRaw(t).d.KeyPackage(t, kolomls.NewMemStore())}, SetExtensions: true, Extensions: exts})
	wantRule(t, "Add with GroupContextExtensions", err)
	_, err = a.g.Commit(kolomls.CommitOptions{PSKs: []*schedule.PSKID{{Type: schedule.PSKExternal, ID: []byte("k")}}})
	wantRule(t, "external PSK", err)
	leave, err := m2.g.ProposeRemove(m2.g.OwnLeaf())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m1.g.Process(leave); err != nil {
		t.Fatal(err)
	}
	_, err = m1.g.Commit(kolomls.CommitOptions{References: m1.g.CachedProposals()})
	wantRule(t, "a member commits a proposal", err)
	_, err = a.g.Commit(kolomls.CommitOptions{Remove: []uint32{a.g.OwnLeaf() + 1}, SetExtensions: true, Extensions: []tls.Extension{roles.Extension()}})
	wantRule(t, "no required capabilities", err)
}

// TestPolicyCommitView runs CheckCommit on views no library sender makes: a
// Commit without a path, and one with an Update proposal.
func TestPolicyCommitView(t *testing.T) {
	rs := rawGroup(t, 1)
	a := rs[0]
	var ctx *schedule.GroupContext
	if err := tls.Decode(a.g.GroupContext(), func(r *tls.Reader) (err error) {
		ctx, err = schedule.ReadGroupContext(r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	admin := a.g.Tree().Leaf(0)
	c, _ := newRaw(t).d.Credential(t)
	member := admin.Clone()
	member.Credential = c
	for name, v := range map[string]kolomls.CommitView{
		"no path":         {Committer: 0, CommitterLeaf: member, Context: ctx, Tree: a.g.Tree()},
		"Update by ref":   {Committer: 0, CommitterLeaf: admin, Path: admin, Context: ctx, Tree: a.g.Tree(), Proposals: []kolomls.ProposalView{{Proposal: &message.Proposal{Type: message.ProposalUpdate}}}},
		"blank committer": {Committer: 0, Path: admin, Context: ctx, Tree: a.g.Tree()},
	} {
		if err := a.p.CheckCommit(v); !errors.Is(err, ErrRule) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := a.p.CheckCommit(kolomls.CommitView{CommitterLeaf: member, Path: member, Context: ctx, Tree: a.g.Tree()}); err != nil {
		t.Fatalf("a member's key update: %v", err)
	}
	if err := (&Policy{}).CheckCommit(kolomls.CommitView{CommitterLeaf: member, Path: member, Context: ctx, Tree: a.g.Tree()}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("a Policy outside NewConfig: %v", err)
	}
}

// TestPolicyGroupInfoExtensions: a Kolo Welcome carries no tree and no
// external_pub (RFC 9750 section 7 choices of Kolo groups).
func TestPolicyGroupInfoExtensions(t *testing.T) {
	rs := rawGroup(t, 1)
	a := rs[0]
	j := newRaw(t)
	kp := j.d.KeyPackage(t, j.st)
	before := sha256.Sum256(a.g.GroupContext())
	pc, err := a.g.Commit(kolomls.CommitOptions{Add: [][]byte{kp}, RatchetTree: true})
	if err != nil {
		t.Fatal(err)
	}
	roles, _ := RolesOf(a.g.Extensions(), Limits{})
	tbs := TBS{GroupID: a.g.GroupID(), Epoch: a.g.Epoch(), Commit: sha256.Sum256(pc.Commit()), ContextBefore: before, ContextAfter: sha256.Sum256(pc.GroupContext()), Braid: roles.Braid}
	sig, _ := sign(a.d.ID, &tbs)
	j.p.welcome = &Settled{TBS: tbs, Shares: []Share{{Signer: a.d.Key(), Signature: [64]byte(sig)}}}
	_, err = kolomls.Join(j.st, pc.Welcome(), nil, kolomls.JoinOptions{Config: j.cfg})
	wantRule(t, "a Welcome with the tree", err)
	gc := &schedule.GroupContext{GroupID: a.g.GroupID(), Extensions: a.g.Extensions()}
	err = j.p.CheckJoin(kolomls.JoinView{Context: gc, InfoExtensions: []tls.Extension{{Type: message.ExtExternalPub}}})
	wantRule(t, "a GroupInfo with external_pub", err)
}

// TestPolicyWelcome: a Welcome is joined only with the SettledCommit of its
// Commit, signed by enough settlers of the joined epoch.
func TestPolicyWelcome(t *testing.T) {
	rs := rawGroup(t, 1)
	a := rs[0]
	j := newRaw(t)
	kp := j.d.KeyPackage(t, j.st)
	before := sha256.Sum256(a.g.GroupContext())
	pc, err := a.g.Commit(kolomls.CommitOptions{Add: [][]byte{kp}})
	if err != nil {
		t.Fatal(err)
	}
	roles, _ := RolesOf(a.g.Extensions(), Limits{})
	good := TBS{GroupID: a.g.GroupID(), Epoch: a.g.Epoch(), Commit: sha256.Sum256(pc.Commit()), ContextBefore: before, ContextAfter: sha256.Sum256(pc.GroupContext()), Braid: roles.Braid}
	if err := a.g.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	tr, _ := a.g.RatchetTree()
	signed := func(edit func(*TBS), extra bool) *Settled {
		tbs := good
		edit(&tbs)
		sig, _ := sign(a.d.ID, &tbs)
		shares := []Share{{Signer: a.d.Key(), Signature: [64]byte(sig)}}
		if extra {
			o := newRaw(t).d
			osig, _ := sign(o.ID, &tbs)
			shares = append(shares, Share{Signer: o.Key(), Signature: [64]byte(osig)})
			slices.SortFunc(shares, func(x, y Share) int { return bytes.Compare(x.Signer[:], y.Signer[:]) })
		}
		return &Settled{TBS: tbs, Shares: shares}
	}
	join := func(w *Settled) error {
		j.p.welcome = w
		defer func() { j.p.welcome = nil }()
		g, err := kolomls.Join(cloneStore(j.st), pc.Welcome(), tr, kolomls.JoinOptions{Config: j.cfg})
		if g != nil {
			g.Close()
		}
		return err
	}
	for name, w := range map[string]*Settled{
		"none":                 nil,
		"no signature":         {TBS: good},
		"another context":      signed(func(t *TBS) { t.ContextAfter[0] ^= 1 }, false),
		"another braid":        signed(func(t *TBS) { t.Braid[0] ^= 1 }, false),
		"another group":        signed(func(t *TBS) { t.GroupID = bytes.Repeat([]byte{9}, 32) }, false),
		"another epoch":        signed(func(t *TBS) { t.Epoch++ }, false),
		"more shares than one": signed(func(*TBS) {}, true),
	} {
		if err := join(w); !errors.Is(err, ErrNotSettled) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := join(signed(func(*TBS) {}, false)); err != nil {
		t.Fatalf("valid: %v", err)
	}
}

// cloneStore copies a MemStore through its records, for joins tried twice.
func cloneStore(st *kolomls.MemStore) *kolomls.MemStore {
	return st.Clone()
}

// TestSealContexts: the tree key and nonce are both exported for the
// sealer's device key, so two sealers never share either.
func TestSealContexts(t *testing.T) {
	var contexts [][]byte
	export := func(label string, context []byte, n int) ([]byte, error) {
		contexts = append(contexts, append([]byte(label+"|"), context...))
		return make([]byte, n), nil
	}
	sealer := key(5)
	if _, err := Seal(export, make([]byte, 32), 3, sealer, []byte("tree")); err != nil {
		t.Fatal(err)
	}
	if len(contexts) != 2 || !bytes.Equal(contexts[0], append([]byte(treeKeyLabel+"|"), sealer[:]...)) || !bytes.Equal(contexts[1], append([]byte(treeNonceLabel+"|"), sealer[:]...)) {
		t.Fatalf("contexts %q", contexts)
	}
}

// TestMemberConfig: a Member needs the Policy made for its Authenticator by
// NewConfig and a clock.
func TestMemberConfig(t *testing.T) {
	rs := rawGroup(t, 1)
	a := rs[0]
	gid := a.g.GroupID()
	a.g.Close()
	other := a.cfg
	other.Authenticator = &cred.Authenticator{Now: time.Now}
	if _, err := OpenMember(a.st, gid, other, MemberOptions{}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("a Policy of another Authenticator: %v", err)
	}
	noClock := a.cfg
	noClock.Now = nil
	if _, err := OpenMember(a.st, gid, noClock, MemberOptions{}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("no clock: %v", err)
	}
	m, err := OpenMember(a.st, gid, a.cfg, MemberOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Commit(kolomls.CommitOptions{RatchetTree: true}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("a Commit whose Welcome carries the tree: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.CatchUp(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled catch-up: %v", err)
	}
}
