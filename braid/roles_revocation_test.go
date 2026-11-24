package braid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// nAdmins builds a group of k admins, all settlers under Majority, and n
// members.
func nAdmins(t *testing.T, k, n int) (*world, *memLog) {
	w := newWorld(t)
	l := newLog(1)
	e := &memEnv{log: l}
	founder := w.device("admin0", nil)
	w.create(founder, e.order(w, founder))
	var nodes []*node
	for i := 1; i < k; i++ {
		nodes = append(nodes, w.device("admin"+string(rune('0'+i)), nil))
	}
	for i := range n {
		nodes = append(nodes, w.device("member"+string(rune('a'+i)), nil))
	}
	w.join(founder, l.settle, nodes...)
	all := append([]*node{founder}, nodes[:k-1]...)
	promote(w, e, founder, all, all, settle.Majority)
	return w, l
}

// strictAdmins gives the nodes Admins whose applications approve no roles
// change.
func strictAdmins(t *testing.T, w *world, nodes ...*node) {
	for _, n := range nodes {
		a, err := NewAdmin(n.dev.ID, n.order, n.m, Options{Pins: w.pins, Now: w.clock})
		if err != nil {
			t.Fatal(err)
		}
		n.admin = a
	}
}

func keysOf(ns ...*node) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, n := range ns {
		out = append(out, n.dev.ID.PublicKey())
	}
	return out
}

// steps has the online admins step rounds times, settling after each round.
func steps(t *testing.T, w *world, l *memLog, rounds int, ns ...*node) {
	t.Helper()
	for range rounds {
		for _, n := range ns {
			if _, err := n.admin.Step(w.ctx); err != nil && !errors.Is(err, errs.ErrRemoved) {
				t.Fatalf("%s: %v", n.name, err)
			}
		}
		l.settle()
	}
}

// TestRolesTakeover: an admin that made itself the braid's only settler
// (one SetSettlers entry that only removes seats activates at once) and
// commits roles naming only itself as settler is refused by the settlers
// whose applications did not approve the change.
func TestRolesTakeover(t *testing.T) {
	w, l := nAdmins(t, 4, 1)
	a := w.nodes[0]
	honest := w.nodes[1:4]
	strictAdmins(t, w, honest...)
	roles, _ := settle.RolesOf(a.m.Extensions(), w.limits)
	r, err := settle.NewRoles(roles.Braid, settle.Majority, keysOf(w.nodes[:4]...), keysOf(a), w.limits)
	if err != nil {
		t.Fatal(err)
	}
	(&memEnv{log: l}).seatOnly(r)
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{SetExtensions: true, Extensions: mustExts(t, r)}); err != nil {
		t.Fatal(err)
	}
	l.settle()
	steps(t, w, l, 10, w.nodes[:4]...)
	if a.m.Epoch() != e {
		t.Fatal("one admin took the settler role through the braid")
	}
	if a.m.Pending() != nil {
		t.Fatal("the takeover was not rejected")
	}
}

// TestRemovedSettlersCheckRoles: settlers that a Commit removes check the
// roles it sets like the others, so an admin cannot remove two honest
// settlers and count their accepts toward its takeover.
func TestRemovedSettlersCheckRoles(t *testing.T) {
	w, l := nAdmins(t, 5, 0)
	a, b, c := w.nodes[0], w.nodes[1], w.nodes[2]
	honest := w.nodes[1:5]
	strictAdmins(t, w, honest...)
	roles, _ := settle.RolesOf(a.m.Extensions(), w.limits)
	r, err := settle.NewRoles(roles.Braid, settle.Majority, keysOf(a, w.nodes[3], w.nodes[4]), keysOf(a), w.limits)
	if err != nil {
		t.Fatal(err)
	}
	(&memEnv{log: l}).seatOnly(r)
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Remove: []uint32{b.m.OwnLeaf(), c.m.OwnLeaf()}, SetExtensions: true, Extensions: mustExts(t, r)}); err != nil {
		t.Fatal(err)
	}
	l.settle()
	steps(t, w, l, 10, w.nodes[:5]...)
	if a.m.Epoch() != e || b.m.Removed() {
		t.Fatal("the removed settlers' accepts settled the takeover")
	}
}

// settledTwice reports whether the settled shares of epoch e hold q valid
// signatures over two different Commits: a fork members would accept.
func settledTwice(t *testing.T, w *world, n *node, e uint64, roles *settle.Roles) bool {
	t.Helper()
	_, _, sigs, err := n.order.Entries(w.gid, e)
	if err != nil {
		t.Fatal(err)
	}
	by := map[[32]byte]map[[32]byte]bool{}
	for _, s := range sigs {
		if !koloid.Verify(ed25519.PublicKey(s.Writer[:]), settle.SettledContext, s.TBS.Encode(), s.Signature[:]) || !roles.Settler(s.Writer[:]) {
			continue
		}
		if by[s.TBS.Commit] == nil {
			by[s.TBS.Commit] = map[[32]byte]bool{}
		}
		by[s.TBS.Commit][s.Writer] = true
	}
	full := 0
	for _, signers := range by {
		if len(signers) >= roles.Q() {
			full++
		}
	}
	return full > 1
}

// TestRevocationFork: with three settlers (q = 2), a thief settler accepts
// its own Commit Z with A, holds its share back, and is then revoked. Every
// settler decides Z whenever it steps, so B never signs another Commit and
// the thief's later shares do not count: no two Commits settle for the
// epoch.
func TestRevocationFork(t *testing.T) {
	w, l := nAdmins(t, 3, 1)
	A, B, S := w.nodes[0], w.nodes[1], w.nodes[2]
	env := &memEnv{log: l}
	e := A.m.Epoch()
	ctx := sha256.Sum256(A.m.GroupContext())
	roles, _ := settle.RolesOf(A.m.Extensions(), w.limits)
	decide := func(n *node) *Ref {
		refs, votes, _, err := n.order.Entries(w.gid, e)
		if err != nil {
			t.Fatal(err)
		}
		return Decide(refs, votes, roles, ctx).Decided
	}
	if _, err := S.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	z := sha256.Sum256(S.m.Pending().Commit())
	l.settle()
	steps(t, w, l, 1, A, S)
	steps(t, w, l, 1, A)
	if _, sigs, _ := A.order.Own(w.gid, e); len(sigs) != 1 || sigs[0].TBS.Commit != z {
		t.Fatal("A did not sign Z")
	}
	if d := decide(A); d == nil || d.Commit != z {
		t.Fatal("Z not decided before the revocation")
	}
	r, err := S.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: S.dev.Person.PublicKey(), Device: S.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	env.revoke(r)
	if _, err := B.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	l.settle()
	steps(t, w, l, 4, A, B)
	// The thief signs whatever another settler signed.
	_, _, sigs, _ := A.order.Entries(w.gid, e)
	for _, s := range sigs {
		tbs := s.TBS
		sig, _ := Sign(S.dev.ID, &tbs)
		if err := S.order.Append(w.ctx, sigBody(S.dev.Cert.Encode(), &tbs, sig)); err != nil {
			t.Fatal(err)
		}
	}
	l.settle()
	if d := decide(B); d == nil || d.Commit != z {
		t.Fatalf("B decides another Commit after the revocation: %v", d)
	}
	if settledTwice(t, w, A, e, roles) {
		t.Fatal("two Commits carry q valid settler signatures for one epoch")
	}
	for _, n := range []*node{A, B} {
		if n.m.Epoch() != e+1 {
			t.Fatalf("%s did not apply Z", n.name)
		}
	}
	if got := w.mustDecode(w.mustGet(settle.SettledKey(w.gid, e))).TBS.Commit; got != z {
		t.Fatal("another Commit settled")
	}
}

// TestRevocationLockout: a Commit rejected with a revoked settler's vote
// stays rejected after the revocation, so the epoch goes on.
func TestRevocationLockout(t *testing.T) {
	w, l := nAdmins(t, 3, 1)
	A, B, S := w.nodes[0], w.nodes[1], w.nodes[2]
	env := &memEnv{log: l}
	e := A.m.Epoch()
	if _, err := A.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	y := sha256.Sum256(A.m.Pending().Commit())
	ad, err := NewAdmin(B.dev.ID, B.order, B.m, Options{Pins: &errPins{Pins: w.pins, key: settle.ObjectKey(y)}, Now: w.clock, ApproveRoles: approveAll})
	if err != nil {
		t.Fatal(err)
	}
	B.admin = ad
	before := sha256.Sum256(A.m.GroupContext())
	if err := S.order.Append(w.ctx, voteBody(S.dev.Cert.Encode(), w.gid, e, y, before, false, ReasonInvalid)); err != nil {
		t.Fatal(err)
	}
	l.settle()
	steps(t, w, l, 1, A, B)
	w.now = w.now.Add(DefaultFetchTimeout)
	steps(t, w, l, 2, A, B)
	if A.m.Pending() != nil {
		t.Fatal("Y was not rejected")
	}
	r, err := S.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: S.dev.Person.PublicKey(), Device: S.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	env.revoke(r)
	S.online = false
	if _, err := A.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	w.pump(e+1, l.settle, 50)
}

// TestLeaveHeldByAdmins: a member's leave request is held by admins only, so
// it never stops other members from sending.
func TestLeaveHeldByAdmins(t *testing.T) {
	w, l := memGroup(t, 3)
	a, leaver, other := w.nodes[0], w.nodes[1], w.nodes[2]
	msg, err := leaver.m.Leave()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.m.Receive(msg); !errors.Is(err, settle.ErrNotHeld) {
		t.Fatalf("a member received a leave request: %v", err)
	}
	if _, err := a.m.Receive(msg); err != nil {
		t.Fatal(err)
	}
	w.send(other, "still sending")
	if _, err := a.m.Encrypt([]byte("x"), nil); !errors.Is(err, errs.ErrPendingProposals) {
		t.Fatalf("an admin sends before committing the leave: %v", err)
	}
	w.commit(a, kolomls.CommitOptions{Remove: []uint32{leaver.m.OwnLeaf()}}, l.settle)
	w.send(a, "after the leave")
}

func TestHaltedAdmin(t *testing.T) {
	w, l := nAdmins(t, 3, 0)
	A, B := w.nodes[0], w.nodes[1]
	e := A.m.Epoch()
	w.commit(A, kolomls.CommitOptions{}, l.settle)
	s := w.mustDecode(w.mustGet(settle.SettledKey(w.gid, e)))
	other := s.TBS
	other.Commit = sha256.Sum256([]byte("another"))
	var shares []settle.Share
	for _, n := range w.nodes[:2] {
		sig, _ := Sign(n.dev.ID, &other)
		shares = append(shares, settle.Share{Signer: n.dev.Key(), Signature: [64]byte(sig)})
	}
	if bytes.Compare(shares[0].Signer[:], shares[1].Signer[:]) > 0 {
		shares[0], shares[1] = shares[1], shares[0]
	}
	forged := (&settle.Settled{TBS: other, Shares: shares}).Encode()
	if _, err := B.m.ApplySettled(forged, []byte("another")); !errors.Is(err, settle.ErrHalted) {
		t.Fatal(err)
	}
	if _, err := A.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	l.settle()
	if _, err := B.admin.Step(w.ctx); !errors.Is(err, settle.ErrHalted) {
		t.Fatalf("a halted admin stepped: %v", err)
	}
	if _, err := B.m.Stage(A.m.Pending().Commit()); !errors.Is(err, settle.ErrHalted) {
		t.Fatalf("a halted member staged: %v", err)
	}
	if votes, _, _ := B.order.Own(w.gid, e+1); len(votes) != 0 {
		t.Fatal("a halted admin voted")
	}
}

// TestOwnCommitRevokedLeaf: a settler votes against its own Commit when a
// leaf it adds is revoked at the reference's position.
func TestOwnCommitRevokedLeaf(t *testing.T) {
	w, l := memGroup(t, 1)
	a := w.nodes[0]
	env := &memEnv{log: l}
	j := w.device("joiner", nil)
	kp := j.dev.KeyPackage(t, j.st)
	r, err := j.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: j.dev.Person.PublicKey(), Device: j.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	e := a.m.Epoch()
	env.revoke(r)
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Add: [][]byte{kp}}); err != nil {
		t.Fatal(err)
	}
	l.settle()
	steps(t, w, l, 5, a)
	if a.m.Epoch() != e {
		t.Fatal("a revoked device was added by its admin's own vote")
	}
}

// TestPinBounds: catch-up asks pins for at most a SettledCommit's and a
// Commit's bound, so hostile pins cannot hand it more.
func TestPinBounds(t *testing.T) {
	w, l := memGroup(t, 2)
	a, m1, m2 := w.nodes[0], w.nodes[1], w.nodes[2]
	e := a.m.Epoch()
	m1.online, m2.online = false, false
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	o := w.memberOptions(m1)
	o.MaxCommitBytes = 10
	m1.m.Close()
	var err error
	if m1.m, err = settle.OpenMember(m1.st, w.gid, w.config(m1), o); err != nil {
		t.Fatal(err)
	}
	if _, err := m1.m.CatchUp(w.ctx, w.pins); !errors.Is(err, settle.ErrPinTooLarge) {
		t.Fatalf("a Commit past the bound: %v", err)
	}
	good := w.mustGet(settle.SettledKey(w.gid, e))
	if err := w.pins.Put(w.ctx, settle.SettledKey(w.gid, e), make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if _, err := m2.m.CatchUp(w.ctx, w.pins); !errors.Is(err, settle.ErrPinTooLarge) {
		t.Fatalf("a SettledCommit past the bound: %v", err)
	}
	if err := w.pins.Put(w.ctx, settle.SettledKey(w.gid, e), good); err != nil {
		t.Fatal(err)
	}
	if _, err := m2.m.CatchUp(w.ctx, w.pins); err != nil {
		t.Fatal(err)
	}
}

// TestRolesApproval: settlers whose applications approve nothing accept a
// roles change that only adds an admin or drops a revoked settler, and
// reject one that adds a settler, changes the quorum rule or drops an admin
// that is not revoked; with approval the settler is added.
func TestRolesApproval(t *testing.T) {
	w, l := nAdmins(t, 4, 2)
	env := &memEnv{log: l}
	a, m := w.nodes[0], w.memberNodes()[0]
	strictAdmins(t, w, w.nodes[1:4]...)
	braidID, _ := settle.RolesOf(a.m.Extensions(), w.limits)
	try := func(name string, admins, settlers []*node, q settle.Quorum, want bool) {
		t.Helper()
		r, err := settle.NewRoles(braidID.Braid, q, keysOf(admins...), keysOf(settlers...), w.limits)
		if err != nil {
			t.Fatal(err)
		}
		env.seatOnly(r)
		e := a.m.Epoch()
		if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{SetExtensions: true, Extensions: mustExts(t, r)}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		l.settle()
		steps(t, w, l, 12, w.admins()...)
		if got := a.m.Epoch() == e+1; got != want {
			t.Fatalf("%s: applied %v", name, got)
		}
		if a.m.Pending() != nil {
			t.Fatalf("%s: still pending", name)
		}
		for _, n := range w.live() {
			if n.m.Epoch() != a.m.Epoch() {
				if _, err := n.m.CatchUp(w.ctx, w.pins); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	four := w.nodes[:4]
	withM := append(append([]*node{}, four...), m)
	try("an admin added", withM, four, settle.Majority, true)
	try("a settler added", withM, withM, settle.Majority, false)
	try("the quorum rule changed", withM, four, settle.TwoThirds, false)
	try("an admin dropped", four, four, settle.Majority, false)
	stolen := w.nodes[3]
	r, err := stolen.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: stolen.dev.Person.PublicKey(), Device: stolen.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	env.revoke(r)
	steps(t, w, l, 1, a)
	three := w.nodes[:3]
	try("a revoked settler dropped", append(append([]*node{}, three...), m), three, settle.Majority, true)
	for _, n := range w.nodes[1:3] {
		n.admin.o.ApproveRoles = func(_, _ *settle.Roles) bool { return false }
	}
	try("a refused settler", append(append([]*node{}, three...), m), append(append([]*node{}, three...), m), settle.Majority, false)
	for _, n := range w.nodes[1:3] {
		n.admin.o.ApproveRoles = approveAll
	}
	try("an approved settler", append(append([]*node{}, three...), m), append(append([]*node{}, three...), m), settle.Majority, true)
}

// TestSignedOnce: a settler that signed for the epoch neither votes on nor
// signs another Commit in it, also one decided at the same position.
func TestSignedOnce(t *testing.T) {
	w, l := memGroup(t, 1)
	a := w.nodes[0]
	e := a.m.Epoch()
	other := &settle.TBS{GroupID: w.gid, Epoch: e, Commit: sha256.Sum256([]byte("another")), RefPosition: 1 << 20}
	if err := a.admin.putRecord("sig", e, other.Encode()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	l.settle()
	if _, err := a.admin.Step(w.ctx); !errors.Is(err, ErrDecision) {
		t.Fatalf("a settler that signed another Commit stepped: %v", err)
	}
	if votes, sigs, _ := a.order.Own(w.gid, e); len(votes) != 0 || len(sigs) != 0 {
		t.Fatal("it voted or signed")
	}
	// Decided at the recorded position, but another Commit.
	if err := a.m.Store().Apply(kolomls.Batch{Delete: [][]byte{recordKey(w.gid, "sig")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.admin.Step(w.ctx); err != nil {
		t.Fatal(err)
	}
	l.settle()
	refs, _, _, _ := a.order.Entries(w.gid, e)
	other.RefPosition = refs[0].Position
	if err := a.admin.putRecord("sig", e, other.Encode()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.admin.Step(w.ctx); !errors.Is(err, ErrDecision) {
		t.Fatalf("a settler signed another Commit at the decided position: %v", err)
	}
}

// TestRemovedSettlerVotes: a settler that a Commit removes still votes on it,
// so the Commit can be decided when the other settlers are away.
func TestRemovedSettlerVotes(t *testing.T) {
	w, l := nAdmins(t, 3, 0)
	a, b, c := w.nodes[0], w.nodes[1], w.nodes[2]
	roles, _ := settle.RolesOf(a.m.Extensions(), w.limits)
	r, err := settle.NewRoles(roles.Braid, settle.Majority, keysOf(a, b), keysOf(a, b), w.limits)
	if err != nil {
		t.Fatal(err)
	}
	(&memEnv{log: l}).seatOnly(r)
	e := a.m.Epoch()
	ctx := sha256.Sum256(a.m.GroupContext())
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Remove: []uint32{c.m.OwnLeaf()}, SetExtensions: true, Extensions: mustExts(t, r)}); err != nil {
		t.Fatal(err)
	}
	l.settle()
	steps(t, w, l, 3, a, c)
	refs, votes, _, _ := a.order.Entries(w.gid, e)
	if d := Decide(refs, votes, roles, ctx); d.Decided == nil {
		t.Fatal("the removed settler did not vote")
	}
	w.pump(e+1, l.settle, 20)
}

// TestEntryCertNotLeaf: entries written with a valid certificate of the
// writer's device other than the one in its leaf, as after the device is
// certified again, pass the braid's apply but count for nothing: such a
// reference is no candidate, such a vote decides nothing and such a share
// settles nothing.
func TestEntryCertNotLeaf(t *testing.T) {
	w, l := nAdmins(t, 3, 0)
	A, B, S := w.nodes[0], w.nodes[1], w.nodes[2]
	offer, err := S.dev.Person.OfferDeviceCert(S.dev.ID.PublicKey(), &koloid.IssueOptions{Serial: 2, Approver: true})
	if err != nil {
		t.Fatal(err)
	}
	again, err := S.dev.ID.AcceptDeviceCert(offer, S.dev.Person.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	cert := again.Encode()
	e := A.m.Epoch()
	before := sha256.Sum256(A.m.GroupContext())
	pc, err := S.m.Commit(kolomls.CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	z, err := settle.PutObject(w.ctx, w.pins, pc.Commit())
	if err != nil {
		t.Fatal(err)
	}
	if err := S.m.DiscardPending(); err != nil {
		t.Fatal(err)
	}
	if err := S.order.Append(w.ctx, refBody(cert, w.gid, e, z)); err != nil {
		t.Fatal(err)
	}
	l.settle()
	steps(t, w, l, 2, A, B)
	if refs, _, _, _ := A.order.Entries(w.gid, e); len(refs) != 1 {
		t.Fatal("the reference did not pass the braid's apply")
	}
	for _, n := range []*node{A, B} {
		if votes, _, _ := n.order.Own(w.gid, e); len(votes) != 0 {
			t.Fatalf("%s voted on a reference made with another certificate", n.name)
		}
	}

	if _, err := A.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	y := sha256.Sum256(A.m.Pending().Commit())
	l.settle()
	steps(t, w, l, 1, A)
	if err := S.order.Append(w.ctx, voteBody(cert, w.gid, e, y, before, true, ReasonNone)); err != nil {
		t.Fatal(err)
	}
	l.settle()
	steps(t, w, l, 2, A)
	if _, sigs, _ := A.order.Own(w.gid, e); len(sigs) != 0 {
		t.Fatal("a vote made with another certificate decided the Commit")
	}

	steps(t, w, l, 1, B)
	steps(t, w, l, 1, A)
	_, sigs, _ := A.order.Own(w.gid, e)
	if len(sigs) != 1 {
		t.Fatalf("A made %d shares", len(sigs))
	}
	tbs := sigs[0].TBS
	sig, err := Sign(S.dev.ID, &tbs)
	if err != nil {
		t.Fatal(err)
	}
	if err := S.order.Append(w.ctx, sigBody(cert, &tbs, sig)); err != nil {
		t.Fatal(err)
	}
	l.settle()
	if ap, err := A.admin.Step(w.ctx); err != nil || ap != nil {
		t.Fatalf("a share made with another certificate settled the Commit: %v", err)
	}
	S.online = false
	w.pump(e+1, l.settle, 50)
	for _, s := range w.mustDecode(w.mustGet(settle.SettledKey(w.gid, e))).Shares {
		if s.Signer == S.dev.Key() {
			t.Fatal("the SettledCommit holds the share made with another certificate")
		}
	}
}

// TestRevokedBetweenReferences: a settler that read a leaf's revocations at
// one reference's position reads them again at a later one's, so a device
// revoked between two references to Commits that add it is refused in the
// second.
func TestRevokedBetweenReferences(t *testing.T) {
	w, l := nAdmins(t, 3, 0)
	A, B, S := w.nodes[0], w.nodes[1], w.nodes[2]
	j := w.device("joiner", nil)
	e := A.m.Epoch()
	if _, err := A.admin.Commit(w.ctx, kolomls.CommitOptions{Add: [][]byte{j.dev.KeyPackage(t, j.st)}}); err != nil {
		t.Fatal(err)
	}
	y1 := sha256.Sum256(A.m.Pending().Commit())
	for _, n := range []*node{B, S} {
		ad, err := NewAdmin(n.dev.ID, n.order, n.m, Options{Pins: &errPins{Pins: w.pins, key: settle.ObjectKey(y1)}, Now: w.clock, ApproveRoles: approveAll})
		if err != nil {
			t.Fatal(err)
		}
		n.admin = ad
	}
	l.settle()
	steps(t, w, l, 1, A, B, S)
	w.now = w.now.Add(DefaultFetchTimeout)
	steps(t, w, l, 2, A, B, S)
	if A.m.Pending() != nil {
		t.Fatal("Y1 was not rejected")
	}
	vote := func(h [32]byte) *Vote {
		votes, _, _ := A.order.Own(w.gid, e)
		for _, v := range votes {
			if v.Commit == h {
				return &v
			}
		}
		return nil
	}
	if v := vote(y1); v == nil || !v.Accept {
		t.Fatal("A did not accept Y1")
	}
	r, err := j.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: j.dev.Person.PublicKey(), Device: j.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	(&memEnv{log: l}).revoke(r)
	if _, err := B.admin.Commit(w.ctx, kolomls.CommitOptions{Add: [][]byte{j.dev.KeyPackage(t, j.st)}}); err != nil {
		t.Fatal(err)
	}
	y2 := sha256.Sum256(B.m.Pending().Commit())
	l.settle()
	steps(t, w, l, 1, A)
	if v := vote(y2); v == nil || v.Accept || v.Reason != ReasonInvalid {
		t.Fatalf("A's vote on the Commit adding the revoked device: %v", v)
	}
}

// revFailOrder fails the first RevocationsAt of one certificate and counts
// the reads of each certificate.
type revFailOrder struct {
	Order
	fail   [32]byte
	failed bool
	reads  map[[32]byte]int
}

var errRevs = errors.New("roster read failed")

func (o *revFailOrder) RevocationsAt(ctx context.Context, position uint64, c *koloid.DeviceCert) ([]*koloid.Revocation, error) {
	h := sha256.Sum256(c.Encode())
	o.reads[h]++
	if h == o.fail && !o.failed {
		o.failed = true
		return nil, errRevs
	}
	return o.Order.RevocationsAt(ctx, position, c)
}

// TestRevocationsAtError: a failed roster read at the reference's position
// stops Step instead of counting the leaf as not revoked, and the answers
// already read are kept for the epoch, so the retry reads only the one that
// failed.
func TestRevocationsAtError(t *testing.T) {
	w, l := memGroup(t, 1)
	a := w.nodes[0]
	j := w.device("joiner", nil)
	kp := j.dev.KeyPackage(t, j.st)
	r, err := j.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: j.dev.Person.PublicKey(), Device: j.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	(&memEnv{log: l}).revoke(r)
	fo := &revFailOrder{Order: a.order, fail: sha256.Sum256(j.dev.Cert.Encode()), reads: map[[32]byte]int{}}
	a.admin = nil
	w.makeAdmin(a, fo)
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Add: [][]byte{kp}}); err != nil {
		t.Fatal(err)
	}
	l.settle()
	if _, err := a.admin.Step(w.ctx); !errors.Is(err, errRevs) {
		t.Fatalf("Step with a failed roster read: %v", err)
	}
	if votes, _, _ := a.order.Own(w.gid, e); len(votes) != 0 {
		t.Fatal("voted without the roster")
	}
	if _, err := a.admin.Step(w.ctx); err != nil {
		t.Fatal(err)
	}
	if votes, _, _ := a.order.Own(w.gid, e); len(votes) != 1 || votes[0].Accept || votes[0].Reason != ReasonInvalid {
		t.Fatal("the Commit adding a revoked device was not refused")
	}
	if own := sha256.Sum256(a.dev.Cert.Encode()); fo.reads[own] != 1 || fo.reads[fo.fail] != 2 {
		t.Fatalf("reads: own leaf %d, joiner %d", fo.reads[own], fo.reads[fo.fail])
	}
}
