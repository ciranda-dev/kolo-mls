package braid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// hostile opens n's group with a Policy that refuses nothing, as a device
// whose own client skips the Kolo rules; n's Member is closed.
func (w *world) hostile(t *testing.T, n *node) *kolomls.Group {
	t.Helper()
	n.m.Close()
	n.online = false
	cfg := kolomls.Config{Authenticator: n.auth, Policy: plainPolicy{}, PrivateHandshakes: true, Envelope: settle.Envelope{}, Now: w.clock}
	g, err := kolomls.Open(n.st, w.gid, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestProposalFlood: a member that floods proposals of its own Remove fills no device's cache
// (one per member), and devices that read the flood in different orders, or through an
// archive, all apply the Commit that removes another member, which carries its proposal by
// value.
func TestProposalFlood(t *testing.T) {
	w, l := memGroup(t, 4)
	a, attacker, b, late := w.nodes[0], w.nodes[1], w.nodes[2], w.nodes[3]
	late.online = false
	g := w.hostile(t, attacker)
	e := a.m.Epoch()
	var flood [][]byte
	for range 4 {
		msg, err := g.ProposeRemove(g.OwnLeaf())
		if err != nil {
			t.Fatal(err)
		}
		if err := w.pins.Put(w.ctx, settle.ArchiveKey(w.gid, e, msg), msg); err != nil {
			t.Fatal(err)
		}
		flood = append(flood, msg)
	}
	for _, n := range w.live() {
		kept := 0
		for i := range flood {
			msg := flood[i]
			if n == a {
				msg = flood[len(flood)-1-i]
			}
			if _, err := n.m.Receive(msg); err == nil {
				kept++
			} else if !errors.Is(err, settle.ErrRule) && !errors.Is(err, settle.ErrNotHeld) {
				t.Fatal(err)
			}
		}
		// The admin holds one per member; other members hold none.
		if want := map[bool]int{true: 1, false: 0}[n == a]; kept != want {
			t.Fatalf("%s kept %d of the flood", n.name, kept)
		}
	}
	w.proposeLeave(b)
	w.commit(a, kolomls.CommitOptions{Remove: []uint32{b.m.OwnLeaf()}}, l.settle)
	if !b.m.Removed() {
		t.Fatal("the leave was not committed")
	}
	late.online = true
	if _, err := late.m.CatchUp(w.ctx, w.pins); err != nil {
		t.Fatalf("catch-up through the flood: %v", err)
	}
	w.check()
}

// TestStolenAdminRoles: an admin, or a stolen admin device, that makes
// itself the only admin and settler is refused by the other settlers,
// because the roles do not match the braid.
func TestStolenAdminRoles(t *testing.T) {
	w, l := fourAdmins(t, 1)
	thief := w.nodes[1]
	roles, _ := settle.RolesOf(thief.m.Extensions(), w.limits)
	me := []ed25519.PublicKey{thief.dev.ID.PublicKey()}
	alone, err := settle.NewRoles(roles.Braid, settle.Majority, me, me, w.limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := thief.admin.Commit(w.ctx, kolomls.CommitOptions{SetExtensions: true, Extensions: mustExts(t, alone)}); !errors.Is(err, ErrRoster) {
		t.Fatalf("Admin.Commit: %v", err)
	}
	e := thief.m.Epoch()
	if _, err := thief.m.Commit(kolomls.CommitOptions{SetExtensions: true, Extensions: mustExts(t, alone)}); err != nil {
		t.Fatal(err)
	}
	if err := thief.admin.Reference(w.ctx); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		for _, n := range w.admins() {
			if _, err := n.admin.Step(w.ctx); err != nil {
				t.Fatal(err)
			}
		}
		l.settle()
	}
	if thief.m.Pending() != nil || thief.m.Epoch() != e {
		t.Fatal("the roles change was not rejected")
	}
	w.commit(w.nodes[0], kolomls.CommitOptions{}, l.settle)
	a := w.nodes[0]
	var all, three []ed25519.PublicKey
	for i, n := range w.nodes[:4] {
		all = append(all, n.dev.ID.PublicKey())
		if i < 3 {
			three = append(three, n.dev.ID.PublicKey())
		}
	}
	withMember, err := settle.NewRoles(roles.Braid, settle.Majority, append(append([]ed25519.PublicKey{}, all...), w.memberNodes()[0].dev.ID.PublicKey()), all, w.limits)
	if err != nil {
		t.Fatal(err)
	}
	fewer, err := settle.NewRoles(roles.Braid, settle.Majority, all, three, w.limits)
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]*settle.Roles{"another admin": withMember, "fewer settlers": fewer} {
		if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{SetExtensions: true, Extensions: mustExts(t, r)}); !errors.Is(err, ErrRoster) {
			t.Errorf("%s: %v", name, err)
		}
	}
	twoThirds, err := settle.NewRoles(roles.Braid, settle.TwoThirds, all, all, w.limits)
	if err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	l.q = 2
	l.mu.Unlock()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{SetExtensions: true, Extensions: mustExts(t, twoThirds)}); !errors.Is(err, ErrRoster) {
		t.Fatalf("another quorum: %v", err)
	}
	// The braid seats three settlers; roles naming another three, with the
	// same quorum, are refused.
	others, err := settle.NewRoles(roles.Braid, settle.Majority, all, all[1:], w.limits)
	if err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	l.settlers = nil
	for _, k := range three {
		l.settlers = append(l.settlers, [32]byte(k))
	}
	slices.SortFunc(l.settlers, func(x, y [32]byte) int { return bytes.Compare(x[:], y[:]) })
	l.mu.Unlock()
	if slices.Equal(l.settlers, others.Settlers) {
		t.Fatal("test setup: the same settlers")
	}
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{SetExtensions: true, Extensions: mustExts(t, others)}); !errors.Is(err, ErrRoster) {
		t.Fatalf("other settlers: %v", err)
	}
}

// TestOwnRolesChecked: the only settler checks its own roles change too.
func TestOwnRolesChecked(t *testing.T) {
	w, l := memGroup(t, 1)
	a, m := w.nodes[0], w.nodes[1]
	roles, _ := settle.RolesOf(a.m.Extensions(), w.limits)
	both := []ed25519.PublicKey{a.dev.ID.PublicKey(), m.dev.ID.PublicKey()}
	r, err := settle.NewRoles(roles.Braid, settle.Majority, both, both, w.limits)
	if err != nil {
		t.Fatal(err)
	}
	e := a.m.Epoch()
	if _, err := a.m.Commit(kolomls.CommitOptions{SetExtensions: true, Extensions: mustExts(t, r)}); err != nil {
		t.Fatal(err)
	}
	if err := a.admin.Reference(w.ctx); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if _, err := a.admin.Step(w.ctx); err != nil {
			t.Fatal(err)
		}
		l.settle()
	}
	if a.m.Pending() != nil || a.m.Epoch() != e {
		t.Fatal("a roles change the braid does not show was applied")
	}
}

// TestRevokedSettlerShare: the share of a settler revoked after the
// decision does not count toward the SettledCommit.
func TestRevokedSettlerShare(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a, s2, stolen := w.nodes[0], w.nodes[2], w.nodes[3]
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		for _, n := range w.admins() {
			if _, err := n.admin.Step(w.ctx); err != nil && n != s2 {
				t.Fatal(err)
			}
		}
		l.settle()
		if _, votes, _, _ := a.order.Entries(w.gid, e); len(votes) == 4 {
			break
		}
	}
	r, err := stolen.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: stolen.dev.Person.PublicKey(), Device: stolen.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	(&memEnv{log: l}).revoke(r)
	s2.online = false
	for range 10 {
		for _, n := range w.admins() {
			if !n.online {
				continue
			}
			if ap, err := n.admin.Step(w.ctx); err != nil || ap != nil {
				t.Fatalf("assembled with a revoked share: %v", err)
			}
		}
		l.settle()
	}
	s2.online = true
	w.pump(e+1, l.settle, 50)
}

// errPins fails every Get of one key with an error other than ErrMissing.
type errPins struct {
	settle.Pins
	key string
}

var errPin = errors.New("pin answered with an error")

func (p *errPins) Get(ctx context.Context, k string, max int) ([]byte, error) {
	if k == p.key {
		return nil, errPin
	}
	return p.Pins.Get(ctx, k, max)
}

// TestFetchAnyError: a pin that answers with any error starts the fetch
// timeout like a missing object; the first sight is kept in the Store, so a
// restarted settler keeps counting from it.
func TestFetchAnyError(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a := w.nodes[0]
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(a.m.Pending().Commit())
	pins := &errPins{Pins: w.pins, key: settle.ObjectKey(h)}
	for _, n := range w.nodes[1:4] {
		ad, err := NewAdmin(n.dev.ID, n.order, n.m, Options{Pins: pins, Now: w.clock})
		if err != nil {
			t.Fatal(err)
		}
		n.admin = ad
	}
	l.settle()
	step := func() {
		for _, n := range w.admins() {
			if _, err := n.admin.Step(w.ctx); err != nil {
				t.Fatalf("%s: %v", n.name, err)
			}
		}
		l.settle()
	}
	step()
	s := w.nodes[1]
	if _, votes, _, _ := s.order.Entries(w.gid, e); len(votes) != 1 || !votes[0].Accept {
		t.Fatalf("%d votes before the timeout", len(votes))
	}
	first, err := s.admin.NextDeadline()
	if err != nil || !first.Equal(w.now.Add(DefaultFetchTimeout)) {
		t.Fatalf("deadline %v: %v", first, err)
	}
	w.now = w.now.Add(DefaultFetchTimeout)
	// Restarted settlers keep the first sight.
	for _, n := range w.nodes[1:4] {
		ad, err := NewAdmin(n.dev.ID, n.order, n.m, Options{Pins: pins, Now: w.clock})
		if err != nil {
			t.Fatal(err)
		}
		n.admin = ad
	}
	step()
	step()
	_, votes, _, _ := s.order.Entries(w.gid, e)
	rejects := 0
	for _, v := range votes {
		if !v.Accept && v.Reason == ReasonUnavailable {
			rejects++
		}
	}
	if rejects != 3 || a.m.Pending() != nil {
		t.Fatalf("%d reject votes", rejects)
	}
	w.now = w.now.Add(time.Second)
	if d, err := s.admin.NextDeadline(); err != nil || !d.IsZero() {
		t.Fatalf("deadline after the vote: %v %v", d, err)
	}
}

// TestRevokedSettlerIgnored: the reference and votes that an admin and
// settler writes after its revocation are rejected at their positions, at
// every settler alike.
func TestRevokedSettlerIgnored(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a, stolen, away := w.nodes[0], w.nodes[3], w.nodes[2]
	r, err := stolen.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: stolen.dev.Person.PublicKey(), Device: stolen.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	(&memEnv{log: l}).revoke(r)
	away.online = false
	e := a.m.Epoch()
	if _, err := stolen.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	theirs := sha256.Sum256(stolen.m.Pending().Commit())
	l.settle()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		for _, n := range w.admins() {
			if n.online {
				if _, err := n.admin.Step(w.ctx); err != nil {
					t.Fatal(err)
				}
			}
		}
		l.settle()
	}
	if a.m.Epoch() != e {
		t.Fatal("the revoked settler's vote counted")
	}
	if _, sigs, _ := a.order.Own(w.gid, e); len(sigs) != 0 {
		t.Fatal("a Commit was decided with the revoked settler's vote")
	}
	_, votes, _, _ := a.order.Entries(w.gid, e)
	for _, v := range votes {
		if v.Commit == theirs && v.Writer != stolen.dev.Key() {
			t.Fatal("a settler voted on the revoked admin's reference")
		}
	}
	away.online = true
	w.pump(e+1, l.settle, 50)
}

// TestCatchUpRefusals: a pin that serves another epoch's SettledCommit
// stops catch-up with an error instead of looping; archived values that do
// not match their keys, or past the bound of one message, are reported while
// the epochs are still applied.
func TestCatchUpRefusals(t *testing.T) {
	w, l := memGroup(t, 5)
	a, m1, m2, m3, m4 := w.nodes[0], w.nodes[1], w.nodes[2], w.nodes[3], w.nodes[4]
	e := a.m.Epoch()
	for _, n := range []*node{m1, m2, m3, m4} {
		n.online = false
	}
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	w.send(a, "epoch two")
	w.send(a, "epoch 2b")
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	good := w.mustGet(settle.SettledKey(w.gid, e+1))
	old := w.mustGet(settle.SettledKey(w.gid, e))
	if err := w.pins.Put(w.ctx, settle.SettledKey(w.gid, e+1), old); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(w.ctx, 10*time.Second)
	defer cancel()
	if _, err := m1.m.CatchUp(ctx, w.pins); !errors.Is(err, settle.ErrNotSettled) || m1.m.Epoch() != e+1 {
		t.Fatalf("stale SettledCommit: %v at epoch %d", err, m1.m.Epoch())
	}
	w.pins.Put(w.ctx, settle.SettledKey(w.gid, e+1), good)
	keys, _ := w.pins.List(w.ctx, settle.ArchivePrefix(w.gid, e+1), "", 0)
	msg := w.mustGet(keys[0])
	w.pins.Put(w.ctx, keys[0], append(bytes.Clone(msg), 0))
	if rs, err := m1.m.CatchUp(ctx, w.pins); !errors.Is(err, settle.ErrCatchUp) || len(rs) != 1 || m1.m.Epoch() != e+2 {
		t.Fatalf("a value that does not match its key: %d %v at epoch %d", len(rs), err, m1.m.Epoch())
	}
	w.pins.Put(w.ctx, keys[0], msg)
	// A pass of one key reads both messages; a bound under a message's
	// size cannot read it.
	for _, c := range []struct {
		n     *node
		max   int
		reads int
		err   bool
	}{{m2, 400, 2, false}, {m3, 100, 0, true}} {
		o := w.memberOptions(c.n)
		o.MaxCatchUpBytes = c.max
		c.n.m.Close()
		var err error
		if c.n.m, err = settle.OpenMember(c.n.st, w.gid, w.config(c.n), o); err != nil {
			t.Fatal(err)
		}
		if rs, err := c.n.m.CatchUp(ctx, w.pins); errors.Is(err, settle.ErrCatchUp) != c.err || len(rs) != c.reads || c.n.m.Epoch() != e+2 {
			t.Fatalf("bound %d: %d read, %v", c.max, len(rs), err)
		}
	}
	if rs, err := m4.m.CatchUp(ctx, w.pins); err != nil || len(rs) != 2 {
		t.Fatalf("catch-up: %d %v", len(rs), err)
	}
	for _, n := range []*node{m1, m2, m3, m4} {
		n.online = true
	}
	w.check()
}

// TestHaltPersists: a member that saw two settled Commits for one epoch
// stays halted after it is opened again.
func TestHaltPersists(t *testing.T) {
	w, l := memGroup(t, 2)
	a, m := w.nodes[0], w.nodes[1]
	e := a.m.Epoch()
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	settled := w.mustGet(settle.SettledKey(w.gid, e))
	s := w.mustDecode(settled)
	other := s.TBS
	other.Commit = sha256.Sum256([]byte("another"))
	sig, _ := Sign(a.dev.ID, &other)
	forged := (&settle.Settled{TBS: other, Shares: []settle.Share{{Signer: a.dev.Key(), Signature: [64]byte(sig)}}}).Encode()
	m.m.Close()
	reopened, err := settle.OpenMember(m.st, w.gid, w.config(m), w.memberOptions(m))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ApplySettled(forged, []byte("another")); !errors.Is(err, settle.ErrHalted) || !errors.Is(err, settle.ErrEquivocation) {
		t.Fatalf("second settled Commit after reopening: %v", err)
	}
	reopened.Close()
	if _, err := settle.OpenMember(m.st, w.gid, w.config(m), w.memberOptions(m)); !errors.Is(err, settle.ErrHalted) {
		t.Fatalf("a halted member opened again: %v", err)
	}
}

// TestHaltNeedsEvidence: a second SettledCommit for the epoch left halts a
// member only when it is of this group and q settlers signed it.
func TestHaltNeedsEvidence(t *testing.T) {
	w, l := fourAdmins(t, 1)
	a, m := w.nodes[0], w.memberNodes()[0]
	e := a.m.Epoch()
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	s := w.mustDecode(w.mustGet(settle.SettledKey(w.gid, e)))
	forge := func(gid []byte, signers ...*node) []byte {
		other := s.TBS
		other.GroupID = gid
		other.Commit = sha256.Sum256([]byte("another"))
		var shares []settle.Share
		for _, n := range signers {
			sig, _ := Sign(n.dev.ID, &other)
			shares = append(shares, settle.Share{Signer: n.dev.Key(), Signature: [64]byte(sig)})
		}
		slices.SortFunc(shares, func(x, y settle.Share) int { return bytes.Compare(x.Signer[:], y.Signer[:]) })
		return (&settle.Settled{TBS: other, Shares: shares}).Encode()
	}
	q := w.nodes[:3]
	if _, err := m.m.ApplySettled(forge(w.gid, q[0]), []byte("another")); errors.Is(err, settle.ErrHalted) {
		t.Fatal("halted on one signature of three needed")
	}
	other := bytes.Repeat([]byte{7}, 32)
	if _, err := m.m.ApplySettled(forge(other, q...), []byte("another")); errors.Is(err, settle.ErrHalted) || !errors.Is(err, settle.ErrNotSettled) {
		t.Fatalf("another group's SettledCommit: %v", err)
	}
	if _, err := m.m.Encrypt([]byte("still here"), nil); err != nil {
		t.Fatalf("member stopped: %v", err)
	}
	if _, err := m.m.ApplySettled(forge(w.gid, q...), []byte("another")); !errors.Is(err, settle.ErrHalted) {
		t.Fatalf("q signatures: %v", err)
	}
}

// TestOldSettled: a SettledCommit older than the epoch just left is
// ErrWrongEpoch.
func TestOldSettled(t *testing.T) {
	w, l := memGroup(t, 1)
	a, m := w.nodes[0], w.nodes[1]
	e := a.m.Epoch()
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	settled := w.mustGet(settle.SettledKey(w.gid, e))
	commit := w.mustObject(w.mustDecode(settled).TBS.Commit)
	if _, err := m.m.ApplySettled(settled, commit); !errors.Is(err, errs.ErrWrongEpoch) {
		t.Fatalf("two epochs back: %v", err)
	}
}

func TestBufferDropsOldest(t *testing.T) {
	w, l := memGroup(t, 2)
	a, m := w.nodes[0], w.nodes[1]
	e := a.m.Epoch()
	m.online = false
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	var msgs [][]byte
	for _, d := range []string{"one", "two", "six"} {
		msgs = append(msgs, w.send(a, d))
	}
	o := w.memberOptions(m)
	o.MaxBufferedBytes = len(msgs[0]) + len(msgs[1])
	m.m.Close()
	mm, err := settle.OpenMember(m.st, w.gid, w.config(m), o)
	if err != nil {
		t.Fatal(err)
	}
	m.m = mm
	for _, msg := range msgs {
		if _, err := mm.Receive(msg); !errors.Is(err, settle.ErrBuffered) {
			t.Fatal(err)
		}
	}
	settled := w.mustGet(settle.SettledKey(w.gid, e))
	s := w.mustDecode(settled)
	c := w.mustObject(s.TBS.Commit)
	rs, err := mm.ApplySettled(settled, c)
	if err != nil || len(rs) != 2 || string(rs[0].Application) != "two" || string(rs[1].Application) != "six" {
		t.Fatalf("kept %d: %v", len(rs), err)
	}
	m.online = true
}

// failOrder fails Append while fail is set.
type failOrder struct {
	Order
	fail bool
}

func (o *failOrder) Append(ctx context.Context, b []byte) error {
	if o.fail {
		return errors.New("braid write failed")
	}
	return o.Order.Append(ctx, b)
}

// TestReferenceRetry: a failed reference keeps the Commit pending, and
// Reference writes it again.
func TestReferenceRetry(t *testing.T) {
	w, l := memGroup(t, 2)
	a := w.nodes[0]
	fo := &failOrder{Order: a.order, fail: true}
	a.admin = nil
	w.makeAdmin(a, fo)
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err == nil {
		t.Fatal("the failed write was not reported")
	}
	if a.m.Pending() == nil {
		t.Fatal("the Commit was dropped")
	}
	fo.fail = false
	if err := a.admin.Reference(w.ctx); err != nil {
		t.Fatal(err)
	}
	w.pump(e+1, l.settle, 50)
	w.check()
	if err := a.admin.Reference(w.ctx); !errors.Is(err, errs.ErrPendingCommit) {
		t.Fatalf("nothing pending: %v", err)
	}
}

// TestSealedTree: two sealers of one epoch use two keys; a blob opens only
// for its group and epoch; an oversized blob is refused before decryption.
func TestSealedTree(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a, b := w.nodes[0], w.nodes[1]
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	sa, err := settle.SealTree(a.m)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := settle.SealTree(b.m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sa[32:], sb[32:]) || !bytes.Equal(sa[:32], a.dev.ID.PublicKey()) {
		t.Fatal("two sealers made the same ciphertext")
	}
	for _, s := range [][]byte{sa, sb} {
		if _, err := settle.OpenTree(a.m.Export, w.gid, a.m.Epoch(), s); err != nil {
			t.Fatal(err)
		}
		if _, err := settle.OpenTree(a.m.Export, w.gid, a.m.Epoch()+1, s); !errors.Is(err, settle.ErrSealedTree) {
			t.Fatalf("another epoch: %v", err)
		}
	}
	if _, err := settle.OpenTree(a.m.Export, w.gid, a.m.Epoch(), sa[:20]); !errors.Is(err, settle.ErrSealedTree) {
		t.Fatalf("short blob: %v", err)
	}
	j := w.device("joiner", nil)
	e := a.m.Epoch()
	welcome, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Add: [][]byte{j.dev.KeyPackage(t, j.st)}})
	if err != nil {
		t.Fatal(err)
	}
	w.pump(e+1, l.settle, 50)
	settled := w.mustGet(settle.SettledKey(w.gid, e))
	huge := func(_ []byte, _ uint64, max int) ([]byte, error) {
		if max != 900+48 {
			t.Errorf("tree read with bound %d", max)
		}
		return make([]byte, 1000), nil
	}
	if _, err := settle.JoinMember(j.st, welcome, settled, huge, kolomls.JoinOptions{Config: w.config(j), MaxTreeBytes: 900}, w.memberOptions(j)); !errors.Is(err, errs.ErrInvalidTree) {
		t.Fatalf("oversized blob: %v", err)
	}
}

// TestAdminChecks: NewAdmin and Succeed refuse what would break their
// records or settings; Index refuses an out-of-range read.
func TestAdminChecks(t *testing.T) {
	w, _ := memGroup(t, 1)
	a, m := w.nodes[0], w.nodes[1]
	for name, o := range map[string]Options{"no clock": {Pins: w.pins}, "negative timeout": {Pins: w.pins, Now: w.clock, FetchTimeout: -1}, "no pins": {Now: w.clock}} {
		if _, err := NewAdmin(a.dev.ID, a.order, a.m, o); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := NewAdmin(m.dev.ID, a.order, a.m, Options{Pins: w.pins, Now: w.clock}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("another device's identity: %v", err)
	}
	co := a.dev.CreateOptions(t, a.st, w.config(a), []tls.Extension{{Type: 1}})
	if _, _, err := a.admin.Succeed(w.ctx, a.order, a.st, SucceedOptions{Create: co, Admin: Options{Pins: w.pins, Now: w.clock}}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("Succeed with extensions: %v", err)
	}
	if _, err := a.m.Commit(kolomls.CommitOptions{RatchetTree: true}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("a Welcome with the tree: %v", err)
	}
	idx := NewIndex([]byte("mls/"), nil)
	if _, _, _, err := idx.Entries(nil, []byte{1}, 0); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("short group id: %v", err)
	}
	if _, _, _, err := idx.Entries(nil, w.gid, ^uint64(0)); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("last epoch: %v", err)
	}
}

// TestEntryRefusals: a reason above a byte and a signature entry whose
// signed bytes do not decode are invalid entries, not unsettled Commits.
func TestEntryRefusals(t *testing.T) {
	gid := bytes.Repeat([]byte{1}, 32)
	var e kolocodec.Encoder
	e.PutString(voteTag)
	e.PutBytes([]byte("cert"))
	e.PutBytes(gid)
	e.PutUvarint(3)
	e.PutFixed(make([]byte, 64))
	e.PutBool(false)
	e.PutUvarint(256)
	if _, ok, err := decodeEntry(e.Bytes()); !ok || !errors.Is(err, ErrEntry) {
		t.Fatalf("reason 256: %v", err)
	}
	_, ok, err := decodeEntry(sigBody([]byte("cert"), &settle.TBS{GroupID: []byte{1}}, make([]byte, 64)))
	if !ok || !errors.Is(err, ErrEntry) || errors.Is(err, settle.ErrNotSettled) || !strings.Contains(err.Error(), "signed bytes") {
		t.Fatalf("bad TBS: %v", err)
	}
}

// TestRecordsGoWithRemoval: a member that a Commit removes deletes the
// record of the epoch it left at once, and an admin its records at its next
// Step.
func TestRecordsGoWithRemoval(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a, gone := w.nodes[0], w.nodes[1]
	var three []ed25519.PublicKey
	var rest []*node
	for _, n := range []*node{w.nodes[0], w.nodes[2], w.nodes[3]} {
		three = append(three, n.dev.ID.PublicKey())
		rest = append(rest, n)
	}
	roles, _ := settle.RolesOf(a.m.Extensions(), w.limits)
	next, err := settle.NewRoles(roles.Braid, settle.Majority, three, three, w.limits)
	if err != nil {
		t.Fatal(err)
	}
	(&memEnv{log: l}).seat(w, rest, settle.Majority)
	if _, err := gone.st.Get(recordKey(w.gid, "last")); err != nil {
		t.Fatalf("no record of the epoch left: %v", err)
	}
	w.commit(a, kolomls.CommitOptions{Remove: []uint32{gone.m.OwnLeaf()}, SetExtensions: true, Extensions: mustExts(t, next)}, l.settle)
	if _, err := gone.st.Get(recordKey(w.gid, "last")); !errors.Is(err, errs.ErrNotFound) {
		t.Fatalf("a removed member keeps its last epoch: %v", err)
	}
	if err := gone.st.Apply(kolomls.Batch{Put: []kolomls.KV{{Key: recordKey(w.gid, "vote"), Value: make([]byte, 8)}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := gone.admin.Step(w.ctx); !errors.Is(err, errs.ErrRemoved) {
		t.Fatalf("removed admin: %v", err)
	}
	for _, name := range recordNames {
		if _, err := gone.st.Get(recordKey(w.gid, name)); !errors.Is(err, errs.ErrNotFound) {
			t.Fatalf("%s record kept", name)
		}
	}
}

// TestMemberExpire: the Member drives the previous-epoch window.
func TestMemberExpire(t *testing.T) {
	w, l := memGroup(t, 2)
	a, m := w.nodes[0], w.nodes[1]
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	end, err := m.m.ExpirePastEpoch()
	if err != nil || !end.Equal(w.now.Add(kolomls.DefaultPastEpochWindow)) {
		t.Fatalf("end %v: %v", end, err)
	}
	w.now = end
	if end, err := m.m.ExpirePastEpoch(); err != nil || !end.IsZero() {
		t.Fatalf("after the end: %v %v", end, err)
	}
}

// boundPins records the bound of every archive read.
type boundPins struct {
	settle.Pins
	gets  map[string]int
	lists []int
}

func (p *boundPins) Get(ctx context.Context, k string, max int) ([]byte, error) {
	if strings.Contains(k, "/archive/") {
		p.gets[k] = max
	}
	return p.Pins.Get(ctx, k, max)
}

func (p *boundPins) List(ctx context.Context, prefix, after string, max int) ([]string, error) {
	p.lists = append(p.lists, max)
	return p.Pins.List(ctx, prefix, after, max)
}

// settledBoundPins records the bound of each SettledCommit read.
type settledBoundPins struct {
	settle.Pins
	bounds []int
}

func (p *settledBoundPins) Get(ctx context.Context, k string, max int) ([]byte, error) {
	if strings.Contains(k, "/settled/") {
		p.bounds = append(p.bounds, max)
	}
	return p.Pins.Get(ctx, k, max)
}

// TestSettledBoundFollowsSettlers: even when the Policy's cap on settlers is
// huge, catch-up reads a SettledCommit of at most one signature per settler.
func TestSettledBoundFollowsSettlers(t *testing.T) {
	w := newWorld(t)
	w.limits = settle.Limits{MaxSettlers: 1 << 20}
	l := newLog(1)
	founder := w.device("admin", nil)
	w.create(founder, &memOrder{l: l, me: founder.dev.Key()})
	joiner := w.device("membera", nil)
	w.join(founder, l.settle, joiner)
	joiner.online = false
	e := founder.m.Epoch()
	w.commit(founder, kolomls.CommitOptions{}, l.settle)
	roles, err := settle.RolesOf(founder.m.Extensions(), settle.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	p := &settledBoundPins{Pins: w.pins}
	if _, err := joiner.m.CatchUp(w.ctx, p); err != nil || joiner.m.Epoch() != e+1 {
		t.Fatalf("catch-up: %v at epoch %d", err, joiner.m.Epoch())
	}
	want := 512 + 96*len(roles.Settlers)
	if len(p.bounds) == 0 || p.bounds[0] != want {
		t.Fatalf("bounds %v, want %d first", p.bounds, want)
	}
}

// TestCatchUpBoundsEveryRead: with a positive MaxCatchUpBytes, catch-up
// never asks pins for an unbounded archive value or key list, also when the
// values read so far fill the bound exactly or the bound is below the
// smallest message; the epoch is still applied.
func TestCatchUpBoundsEveryRead(t *testing.T) {
	for _, max := range []int{1000, 100} {
		w, l := memGroup(t, 2)
		a, m1 := w.nodes[0], w.nodes[1]
		e := a.m.Epoch()
		m1.online = false
		w.commit(a, kolomls.CommitOptions{}, l.settle)
		prefix := settle.ArchivePrefix(w.gid, e)
		if err := w.pins.Put(w.ctx, prefix+"00", make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
		if err := w.pins.Put(w.ctx, prefix+"01", make([]byte, 50000)); err != nil {
			t.Fatal(err)
		}
		o := w.memberOptions(m1)
		o.MaxCatchUpBytes = max
		m1.m.Close()
		var err error
		if m1.m, err = settle.OpenMember(m1.st, w.gid, w.config(m1), o); err != nil {
			t.Fatal(err)
		}
		p := &boundPins{Pins: w.pins, gets: map[string]int{}}
		if _, err := m1.m.CatchUp(w.ctx, p); !errors.Is(err, settle.ErrCatchUp) || m1.m.Epoch() != e+1 {
			t.Fatalf("bound %d: %v at epoch %d", max, err, m1.m.Epoch())
		}
		for k, v := range p.gets {
			if v <= 0 {
				t.Errorf("bound %d: archive Get of %s with max %d", max, k[len(prefix):], v)
			}
		}
		for _, v := range p.lists {
			if v <= 0 {
				t.Errorf("bound %d: archive List with max %d", max, v)
			}
		}
		m1.online = true
		w.check()
	}
}

// TestStageRefusesNonCommit: a reference to an application message, a
// proposal or a message of the previous epoch is voted invalid before any
// settler processes it, so none uses up a key or caches a proposal.
func TestStageRefusesNonCommit(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a, x, s := w.nodes[0], w.nodes[1], w.nodes[2]
	steps := func() {
		for range 5 {
			for _, n := range w.admins() {
				if _, err := n.admin.Step(w.ctx); err != nil {
					t.Fatalf("%s: %v", n.name, err)
				}
			}
			l.settle()
		}
	}
	refused := func(name string, e uint64, msg []byte) {
		t.Helper()
		roles, err := settle.RolesOf(a.m.Extensions(), a.m.Limits())
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(msg)
		_, votes, _, _ := s.order.Entries(w.gid, e)
		n := 0
		for _, v := range votes {
			if v.Commit != h {
				continue
			}
			if v.Accept || v.Reason != ReasonInvalid {
				t.Fatalf("%s: vote %+v", name, v)
			}
			n++
		}
		if n < roles.RejectQuorum() {
			t.Fatalf("%s: %d invalid votes", name, n)
		}
	}
	e := a.m.Epoch()
	app, err := x.m.Encrypt([]byte("for everyone"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.admin.Refer(w.ctx, app); err != nil {
		t.Fatal(err)
	}
	steps()
	refused("application", e, app)
	if r, err := s.m.Receive(app); err != nil || string(r.Application) != "for everyone" {
		t.Fatalf("settler reads the referenced message: %v", err)
	}
	leave, err := x.m.Leave()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.admin.Refer(w.ctx, leave); err != nil {
		t.Fatal(err)
	}
	steps()
	refused("proposal", e, leave)
	if _, err := s.m.Encrypt([]byte("no proposal cached"), nil); err != nil {
		t.Fatalf("settler after a referenced proposal: %v", err)
	}
	late, err := w.nodes[3].m.Encrypt([]byte("late"), nil)
	if err != nil {
		t.Fatal(err)
	}
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	if err := a.admin.Refer(w.ctx, late); err != nil {
		t.Fatal(err)
	}
	steps()
	refused("previous epoch", e+1, late)
	if r, err := s.m.Receive(late); err != nil || string(r.Application) != "late" {
		t.Fatalf("settler reads the referenced message of the previous epoch: %v", err)
	}
}

// TestSettledCountsEachSettlerOnce: copies of one settler's share count
// once in Valid, and Check refuses them as fewer than q signatures.
func TestSettledCountsEachSettlerOnce(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a := w.nodes[0]
	e := a.m.Epoch()
	roles, err := settle.RolesOf(a.m.Extensions(), a.m.Limits())
	if err != nil {
		t.Fatal(err)
	}
	before := a.m.GroupContext()
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	s := w.mustDecode(w.mustGet(settle.SettledKey(w.gid, e)))
	commit := w.mustGet(settle.ObjectKey(s.TBS.Commit))
	all := func([32]byte) bool { return true }
	if err := s.Check(before, commit, w.gid, e, roles, all); err != nil {
		t.Fatal(err)
	}
	dup := &settle.Settled{TBS: s.TBS}
	for range roles.Q() {
		dup.Shares = append(dup.Shares, s.Shares[0])
	}
	if n := dup.Valid(roles, all); n != 1 {
		t.Errorf("Valid of %d copies of one share: %d", roles.Q(), n)
	}
	if err := dup.Check(before, commit, w.gid, e, roles, all); !errors.Is(err, settle.ErrNotSettled) {
		t.Errorf("Check of %d copies of one share: %v", roles.Q(), err)
	}
}

// TestNextDeadlineAfterDecision: a settler waits for nothing once it voted
// on the candidate, or once the others rejected it before its own fetch
// timeout ran out, so NextDeadline gives no past time.
func TestNextDeadlineAfterDecision(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a, s1, s2, late := w.nodes[0], w.nodes[1], w.nodes[2], w.nodes[3]
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	pins := &errPins{Pins: w.pins, key: settle.ObjectKey(sha256.Sum256(a.m.Pending().Commit()))}
	for _, n := range w.nodes[1:4] {
		ad, err := NewAdmin(n.dev.ID, n.order, n.m, Options{Pins: pins, Now: w.clock})
		if err != nil {
			t.Fatal(err)
		}
		n.admin = ad
	}
	l.settle()
	step := func(ns ...*node) {
		for _, n := range ns {
			if _, err := n.admin.Step(w.ctx); err != nil {
				t.Fatalf("%s: %v", n.name, err)
			}
		}
		l.settle()
	}
	step(a, s1, s2)
	w.now = w.now.Add(DefaultFetchTimeout / 2)
	step(late)
	if d, err := late.admin.NextDeadline(); err != nil || !d.Equal(w.now.Add(DefaultFetchTimeout)) {
		t.Fatalf("deadline while waiting: %v %v", d, err)
	}
	w.now = w.now.Add(DefaultFetchTimeout / 2)
	step(s1)
	w.now = w.now.Add(time.Second)
	if d, err := s1.admin.NextDeadline(); err != nil || !d.IsZero() {
		t.Fatalf("deadline after the vote, the candidate still open: %v %v", d, err)
	}
	step(s2)
	if _, votes, _, _ := late.order.Entries(w.gid, e); len(votes) != 3 {
		t.Fatalf("%d votes", len(votes))
	}
	w.now = w.now.Add(DefaultFetchTimeout)
	step(late)
	if d, err := late.admin.NextDeadline(); err != nil || (!d.IsZero() && !d.After(w.now)) {
		t.Fatalf("deadline after the candidate was rejected: %v (now %v) %v", d, w.now, err)
	}
}

// otherBraid is an Order whose ID is not the braid the roles name.
type otherBraid struct {
	Order
	id [32]byte
}

func (o *otherBraid) ID() [32]byte { return o.id }

// TestAdminChecksBraid: an Admin over an order that is not the braid the
// roles name is refused, in NewAdmin and in Step.
func TestAdminChecksBraid(t *testing.T) {
	w, _ := memGroup(t, 1)
	a := w.nodes[0]
	o := &otherBraid{Order: a.order, id: sha256.Sum256([]byte("another braid"))}
	if _, err := NewAdmin(a.dev.ID, o, a.m, Options{Pins: w.pins, Now: w.clock}); !errors.Is(err, ErrRoster) {
		t.Fatalf("NewAdmin over another braid: %v", err)
	}
	o.id = a.order.ID()
	ad, err := NewAdmin(a.dev.ID, o, a.m, Options{Pins: w.pins, Now: w.clock})
	if err != nil {
		t.Fatal(err)
	}
	o.id = sha256.Sum256([]byte("another braid"))
	if _, err := ad.Step(w.ctx); !errors.Is(err, ErrRoster) {
		t.Fatalf("Step over another braid: %v", err)
	}
}
