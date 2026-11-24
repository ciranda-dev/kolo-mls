package braid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	kolobraid "github.com/ciranda-dev/kolo-braid"
	kolostore "github.com/ciranda-dev/kolo-store"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/backendstore"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/kolotest"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// TestMemberBuffer: a message of the next epoch is kept within the bound
// and read once that epoch starts; one further ahead is not kept.
func TestMemberBuffer(t *testing.T) {
	w, l := memGroup(t, 2)
	a, m1, m2 := w.nodes[0], w.nodes[1], w.nodes[2]
	e := a.m.Epoch()
	m2.online = false
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	next := w.send(a, "next epoch")
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	later := w.send(a, "two ahead")
	if _, err := m2.m.Receive(next); !errors.Is(err, settle.ErrBuffered) {
		t.Fatalf("next epoch: %v", err)
	}
	if _, err := m2.m.Receive(later); !errors.Is(err, errs.ErrFutureEpoch) {
		t.Fatalf("two epochs ahead: %v", err)
	}
	if _, err := m2.m.Receive([]byte{1}); err == nil {
		t.Fatal("garbage accepted")
	}
	settled := w.mustGet(settle.SettledKey(w.gid, e))
	h := w.mustDecode(settled)
	commit := w.mustObject(h.TBS.Commit)
	rs, err := m2.m.ApplySettled(settled, commit)
	if err != nil || len(rs) != 1 || string(rs[0].Application) != "next epoch" {
		t.Fatalf("redelivered %d: %v", len(rs), err)
	}
	// Already applied: nothing to do.
	if rs, err := m2.m.ApplySettled(settled, commit); err != nil || rs != nil {
		t.Fatalf("again: %v", err)
	}
	// A later SettledCommit is for after catching up.
	far := w.mustGet(settle.SettledKey(w.gid, e+1))
	m2.m.Close()
	mm2, err := settle.OpenMember(m2.st, w.gid, w.config(m2), w.memberOptions(m2))
	if err != nil {
		t.Fatal(err)
	}
	m2.m = mm2
	if g := m2.m; g.Epoch() != e+1 {
		t.Fatalf("reopened at epoch %d", g.Epoch())
	}
	fh := w.mustDecode(far)
	fc := w.mustObject(fh.TBS.Commit)
	if _, err := m2.m.ApplySettled(far, fc); err != nil {
		t.Fatalf("next: %v", err)
	}
	m2.online = true
	w.check()

	// The bound: nothing is kept with a negative bound, and a message past
	// the bound is not kept.
	for _, max := range []int{-1, len(next) - 1} {
		o := w.memberOptions(m1)
		o.MaxBufferedBytes = max
		mm, err := settle.OpenMember(m1.st, w.gid, w.config(m1), o)
		if err != nil {
			t.Fatal(err)
		}
		m1.m.Close()
		m1.m = mm
		m1.online = false
		w.commit(a, kolomls.CommitOptions{}, l.settle)
		msg := w.send(a, "not kept")
		if _, err := mm.Receive(msg); !errors.Is(err, errs.ErrFutureEpoch) {
			t.Fatalf("bound %d: %v", max, err)
		}
		if err := w.catchUpNode(m1); err != nil {
			t.Fatal(err)
		}
		m1.online = true
	}
}

func (w *world) catchUpNode(n *node) error {
	_, err := n.m.CatchUp(w.ctx, w.pins)
	return err
}

// TestMemberRefusals: a Commit is not processed outside ApplySettled; a
// SettledCommit whose proposals are missing waits for them; a non-Kolo
// configuration is refused.
func TestMemberRefusals(t *testing.T) {
	w, l := memGroup(t, 2)
	a, m1 := w.nodes[0], w.nodes[1]
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	commit := a.m.Pending().Commit()
	if _, err := m1.m.Receive(commit); !errors.Is(err, settle.ErrNotSettled) {
		t.Fatalf("Commit through Receive: %v", err)
	}
	w.pump(e+1, l.settle, 50)
	w.check()

	// A device that never read a member's leave proposal applies the
	// removal: the admin commits it by value.
	leaver := w.nodes[2]
	m1.online = false
	w.proposeLeave(leaver)
	e = a.m.Epoch()
	w.commit(a, kolomls.CommitOptions{Remove: []uint32{leaver.m.OwnLeaf()}}, l.settle)
	settled := w.mustGet(settle.SettledKey(w.gid, e))
	h := w.mustDecode(settled)
	c2 := w.mustObject(h.TBS.Commit)
	m1.online = true
	if _, err := m1.m.ApplySettled(settled, c2); err != nil {
		t.Fatalf("without the proposal: %v", err)
	}

	st := w.device("x", nil)
	cfg := w.config(st)
	cfg.PrivateHandshakes = false
	if _, err := settle.OpenMember(st.st, w.gid, cfg, settle.MemberOptions{}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("public handshakes: %v", err)
	}
	cfg = w.config(st)
	cfg.Envelope = nil
	if _, err := settle.OpenMember(st.st, w.gid, cfg, settle.MemberOptions{}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("no envelope: %v", err)
	}
	cfg = w.config(st)
	cfg.Authenticator = nil
	if _, err := settle.OpenMember(st.st, w.gid, cfg, settle.MemberOptions{}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("another Authenticator: %v", err)
	}
	co := st.dev.CreateOptions(t, st.st, w.config(st), nil)
	if _, err := settle.CreateMember(st.st, co, settle.MemberOptions{}); !errors.Is(err, settle.ErrRule) {
		t.Fatalf("a group without the Kolo extensions: %v", err)
	}
}

// TestReferenceRefused: a Commit that names a proposal by reference is
// refused, by the committing admin and by every settler.
func TestReferenceRefused(t *testing.T) {
	w, l := memGroup(t, 3)
	a, leaver := w.nodes[0], w.nodes[3]
	_, ref := w.proposeLeave(leaver)
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{References: [][]byte{ref}}); !errors.Is(err, settle.ErrRule) {
		t.Fatalf("by reference: %v", err)
	}
	w.commit(a, kolomls.CommitOptions{Remove: []uint32{leaver.m.OwnLeaf()}}, l.settle)
	if !leaver.m.Removed() {
		t.Fatal("leaver not removed")
	}
}

// TestMemberOwnCommit: a member's own Commit is applied from its pending
// record, and refused when the settlers signed another GroupContext.
func TestMemberOwnCommit(t *testing.T) {
	w, l := memGroup(t, 2)
	a, m := w.nodes[0], w.nodes[1]
	e := a.m.Epoch()
	pc, err := m.m.Commit(kolomls.CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.admin.Refer(w.ctx, pc.Commit()); err != nil {
		t.Fatal(err)
	}
	roles, _ := settle.RolesOf(a.m.Extensions(), w.limits)
	bad := settle.TBS{GroupID: w.gid, Epoch: e, Commit: sha256.Sum256(pc.Commit()), ContextBefore: sha256.Sum256(m.m.GroupContext()), ContextAfter: sha256.Sum256([]byte("x")), Braid: roles.Braid}
	sig, _ := Sign(a.dev.ID, &bad)
	s := Assemble(&bad, []settle.Share{{Signer: a.dev.Key(), Signature: [64]byte(sig)}}, roles)
	if _, err := m.m.ApplySettled(s.Encode(), pc.Commit()); !errors.Is(err, settle.ErrSettledMismatch) {
		t.Fatalf("own Commit with another GroupContext: %v", err)
	}
	if m.m.Pending() == nil || m.m.Epoch() != e {
		t.Fatal("state changed")
	}
	w.pump(e+1, l.settle, 50)
	w.check()
	if w.applied[e]["admin"] != sha256.Sum256(pc.Commit()) {
		t.Fatal("the member's own key update was not the Commit applied")
	}
}

// TestFetchTimeout: a settler waits FetchTimeout for a Commit that is not on
// pins, then votes reject; the committer drops its rejected Commit.
func TestFetchTimeout(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a := w.nodes[0]
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(a.m.Pending().Commit())
	w.pins.drop(settle.ObjectKey(h))
	l.settle()
	step := func() {
		for _, n := range w.admins() {
			if _, err := n.admin.Step(w.ctx); err != nil {
				t.Fatal(err)
			}
		}
		l.settle()
	}
	for range 5 {
		step()
	}
	_, votes, _, _ := w.nodes[1].order.Entries(w.gid, e)
	if len(votes) != 1 || !votes[0].Accept {
		t.Fatalf("before the timeout: %d votes", len(votes))
	}
	w.now = w.now.Add(DefaultFetchTimeout - time.Nanosecond)
	step()
	if _, votes, _, _ := w.nodes[1].order.Entries(w.gid, e); len(votes) != 1 {
		t.Fatal("voted before the timeout")
	}
	w.now = w.now.Add(time.Nanosecond)
	for range 3 {
		step()
	}
	_, votes, _, _ = w.nodes[1].order.Entries(w.gid, e)
	rejects := 0
	for _, v := range votes {
		if !v.Accept && v.Reason == ReasonUnavailable {
			rejects++
		}
	}
	if rejects != 3 || a.m.Pending() != nil || a.m.Epoch() != e {
		t.Fatalf("%d reject votes", rejects)
	}
	w.commit(a, kolomls.CommitOptions{}, l.settle)
}

// TestEntries round-trips each braid entry and refuses malformed ones.
func TestEntries(t *testing.T) {
	tc := []byte("cert")
	gid := bytes.Repeat([]byte{1}, 32)
	tbs := &settle.TBS{GroupID: gid, Epoch: 3, RefPosition: 9}
	for _, b := range [][]byte{
		refBody(tc, gid, 3, [32]byte{2}),
		voteBody(tc, gid, 3, [32]byte{2}, [32]byte{6}, true, 0),
		voteBody(tc, gid, 3, [32]byte{2}, [32]byte{6}, false, ReasonUnavailable),
		sigBody(tc, tbs, make([]byte, 64)),
	} {
		e, ok, err := decodeEntry(b)
		if !ok || err != nil || !bytes.Equal(e.groupID, gid) || e.epoch != 3 {
			t.Fatalf("round trip: %v", err)
		}
	}
	if _, ok, _ := decodeEntry([]byte("kolo-braid/kv/v0")); ok {
		t.Fatal("another body taken")
	}
	for name, b := range map[string][]byte{
		"short group id":   refBody(tc, []byte{1}, 3, [32]byte{}),
		"trailing":         append(refBody(tc, gid, 3, [32]byte{}), 0),
		"vote bool":        append(voteBody(tc, gid, 3, [32]byte{}, [32]byte{}, true, 0)[:len(voteBody(tc, gid, 3, [32]byte{}, [32]byte{}, true, 0))-2], 2, 0),
		"short signature":  sigBody(tc, tbs, make([]byte, 10)),
		"bad TBS":          sigBody(tc, &settle.TBS{GroupID: []byte{1}}, make([]byte, 64)),
		"truncated vote":   voteBody(tc, gid, 3, [32]byte{}, [32]byte{}, true, 0)[:40],
		"truncated commit": refBody(tc, gid, 3, [32]byte{})[:50],
		"no certificate":   refBody(nil, gid, 3, [32]byte{}),
	} {
		if _, ok, err := decodeEntry(b); !ok || !errors.Is(err, ErrEntry) {
			t.Errorf("%s: %v %v", name, ok, err)
		}
	}
}

// TestIndex: the apply function records kolo-mls entries by group, epoch
// and position, rejects malformed ones and those whose certificate is not
// the writer's on every peer, and leaves others.
func TestIndex(t *testing.T) {
	idx := NewIndex([]byte("mls/"), nil)
	gid := bytes.Repeat([]byte{1}, 32)
	apply := func(tx *kolobraid.Tx, e *kolobraid.Entry) error {
		if ok, err := idx.Apply(tx, e); ok || err != nil {
			return err
		}
		return tx.Put([]byte("other"), e.Body)
	}
	dev := kolotest.NewDevice(t, kolotest.Person(t), true)
	other := kolotest.NewDevice(t, kolotest.Person(t), true)
	id, cert := dev.ID, dev.Cert.Encode()
	b, err := kolobraid.Create(context.Background(), id, kolobraid.GroupConfig{App: testApp}, kolobraid.Options{Backend: kolostore.NewMemory(), App: testApp, Apply: apply, Limits: braidLimits()})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, body := range [][]byte{refBody(cert, gid, 1, [32]byte{2}), voteBody(cert, gid, 1, [32]byte{2}, [32]byte{3}, true, 0), []byte("not ours"), append(refBody(cert, gid, 1, [32]byte{2}), 0), refBody(other.Cert.Encode(), gid, 1, [32]byte{5}), refBody([]byte("not a certificate"), gid, 1, [32]byte{6}), refBody(cert, gid, 2, [32]byte{4})} {
		if _, err := b.Append(ctx, body); err != nil {
			t.Fatal(err)
		}
	}
	o := NewBraidOrder(b, idx, nil)
	for {
		refs, votes, _, err := o.Entries(gid, 1)
		if err != nil {
			t.Fatal(err)
		}
		s := b.Settled()
		other, _ := s.Get([]byte("other"))
		s.Close()
		later, _, _, err := o.Entries(gid, 2)
		if err != nil {
			t.Fatal(err)
		}
		// Every entry settled: the last one appended is in epoch 2.
		if len(refs) == 1 && len(votes) == 1 && string(other) == "not ours" && len(later) == 1 {
			if refs[0].Writer != [32]byte(id.PublicKey()) || refs[0].Position >= votes[0].Position {
				t.Fatal("writer or position")
			}
			break
		}
		if _, err := b.Next(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if mine, _, err := o.Own(gid, 1); err != nil || len(mine) != 1 {
		t.Fatalf("written: %v", err)
	}
	// The malformed kolo-mls body is rejected on every peer.
	rejected := 0
	for en, err := range b.Entries(0) {
		if err != nil {
			t.Fatal(err)
		}
		if en.Rejected {
			rejected++
		}
	}
	if rejected != 3 {
		t.Fatalf("%d entries rejected", rejected)
	}
	if revs, err := o.Revocations(dev.Cert); err != nil || revs != nil {
		t.Fatal("no roster")
	}
}

func TestNewAdminRefuses(t *testing.T) {
	if _, err := NewAdmin(nil, nil, nil, Options{}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatal(err)
	}
}

// TestBackendStoreOnDisk runs a group on kolo-store's on-disk backend, closes it and opens
// it again with the same state.
func TestBackendStoreOnDisk(t *testing.T) {
	w, l := memGroup(t, 1)
	a := w.nodes[0]
	dir := filepath.Join(t.TempDir(), "db")
	db, err := kolostore.OpenPebble(dir)
	if err != nil {
		t.Fatal(err)
	}
	j := w.device("disk", nil)
	j.backend, j.st = db, backendstore.New(db, []byte("mls/"))
	w.join(a, l.settle, j)
	w.send(j, "from disk")
	auth, _ := j.m.EpochAuthenticator()
	j.m.Close()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = kolostore.OpenPebble(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j.st = backendstore.New(db, []byte("mls/"))
	m, err := settle.OpenMember(j.st, w.gid, w.config(j), w.memberOptions(j))
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := m.EpochAuthenticator(); !bytes.Equal(again, auth) {
		t.Fatal("reopened state differs")
	}
	j.m = m
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	w.send(j, "after reopening")
}

// TestBackendStoreContract: deletes then puts in one atomic batch, a key in
// both refused, copies kept, ErrNotFound mapped.
func TestBackendStoreContract(t *testing.T) {
	b := kolostore.NewMemory()
	s := backendstore.New(b, []byte("p/"))
	if _, err := s.Get([]byte("k")); !errors.Is(err, errs.ErrNotFound) {
		t.Fatal(err)
	}
	v := []byte("value")
	if err := s.Apply(kolomls.Batch{Put: []kolomls.KV{{Key: []byte("k"), Value: v}}}); err != nil {
		t.Fatal(err)
	}
	clear(v)
	if got, err := s.Get([]byte("k")); err != nil || string(got) != "value" {
		t.Fatalf("copy: %q %v", got, err)
	}
	if err := s.Apply(kolomls.Batch{Put: []kolomls.KV{{Key: []byte("k"), Value: v}}, Delete: [][]byte{[]byte("k")}}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("key in both: %v", err)
	}
	if err := s.Apply(kolomls.Batch{Delete: [][]byte{[]byte("k")}, Put: []kolomls.KV{{Key: []byte("j"), Value: []byte("x")}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get([]byte("k")); !errors.Is(err, errs.ErrNotFound) {
		t.Fatal("not deleted")
	}
	other := backendstore.New(b, []byte("q/"))
	if _, err := other.Get([]byte("j")); !errors.Is(err, errs.ErrNotFound) {
		t.Fatal("prefix")
	}
}

// TestMemberFutureSettled: a SettledCommit two epochs ahead waits for the
// one before it.
func TestMemberFutureSettled(t *testing.T) {
	w, l := memGroup(t, 2)
	a, m := w.nodes[0], w.nodes[1]
	e := m.m.Epoch()
	m.online = false
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	w.commit(a, kolomls.CommitOptions{}, l.settle)
	far := w.mustGet(settle.SettledKey(w.gid, e+1))
	h := w.mustDecode(far)
	c := w.mustObject(h.TBS.Commit)
	if _, err := m.m.ApplySettled(far, c); !errors.Is(err, errs.ErrFutureEpoch) {
		t.Fatalf("two epochs ahead: %v", err)
	}
	if err := w.catchUpNode(m); err != nil {
		t.Fatal(err)
	}
	m.online = true
	w.check()
}

// failing is a Store that fails its writes while fail is set, after
// writing them when late is set too.
type failing struct {
	kolomls.Store
	fail, late bool
}

func (s *failing) Apply(b kolomls.Batch) error {
	if s.fail && !s.late {
		return errors.New("disk full")
	}
	if err := s.Store.Apply(b); err != nil {
		return err
	}
	if s.fail {
		return errors.New("acknowledgement lost")
	}
	return nil
}

// TestMemberStoreError: a write that fails leaves the Member to open its
// Group again from the Store; the Commit is then applied once.
func TestMemberStoreError(t *testing.T) {
	for _, late := range []bool{false, true} {
		w, l := memGroup(t, 2)
		a, m := w.nodes[0], w.nodes[1]
		fs := &failing{Store: m.st}
		mm, err := settle.OpenMember(fs, w.gid, w.config(m), w.memberOptions(m))
		if err != nil {
			t.Fatal(err)
		}
		m.m.Close()
		m.m = mm
		m.online = false
		e := a.m.Epoch()
		w.commit(a, kolomls.CommitOptions{}, l.settle)
		settled := w.mustGet(settle.SettledKey(w.gid, e))
		h := w.mustDecode(settled)
		c := w.mustObject(h.TBS.Commit)
		fs.fail, fs.late = true, late
		if _, err := mm.ApplySettled(settled, c); !errors.Is(err, errs.ErrStore) {
			t.Fatalf("late %v: %v", late, err)
		}
		fs.fail = false
		if _, err := mm.ApplySettled(settled, c); err != nil {
			t.Fatalf("late %v, after the failure: %v", late, err)
		}
		if mm.Epoch() != e+1 {
			t.Fatalf("late %v: epoch %d", late, mm.Epoch())
		}
		m.online = true
		w.check()
	}
}

// lagOrder hides this admin's writes from Written, as a braid that has not
// applied them yet.
type lagOrder struct {
	Order
	hide bool
}

func (o *lagOrder) Written(gid []byte, epoch uint64) ([]Vote, []Sig, error) {
	if o.hide {
		return nil, nil, nil
	}
	return o.Order.Own(gid, epoch)
}

// TestVoteOnce: a settler writes its vote once while the order already
// shows it, and after a restart writes the recorded vote again, never
// another one, even when its own judgment would now differ.
func TestVoteOnce(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a, s := w.nodes[0], w.nodes[1]
	lag := &lagOrder{Order: s.order}
	s.admin = nil
	w.makeAdmin(s, lag)
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(a.m.Pending().Commit())
	l.settle()
	for range 2 {
		if _, err := s.admin.Step(w.ctx); err != nil {
			t.Fatal(err)
		}
	}
	mine := func() []Vote {
		votes, _, err := lag.Order.Own(w.gid, e)
		if err != nil {
			t.Fatal(err)
		}
		return votes
	}
	if v := mine(); len(v) != 1 || !v[0].Accept || v[0].Commit != h {
		t.Fatalf("%d votes", len(v))
	}
	// Restart: the Commit is gone from pins and the timeout passed, so a
	// fresh judgment would reject it; the braid has not shown the vote yet.
	w.pins.drop(settle.ObjectKey(h))
	w.now = w.now.Add(2 * DefaultFetchTimeout)
	s.admin = nil
	w.makeAdmin(s, lag)
	lag.hide = true
	for range 2 {
		if _, err := s.admin.Step(w.ctx); err != nil {
			t.Fatal(err)
		}
		w.now = w.now.Add(2 * DefaultFetchTimeout)
	}
	lag.hide = false
	for _, v := range mine() {
		if !v.Accept {
			t.Fatal("a restart cast another vote")
		}
	}
}

// TestShareOnce: a settler writes its signature share of the decided Commit
// once while the order already shows it.
func TestShareOnce(t *testing.T) {
	w, l := fourAdmins(t, 1)
	a, s := w.nodes[0], w.nodes[1]
	e := a.m.Epoch()
	w.proposeLeave(w.memberNodes()[0])
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		l.settle()
		refs, votes, _, _ := s.order.Entries(w.gid, e)
		roles, _ := settle.RolesOf(s.m.Extensions(), w.limits)
		if Decide(refs, votes, roles, sha256.Sum256(s.m.GroupContext())).Decided != nil {
			break
		}
		for _, n := range w.admins() {
			if _, err := n.admin.Step(w.ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	for range 2 {
		if _, err := s.admin.Step(w.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, shares, _ := s.order.Own(w.gid, e); len(shares) != 1 {
		t.Fatalf("%d shares", len(shares))
	}
	w.pump(e+1, l.settle, 50)
	w.check()
	// The vote and share records of the epoch left are deleted at the next
	// Step, also on admins that applied the epoch from gossip.
	for _, n := range w.admins() {
		if _, err := n.admin.Step(w.ctx); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"vote", "sig"} {
			if _, err := n.st.Get(recordKey(w.gid, name)); !errors.Is(err, errs.ErrNotFound) {
				t.Fatalf("%s keeps its %s record: %v", n.name, name, err)
			}
		}
	}
}

// TestAssembleDecidedOnly: shares of q settlers over another Commit at the
// decided reference's position are not assembled.
func TestAssembleDecidedOnly(t *testing.T) {
	w, l := fourAdmins(t, 0)
	a := w.nodes[0]
	e := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	l.settle()
	refs, _, _, _ := a.order.Entries(w.gid, e)
	roles, _ := settle.RolesOf(a.m.Extensions(), w.limits)
	forged := settle.TBS{GroupID: w.gid, Epoch: e, ContextBefore: sha256.Sum256(a.m.GroupContext()), ContextAfter: [32]byte{1}, Braid: roles.Braid, RefPosition: refs[0].Position}
	for _, n := range w.nodes[1:4] {
		sig, err := Sign(n.dev.ID, &forged)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.order.Append(w.ctx, sigBody(n.dev.Cert.Encode(), &forged, sig)); err != nil {
			t.Fatal(err)
		}
	}
	w.pump(e+1, l.settle, 50)
	w.check()
	// The three settlers signed two TBS for the epoch: evidence.
	if ev := a.admin.Evidence(); len(ev) != 3 {
		t.Fatalf("evidence %d", len(ev))
	}
}

// failingBackend fails every scan once fail is set, as a storage error
// would.
type failingBackend struct {
	kolostore.Backend
	fail atomic.Bool
}

var errStorage = errors.New("storage failed")

func (f *failingBackend) Scan(start, end []byte, reverse bool, limit int, fn func(key, value []byte) bool) error {
	if f.fail.Load() {
		return errStorage
	}
	return f.Backend.Scan(start, end, reverse, limit, fn)
}

// TestIndexScanError: a storage error that cuts the Index's read short is
// returned, not a shorter list for the decision.
func TestIndexScanError(t *testing.T) {
	idx := NewIndex([]byte("mls/"), nil)
	gid := bytes.Repeat([]byte{1}, 32)
	apply := func(tx *kolobraid.Tx, e *kolobraid.Entry) error {
		_, err := idx.Apply(tx, e)
		return err
	}
	dev := kolotest.NewDevice(t, kolotest.Person(t), true)
	be := &failingBackend{Backend: kolostore.NewMemory()}
	b, err := kolobraid.Create(context.Background(), dev.ID, kolobraid.GroupConfig{App: testApp}, kolobraid.Options{Backend: be, App: testApp, Apply: apply, Limits: braidLimits()})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := range 40 {
		if _, err := b.Append(ctx, refBody(dev.Cert.Encode(), gid, 1, [32]byte{byte(i)})); err != nil {
			t.Fatal(err)
		}
	}
	o := NewBraidOrder(b, idx, nil)
	for {
		refs, _, _, err := o.Entries(gid, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) == 40 {
			break
		}
		if _, err := b.Next(ctx); err != nil {
			t.Fatal(err)
		}
	}
	be.fail.Store(true)
	defer be.fail.Store(false)
	s := b.Settled()
	defer s.Close()
	refs, _, _, err := idx.Entries(s, gid, 1)
	if len(refs) == 40 {
		t.Skip("the records were read from memory, not storage")
	}
	if !errors.Is(err, errStorage) {
		t.Fatalf("a storage error during the read: %d records, %v", len(refs), err)
	}
}
