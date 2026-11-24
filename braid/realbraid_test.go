package braid

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	kolobraid "github.com/ciranda-dev/kolo-braid"
	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// braidAdmins builds a group over real braids whose k admins are all
// settlers under Majority.
func braidAdmins(t *testing.T, k int) (*world, *braidEnv) {
	w := newWorld(t)
	e := newBraidEnv(t)
	founder := w.device("admin0", nil)
	w.create(founder, e.order(w, founder))
	var rest []*node
	for i := 1; i < k; i++ {
		rest = append(rest, w.device(fmt.Sprintf("admin%d", i), nil))
	}
	w.join(founder, e.settle, rest...)
	all := append([]*node{founder}, rest...)
	promote(w, e, founder, all, all, settle.Majority)
	return w, e
}

// TestBraidRevocationFork is the fork scenario on real braids: settlers A, B and S (q = 2). S
// references its own Commit Z at position p, A votes, S's revocation settles at r, S writes an
// accept vote at v, then B votes. Every braid's apply rejects S's vote at v and keeps the
// reference at p (p < r < v); RevocationsAt finds nothing for S at p and its revocation at r; A
// (before the revocation) and B (after it) decide the same reference and apply Z, the epoch's
// only SettledCommit.
func TestBraidRevocationFork(t *testing.T) {
	w, e := braidAdmins(t, 3)
	A, B, S := w.nodes[0], w.nodes[1], w.nodes[2]
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	ep := A.m.Epoch()
	before := sha256.Sum256(A.m.GroupContext())
	roles, err := settle.RolesOf(A.m.Extensions(), w.limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := S.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	z := sha256.Sum256(S.m.Pending().Commit())
	var ref Ref
	e.waitFor(ctx, func() bool {
		for _, n := range []*node{A, B} {
			refs, _, _, err := n.order.Entries(w.gid, ep)
			if err != nil || len(refs) != 1 {
				return false
			}
			ref = refs[0]
		}
		return true
	})
	if ref.Commit != z || ref.Writer != S.dev.Key() {
		t.Fatal("the settled reference is not S's reference to Z")
	}
	ownVote := func(n *node) Vote {
		t.Helper()
		if _, err := n.admin.Step(ctx); err != nil {
			t.Fatalf("%s: %v", n.name, err)
		}
		var votes []Vote
		var err error
		// The braid applies an append to the view shortly after it returns.
		for ; ctx.Err() == nil; time.Sleep(10 * time.Millisecond) {
			if votes, _, err = n.order.Own(w.gid, ep); err != nil || len(votes) > 0 {
				break
			}
		}
		if err != nil || len(votes) != 1 {
			t.Fatalf("%s cast %d votes on Z: %v", n.name, len(votes), err)
		}
		return votes[0]
	}
	va := ownVote(A)

	r, err := S.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: S.dev.Person.PublicKey(), Device: S.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	revRef := e.revokeEntry(r)
	pS, pA, pB := e.peer(S), e.peer(A), e.peer(B)
	late, err := pS.b.Append(ctx, voteBody(S.dev.Cert.Encode(), w.gid, ep, z, before, true, ReasonNone))
	if err != nil {
		t.Fatal(err)
	}
	S.online = false
	revPos := e.settledEntry(ctx, revRef.ID, pA)[0].Position
	for i, o := range e.settledEntry(ctx, late.ID, pA, pB, pS) {
		if !o.Rejected {
			t.Fatalf("peer %d applied the vote S wrote after its revocation", i)
		}
		if !(ref.Position < revPos && revPos < o.Position) {
			t.Fatalf("positions: reference %d, revocation %d, late vote %d", ref.Position, revPos, o.Position)
		}
	}
	for at, want := range map[uint64]int{ref.Position: 0, revPos: 1} {
		revs, err := B.order.RevocationsAt(ctx, at, S.dev.Cert)
		if err != nil || len(revs) != want {
			t.Fatalf("RevocationsAt %d: %d revocations, %v", at, len(revs), err)
		}
	}

	vb := ownVote(B)
	for _, v := range []Vote{va, vb} {
		if v.Commit != z || !v.Accept || v.Reason != ReasonNone {
			t.Fatalf("a settler voted %v on Z", v)
		}
	}
	w.pump(ep+1, e.settle, 200)
	var decided []Decision
	for _, n := range []*node{A, B} {
		refs, votes, _, err := n.order.Entries(w.gid, ep)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 1 || refs[0] != ref {
			t.Fatalf("%s reads %d references", n.name, len(refs))
		}
		for _, v := range votes {
			if v.Writer == S.dev.Key() {
				t.Fatalf("%s reads a vote of S", n.name)
			}
		}
		decided = append(decided, Decide(refs, votes, roles, before))
	}
	for i, d := range decided {
		if d.Decided == nil || *d.Decided != ref || !slices.Equal(d.Rejected, decided[0].Rejected) {
			t.Fatalf("settler %d decides %v", i, d.Decided)
		}
	}
	if settledTwice(t, w, A, ep, roles) {
		t.Fatal("two Commits carry q valid settler signatures for one epoch")
	}
	if got := w.mustDecode(w.mustGet(settle.SettledKey(w.gid, ep))).TBS.Commit; got != z {
		t.Fatal("another Commit settled")
	}
	for _, n := range []*node{A, B} {
		if w.applied[ep][n.name] != z || n.m.Epoch() != ep+1 {
			t.Fatalf("%s did not apply Z", n.name)
		}
	}
}

// rosterView is one Roster answer.
type rosterView struct {
	admins, settlers [][32]byte
	q                int
}

func (v rosterView) String() string {
	return fmt.Sprintf("%d admins, %d seats, q %d", len(v.admins), len(v.settlers), v.q)
}

func (v rosterView) equal(o rosterView) bool {
	return slices.Equal(v.admins, o.admins) && slices.Equal(v.settlers, o.settlers) && v.q == o.q
}

func readRoster(o Order) (rosterView, error) {
	a, s, q, err := o.Roster()
	return rosterView{a, s, q}, err
}

func sortedKeys(ns ...*node) [][32]byte {
	var out [][32]byte
	for _, n := range ns {
		out = append(out, n.dev.Key())
	}
	slices.SortFunc(out, func(x, y [32]byte) int { return slices.Compare(x[:], y[:]) })
	return out
}

// TestBraidRosterActivation: Roster across a settler config activation on real braids. Seats
// a, b, c (q = 2) become a, b, c, d (q = 3) while d is cut off, then d is linked again and the
// config activates. On every peer, also for a reader polling throughout, the admins are the
// four devices and the seats and q are those of one config, never a mix: the old one while the
// config is pending and until an entry settles under the new one, the new one after.
func TestBraidRosterActivation(t *testing.T) {
	w := newWorld(t)
	e := newBraidEnv(t)
	a, b, c, d := w.device("a", nil), w.device("b", nil), w.device("c", nil), w.device("d", nil)
	for _, n := range []*node{a, b, c} {
		e.order(w, n)
	}
	cut := len(e.conns)
	e.order(w, d)
	e.mu.Lock()
	dConns := slices.Clone(e.conns[cut:])
	e.mu.Unlock()
	e.seat(w, []*node{a, b, c}, settle.Majority)
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	peers := []*braidPeer{e.peer(a), e.peer(b), e.peer(c), e.peer(d)}
	admins := sortedKeys(a, b, c, d)
	old := rosterView{admins, sortedKeys(a, b, c), 2}
	next := rosterView{admins, sortedKeys(a, b, c, d), 3}
	cfg := peers[0].b.Status().Config
	for _, p := range peers {
		if v, err := readRoster(p.order); err != nil || !v.equal(old) {
			t.Fatalf("%s before the change: %v %v", p.n.name, v, err)
		}
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		seenNext := make([]bool, len(peers))
		for {
			select {
			case <-stop:
				return
			default:
			}
			for i, p := range peers {
				v, err := readRoster(p.order)
				pending := p.b.Status().PendingConfig != nil
				switch {
				case err != nil:
					t.Errorf("%s: %v", p.n.name, err)
				case v.equal(next) && !pending:
					seenNext[i] = true
				case v.equal(old) && !seenNext[i]:
				default:
					t.Errorf("%s reads %v, pending %v", p.n.name, v, pending)
				}
			}
			if t.Failed() {
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	defer func() {
		close(stop)
		wg.Wait()
	}()

	for _, cn := range dConns {
		cn.Close()
	}
	if _, err := peers[0].b.SetSettlers(ctx, keysOf(a, b, c, d), kolobraid.QuorumRule(settle.Majority)); err != nil {
		t.Fatal(err)
	}
	e.waitFor(ctx, func() bool {
		for _, p := range peers[:3] {
			if len(p.b.Status().PendingConfig) != 4 {
				return false
			}
		}
		return true
	})
	mark := func(body string, ps ...*braidPeer) {
		t.Helper()
		ref, err := peers[0].b.Append(ctx, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		e.settledEntry(ctx, ref.ID, ps...)
	}
	mark("while pending", peers[:3]...)
	for _, p := range peers[:3] {
		v, err := readRoster(p.order)
		if st := p.b.Status(); st.PendingConfig == nil || st.Config != cfg {
			t.Fatalf("%s activated the config while d was cut off", p.n.name)
		}
		if err != nil || !v.equal(old) {
			t.Fatalf("%s while pending: %v %v", p.n.name, v, err)
		}
	}

	for _, p := range peers[:3] {
		e.link(peers[3], p)
	}
	e.waitFor(ctx, func() bool {
		for _, p := range peers {
			if st := p.b.Status(); st.Config == cfg || st.PendingConfig != nil {
				return false
			}
		}
		return true
	})
	for _, p := range peers {
		if v, err := readRoster(p.order); err != nil || !v.equal(old) {
			t.Fatalf("%s after activation, before an entry settled under it: %v %v", p.n.name, v, err)
		}
	}
	mark("active", peers...)
	for _, p := range peers {
		if v, err := readRoster(p.order); err != nil || !v.equal(next) {
			t.Fatalf("%s after an entry settled under the new config: %v %v", p.n.name, v, err)
		}
	}
}
