package braid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	kolobraid "github.com/ciranda-dev/kolo-braid"
	"github.com/ciranda-dev/kolo-braid/devices"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"

	"github.com/ciranda-dev/kolo-mls/settle"
)

const testApp = "kolo-mls-test/v0"

// braidLimits are the smallest pacing values kolo-braid allows, so tests
// settle in milliseconds.
func braidLimits() *kolobraid.Limits {
	return &kolobraid.Limits{MaxTail: 64, PulseGap: 10 * time.Millisecond, PivotWait: 100 * time.Millisecond, ConfirmWait: time.Second, AnnounceGap: 10 * time.Millisecond}
}

// braidPeer is one admin device's braid.
type braidPeer struct {
	n      *node
	b      *kolobraid.Braid
	order  *BraidOrder
	ls     *kolosecure.Listener
	cancel context.CancelFunc
}

// braidEnv runs the admins' order on real kolo-braid braids, one per admin
// device, linked over kolo-secure on 127.0.0.1.
type braidEnv struct {
	t      testing.TB
	ctx    context.Context
	idx    *Index
	roster *devices.Store
	mu     sync.Mutex
	peers  []*braidPeer
	conns  []*kolosecure.Conn
	events chan struct{}
	// settled gets a signal each time a braid settles further.
	settled chan struct{}
	wg      sync.WaitGroup
}

func newBraidEnv(t testing.TB) *braidEnv {
	ctx, cancel := context.WithCancel(context.Background())
	roster, err := devices.New([]byte("devices/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &braidEnv{t: t, ctx: ctx, idx: NewIndex([]byte("mls/"), roster), roster: roster, events: make(chan struct{}, 1), settled: make(chan struct{}, 1)}
	t.Cleanup(func() {
		cancel()
		e.mu.Lock()
		for _, c := range e.conns {
			c.Close()
		}
		for _, p := range e.peers {
			p.cancel()
			p.b.Close()
			p.ls.Close()
		}
		e.mu.Unlock()
		e.wg.Wait()
	})
	return e
}

func (e *braidEnv) apply(tx *kolobraid.Tx, en *kolobraid.Entry) error {
	if ok, err := e.idx.Apply(tx, en); ok || err != nil {
		return err
	}
	if ok, err := e.roster.Apply(tx, en); ok || err != nil {
		return err
	}
	return nil
}

func (e *braidEnv) options() kolobraid.Options {
	return kolobraid.Options{Backend: kolostore.NewMemory(), App: testApp, Apply: e.apply, Limits: braidLimits()}
}

// start listens for n's braid on 127.0.0.1, links it to every peer and
// forwards its events.
func (e *braidEnv) start(n *node, b *kolobraid.Braid) *braidPeer {
	e.t.Helper()
	ctx, cancel := context.WithCancel(e.ctx)
	ls, err := kolosecure.Listen(ctx, "127.0.0.1:0", n.dev.ID, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	p := &braidPeer{n: n, b: b, order: NewBraidOrder(b, e.idx, e.roster), ls: ls, cancel: cancel}
	e.wg.Go(func() {
		for {
			c, err := ls.Accept(ctx)
			if err != nil {
				return
			}
			e.wg.Go(func() { b.ServeConn(ctx, c) })
		}
	})
	e.wg.Go(func() {
		for {
			ev, err := b.Next(ctx)
			if err != nil {
				return
			}
			if ev.Kind == kolobraid.EventSettled {
				select {
				case e.settled <- struct{}{}:
				default:
				}
			}
			if ev.Kind == kolobraid.EventSettled || ev.Kind == kolobraid.EventApplied {
				select {
				case e.events <- struct{}{}:
				default:
				}
			}
		}
	})
	e.mu.Lock()
	others := append([]*braidPeer(nil), e.peers...)
	e.peers = append(e.peers, p)
	e.mu.Unlock()
	for _, o := range others {
		e.link(p, o)
	}
	return p
}

// link dials o from p and serves the connection on p's side.
func (e *braidEnv) link(p, o *braidPeer) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()
	c, err := kolosecure.Dial(ctx, o.ls.Addr().String(), p.n.dev.ID, o.n.dev.ID.PublicKey(), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.mu.Lock()
	e.conns = append(e.conns, c)
	e.mu.Unlock()
	b := p.b
	e.wg.Go(func() { b.ServeConn(e.ctx, c) })
}

func (e *braidEnv) peer(n *node) *braidPeer {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range e.peers {
		if p.n == n {
			return p
		}
	}
	return nil
}

// order creates the braid with the first admin and admits the others as
// admins; seat makes them settlers.
func (e *braidEnv) order(_ *world, n *node) Order {
	e.t.Helper()
	admin := kolobraid.RoleAdmin
	return e.admit(n, &admin)
}

// admit is order with the roles of a device the braid admits; nil admits a
// plain member.
func (e *braidEnv) admit(n *node, roles *kolobraid.Role) Order {
	e.t.Helper()
	if p := e.peer(n); p != nil {
		return p.order
	}
	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	e.mu.Lock()
	founder := len(e.peers) == 0
	var first *braidPeer
	if !founder {
		first = e.peers[0]
	}
	e.mu.Unlock()
	if founder {
		b, err := kolobraid.Create(ctx, n.dev.ID, kolobraid.GroupConfig{App: testApp}, e.options())
		if err != nil {
			e.t.Fatal(err)
		}
		return e.start(n, b).order
	}
	j, err := kolobraid.NewJoin(ctx, n.dev.ID, e.options())
	if err != nil {
		e.t.Fatal(err)
	}
	req, err := j.Request(nil)
	if err != nil {
		e.t.Fatal(err)
	}
	welcome, err := first.b.Admit(ctx, n.dev.ID.PublicKey(), req, &kolobraid.AdmitOptions{Roles: roles})
	if err != nil {
		e.t.Fatal(err)
	}
	b, err := j.Complete(ctx, welcome)
	if err != nil {
		e.t.Fatal(err)
	}
	p := e.start(n, b)
	// Wait until the new admin can write: its AddMember entry is ordered.
	e.waitFor(ctx, func() bool {
		st := b.Status()
		return !st.Unconfirmed && st.Halted == nil && member(b, n.dev.ID.PublicKey())
	})
	return p.order
}

func member(b *kolobraid.Braid, key []byte) bool {
	s := b.View()
	defer s.Close()
	for _, m := range s.Members() {
		if string(m.Key) == string(key) {
			return true
		}
	}
	return false
}

// waitFor waits for braid events until cond holds or ctx ends.
func (e *braidEnv) waitFor(ctx context.Context, cond func() bool) {
	e.t.Helper()
	for !cond() {
		select {
		case <-e.events:
		case <-ctx.Done():
			e.t.Fatal("braid condition not reached")
		}
	}
}

// settle waits until a braid settles further, at most one second, so the
// admins' next Step reads what settled.
func (e *braidEnv) settle() {
	ctx, cancel := context.WithTimeout(e.ctx, time.Second)
	defer cancel()
	select {
	case <-e.settled:
	case <-ctx.Done():
	}
}

// revoke writes r to the roster and waits until every braid settled it.
func (e *braidEnv) revoke(r *koloid.Revocation) {
	e.t.Helper()
	e.revokeEntry(r)
}

// revokeEntry is revoke that returns the roster entry it wrote.
func (e *braidEnv) revokeEntry(r *koloid.Revocation) kolobraid.EntryRef {
	e.t.Helper()
	body, err := devices.RevocationBody(r, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.mu.Lock()
	first := e.peers[0]
	peers := append([]*braidPeer(nil), e.peers...)
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	ref, err := first.b.Append(ctx, body)
	if err != nil {
		e.t.Fatal(err)
	}
	e.waitFor(ctx, func() bool {
		for _, p := range peers {
			if !p.n.online {
				continue
			}
			s := p.b.Settled()
			revs, err := p.order.roster.Revocations(s, r.Person(), r.Device())
			s.Close()
			if err != nil || len(revs) == 0 {
				return false
			}
		}
		return true
	})
	return ref
}

// settledEntry waits until the settled order of each of peers holds entry id
// and returns it as each peer ordered it.
func (e *braidEnv) settledEntry(ctx context.Context, id kolobraid.EntryID, peers ...*braidPeer) []kolobraid.Ordered {
	e.t.Helper()
	out := make([]kolobraid.Ordered, len(peers))
	e.waitFor(ctx, func() bool {
		for i, p := range peers {
			found := false
			for o, err := range p.b.Entries(0) {
				if err != nil || !o.Settled {
					break
				}
				if o.ID == id {
					out[i], found = o, true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	})
	return out
}

// halt closes the braids of the admins marked offline: with two of four
// settlers gone, the braid settles no more. A braid of one settler cannot
// lose its quorum while its device runs; halt reports false then.
func (e *braidEnv) halt() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	stalled := false
	for _, p := range e.peers {
		if !p.n.online {
			p.cancel()
			p.b.Close()
			stalled = true
		}
	}
	return stalled
}

// successor starts the successor braid of n's braid, alone.
func (e *braidEnv) successor(_ *world, n *node) Order {
	e.t.Helper()
	old := e.peer(n)
	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	b, err := kolobraid.Succeed(ctx, n.dev.ID, old.b, kolobraid.GroupConfig{App: testApp}, e.options())
	if err != nil {
		e.t.Fatal(err)
	}
	e.mu.Lock()
	e.peers = nil
	e.mu.Unlock()
	return e.start(n, b).order
}

// seat makes settlers the braid's settler seats and waits until every peer's
// settled roster shows them, so roles that name them match the braid.
func (e *braidEnv) seat(_ *world, settlers []*node, q settle.Quorum) {
	e.t.Helper()
	var keys []ed25519.PublicKey
	want := map[[32]byte]bool{}
	for _, n := range settlers {
		keys = append(keys, n.dev.ID.PublicKey())
		want[n.dev.Key()] = true
	}
	e.mu.Lock()
	first := e.peers[0]
	peers := append([]*braidPeer(nil), e.peers...)
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(e.ctx, 60*time.Second)
	defer cancel()
	if _, err := first.b.SetSettlers(ctx, keys, kolobraid.QuorumRule(q)); err != nil {
		e.t.Fatal(err)
	}
	e.waitFor(ctx, func() bool {
		for _, p := range peers {
			if st := p.b.Status(); st.Seats != len(want) || len(st.PendingConfig) != 0 {
				return false
			}
		}
		return true
	})
	// A view's roster is the one at its last applied entry: one more entry
	// shows the new seats.
	if _, err := first.b.Append(ctx, []byte("seats")); err != nil {
		e.t.Fatal(err)
	}
	e.waitFor(ctx, func() bool {
		for _, p := range peers {
			_, seats, _, err := p.order.Roster()
			if err != nil || len(seats) != len(want) {
				return false
			}
			for _, k := range seats {
				if !want[k] {
					return false
				}
			}
		}
		return true
	})
}

// TestOrderAfterSettled: on a real braid, a reference written after another
// one settled is ordered after it, so an admin cannot place its reference
// before one it has already seen settle; only references written at about
// the same time can be ordered either way (docs/design.md).
func TestOrderAfterSettled(t *testing.T) {
	w := newWorld(t)
	e := newBraidEnv(t)
	a, b := w.device("a", nil), w.device("b", nil)
	oa, ob := e.order(w, a), e.order(w, b)
	gid := bytes.Repeat([]byte{4}, 32)
	ctx, cancel := context.WithTimeout(e.ctx, time.Minute)
	defer cancel()
	settledRefs := func(o Order) []Ref {
		refs, _, _, err := o.Entries(gid, 0)
		if err != nil {
			t.Fatal(err)
		}
		return refs
	}
	if err := ob.Append(ctx, refBody(b.dev.Cert.Encode(), gid, 0, [32]byte{1})); err != nil {
		t.Fatal(err)
	}
	e.waitFor(ctx, func() bool { return len(settledRefs(oa)) == 1 })
	if err := oa.Append(ctx, refBody(a.dev.Cert.Encode(), gid, 0, [32]byte{2})); err != nil {
		t.Fatal(err)
	}
	e.waitFor(ctx, func() bool { return len(settledRefs(ob)) == 2 })
	refs := settledRefs(ob)
	if refs[0].Commit != [32]byte{1} || refs[0].Position >= refs[1].Position {
		t.Fatal("a reference written after another settled was ordered before it")
	}
}

// TestBraidRoster: the Roster of a real braid names every admin, no plain
// member, and only the settler seats.
func TestBraidRoster(t *testing.T) {
	w := newWorld(t)
	e := newBraidEnv(t)
	ns := []*node{w.device("a", nil), w.device("b", nil), w.device("c", nil)}
	var orders []Order
	for _, n := range ns {
		orders = append(orders, e.order(w, n))
	}
	e.admit(w.device("plain", nil), nil)
	e.seat(w, ns[:2], settle.Majority)
	admins, seats, q, err := orders[2].Roster()
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 3 || len(seats) != 2 || q != 2 {
		t.Fatalf("%d admins, %d seats, q %d", len(admins), len(seats), q)
	}
	for _, k := range seats {
		if k == ns[2].dev.Key() {
			t.Fatal("an admin without a seat listed as a settler")
		}
	}
}
