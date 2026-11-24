package braid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/kolotest"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// env is where the admins' order lives: in memory or on real braids.
type env interface {
	// order returns admin n's order on the group's braid, joining n to it.
	order(w *world, n *node) Order
	// settle lets the order settle what was written, one round.
	settle()
	// revoke records r in the settled roster.
	revoke(r *koloid.Revocation)
	// halt stops settlement for good, as a lost settler quorum does, for
	// the admins marked offline; it reports false when the order cannot
	// stall that way.
	halt() bool
	// successor starts a successor braid with n as founder, returns n's
	// order on it, and makes settle work on it.
	successor(w *world, n *node) Order
	// seat makes settlers the braid's settler seats under rule q, so roles
	// that name them match the braid.
	seat(w *world, settlers []*node, q settle.Quorum)
}

// memEnv is an env in memory.
type memEnv struct {
	log    *memLog
	halted bool
}

func (e *memEnv) order(_ *world, n *node) Order { return &memOrder{l: e.log, me: n.dev.Key()} }

func (e *memEnv) settle() {
	if !e.halted {
		e.log.settle()
	}
}

func (e *memEnv) revoke(r *koloid.Revocation) {
	e.log.mu.Lock()
	defer e.log.mu.Unlock()
	d := [32]byte(r.Device())
	e.log.revs[d] = append(e.log.revs[d], posRev{pos: len(e.log.entries), rev: r})
}

func (e *memEnv) seat(_ *world, settlers []*node, q settle.Quorum) {
	var keys []ed25519.PublicKey
	for _, n := range settlers {
		keys = append(keys, n.dev.ID.PublicKey())
	}
	r, err := settle.NewRoles(e.log.id, q, keys, keys, settle.Limits{})
	if err != nil {
		panic(err)
	}
	e.log.mu.Lock()
	defer e.log.mu.Unlock()
	e.log.admins, e.log.settlers, e.log.q = r.Admins, r.Settlers, r.Q()
}

// seatOnly sets the braid's roster to the admins, settlers and quorum of r,
// as admins' braid entries alone can.
func (e *memEnv) seatOnly(r *settle.Roles) {
	e.log.mu.Lock()
	defer e.log.mu.Unlock()
	e.log.admins, e.log.settlers, e.log.q = r.Admins, r.Settlers, r.Q()
}

func (e *memEnv) halt() bool {
	e.halted = true
	return true
}

func (e *memEnv) successor(_ *world, n *node) Order {
	revs := e.log.revs
	e.log, e.halted = newLog(2), false
	e.log.revs = revs
	return &memOrder{l: e.log, me: n.dev.Key()}
}

// shape is a group shape of the scenario tests.
type shape struct {
	name            string
	admins, members int
	batch           int
	quorum          settle.Quorum
	shortMembers    int
}

var (
	small = shape{name: "1 admin, 3 members", admins: 1, members: 3, batch: 3, quorum: settle.Majority, shortMembers: 3}
	large = shape{name: "4 admins, 200 members", admins: 4, members: 200, batch: 50, quorum: settle.Majority, shortMembers: 40}
)

// stats are the counts a scenario run asserts and reports.
type stats struct {
	reads, dropped, rejectedAdds, stolenTried, caughtUp, epochs int
}

// scenario builds a group of shape s over e and runs every scenario on it.
func scenario(t *testing.T, s shape, e env) *stats {
	w := newWorld(t)
	st := &stats{}
	members := s.members
	if testing.Short() || raceEnabled {
		members = s.shortMembers
	}
	founder := w.device("admin0", nil)
	w.create(founder, e.order(w, founder))
	var admins []*node
	for i := 1; i < s.admins; i++ {
		admins = append(admins, w.device(fmt.Sprintf("admin%d", i), nil))
	}
	if len(admins) > 0 {
		w.join(founder, e.settle, admins...)
	}
	for i := 0; i < members; i += s.batch {
		var batch []*node
		for j := i; j < min(i+s.batch, members); j++ {
			batch = append(batch, w.device(fmt.Sprintf("member%d", j), nil))
		}
		w.join(founder, e.settle, batch...)
	}
	all := append([]*node{founder}, admins...)
	if len(admins) > 0 {
		promote(w, e, founder, all, all, s.quorum)
	}
	t.Logf("%s: %d devices at epoch %d", s.name, len(w.live()), founder.m.Epoch())

	// Steps that remove a member add a new one, so the group keeps its shape.
	refill := func() {
		for i := len(w.memberNodes()); i < members; i++ {
			w.join(w.admins()[0], e.settle, w.device(fmt.Sprintf("member%d", len(w.nodes)), nil))
		}
	}
	var thieves []*stolen
	if !w.run(t, "messages", func(t *testing.T) {
		for _, n := range w.live() {
			w.send(n, "hello from "+n.name)
			st.reads += len(w.live()) - 1
		}
	}) {
		return st
	}
	if !w.run(t, "concurrent commits", func(t *testing.T) {
		concurrent(t, w, e)
	}) {
		return st
	}
	if !w.run(t, "self-update races a removal", func(t *testing.T) {
		thieves = append(thieves, raceRemoval(t, w, e))
		refill()
	}) {
		return st
	}
	if !w.run(t, "removal", func(t *testing.T) {
		victim := w.memberNodes()[0]
		thieves = append(thieves, w.steal(victim))
		w.commit(w.admins()[0], kolomls.CommitOptions{Remove: []uint32{victim.m.OwnLeaf()}}, e.settle)
		if !victim.m.Removed() {
			t.Fatal("not removed")
		}
		refill()
	}) {
		return st
	}
	if !w.run(t, "revocation", func(t *testing.T) {
		thieves = append(thieves, revocation(t, w, e, st))
		refill()
	}) {
		return st
	}
	if !w.run(t, "leave", func(t *testing.T) {
		leaver := w.memberNodes()[0]
		thieves = append(thieves, w.steal(leaver))
		w.proposeLeave(leaver)
		w.commit(w.admins()[0], kolomls.CommitOptions{Remove: []uint32{leaver.m.OwnLeaf()}}, e.settle)
		if !leaver.m.Removed() {
			t.Fatal("leaver not removed")
		}
		refill()
	}) {
		return st
	}
	if !w.run(t, "linked device", func(t *testing.T) {
		linked(t, w, e)
	}) {
		return st
	}
	if !w.run(t, "catch-up", func(t *testing.T) {
		st.caughtUp = catchUp(t, w, e)
	}) {
		return st
	}
	if !w.run(t, "settled checks", func(t *testing.T) {
		settledChecks(t, w, e)
		refill()
	}) {
		return st
	}
	if !w.run(t, "double vote", func(t *testing.T) {
		doubleVote(t, w, e)
	}) {
		return st
	}
	if !w.run(t, "restart", func(t *testing.T) {
		restart(t, w, e)
	}) {
		return st
	}
	if !w.run(t, "removed devices decrypt nothing", func(t *testing.T) {
		for _, n := range w.live() {
			w.send(n, "late")
		}
		for _, th := range thieves {
			st.stolenTried += w.decryptsNothing(th)
		}
		if st.stolenTried == 0 {
			t.Fatal("no later message tried")
		}
	}) {
		return st
	}
	st.epochs = int(founder.m.Epoch())
	if !w.run(t, "quorum loss and successor", func(t *testing.T) {
		successor(t, w, e, s)
	}) {
		return st
	}
	t.Logf("%s: %d epochs, %d reads, %d dropped from a revoked device, %d revoked Adds refused, %d messages read in catch-up, %d later messages tried by removed devices, none read",
		s.name, st.epochs, st.reads, st.dropped, st.rejectedAdds, st.caughtUp, st.stolenTried)
	return st
}

func (w *world) memberNodes() []*node {
	var out []*node
	for _, n := range w.live() {
		if n.admin == nil {
			out = append(out, n)
		}
	}
	return out
}

// commit has admin commit o and pumps until every live node applied it.
func (w *world) commit(admin *node, o kolomls.CommitOptions, settleOrder func()) []*Applied {
	w.t.Helper()
	e := admin.m.Epoch()
	if _, err := admin.admin.Commit(w.ctx, o); err != nil {
		w.t.Fatalf("%s Commit: %v", admin.name, err)
	}
	out := w.pump(e+1, settleOrder, 200)
	w.check()
	return out
}

// promote makes admins and settlers the roles of the group, by a Commit of
// the founder, and runs an Admin for each new admin.
func promote(w *world, e env, founder *node, admins, settlers []*node, q settle.Quorum) {
	w.t.Helper()
	var ak, sk []ed25519.PublicKey
	for _, n := range admins {
		ak = append(ak, n.dev.ID.PublicKey())
	}
	for _, n := range settlers {
		sk = append(sk, n.dev.ID.PublicKey())
	}
	roles, err := settle.NewRoles(founder.order.ID(), q, ak, sk, w.limits)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, n := range admins {
		if n.admin == nil {
			w.makeAdmin(n, e.order(w, n))
		}
	}
	e.seat(w, settlers, q)
	w.commit(founder, kolomls.CommitOptions{SetExtensions: true, Extensions: mustExts(w.t, roles)}, e.settle)
}

// concurrent has two devices commit in one epoch: two admins, or the admin
// and a member's own key update. Exactly one is applied everywhere.
func concurrent(t *testing.T, w *world, e env) {
	admins := w.admins()
	a := admins[0]
	epoch := a.m.Epoch()
	var hashes [][32]byte
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	hashes = append(hashes, sha256.Sum256(a.m.Pending().Commit()))
	if len(admins) > 1 {
		b := admins[1]
		if _, err := b.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, sha256.Sum256(b.m.Pending().Commit()))
	} else {
		m := w.memberNodes()[0]
		pc, err := m.m.Commit(kolomls.CommitOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.admin.Refer(w.ctx, pc.Commit()); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, sha256.Sum256(pc.Commit()))
	}
	w.pump(epoch+1, e.settle, 200)
	w.check()
	got := w.applied[epoch]
	var winner [32]byte
	for _, h := range got {
		winner = h
	}
	if len(got) != len(w.live()) || !slices.Contains(hashes, winner) {
		t.Fatalf("%d devices applied epoch %d", len(got), epoch)
	}
	for _, n := range w.live() {
		if n.m.Pending() != nil {
			t.Fatalf("%s keeps a losing Commit", n.name)
		}
	}
	// Every admin decides the same from its own reading of the order.
	for _, n := range w.admins() {
		refs, votes, _, err := n.order.Entries(w.gid, epoch)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != len(hashes) || len(votes) == 0 {
			t.Fatalf("%s reads %d references and %d votes", n.name, len(refs), len(votes))
		}
	}
}

// raceRemoval has a member update its key while an admin removes it; the
// removal is referenced first and wins. It returns the member's stolen
// state from before the removal.
func raceRemoval(t *testing.T, w *world, e env) *stolen {
	a := w.admins()[0]
	m := w.memberNodes()[0]
	th := w.steal(m)
	epoch := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Remove: []uint32{m.m.OwnLeaf()}}); err != nil {
		t.Fatal(err)
	}
	removal := sha256.Sum256(a.m.Pending().Commit())
	pc, err := m.m.Commit(kolomls.CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.admin.Refer(w.ctx, pc.Commit()); err != nil {
		t.Fatal(err)
	}
	w.pump(epoch+1, e.settle, 200)
	w.check()
	for _, h := range w.applied[epoch] {
		if h != removal {
			t.Fatal("the key update won")
		}
	}
	if !m.m.Removed() {
		t.Fatal("member not removed")
	}
	return th
}

// revocation: an Add of a revoked device is refused (by the other settlers,
// or by the committing admin when it is the only one); a member device whose
// revocation some devices hold has its messages dropped there and is then
// removed by an admin.
func revocation(t *testing.T, w *world, e env, st *stats) *stolen {
	person := kolotest.Person(t)
	bad := w.device("revoked-joiner", person)
	r, err := person.RevokeDevice(&koloid.RevokeOptions{Person: person.PublicKey(), Device: bad.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.revoke(r)
	admins := w.admins()
	a := admins[0]
	epoch := a.m.Epoch()
	kp := bad.dev.KeyPackage(t, bad.st)
	if len(admins) == 1 {
		a.auth.Revocations = func(p, d ed25519.PublicKey) []*koloid.Revocation {
			if bytes.Equal(d, bad.dev.ID.PublicKey()) {
				return []*koloid.Revocation{r}
			}
			return nil
		}
		if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Add: [][]byte{kp}}); !errors.Is(err, koloid.ErrCertRevoked) {
			t.Fatalf("Add of a revoked device: %v", err)
		}
		a.auth.Revocations = nil
	} else {
		if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Add: [][]byte{kp}}); err != nil {
			t.Fatal(err)
		}
		for range 200 {
			for _, n := range w.admins() {
				if _, err := n.admin.Step(w.ctx); err != nil {
					t.Fatal(err)
				}
			}
			if a.m.Pending() == nil {
				break
			}
			e.settle()
		}
		if a.m.Pending() != nil || a.m.Epoch() != epoch {
			t.Fatal("the Add of a revoked device was not rejected")
		}
	}
	st.rejectedAdds++

	// A member device revoked after it joined.
	victim := w.device("revoked-member", nil)
	w.join(a, e.settle, victim)
	rv, err := victim.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: victim.dev.Person.PublicKey(), Device: victim.dev.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.revoke(rv)
	holders := 0
	for i, n := range w.live() {
		if n != victim && i%2 == 0 {
			n.revs = append(n.revs, rv)
			holders++
		}
	}
	_, dropped := w.sendCount(victim, "from a revoked device")
	if dropped != holders {
		t.Fatalf("%d of %d holders dropped the message", dropped, holders)
	}
	st.dropped += dropped
	leaf := victim.m.OwnLeaf()
	for _, n := range w.live() {
		if n.revs != nil && !slices.Contains(n.m.RevokedLeaves(), leaf) {
			t.Fatalf("%s does not list the revoked leaf", n.name)
		}
	}
	th := w.steal(victim)
	w.commit(a, kolomls.CommitOptions{Remove: []uint32{leaf}}, e.settle)
	if !victim.m.Removed() {
		t.Fatal("revoked device not removed")
	}
	for _, n := range w.live() {
		n.revs = nil
	}
	return th
}

// mustExts returns the GroupContext extensions of roles.
func mustExts(t testing.TB, r *settle.Roles) []tls.Extension {
	t.Helper()
	exts, err := settle.GroupExtensions(r)
	if err != nil {
		t.Fatal(err)
	}
	return exts
}

// linked: a second device of a member's person, linked later, joins as a new
// leaf and reads nothing sent before it joined.
func linked(t *testing.T, w *world, e env) {
	owner := w.memberNodes()[0]
	before := w.send(owner, "before the second device")
	beforeEpoch := owner.m.Epoch()
	second := w.device("second-device", owner.dev.Person)
	w.join(w.admins()[0], e.settle, second)
	g := second.m
	if _, err := g.Receive(before); !errors.Is(err, errs.ErrWrongEpoch) {
		t.Fatalf("an earlier message: %v", err)
	}
	m, _ := message.UnmarshalMLSMessage(before)
	m.Private.Epoch = g.Epoch()
	b, _ := m.Marshal()
	if _, err := g.Receive(b); !errors.Is(err, errs.ErrDecrypt) {
		t.Fatalf("an earlier message under the new epoch: %v", err)
	}
	if beforeEpoch >= g.Epoch() {
		t.Fatal("the second device joined in an earlier epoch")
	}
	w.send(second, "from the second device")
}

// catchUp has a member miss two epochs and their messages, then catch up
// from pins; it returns the messages read while catching up.
func catchUp(t *testing.T, w *world, e env) int {
	away := w.memberNodes()[0]
	away.online = false
	want := 0
	for range 2 {
		for _, n := range w.live() {
			w.send(n, "while away")
			want++
		}
		w.commit(w.admins()[0], kolomls.CommitOptions{}, e.settle)
	}
	away.online = true
	rs, err := away.m.CatchUp(w.ctx, w.pins)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != want {
		t.Fatalf("read %d of %d archived messages", len(rs), want)
	}
	w.check()
	return len(rs)
}

// settledChecks: a member refuses a Commit with fewer than q signatures,
// keeps its state on one that leads to another GroupContext, and halts on a
// second settled Commit for an epoch it applied.
func settledChecks(t *testing.T, w *world, e env) {
	a := w.admins()[0]
	m := w.memberNodes()[0]
	epoch := a.m.Epoch()
	roles, err := settle.RolesOf(a.m.Extensions(), w.limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	commit := a.m.Pending().Commit()
	ctxBefore := sha256.Sum256(m.m.GroupContext())
	tbs := settle.TBS{GroupID: w.gid, Epoch: epoch, Commit: sha256.Sum256(commit), ContextBefore: ctxBefore, ContextAfter: sha256.Sum256(a.m.Pending().GroupContext()), Braid: roles.Braid}
	signers := w.settlerIDs(roles)
	sign := func(t2 settle.TBS, n int) []byte {
		var shares []settle.Share
		for _, id := range signers[:n] {
			sig, err := Sign(id, &t2)
			if err != nil {
				t.Fatal(err)
			}
			shares = append(shares, settle.Share{Signer: [32]byte(id.PublicKey()), Signature: [64]byte(sig)})
		}
		return Assemble(&t2, shares, roles).Encode()
	}
	auth, _ := m.m.EpochAuthenticator()
	if roles.Q() > 1 {
		if _, err := m.m.ApplySettled(sign(tbs, roles.Q()-1), commit); !errors.Is(err, settle.ErrNotSettled) {
			t.Fatalf("q - 1 signatures: %v", err)
		}
	}
	wrong := tbs
	wrong.ContextAfter = sha256.Sum256([]byte("another context"))
	if _, err := m.m.ApplySettled(sign(wrong, roles.Q()), commit); !errors.Is(err, settle.ErrSettledMismatch) {
		t.Fatalf("another GroupContext: %v", err)
	}
	if now, _ := m.m.EpochAuthenticator(); !bytes.Equal(now, auth) || m.m.Epoch() != epoch {
		t.Fatal("a refused settled Commit changed the member")
	}
	w.pump(epoch+1, e.settle, 200)
	w.check()
	// A second Commit for the same epoch, signed by q settlers.
	other := tbs
	other.Commit = sha256.Sum256([]byte("another Commit"))
	if _, err := m.m.ApplySettled(sign(other, roles.Q()), []byte("another Commit")); !errors.Is(err, settle.ErrEquivocation) || !errors.Is(err, settle.ErrHalted) {
		t.Fatalf("second settled Commit: %v", err)
	}
	if _, err := m.m.Receive(nil); !errors.Is(err, settle.ErrHalted) {
		t.Fatalf("a halted member goes on: %v", err)
	}
	// The halted member is set aside: the application would alert its user.
	m.online = false
}

// settlerIDs returns the identities of the settlers of roles.
func (w *world) settlerIDs(roles *settle.Roles) []*koloid.Identity {
	var out []*koloid.Identity
	for _, n := range w.nodes {
		if roles.Settler(n.dev.ID.PublicKey()) {
			out = append(out, n.dev.ID)
		}
	}
	return out
}

// doubleVote: a settler that votes twice on one Commit is evidence.
func doubleVote(t *testing.T, w *world, e env) {
	a := w.admins()[0]
	epoch := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(a.m.Pending().Commit())
	before := sha256.Sum256(a.m.GroupContext())
	e.settle()
	for _, accept := range []bool{true, false} {
		if err := a.order.Append(w.ctx, voteBody(a.dev.Cert.Encode(), w.gid, epoch, h, before, accept, ReasonNone)); err != nil {
			t.Fatal(err)
		}
	}
	roles, _ := settle.RolesOf(a.m.Extensions(), w.limits)
	var d Decision
	for range 200 {
		e.settle()
		refs, votes, _, err := a.order.Entries(w.gid, epoch)
		if err != nil {
			t.Fatal(err)
		}
		if d = Decide(refs, votes, roles, before); len(d.Equivocators) > 0 {
			break
		}
	}
	if len(d.Equivocators) != 1 || d.Equivocators[0] != a.dev.Key() {
		t.Fatalf("equivocators %v", d.Equivocators)
	}
	if _, err := a.admin.Step(w.ctx); err != nil {
		t.Fatal(err)
	}
	if ev := a.admin.Evidence(); len(ev) != 1 || ev[0] != a.dev.Key() {
		t.Fatalf("evidence %v", ev)
	}
	w.pump(epoch+1, e.settle, 200)
	w.check()
}

// restart: an admin stops after it wrote its vote and opens again from its
// Store; it neither votes again nor loses the epoch.
func restart(t *testing.T, w *world, e env) {
	a := w.admins()[0]
	epoch := a.m.Epoch()
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	e.settle()
	if _, err := a.admin.Step(w.ctx); err != nil {
		t.Fatal(err)
	}
	a.m.Close()
	m, err := settle.OpenMember(a.st, w.gid, w.config(a), w.memberOptions(a))
	if err != nil {
		t.Fatal(err)
	}
	if m.Pending() == nil {
		t.Fatal("pending Commit lost on restart")
	}
	a.m = m
	order := a.order
	a.admin = nil
	w.makeAdmin(a, order)
	w.pump(epoch+1, e.settle, 200)
	w.check()
	// The recorded vote may be written again after the restart, when the
	// braid had not applied the first copy yet: same value, so never a
	// second opinion.
	votes, _, err := order.Own(w.gid, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if len(votes) == 0 {
		t.Fatal("no vote")
	}
	for _, v := range votes {
		if v.Accept != votes[0].Accept || v.Reason != votes[0].Reason || v.Commit != votes[0].Commit {
			t.Fatal("a restart cast another vote")
		}
	}
}

// successor: the settlers are lost for good, so no Commit settles; an admin
// starts the successor group, and every remaining device joins it with a
// branch of the old group's last epoch.
func successor(t *testing.T, w *world, e env, s shape) {
	admins := w.admins()
	a := admins[0]
	epoch := a.m.Epoch()
	// Two of four settlers lost: no Commit gets q = 3 votes.
	if len(admins) > 1 {
		for _, n := range admins[2:] {
			n.online = false
		}
	}
	if e.halt() {
		if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{}); err != nil {
			t.Fatal(err)
		}
		for range 5 {
			for _, n := range w.admins() {
				if !n.online {
					continue
				}
				if ap, err := n.admin.Step(w.ctx); err != nil || ap != nil {
					t.Fatalf("a Commit settled without the quorum: %v", err)
				}
			}
			e.settle()
		}
		if a.m.Epoch() != epoch {
			t.Fatal("epoch moved")
		}
		if err := a.m.DiscardPending(); err != nil {
			t.Fatal(err)
		}
	}
	// Every remaining device makes a KeyPackage for the successor.
	var rest []*node
	stores := map[*node]*node{}
	for _, n := range w.live() {
		if n != a {
			rest = append(rest, n)
		}
	}
	var kps [][]byte
	for _, n := range rest {
		fresh := w.device(n.name+"-next", n.dev.Person)
		fresh.dev = n.dev
		stores[n] = fresh
		kps = append(kps, n.dev.KeyPackage(t, fresh.st))
	}
	order := e.successor(w, a)
	next := w.device("admin0-next", a.dev.Person)
	next.dev = a.dev
	co := a.dev.CreateOptions(t, next.st, w.config(next), nil)
	na, welcome, err := a.admin.Succeed(w.ctx, order, next.st, SucceedOptions{Create: co, KeyPackages: kps, Member: w.memberOptions(next), Admin: Options{Pins: w.pins, Now: w.clock}})
	if err != nil {
		t.Fatal(err)
	}
	var ap *Applied
	for range 200 {
		if ap, err = na.Step(w.ctx); err != nil {
			t.Fatal(err)
		}
		if ap != nil {
			break
		}
		e.settle()
	}
	if ap == nil || welcome == nil {
		t.Fatal("the successor's first Commit did not settle")
	}
	old := a.m
	newGID := na.m.GroupID()
	joined := 0
	for _, n := range rest {
		pred, err := settle.PredecessorOf(n.m, [32]byte{})
		if err != nil {
			t.Fatal(err)
		}
		psk, err := n.m.BranchPSK()
		if err != nil {
			t.Fatal(err)
		}
		fresh := stores[n]
		cfg := settle.NewConfig(n.auth, &settle.Policy{Limits: w.limits, Predecessor: pred}, w.clock)
		cfg.PSKs = psk
		m, err := settle.JoinMember(fresh.st, welcome, ap.Settled, func(gid []byte, epoch uint64, max int) ([]byte, error) {
			return w.pins.Get(w.ctx, settle.TreeKey(gid, epoch), max)
		}, kolomls.JoinOptions{Config: cfg}, w.memberOptions(fresh))
		if err != nil {
			t.Fatalf("%s joining the successor: %v", n.name, err)
		}
		mine, _ := m.EpochAuthenticator()
		theirs, _ := na.m.EpochAuthenticator()
		if !bytes.Equal(mine, theirs) || !bytes.Equal(m.GroupID(), newGID) {
			t.Fatalf("%s differs in the successor", n.name)
		}
		joined++
	}
	// TestPolicyBranch checks the refusals of a branch.
	if joined != len(rest) || bytes.Equal(old.GroupID(), newGID) {
		t.Fatal("successor joins")
	}
	t.Logf("%s: successor group joined by %d devices", s.name, joined+1)
}

func TestScenarioSmallMemory(t *testing.T) {
	scenario(t, small, &memEnv{log: newLog(1)})
}

func TestScenarioLargeMemory(t *testing.T) {
	scenario(t, large, &memEnv{log: newLog(1)})
}

func TestScenarioSmallBraid(t *testing.T) {
	scenario(t, small, newBraidEnv(t))
}

func TestScenarioLargeBraid(t *testing.T) {
	scenario(t, large, newBraidEnv(t))
}

// run runs a subtest with w failing through it, and reports whether it
// passed.
func (w *world) run(t *testing.T, name string, f func(t *testing.T)) bool {
	return t.Run(name, func(t *testing.T) {
		old := w.t
		w.t = t
		defer func() { w.t = old }()
		f(t)
	})
}
