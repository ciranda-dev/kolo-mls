package braid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/settle"
)

func wantRule(t *testing.T, name string, err error) {
	t.Helper()
	if !errors.Is(err, errs.ErrPolicy) || !errors.Is(err, settle.ErrRule) {
		t.Errorf("%s: %v", name, err)
	}
}

// fourAdmins builds a group of four admins (all settlers) and n members.
func fourAdmins(t *testing.T, n int) (*world, *memLog) {
	w := newWorld(t)
	l := newLog(1)
	e := &memEnv{log: l}
	founder := w.device("admin0", nil)
	w.create(founder, e.order(w, founder))
	var nodes []*node
	for i := 1; i < 4; i++ {
		nodes = append(nodes, w.device("admin"+string(rune('0'+i)), nil))
	}
	for i := range n {
		nodes = append(nodes, w.device("member"+string(rune('a'+i)), nil))
	}
	w.join(founder, l.settle, nodes...)
	all := append([]*node{founder}, nodes[:3]...)
	promote(w, e, founder, all, all, settle.Majority)
	return w, l
}

// TestPolicyRoleChanges: an admin removes another with roles that drop it,
// when the braid's roster matches; q settlers must stay; a roles change
// the braid does not show is rejected.
func TestPolicyRoleChanges(t *testing.T) {
	w, l := fourAdmins(t, 2)
	a := w.nodes[0]
	admin1 := w.nodes[1]
	var keep []ed25519.PublicKey
	for _, n := range w.nodes[:2] {
		keep = append(keep, n.dev.ID.PublicKey())
	}
	roles, _ := settle.RolesOf(a.m.Extensions(), w.limits)
	two, err := settle.NewRoles(roles.Braid, settle.Majority, keep, keep, w.limits)
	if err != nil {
		t.Fatal(err)
	}
	exts, _ := settle.GroupExtensions(two)
	_, err = a.m.Commit(kolomls.CommitOptions{Remove: []uint32{w.nodes[2].m.OwnLeaf(), w.nodes[3].m.OwnLeaf()}, SetExtensions: true, Extensions: exts})
	if !errors.Is(err, errs.ErrPolicy) {
		t.Fatalf("fewer than q settlers stay: %v", err)
	}
	var three []ed25519.PublicKey
	for _, n := range []*node{w.nodes[0], w.nodes[2], w.nodes[3]} {
		three = append(three, n.dev.ID.PublicKey())
	}
	next, err := settle.NewRoles(roles.Braid, settle.Majority, three, three, w.limits)
	if err != nil {
		t.Fatal(err)
	}
	nexts, _ := settle.GroupExtensions(next)
	// The braid still lists admin1.
	if _, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Remove: []uint32{admin1.m.OwnLeaf()}, SetExtensions: true, Extensions: nexts}); !errors.Is(err, ErrRoster) {
		t.Fatalf("roles the braid does not show: %v", err)
	}
	(&memEnv{log: l}).seat(w, []*node{w.nodes[0], w.nodes[2], w.nodes[3]}, settle.Majority)
	w.commit(a, kolomls.CommitOptions{Remove: []uint32{admin1.m.OwnLeaf()}, SetExtensions: true, Extensions: nexts}, l.settle)
	if !admin1.m.Removed() {
		t.Fatal("admin not removed")
	}
	// The removed settler could not sign; the three others settled it.
	member := w.memberNodes()[0]
	w.proposeLeave(member)
	w.commit(a, kolomls.CommitOptions{Remove: []uint32{member.m.OwnLeaf()}}, l.settle)
	if !member.m.Removed() {
		t.Fatal("leaver not removed")
	}
}

// TestPolicyJoin: a Welcome is joined only with its SettledCommit
// (TestPolicyWelcome in package settle checks each field) and only with the
// Kolo Policy.
func TestPolicyJoin(t *testing.T) {
	w, l := memGroup(t, 1)
	a := w.nodes[0]
	j := w.device("joiner", nil)
	kp := j.dev.KeyPackage(t, j.st)
	e := a.m.Epoch()
	welcome, err := a.admin.Commit(w.ctx, kolomls.CommitOptions{Add: [][]byte{kp}})
	if err != nil {
		t.Fatal(err)
	}
	w.pump(e+1, l.settle, 50)
	settled := w.mustGet(settle.SettledKey(w.gid, e))
	tree := func(gid []byte, epoch uint64, max int) ([]byte, error) {
		return w.pins.Get(w.ctx, settle.TreeKey(gid, epoch), max)
	}
	o := kolomls.JoinOptions{Config: w.config(j)}
	// Join without the SettledCommit.
	o.Tree = func(export func(string, []byte, int) ([]byte, error)) ([]byte, error) {
		sealed, err := tree(w.gid, e+1, 0)
		if err != nil {
			return nil, err
		}
		return settle.OpenTree(export, w.gid, e+1, sealed)
	}
	if _, err := kolomls.Join(j.st, welcome, nil, o); !errors.Is(err, settle.ErrNotSettled) {
		t.Fatalf("no SettledCommit: %v", err)
	}
	if _, err := settle.JoinMember(j.st, welcome, settled, tree, o, w.memberOptions(j)); err != nil {
		t.Fatalf("valid: %v", err)
	}
	var plain kolomls.JoinOptions
	plain.Config = kolomls.Config{Authenticator: j.auth, Policy: plainPolicy{}, PrivateHandshakes: true, Envelope: settle.Envelope{}, Now: w.clock}
	if _, err := settle.JoinMember(j.st, welcome, settled, tree, plain, w.memberOptions(j)); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("another Policy: %v", err)
	}
}

type plainPolicy struct{}

func (plainPolicy) CheckProposal(kolomls.ProposalView) error { return nil }
func (plainPolicy) CheckCommit(kolomls.CommitView) error     { return nil }
func (plainPolicy) CheckJoin(kolomls.JoinView) error         { return nil }

func TestPolicyBranch(t *testing.T) {
	w, l := memGroup(t, 2)
	e := &memEnv{log: l}
	a := w.nodes[0]
	m := w.nodes[1]
	outsider := w.device("outsider", nil)
	kp := m.dev.KeyPackage(t, outsider.st)
	order := e.successor(w, a)
	next := w.device("admin0-next", a.dev.Person)
	next.dev = a.dev
	co := a.dev.CreateOptions(t, next.st, w.config(next), nil)
	if err := a.st.Apply(kolomls.Batch{Put: []kolomls.KV{{Key: recordKey(w.gid, "sig"), Value: make([]byte, 8)}}}); err != nil {
		t.Fatal(err)
	}
	na, welcome, err := a.admin.Succeed(w.ctx, order, next.st, SucceedOptions{Create: co, KeyPackages: [][]byte{kp}, Member: w.memberOptions(next), Admin: Options{Pins: w.pins, Now: w.clock}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.st.Get(recordKey(w.gid, "sig")); !errors.Is(err, errs.ErrNotFound) {
		t.Fatal("the old group's records were kept")
	}
	var ap *Applied
	for ap == nil {
		if ap, err = na.Step(w.ctx); err != nil {
			t.Fatal(err)
		}
		e.settle()
	}
	tree := func(gid []byte, epoch uint64, max int) ([]byte, error) {
		return w.pins.Get(w.ctx, settle.TreeKey(gid, epoch), max)
	}
	bp, err := m.m.BranchPSK()
	if err != nil {
		t.Fatal(err)
	}
	id, v := bp.ID(), bp.Value
	join := func(pred *settle.Predecessor, psk *settle.BranchPSK) error {
		cfg := settle.NewConfig(m.auth, &settle.Policy{Limits: w.limits, Predecessor: pred}, w.clock)
		cfg.PSKs = psk
		st := copyStore(t, outsider)
		_, err := settle.JoinMember(st, welcome, ap.Settled, tree, kolomls.JoinOptions{Config: cfg}, w.memberOptions(m))
		return err
	}
	psk := &settle.BranchPSK{GroupID: id.GroupID, Epoch: id.Epoch, Value: v}
	good, err := settle.PredecessorOf(m.m, order.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := join(good, psk); err != nil {
		t.Fatalf("valid branch: %v", err)
	}
	if err := join(nil, psk); !errors.Is(err, settle.ErrRule) {
		t.Fatalf("no predecessor: %v", err)
	}
	cases := map[string]func(p *settle.Predecessor){
		"another group": func(p *settle.Predecessor) { p.GroupID = bytes.Repeat([]byte{7}, 32) },
		"another epoch": func(p *settle.Predecessor) { p.Epoch++ },
		"another braid": func(p *settle.Predecessor) { p.Braid[0] ^= 1 },
		"creator no settler": func(p *settle.Predecessor) {
			p.Roles = &settle.Roles{Admins: [][32]byte{a.dev.Key()}, Settlers: [][32]byte{{1}}}
		},
		"creator revoked": func(p *settle.Predecessor) {
			r, err := a.dev.Person.RevokeDevice(&koloid.RevokeOptions{Person: a.dev.Person.PublicKey(), Device: a.dev.ID.PublicKey(), UpToSerial: 1})
			if err != nil {
				t.Fatal(err)
			}
			p.Revocations = func(_, d ed25519.PublicKey) []*koloid.Revocation { return []*koloid.Revocation{r} }
		},
		"unknown device": func(p *settle.Predecessor) { p.Devices = map[[32]byte]bool{a.dev.Key(): true} },
	}
	for name, edit := range cases {
		p := *good
		edit(&p)
		if err := join(&p, psk); !errors.Is(err, settle.ErrRule) {
			t.Errorf("%s: %v", name, err)
		}
	}
	unchecked := *good
	unchecked.Braid = [32]byte{}
	if err := join(&unchecked, psk); err != nil {
		t.Fatalf("a member that is not in the braid: %v", err)
	}
	if err := join(good, &settle.BranchPSK{GroupID: id.GroupID, Epoch: id.Epoch + 1, Value: v}); !errors.Is(err, errs.ErrPSKNotFound) {
		t.Fatalf("PSK of another epoch: %v", err)
	}
}

// copyStore returns a copy of n's Store, so one KeyPackage can be tried in
// several joins.
func copyStore(t *testing.T, n *node) kolomls.Store {
	return backendStore(copyBackend(t, n.backend))
}

// pskAny serves the same value for every external PSK.
type pskAny []byte

func (p pskAny) PSK(id *schedule.PSKID) ([]byte, error) {
	return bytes.Clone(p), nil
}

// TestPolicyJoinPSK: a Welcome with a PSK other than a branch, from a
// creator whose own client skipped the Kolo rules, is refused even by a
// joiner that holds the PSK and follows the group the PSK names; a branch
// against a Predecessor without roles is refused, not a panic.
func TestPolicyJoinPSK(t *testing.T) {
	oldGID := bytes.Repeat([]byte{5}, 32)
	for name, id := range map[string]*schedule.PSKID{
		"external":                {Type: schedule.PSKExternal, ID: []byte("k")},
		"resumption, application": {Type: schedule.PSKResumption, Usage: schedule.UsageApplication, GroupID: oldGID, Epoch: 7},
		"branch, no roles":        {Type: schedule.PSKResumption, Usage: schedule.UsageBranch, GroupID: oldGID, Epoch: 7},
	} {
		w := newWorld(t)
		creator := w.device("creator", nil)
		roles, err := settle.NewRoles([32]byte{3}, settle.Majority, []ed25519.PublicKey{creator.dev.ID.PublicKey()}, []ed25519.PublicKey{creator.dev.ID.PublicKey()}, w.limits)
		if err != nil {
			t.Fatal(err)
		}
		cfg := kolomls.Config{Authenticator: creator.auth, Policy: plainPolicy{}, PSKs: pskAny("secret"), PrivateHandshakes: true, Envelope: settle.Envelope{}, Now: w.clock}
		cexts, _ := settle.GroupExtensions(roles)
		g, err := kolomls.Create(creator.st, creator.dev.CreateOptions(t, creator.st, cfg, cexts))
		if err != nil {
			t.Fatal(err)
		}
		j := w.device("joiner", nil)
		before := sha256.Sum256(g.GroupContext())
		pc, err := g.Commit(kolomls.CommitOptions{Add: [][]byte{j.dev.KeyPackage(t, j.st)}, PSKs: []*schedule.PSKID{id}})
		if err != nil {
			t.Fatal(err)
		}
		tbs := settle.TBS{GroupID: g.GroupID(), Epoch: 0, Commit: sha256.Sum256(pc.Commit()), ContextBefore: before, ContextAfter: sha256.Sum256(pc.GroupContext()), Braid: roles.Braid}
		sig, err := Sign(creator.dev.ID, &tbs)
		if err != nil {
			t.Fatal(err)
		}
		settled := (&settle.Settled{TBS: tbs, Shares: []settle.Share{{Signer: creator.dev.Key(), Signature: [64]byte(sig)}}}).Encode()
		if err := g.ApplyPending(); err != nil {
			t.Fatal(err)
		}
		tr, err := g.RatchetTree()
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := settle.Seal(g.Export, g.GroupID(), g.Epoch(), creator.dev.Key(), tr)
		if err != nil {
			t.Fatal(err)
		}
		pred := &settle.Predecessor{GroupID: oldGID, Epoch: 7, Roles: roles, Devices: map[[32]byte]bool{creator.dev.Key(): true, j.dev.Key(): true}}
		if id.Usage == schedule.UsageBranch {
			// An application-built Predecessor that names no roles.
			pred.Roles = nil
		}
		jc := settle.NewConfig(j.auth, &settle.Policy{Limits: w.limits, Predecessor: pred}, w.clock)
		jc.PSKs = pskAny("secret")
		_, err = settle.JoinMember(j.st, pc.Welcome(), settled, func([]byte, uint64, int) ([]byte, error) { return sealed, nil }, kolomls.JoinOptions{Config: jc}, w.memberOptions(j))
		wantRule(t, name, err)
	}
}
