package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/framing"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// start is the time of the test clock; leaves are made with the real one.
var start = time.Now().Truncate(time.Second)

// clock is a test clock for Config.Now.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func pastWorld(t *testing.T, n int, window time.Duration) (*world, *clock) {
	t.Helper()
	c := &clock{t: start}
	cfg := privateConfig()
	cfg.Now = c.now
	cfg.PastEpochWindow = window
	cfg.Envelope = genEnvelope{}
	return newWorldWith(t, n, cfg), c
}

// pastRecords counts the records of the previous epoch epoch in g's Store:
// its secret tree and its prev record.
func pastRecords(g *Group, epoch uint64) int {
	n := 0
	prefix := string(epochKey(g.s.ctx.GroupID, epoch)) + "/"
	g.st().each(func(k, v []byte) {
		if strings.HasPrefix(string(k), prefix) {
			n++
		}
		if bytes.Equal(k, groupKey(g.s.ctx.GroupID, "prev")) {
			if p, err := unmarshalPast(v); err == nil && p.epoch == epoch {
				n++
			}
		}
	})
	return n
}

// readLate has member l read an application message of the previous epoch.
func readLate(t *testing.T, w *world, l, sender uint32, msg, data []byte) {
	t.Helper()
	g := w.members[l].g
	r, err := g.Process(msg)
	if err != nil {
		t.Fatalf("member %d reading a late message: %v", l, err)
	}
	if r.Epoch != g.Epoch()-1 || r.Sender != sender || !bytes.Equal(r.Application, data) || len(r.AuthenticatedData) != 0 || r.Commit != nil || r.ProposalRef != nil {
		t.Fatalf("member %d: late message differs", l)
	}
	storeMatches(t, g)
}

// refusedPast checks that member l refuses msg with want and that its Store
// did not change.
func refusedPast(t *testing.T, w *world, l uint32, msg []byte, want error) {
	t.Helper()
	g := w.members[l].g
	before := snapshotStore(g.st())
	if _, err := g.Process(msg); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if !sameStore(before, snapshotStore(g.st())) {
		t.Fatal("a refused late message changed the Store")
	}
}

// TestPastEpochWindow: after a Commit, application messages of the previous
// epoch are read until the window ends, each once; then the previous epoch
// is deleted and they are refused.
func TestPastEpochWindow(t *testing.T) {
	w, c := pastWorld(t, 3, 0)
	m1 := w.encrypt(0, []byte("one"), nil)
	m2 := w.encrypt(0, []byte("two"), nil)
	m3 := w.encrypt(0, []byte("three"), nil)
	g1 := w.members[1].g
	if end, err := g1.ExpirePastEpoch(); err != nil || !end.IsZero() {
		t.Fatalf("no previous epoch yet: %v %v", end, err)
	}
	e := g1.Epoch()
	w.commit(2, CommitOptions{})
	if g1.Epoch() != e+1 || pastRecords(g1, e) == 0 || g1.prev.epoch != e {
		t.Fatal("the previous epoch was not kept")
	}
	readLate(t, w, 1, 0, m1, []byte("one"))
	refusedPast(t, w, 1, m1, errs.ErrReplay)
	w.reopen(1)
	refusedPast(t, w, 1, m1, errs.ErrReplay)
	readLate(t, w, 1, 0, m3, []byte("three"))

	c.t = c.t.Add(DefaultPastEpochWindow - time.Nanosecond)
	end, err := w.members[1].g.ExpirePastEpoch()
	if err != nil || !end.Equal(start.Add(DefaultPastEpochWindow)) {
		t.Fatalf("ExpirePastEpoch inside the window: %v %v", end, err)
	}
	c.t = c.t.Add(time.Nanosecond)
	g1 = w.members[1].g
	if _, err := g1.Process(m2); !errors.Is(err, errs.ErrWrongEpoch) {
		t.Fatalf("late message after the window: %v", err)
	}
	if g1.prev != nil || pastRecords(g1, e) != 0 {
		t.Fatal("the previous epoch was not deleted at the end of its window")
	}
	storeMatches(t, g1)

	// ExpirePastEpoch deletes it without a message.
	g2 := w.members[2].g
	if pastRecords(g2, e) == 0 {
		t.Fatal("member 2 keeps no previous epoch")
	}
	if end, err := g2.ExpirePastEpoch(); err != nil || !end.IsZero() || g2.prev != nil || pastRecords(g2, e) != 0 {
		t.Fatalf("ExpirePastEpoch after the window: %v %v", end, err)
	}
	storeMatches(t, g2)

	// Open deletes a previous epoch whose window ended while the group was closed.
	w.commit(1, CommitOptions{})
	if pastRecords(w.members[0].g, e+1) == 0 {
		t.Fatal("the previous epoch was not kept")
	}
	c.t = c.t.Add(DefaultPastEpochWindow)
	w.reopen(0)
	if g := w.members[0].g; g.prev != nil || pastRecords(g, e+1) != 0 {
		t.Fatal("Open kept a previous epoch past its window")
	}
	storeMatches(t, w.members[0].g)
}

// TestPastEpochOnlyPrevious: only the epoch right before the current one is
// kept, and a second Commit deletes the one before.
func TestPastEpochOnlyPrevious(t *testing.T) {
	w, _ := pastWorld(t, 3, time.Hour)
	e := w.members[1].g.Epoch()
	m0 := w.encrypt(0, []byte("epoch 0"), nil)
	w.commit(2, CommitOptions{})
	m1 := w.encrypt(0, []byte("epoch 1"), nil)
	w.commit(2, CommitOptions{})
	g := w.members[1].g
	if pastRecords(g, e) != 0 || pastRecords(g, e+1) == 0 {
		t.Fatal("wrong epochs kept")
	}
	refusedPast(t, w, 1, m0, errs.ErrWrongEpoch)
	readLate(t, w, 1, 0, m1, []byte("epoch 1"))
}

// TestPastEpochHandshakeRefused: proposals and Commits of the previous epoch
// are refused inside the window; only application data is read.
func TestPastEpochHandshakeRefused(t *testing.T) {
	w, _ := pastWorld(t, 3, 0)
	prop, err := w.members[0].g.ProposeRemove(2)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := w.members[0].g.Commit(CommitOptions{References: w.members[0].g.CachedProposals()})
	if err != nil {
		t.Fatal(err)
	}
	commit := pc.Commit()
	if err := w.members[0].g.DiscardPending(); err != nil {
		t.Fatal(err)
	}
	w.commit(1, CommitOptions{})
	refusedPast(t, w, 2, prop, errs.ErrWrongEpoch)
	refusedPast(t, w, 2, commit, errs.ErrWrongEpoch)
}

// TestPastEpochRemovedSender: a member that the Commit removes cannot slip a
// message into the previous epoch, nor can the client that took its leaf.
func TestPastEpochRemovedSender(t *testing.T) {
	w, _ := pastWorld(t, 4, 0)
	m0 := w.encrypt(0, []byte("from 0"), nil)
	m3 := w.encrypt(3, []byte("from 3"), nil)
	joiner := newClient(t)
	pc := w.commit(2, CommitOptions{Remove: []uint32{0, 3}, Add: [][]byte{joiner.keyPackage(t)}})
	got := w.join(2, pc, []*client{joiner})
	if got[0] != 0 {
		t.Fatalf("joiner at leaf %d, want 0", got[0])
	}
	refusedPast(t, w, 1, m0, errs.ErrUnknownSender)
	refusedPast(t, w, 1, m3, errs.ErrUnknownSender)
	if g := w.members[1].g; !g.prev.gone[0] || !g.prev.gone[3] {
		t.Fatal("removed leaves not marked")
	}
}

// TestPastEpochAddedLeaf: a leaf that a Commit fills had no member in the
// previous epoch, so no message of that epoch is read from it, even one
// its new member signs.
func TestPastEpochAddedLeaf(t *testing.T) {
	w, _ := pastWorld(t, 3, 0)
	w.commit(0, CommitOptions{Remove: []uint32{1}})
	joiner := newClient(t)
	pc := w.commit(0, CommitOptions{Add: [][]byte{joiner.keyPackage(t)}})
	got := w.join(0, pc, []*client{joiner})
	if got[0] != 1 || !w.members[2].g.prev.gone[1] {
		t.Fatalf("joiner at leaf %d, or the leaf not marked", got[0])
	}
	c := &message.FramedContent{ContentType: message.ContentApplication, ApplicationData: []byte("forged")}
	c.AuthenticatedData, _ = genEnvelope{}.Wrap(0, nil)
	forged := forgePastPrivate(t, w.members[2].g, got[0], 0, c, w.members[got[0]].g.s.sig)
	refusedPast(t, w, 2, forged, errs.ErrUnknownSender)
}

// TestPastEpochChangedKey: a member whose Commit changed its signature key
// is read in the previous epoch with its old key.
func TestPastEpochChangedKey(t *testing.T) {
	w, _ := pastWorld(t, 3, 0)
	m := w.encrypt(0, []byte("old key"), nil)
	g0 := w.members[0].g
	_, sig, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf := g0.s.tree.Leaf(0).Clone()
	leaf.SignatureKey = sig.Public().(ed25519.PublicKey)
	w.commit(0, CommitOptions{Leaf: leaf, SignatureKey: sig})
	if g := w.members[1].g; g.prev.sigs[0] == nil {
		t.Fatal("old signature key not kept")
	}
	readLate(t, w, 1, 0, m, []byte("old key"))
	// A message the new key signs for the old epoch is refused.
	c := &message.FramedContent{ContentType: message.ContentApplication, ApplicationData: []byte("forged")}
	c.AuthenticatedData, _ = genEnvelope{}.Wrap(1, nil)
	forged := forgePastPrivate(t, w.members[2].g, 0, 1, c, sig)
	refusedPast(t, w, 1, forged, errs.ErrSignature)
}

// forgePastPrivate builds, from the insider's previous epoch, a message of
// sender at generation gen with content c signed by key.
func forgePastPrivate(t *testing.T, insider *Group, sender, gen uint32, c *message.FramedContent, key ed25519.PrivateKey) []byte {
	t.Helper()
	p := insider.prev
	ctx, err := unmarshalGroupContext(p.ctxBytes)
	if err != nil {
		t.Fatal(err)
	}
	c.GroupID, c.Epoch, c.Sender = ctx.GroupID, ctx.Epoch, message.Sender{Type: message.SenderMember, Index: sender}
	sig, err := framing.Sign(key, message.WirePrivate, c, p.ctxBytes)
	if err != nil {
		t.Fatal(err)
	}
	lk, err := p.keys.Peek(sender, secrettree.Application, gen)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Discard()
	ac := &message.AuthenticatedContent{WireFormat: message.WirePrivate, Content: c, Auth: message.AuthData{Signature: sig}}
	pm, err := framing.ProtectPrivate(ac, p.senderData, lk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&message.MLSMessage{WireFormat: message.WirePrivate, Private: pm}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unmarshalGroupContext(b []byte) (ctx *schedule.GroupContext, err error) {
	err = tls.Decode(b, func(r *tls.Reader) error {
		ctx, err = schedule.ReadGroupContext(r)
		return err
	})
	return ctx, err
}

// TestPastEpochOff: a negative window keeps nothing.
func TestPastEpochOff(t *testing.T) {
	w, _ := pastWorld(t, 3, -1)
	m := w.encrypt(0, []byte("late"), nil)
	w.commit(2, CommitOptions{})
	refusedPast(t, w, 1, m, errs.ErrWrongEpoch)
	if g := w.members[1].g; g.prev != nil || pastRecords(g, 0) != 0 {
		t.Fatal("a previous epoch was kept with the window off")
	}
}

// TestPastEpochStoreFailure: a failed write while the previous epoch is
// kept makes the Group refuse calls, and Open reads what the Store holds.
func TestPastEpochStoreFailure(t *testing.T) {
	w, _ := pastWorld(t, 3, 0)
	m := w.encrypt(0, []byte("late"), nil)
	w.commit(2, CommitOptions{})
	c := w.members[1]
	c.g.store = &countStore{MemStore: c.st, fail: true}
	if _, err := c.g.Process(m); !errors.Is(err, errs.ErrStore) {
		t.Fatalf("failed write: %v", err)
	}
	if _, err := c.g.ExpirePastEpoch(); !errors.Is(err, errs.ErrStore) {
		t.Fatalf("after a failed write: %v", err)
	}
	reopen(t, c, c.st, w.cfg)
	readLate(t, w, 1, 0, m, []byte("late"))
}

// TestPastEpochStoredChecks: Open refuses a previous-epoch record that does
// not belong to the epoch before the current one or does not decode.
func TestPastEpochStoredChecks(t *testing.T) {
	w, _ := pastWorld(t, 2, 0)
	w.commit(1, CommitOptions{})
	c := w.members[0]
	key := groupKey(c.g.GroupID(), "prev")
	good, err := c.st.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := unmarshalPast(good)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(p *past){
		"epoch":  func(p *past) { p.epoch++ },
		"leaves": func(p *past) { p.leaves = 3 },
		"none":   func(p *past) { p.leaves = 0 },
	} {
		q := *p
		q.senderData = bytes.Clone(p.senderData)
		edit(&q)
		b, err := q.marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := c.st.Apply(Batch{Put: []KV{{Key: key, Value: b}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(c.st, c.g.GroupID(), w.cfg); !errors.Is(err, errs.ErrMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"version":     append([]byte{1}, good[1:]...),
		"short":       good[:len(good)-1],
		"sender data": shortSenderData(t, p),
	} {
		if err := c.st.Apply(Batch{Put: []KV{{Key: key, Value: b}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(c.st, c.g.GroupID(), w.cfg); err == nil {
			t.Fatalf("%s: stored record accepted", name)
		}
	}
}

func shortSenderData(t *testing.T, p *past) []byte {
	q := *p
	q.senderData = p.senderData[:16]
	b, err := q.marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPastEpochExpiresOnUse: Process and Encrypt delete a previous epoch
// whose window has ended, without ExpirePastEpoch.
func TestPastEpochExpiresOnUse(t *testing.T) {
	for _, op := range []string{"Process", "Encrypt"} {
		w, c := pastWorld(t, 3, 0)
		w.commit(2, CommitOptions{})
		msg := w.encrypt(0, []byte("now"), nil)
		g := w.members[1].g
		e := g.prev.epoch
		c.t = c.t.Add(DefaultPastEpochWindow)
		var err error
		if op == "Process" {
			_, err = g.Process(msg)
		} else {
			_, err = g.Encrypt([]byte("x"), nil)
		}
		if err != nil || g.prev != nil || pastRecords(g, e) != 0 {
			t.Fatalf("%s after the window: %v", op, err)
		}
		storeMatches(t, g)
	}
}

// viewPolicy records the proposal views it is shown.
type viewPolicy struct {
	rfcPolicy
	views *[]ProposalView
	joins *[]JoinView
}

func (p viewPolicy) CheckProposal(v ProposalView) error {
	*p.views = append(*p.views, v)
	return nil
}

func (p viewPolicy) CheckJoin(v JoinView) error {
	*p.joins = append(*p.joins, v)
	return nil
}

// TestPolicyViewCounts: a ProposalView counts the cached proposals and the
// sender's; a JoinView carries the GroupInfo extensions.
func TestPolicyViewCounts(t *testing.T) {
	var views []ProposalView
	var joins []JoinView
	cfg := testConfig()
	cfg.Policy = viewPolicy{views: &views, joins: &joins}
	w := newWorldWith(t, 3, cfg)
	p1, err := w.members[1].g.ProposeRemove(1)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := w.members[1].g.ProposeRemove(1)
	if err != nil {
		t.Fatal(err)
	}
	g := w.members[0].g
	views = nil
	if _, err := g.Process(p1); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Process(p2); err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 || views[0].FromSender != 0 || views[1].FromSender != 1 || views[1].Cached != 1 {
		t.Fatalf("views %+v", views)
	}
	if !slices.EqualFunc(views[0].Extensions, g.Extensions(), func(x, y tls.Extension) bool { return x.Type == y.Type && bytes.Equal(x.Data, y.Data) }) {
		t.Fatal("the view lacks the epoch's extensions")
	}
	j := newClient(t)
	joins = nil
	pc := w.commit(0, CommitOptions{Add: [][]byte{j.keyPackage(t)}, RatchetTree: true})
	if _, err := Join(j.st, pc.Welcome(), nil, JoinOptions{Config: w.cfg}); err != nil {
		t.Fatal(err)
	}
	if len(joins) != 1 || len(joins[0].InfoExtensions) != 2 || joins[0].InfoExtensions[0].Type != message.ExtRatchetTree || !isGrease(joins[0].InfoExtensions[1].Type) {
		t.Fatal("GroupInfo extensions not shown")
	}
}

// TestExtensionsCopy: Extensions returns a copy, and the reads that hold no
// secret still answer after Close.
func TestExtensionsCopy(t *testing.T) {
	w := newWorld(t, 2)
	g := w.members[0].g
	exts := []tls.Extension{{Type: message.ExtRequiredCapabilities, Data: []byte{0, 0, 0}}}
	w.commit(0, CommitOptions{SetExtensions: true, Extensions: exts})
	got := g.Extensions()
	got[0].Data[0] = 9
	if g.Extensions()[0].Data[0] != 0 {
		t.Fatal("Extensions shares memory")
	}
	ctx, epoch := g.GroupContext(), g.Epoch()
	g.Close()
	if !bytes.Equal(g.GroupContext(), ctx) || g.Epoch() != epoch || len(g.Extensions()) != 1 || len(g.Tree().Members()) != 2 {
		t.Fatal("reads after Close")
	}
}

func TestMemStoreClone(t *testing.T) {
	s := NewMemStore()
	if err := s.Apply(Batch{Put: []KV{{Key: []byte("k"), Value: []byte("v")}}}); err != nil {
		t.Fatal(err)
	}
	c := s.Clone()
	if err := s.Apply(Batch{Delete: [][]byte{[]byte("k")}}); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Get([]byte("k")); err != nil || string(v) != "v" {
		t.Fatalf("clone: %q %v", v, err)
	}
}
