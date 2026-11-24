package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/framing"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
)

func privateConfig() Config {
	c := testConfig()
	c.PrivateHandshakes = true
	return c
}

func wireFormat(t testing.TB, msg []byte) uint16 {
	t.Helper()
	m, err := message.UnmarshalMLSMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	return m.WireFormat
}

// encrypt has member l encrypt data with aad.
func (w *world) encrypt(l uint32, data, aad []byte) []byte {
	w.t.Helper()
	msg, err := w.members[l].g.Encrypt(data, aad)
	if err != nil {
		w.t.Fatalf("Encrypt by %d: %v", l, err)
	}
	return msg
}

// receive has member l process an application message of sender and checks
// what it returns and what its Store holds.
func (w *world) receive(l, sender uint32, msg, data, aad []byte) {
	w.t.Helper()
	g := w.members[l].g
	r, err := g.Process(msg)
	if err != nil {
		w.t.Fatalf("member %d processing an application message: %v", l, err)
	}
	if r.Sender != sender || !bytes.Equal(r.Application, data) || !bytes.Equal(r.AuthenticatedData, aad) || r.Commit != nil || r.ProposalRef != nil {
		w.t.Fatalf("member %d: application message differs", l)
	}
	storeMatches(w.t, g)
}

// snapshotStore copies every key and value of st.
func snapshotStore(st *MemStore) map[string]string {
	out := map[string]string{}
	st.each(func(k, v []byte) { out[string(k)] = string(v) })
	return out
}

func sameStore(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// refusedPrivate checks that member l refuses msg with want and that neither
// its Store nor its secret tree changed.
func refusedPrivate(t *testing.T, w *world, l uint32, msg []byte, want error) {
	t.Helper()
	g := w.members[l].g
	before := snapshotStore(g.st())
	keys, err := g.s.keys.Records()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Process(msg); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if !sameStore(before, snapshotStore(g.st())) {
		t.Fatal("a refused PrivateMessage changed the Store")
	}
	after, _ := g.s.keys.Records()
	if fmt.Sprint(keys) != fmt.Sprint(after) {
		t.Fatal("a refused PrivateMessage changed the secret tree")
	}
}

// forgePrivate returns a PrivateMessage that the insider builds under the
// key of sender's generation gen (every member can derive every key of the
// epoch), with content c signed by key.
func forgePrivate(t testing.TB, insider *Group, sender, gen uint32, c *message.FramedContent, key ed25519.PrivateKey) []byte {
	t.Helper()
	s := insider.s
	c.GroupID, c.Epoch, c.Sender = s.ctx.GroupID, s.ctx.Epoch, message.Sender{Type: message.SenderMember, Index: sender}
	sig, err := framing.Sign(key, message.WirePrivate, c, s.ctxBytes)
	if err != nil {
		t.Fatal(err)
	}
	return seal(t, insider, &message.AuthenticatedContent{WireFormat: message.WirePrivate, Content: c, Auth: message.AuthData{Signature: sig}}, gen)
}

// seal encrypts signed content ac as the insider at generation gen of the
// content's sender, leaving the insider's own state as it was.
func seal(t testing.TB, insider *Group, ac *message.AuthenticatedContent, gen uint32) []byte {
	t.Helper()
	lk, err := insider.s.keys.Peek(ac.Content.Sender.Index, framing.RatchetKind(ac.Content.ContentType), gen)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Discard()
	pm, err := framing.ProtectPrivate(ac, insider.s.secrets.SenderData, lk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&message.MLSMessage{WireFormat: message.WirePrivate, Private: pm}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPeekSender: the sender data names the leaf and generation, no key is
// used up, and what is not a PrivateMessage of this group and epoch is
// refused.
func TestPeekSender(t *testing.T) {
	w := newWorldWith(t, 3, privateConfig())
	msgs := [][]byte{w.encrypt(1, []byte("a"), nil), w.encrypt(1, []byte("b"), nil), w.encrypt(2, []byte("c"), nil)}
	g := w.members[0].g
	before := snapshotStore(g.st())
	for i, c := range [][2]uint32{{1, 0}, {1, 1}, {2, 0}} {
		if leaf, gen, err := g.PeekSender(msgs[i]); err != nil || leaf != c[0] || gen != c[1] {
			t.Fatalf("message %d: leaf %d generation %d: %v", i, leaf, gen, err)
		}
	}
	if !sameStore(before, snapshotStore(g.st())) {
		t.Fatal("PeekSender changed the Store")
	}
	w.receive(0, 1, msgs[1], []byte("b"), nil)
	w.receive(0, 1, msgs[0], []byte("a"), nil)
	edit := func(f func(*message.PrivateMessage)) []byte {
		m, err := message.UnmarshalMLSMessage(msgs[0])
		if err != nil {
			t.Fatal(err)
		}
		f(m.Private)
		b, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	public, err := newWorld(t, 2).members[0].g.ProposeRemove(1)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		msg  []byte
		want error
	}{
		"garbage":      {[]byte{1, 2, 3}, errs.ErrUnsupported},
		"public":       {public, errs.ErrInvalidArgument},
		"other group":  {edit(func(p *message.PrivateMessage) { p.GroupID = []byte("other") }), errs.ErrWrongGroup},
		"other epoch":  {edit(func(p *message.PrivateMessage) { p.Epoch++ }), errs.ErrWrongEpoch},
		"sender data":  {edit(func(p *message.PrivateMessage) { p.EncryptedSenderData[0] ^= 1 }), errs.ErrDecrypt},
		"short sender": {edit(func(p *message.PrivateMessage) { p.EncryptedSenderData = nil }), errs.ErrDecrypt},
	} {
		if _, _, err := g.PeekSender(c.msg); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	g.Close()
	if _, _, err := g.PeekSender(msgs[0]); err == nil {
		t.Fatal("a closed group read sender data")
	}
}

// TestPrivateHandshakes runs proposals and Commits as PrivateMessages
// in a Kolo group: every member follows them, every Store holds exactly the
// state with its secret tree, and reopened members keep going.
func TestPrivateHandshakes(t *testing.T) {
	w := newWorldWith(t, 2, privateConfig())
	pc := w.commit(0, CommitOptions{})
	if wireFormat(t, pc.Commit()) != message.WirePrivate {
		t.Fatal("Commit not sent as a PrivateMessage")
	}
	w.add(1, 3)
	// A private Commit keeps its key until Apply: processed twice, it is
	// staged twice, the first Apply wins and the second is stale.
	pc, err := w.members[0].g.Commit(CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b := w.members[1].g
	before := snapshotStore(b.st())
	r1, err := b.Process(pc.Commit())
	if err != nil || !sameStore(before, snapshotStore(b.st())) {
		t.Fatalf("Process of a private Commit: %v, or it wrote", err)
	}
	r2, err := b.Process(pc.Commit())
	if err != nil {
		t.Fatalf("second Process of a private Commit: %v", err)
	}
	if err := b.Apply(r1.Commit); err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(r2.Commit); !errors.Is(err, errs.ErrInvalidArgument) || r2.Commit.next != nil {
		t.Fatalf("second Apply: %v", err)
	}
	for _, l := range w.leaves()[2:] {
		r, err := w.members[l].g.Process(pc.Commit())
		if err != nil {
			t.Fatal(err)
		}
		if err := w.members[l].g.Apply(r.Commit); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.members[0].g.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	w.check()
	msg, err := w.members[2].g.ProposeUpdate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if wireFormat(t, msg) != message.WirePrivate {
		t.Fatal("proposal not sent as a PrivateMessage")
	}
	var ref []byte
	for _, l := range w.leaves() {
		if l == 2 {
			continue
		}
		r, err := w.members[l].g.Process(msg)
		if err != nil {
			t.Fatalf("member %d: %v", l, err)
		}
		if r.Sender != 2 {
			t.Fatal("wrong sender")
		}
		ref = r.ProposalRef
		storeMatches(t, w.members[l].g)
	}
	w.reopen(3)
	w.commit(3, CommitOptions{References: [][]byte{ref}})
	w.check()
	for _, l := range w.leaves() {
		w.reopen(l)
	}
	ref = w.propose(4, func(g *Group) ([]byte, error) { return g.ProposeRemove(1) })
	w.commit(0, CommitOptions{References: [][]byte{ref}})
	w.check()
	data := []byte("after the private handshakes")
	m := w.encrypt(0, data, nil)
	for _, l := range w.leaves()[1:] {
		w.receive(l, 0, m, data, nil)
	}
}

// TestPublicHandshakeRefused: a member that sends handshakes privately
// refuses another member's PublicMessage.
func TestPublicHandshakeRefused(t *testing.T) {
	w := newWorldWith(t, 3, privateConfig())
	g1 := w.members[1].g
	g1.cfg.PrivateHandshakes = false
	msg, err := g1.ProposeRemove(2)
	if err != nil {
		t.Fatal(err)
	}
	if wireFormat(t, msg) != message.WirePublic {
		t.Fatal("not a PublicMessage")
	}
	g := w.members[0].g
	before := snapshotStore(g.st())
	if _, err := g.Process(msg); !errors.Is(err, errs.ErrPolicy) || !sameStore(before, snapshotStore(g.st())) {
		t.Fatalf("PublicMessage handshake: %v", err)
	}
	g.cfg.PrivateHandshakes = false
	if _, err := g.Process(msg); err != nil {
		t.Fatalf("PublicMessage accepted without the setting: %v", err)
	}
}

// TestApplicationMessages sends application data between members: order,
// out-of-order inside the window, replay, the bounds of Config, reopening
// from the Store, and a Commit that ends the epoch's keys.
func TestApplicationMessages(t *testing.T) {
	cfg := testConfig()
	cfg.OutOfOrderTolerance, cfg.MaxForwardDistance = 2, 3
	cfg.PastEpochWindow = -1
	w := newWorldWith(t, 3, cfg)
	var msgs [][]byte
	for i := range 6 {
		msgs = append(msgs, w.encrypt(0, []byte{byte(i)}, []byte{9, byte(i)}))
	}
	if wireFormat(t, msgs[0]) != message.WirePrivate {
		t.Fatal("application data not in a PrivateMessage")
	}
	w.receive(1, 0, msgs[0], []byte{0}, []byte{9, 0})
	refusedPrivate(t, w, 1, msgs[0], errs.ErrReplay)
	w.receive(1, 0, msgs[3], []byte{3}, []byte{9, 3})
	w.reopen(1)
	refusedPrivate(t, w, 1, msgs[3], errs.ErrReplay)
	refusedPrivate(t, w, 1, msgs[1], errs.ErrTooOld)
	w.receive(1, 0, msgs[2], []byte{2}, []byte{9, 2})
	refusedPrivate(t, w, 1, msgs[2], errs.ErrReplay)
	// Member 2 has seen nothing: generation 4 is 4 steps ahead of its head 0.
	refusedPrivate(t, w, 2, msgs[4], errs.ErrTooFarAhead)
	w.receive(2, 0, msgs[3], []byte{3}, []byte{9, 3})
	w.reopen(2)
	w.receive(2, 0, msgs[5], []byte{5}, []byte{9, 5})
	w.receive(2, 0, msgs[4], []byte{4}, []byte{9, 4})
	// A member reads its own message as a replay: the sender used the key.
	refusedPrivate(t, w, 0, msgs[5], errs.ErrReplay)

	w.commit(2, CommitOptions{})
	refusedPrivate(t, w, 1, msgs[5], errs.ErrWrongEpoch)
	data := []byte("next epoch")
	m := w.encrypt(1, data, nil)
	w.receive(0, 1, m, data, nil)
	w.receive(2, 1, m, data, nil)
}

// TestEncryptWithProposals: a member that holds proposals commits before it
// sends application data (RFC 9420 section 12.4).
func TestEncryptWithProposals(t *testing.T) {
	w := newWorld(t, 3)
	ref := w.propose(1, func(g *Group) ([]byte, error) { return g.ProposeRemove(2) })
	for _, l := range []uint32{0, 1} {
		if _, err := w.members[l].g.Encrypt([]byte("x"), nil); !errors.Is(err, errs.ErrPendingProposals) {
			t.Fatalf("member %d: %v", l, err)
		}
	}
	w.commit(0, CommitOptions{References: [][]byte{ref}})
	w.encrypt(0, []byte("x"), nil)
}

// TestForgedPrivateConsumesNothing: an insider can build a valid ciphertext
// under any member's key, but not that member's signature. Such a message,
// and any other refused one, consumes no key, so the real message of that
// generation is still read.
func TestForgedPrivateConsumesNothing(t *testing.T) {
	w := newWorldWith(t, 5, privateConfig())
	insider := w.members[2].g
	app := func(s string) *message.FramedContent {
		return &message.FramedContent{ContentType: message.ContentApplication, ApplicationData: []byte(s)}
	}
	forged := forgePrivate(t, insider, 0, 0, app("forged"), insider.s.sig)
	refusedPrivate(t, w, 1, forged, errs.ErrSignature)
	garbled := bytes.Clone(forged)
	garbled[len(garbled)-1] ^= 1
	refusedPrivate(t, w, 1, garbled, errs.ErrDecrypt)
	refusedPrivate(t, w, 1, forgePrivate(t, insider, 6, 0, app("blank"), insider.s.sig), errs.ErrUnknownSender)
	// A handshake forgery leaves the handshake ratchet unused too.
	proposal := &message.FramedContent{ContentType: message.ContentProposal, Proposal: &message.Proposal{Type: message.ProposalRemove, Removed: 3}}
	refusedPrivate(t, w, 1, forgePrivate(t, insider, 0, 0, proposal, insider.s.sig), errs.ErrSignature)

	data := []byte("real")
	m := w.encrypt(0, data, nil)
	w.receive(1, 0, m, data, nil)
	refusedPrivate(t, w, 1, m, errs.ErrReplay)
	ref := w.propose(0, func(g *Group) ([]byte, error) { return g.ProposeRemove(3) })
	if ref == nil {
		t.Fatal("real proposal of generation 0 refused")
	}
	// A proposal refused after its signature verified still uses its key,
	// so it cannot be sent again under that generation.
	bad := forgePrivate(t, insider, 2, 1, &message.FramedContent{ContentType: message.ContentProposal, Proposal: &message.Proposal{Type: message.ProposalRemove, Removed: 9}}, insider.s.sig)
	if _, err := w.members[1].g.Process(bad); !errors.Is(err, errs.ErrInvalidProposal) {
		t.Fatalf("invalid proposal: %v", err)
	}
	storeMatches(t, w.members[1].g)
	refusedPrivate(t, w, 1, bad, errs.ErrReplay)
}

// TestConsumedKeyLeavesTheStore: once a member reads generation g, neither
// its memory nor its Store holds that generation's key or nonce, and the
// epoch's root secret is gone after the first message (RFC 9420 section 9.2).
func TestConsumedKeyLeavesTheStore(t *testing.T) {
	w := newWorld(t, 3)
	a, b := w.members[0].g, w.members[1].g
	lk, err := a.s.keys.PeekNext(0, secrettree.Application)
	if err != nil {
		t.Fatal(err)
	}
	key, nonce := lk.Key(), lk.Nonce()
	lk.Discard()
	for _, g := range []*Group{a, b} {
		if g.s.secrets.Encryption != nil {
			t.Fatal("encryption_secret kept once the secret tree started")
		}
	}
	root, _ := b.s.keys.Records()
	if len(root) != 1 || root[0].Leaf {
		t.Fatal("a new epoch's secret tree is not its root record")
	}
	m := w.encrypt(0, []byte("x"), nil)
	w.receive(1, 0, m, []byte("x"), nil)
	b.st().each(func(k, v []byte) {
		if bytes.Contains(v, key) || bytes.Contains(v, nonce) || bytes.Contains(v, root[0].Value) {
			t.Fatalf("record %s keeps a consumed value", k)
		}
	})
	if _, err := b.st().Get(secretKey(b.GroupID(), b.Epoch(), root[0])); !errors.Is(err, errs.ErrNotFound) {
		t.Fatal("root record kept")
	}
}

// genEnvelope puts the generation in front of the application's aad, as the
// Kolo envelope does.
type genEnvelope struct{ fail bool }

var errEnvelope = errors.New("envelope refused")

func (e genEnvelope) Wrap(gen uint32, aad []byte) ([]byte, error) {
	if e.fail {
		return nil, errEnvelope
	}
	return append(binary.BigEndian.AppendUint32(nil, gen), aad...), nil
}

func (genEnvelope) Unwrap(gen uint32, ad []byte) ([]byte, error) {
	if len(ad) < 4 || binary.BigEndian.Uint32(ad) != gen {
		return nil, errEnvelope
	}
	return ad[4:], nil
}

// TestEnvelope: an insider re-encrypts another member's signed content
// under a later generation (RFC 9750 section 8.6). Without an Envelope the
// copy is accepted and burns that generation; with one it is refused before
// any key is used, and the real message of the generation is read.
func TestEnvelope(t *testing.T) {
	for _, withEnvelope := range []bool{false, true} {
		cfg := privateConfig()
		if withEnvelope {
			cfg.Envelope = genEnvelope{}
		}
		w := newWorldWith(t, 3, cfg)
		insider := w.members[2].g
		data, aad := []byte("pay 10"), []byte("note")
		m0 := w.encrypt(0, data, aad)
		pm, _ := message.UnmarshalMLSMessage(m0)
		ac, lk, err := framing.UnprotectPrivate(pm.Private, insider.s.secrets.SenderData, insider.s.keys, func(uint32) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		lk.Discard()
		copied := seal(t, insider, ac, 1)
		w.receive(1, 0, m0, data, aad)
		m1 := w.encrypt(0, data, aad)
		if !withEnvelope {
			w.receive(1, 0, copied, data, aad)
			refusedPrivate(t, w, 1, m1, errs.ErrReplay)
			continue
		}
		refusedPrivate(t, w, 1, copied, errs.ErrMalformed)
		w.receive(1, 0, m1, data, aad)

		a := w.members[0].g
		a.cfg.Envelope = genEnvelope{fail: true}
		if _, err := a.Encrypt(data, nil); !errors.Is(err, errs.ErrInvalidArgument) || !errors.Is(err, errEnvelope) {
			t.Fatalf("failing Wrap: %v", err)
		}
		if _, err := a.ProposeRemove(2); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Fatalf("failing Wrap on a proposal: %v", err)
		}
		if _, err := a.Commit(CommitOptions{}); !errors.Is(err, errs.ErrInvalidArgument) || a.pending != nil {
			t.Fatalf("failing Wrap on a Commit: %v", err)
		}
		a.cfg.Envelope = genEnvelope{}
		m2 := w.encrypt(0, data, aad)
		w.receive(1, 0, m2, data, aad)
		w.commit(0, CommitOptions{})
		w.check()
	}
}

// TestPrivateStoreAtomicity: each private send or receive is one Store
// batch, and a failed batch uses no key, so the same generation follows.
func TestPrivateStoreAtomicity(t *testing.T) {
	w := newWorldWith(t, 3, privateConfig())
	a, b := w.members[0], w.members[1]
	as := &countStore{MemStore: a.st}
	bs := &countStore{MemStore: b.st}
	a.g.store, b.g.store = as, bs
	gen := func(msg []byte) uint32 {
		t.Helper()
		m, _ := message.UnmarshalMLSMessage(msg)
		_, lk, err := framing.UnprotectPrivate(m.Private, w.members[2].g.s.secrets.SenderData, w.members[2].g.s.keys, func(uint32) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		defer lk.Discard()
		return lk.Generation()
	}
	for _, c := range []struct {
		name string
		op   func() ([]byte, error)
	}{
		{"Encrypt", func() ([]byte, error) { return a.g.Encrypt([]byte("x"), nil) }},
		{"ProposeRemove", func() ([]byte, error) { return a.g.ProposeRemove(2) }},
	} {
		name, op := c.name, c.op
		as.fail, as.applies = true, 0
		if _, err := op(); !errors.Is(err, errDisk) || as.applies != 1 {
			t.Fatalf("%s with a failing Store: %v, %d batches", name, err, as.applies)
		}
		as.fail, as.applies = false, 0
		reopen(t, a, as, w.cfg)
		msg, err := op()
		if err != nil || as.applies != 1 || gen(msg) != 0 {
			t.Fatalf("%s: %v, %d batches", name, err, as.applies)
		}
		bs.fail, bs.applies = true, 0
		if _, err := b.g.Process(msg); !errors.Is(err, errDisk) || bs.applies != 1 {
			t.Fatalf("Process of %s with a failing Store: %v", name, err)
		}
		bs.fail, bs.applies = false, 0
		reopen(t, b, bs, w.cfg)
		if _, err := b.g.Process(msg); err != nil || bs.applies != 1 {
			t.Fatalf("Process of %s: %v, %d batches", name, err, bs.applies)
		}
		storeMatches(t, b.g)
		storeMatches(t, a.g)
	}
	// A private Commit is one batch: the pending record and the key.
	as.applies = 0
	pc, err := a.g.Commit(CommitOptions{})
	if err != nil || as.applies != 1 {
		t.Fatalf("Commit: %v, %d batches", err, as.applies)
	}
	if err := a.g.DiscardPending(); err != nil {
		t.Fatal(err)
	}
	pc2, err := a.g.Commit(CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gen(pc.Commit()) == gen(pc2.Commit()) {
		t.Fatal("a second Commit reused the handshake generation")
	}
}

// TestDuplicateProposalCopy: an insider re-encrypts a member's signed
// proposal under the next generation; the receiver already holds the
// proposal, and the copy still uses its key.
func TestDuplicateProposalCopy(t *testing.T) {
	w := newWorldWith(t, 3, privateConfig())
	insider := w.members[2].g
	msg, err := w.members[0].g.ProposeRemove(2)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := message.UnmarshalMLSMessage(msg)
	ac, lk, err := framing.UnprotectPrivate(m.Private, insider.s.secrets.SenderData, insider.s.keys, func(uint32) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	lk.Discard()
	copied := seal(t, insider, ac, 1)
	b := w.members[1].g
	r1, err := b.Process(msg)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b.Process(copied)
	if err != nil || !bytes.Equal(r1.ProposalRef, r2.ProposalRef) || len(b.props) != 1 {
		t.Fatalf("copy of a cached proposal: %v", err)
	}
	storeMatches(t, b)
	refusedPrivate(t, w, 1, copied, errs.ErrReplay)
}

// TestWriteAppliedThenFailed: a Store whose Apply wrote the batch but
// reported an error. The Group refuses every later call; opened again it
// holds what the Store holds, so the used generation is never used twice.
func TestWriteAppliedThenFailed(t *testing.T) {
	w := newWorldWith(t, 3, privateConfig())
	a, b := w.members[0], w.members[1]
	as := &countStore{MemStore: a.st, fail: true, late: true}
	a.g.store = as
	exporter := a.g.s.secrets.Exporter
	if _, err := a.g.Encrypt([]byte("lost"), nil); !errors.Is(err, errDisk) {
		t.Fatalf("Encrypt: %v", err)
	}
	if strings.Trim(string(exporter), "\x00") != "" {
		t.Fatal("a Group with a failed write kept its secrets")
	}
	for name, f := range map[string]func() error{
		"Encrypt": func() error { _, err := a.g.Encrypt([]byte("x"), nil); return err },
		"Process": func() error { _, err := a.g.Process(nil); return err },
		"Commit":  func() error { _, err := a.g.Commit(CommitOptions{}); return err },
		"Export":  func() error { _, err := a.g.Export("x", nil, 32); return err },
	} {
		if err := f(); !errors.Is(err, errs.ErrStore) {
			t.Fatalf("%s after a failed write: %v", name, err)
		}
	}
	as.fail = false
	reopen(t, a, as, w.cfg)
	storeMatches(t, a.g)
	m := w.encrypt(0, []byte("next"), nil)
	pm, _ := message.UnmarshalMLSMessage(m)
	_, lk, err := framing.UnprotectPrivate(pm.Private, b.g.s.secrets.SenderData, b.g.s.keys, func(uint32) bool { return true })
	if err != nil || lk.Generation() != 1 {
		t.Fatalf("message after Open: %v, want generation 1", err)
	}
	lk.Discard()
	w.receive(1, 0, m, []byte("next"), nil)
	w.receive(2, 0, m, []byte("next"), nil)
}

// TestCommitAfterRestart: a member that processed a private Commit and
// stopped before Apply reads the same Commit again after Open and applies
// it (RFC 9420 section 14).
func TestCommitAfterRestart(t *testing.T) {
	w := newWorldWith(t, 3, privateConfig())
	pc, err := w.members[0].g.Commit(CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b := w.members[1]
	if _, err := b.g.Process(pc.Commit()); err != nil {
		t.Fatal(err)
	}
	reopen(t, b, b.st, w.cfg)
	r, err := b.g.Process(pc.Commit())
	if err != nil {
		t.Fatalf("Process after Open: %v", err)
	}
	if err := b.g.Apply(r.Commit); err != nil {
		t.Fatal(err)
	}
	r, err = w.members[2].g.Process(pc.Commit())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.members[2].g.Apply(r.Commit); err != nil {
		t.Fatal(err)
	}
	if err := w.members[0].g.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	w.check()
}

// TestCommitAfterTransientError: staging that fails on a transient error
// (here the PSKStore) can be retried with the same Commit.
func TestCommitAfterTransientError(t *testing.T) {
	fail := true
	cfg := privateConfig()
	cfg.PSKs = pskFunc(func(id *schedule.PSKID) ([]byte, error) {
		if fail {
			return nil, errDisk
		}
		return bytes.Repeat([]byte{5}, 32), nil
	})
	w := newWorldWith(t, 2, cfg)
	fail = false
	pc, err := w.members[0].g.Commit(CommitOptions{PSKs: []*schedule.PSKID{pskID("x")}})
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	b := w.members[1].g
	if _, err := b.Process(pc.Commit()); !errors.Is(err, errs.ErrStore) || !errors.Is(err, errDisk) {
		t.Fatalf("PSKStore failure: %v", err)
	}
	fail = false
	r, err := b.Process(pc.Commit())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := b.Apply(r.Commit); err != nil {
		t.Fatal(err)
	}
	if err := w.members[0].g.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	w.check()
}
