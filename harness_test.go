package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/framing"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// client is one device in the tests: its own Store, signature key and
// credential.
type client struct {
	st  *MemStore
	sig ed25519.PrivateKey
	id  []byte
	g   *Group
}

var nextID int

func newClient(t testing.TB) *client {
	t.Helper()
	_, sig, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	nextID++
	return &client{st: NewMemStore(), sig: sig, id: fmt.Appendf(nil, "client %d", nextID)}
}

func testConfig() Config {
	return Config{Authenticator: testAuth{}, Policy: rfcPolicy{}, PSKs: pskMap{}}
}

func (c *client) keyPackage(t testing.TB) []byte {
	t.Helper()
	kp, err := NewKeyPackage(c.st, KeyPackageOptions{Credential: tree.Credential{Type: tree.CredentialBasic, Identity: c.id}, SignatureKey: c.sig})
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// world is a group of clients that all follow every Commit.
type world struct {
	t       testing.TB
	cfg     Config
	members map[uint32]*client
}

// newWorld creates a group of n members, the first one the creator.
func newWorld(t testing.TB, n int) *world {
	t.Helper()
	return newWorldWith(t, n, testConfig())
}

// newWorldWith creates a group of n members that all use cfg.
func newWorldWith(t testing.TB, n int, cfg Config) *world {
	t.Helper()
	w := &world{t: t, cfg: cfg, members: map[uint32]*client{}}
	c := newClient(t)
	g, err := Create(c.st, CreateOptions{Config: w.cfg, KeyPackage: c.keyPackage(t)})
	if err != nil {
		t.Fatal(err)
	}
	c.g = g
	w.members[0] = c
	if n > 1 {
		w.add(0, n-1)
	}
	return w
}

// keyPackageRecord reads back the stored record of kp.
func (c *client) keyPackageRecord(t testing.TB, kp []byte) *keyPackageRecord {
	t.Helper()
	k, err := decodeKeyPackage(kp)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := k.Ref()
	b, err := c.st.Get(keyPackageKey(ref))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := unmarshalKeyPackageRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func (w *world) leaves() []uint32 {
	return slices.Sorted(maps.Keys(w.members))
}

// add has committer add n new clients and returns their leaves.
func (w *world) add(committer uint32, n int) []uint32 {
	w.t.Helper()
	var kps [][]byte
	var joiners []*client
	for range n {
		c := newClient(w.t)
		joiners = append(joiners, c)
		kps = append(kps, c.keyPackage(w.t))
	}
	pc := w.commit(committer, CommitOptions{Add: kps})
	return w.join(committer, pc, joiners)
}

// join lets joiners join with the Welcome of pc, applied by committer.
func (w *world) join(committer uint32, pc *PendingCommit, joiners []*client) []uint32 {
	w.t.Helper()
	tr, err := w.members[committer].g.RatchetTree()
	if err != nil {
		w.t.Fatal(err)
	}
	var out []uint32
	for _, c := range joiners {
		g, err := Join(c.st, pc.Welcome(), tr, JoinOptions{Config: w.cfg})
		if err != nil {
			w.t.Fatalf("join: %v", err)
		}
		c.g = g
		w.members[g.OwnLeaf()] = c
		out = append(out, g.OwnLeaf())
	}
	w.check()
	return out
}

// commit has committer commit o and every other member apply it.
func (w *world) commit(committer uint32, o CommitOptions) *PendingCommit {
	w.t.Helper()
	pc, err := w.members[committer].g.Commit(o)
	if err != nil {
		w.t.Fatalf("commit by %d: %v", committer, err)
	}
	w.deliver(committer, pc.Commit())
	if err := w.members[committer].g.ApplyPending(); err != nil {
		w.t.Fatal(err)
	}
	return pc
}

// deliver has every member but sender process and apply a Commit.
func (w *world) deliver(sender uint32, msg []byte) {
	w.t.Helper()
	for _, l := range w.leaves() {
		if l == sender {
			continue
		}
		r, err := w.members[l].g.Process(msg)
		if err != nil {
			w.t.Fatalf("member %d processing: %v", l, err)
		}
		err = w.members[l].g.Apply(r.Commit)
		if r.Commit.RemovesSelf() {
			g := w.members[l].g
			if _, perr := g.Process(msg); err != nil || !g.Removed() || !errors.Is(perr, errs.ErrRemoved) {
				w.t.Fatalf("removed member %d: %v, then %v", l, err, perr)
			}
			g.st().each(func(k, _ []byte) {
				if bytes.HasPrefix(k, groupKey(g.s.ctx.GroupID, "")) {
					w.t.Fatalf("removed member %d keeps %s", l, k)
				}
			})
			delete(w.members, l)
			continue
		}
		if err != nil {
			w.t.Fatalf("member %d applying: %v", l, err)
		}
	}
}

// propose has member l send a proposal that every other member caches.
func (w *world) propose(l uint32, f func(g *Group) ([]byte, error)) []byte {
	w.t.Helper()
	msg, err := f(w.members[l].g)
	if err != nil {
		w.t.Fatalf("proposal by %d: %v", l, err)
	}
	var ref []byte
	for _, o := range w.leaves() {
		if o == l {
			continue
		}
		r, err := w.members[o].g.Process(msg)
		if err != nil {
			w.t.Fatalf("member %d processing a proposal: %v", o, err)
		}
		ref = r.ProposalRef
	}
	return ref
}

// check verifies that every member has the same epoch, GroupContext (with
// the tree hash), epoch authenticator, exported secret and tree.
func (w *world) check() {
	w.t.Helper()
	var first *Group
	for _, l := range w.leaves() {
		g := w.members[l].g
		if g.OwnLeaf() != l {
			w.t.Fatalf("member at %d has leaf %d", l, g.OwnLeaf())
		}
		if first == nil {
			first = g
			continue
		}
		e1, _ := first.Export("test", nil, 32)
		e2, _ := g.Export("test", nil, 32)
		t1, _ := first.RatchetTree()
		t2, _ := g.RatchetTree()
		if !bytes.Equal(first.GroupContext(), g.GroupContext()) || !bytes.Equal(epochAuth(first), epochAuth(g)) || !bytes.Equal(e1, e2) || !bytes.Equal(t1, t2) {
			w.t.Fatalf("member %d diverged at epoch %d", l, g.Epoch())
		}
		if err := g.s.priv.Check(g.s.tree); err != nil {
			w.t.Fatalf("member %d private keys: %v", l, err)
		}
	}
	for _, l := range w.leaves() {
		storeMatches(w.t, w.members[l].g)
	}
}

// storeMatches fails unless the Store holds exactly the records of g's
// state: one epoch record, the non-blank nodes, the private keys held, the
// cached proposals and the pending Commit, so nothing consumed is left.
func storeMatches(t testing.TB, g *Group) {
	t.Helper()
	gid := g.s.ctx.GroupID
	want := map[string][]byte{}
	var b Batch
	if err := writeState(&b, nil, g.s, g.props); err != nil {
		t.Fatal(err)
	}
	if err := writeProps(&b, gid, nil, g.props); err != nil {
		t.Fatal(err)
	}
	if g.prev != nil {
		pb, err := g.prev.marshal()
		if err != nil {
			t.Fatal(err)
		}
		b.put(groupKey(gid, "prev"), pb)
		rs, err := g.prev.keys.Records()
		if err != nil {
			t.Fatal(err)
		}
		writeKeys(&b, gid, g.prev.epoch, rs)
	}
	for _, kv := range b.Put {
		want[string(kv.Key)] = kv.Value
	}
	got := map[string][]byte{}
	g.st().each(func(k, v []byte) {
		if bytes.HasPrefix(k, groupKey(gid, "")) {
			got[string(k)] = bytes.Clone(v)
		}
	})
	if g.pending != nil {
		if got[string(groupKey(gid, "pending"))] == nil {
			t.Fatal("pending Commit not stored")
		}
		delete(got, string(groupKey(gid, "pending")))
	}
	for k, v := range want {
		if !bytes.Equal(got[k], v) {
			t.Fatalf("stored %s differs from the state", k)
		}
		delete(got, k)
	}
	for k := range got {
		t.Fatalf("stale record %s in the Store", k)
	}
}

// reopen replaces member l's Group with one loaded from its Store.
func (w *world) reopen(l uint32) {
	w.t.Helper()
	c := w.members[l]
	g, err := Open(c.st, c.g.GroupID(), w.cfg)
	if err != nil {
		w.t.Fatalf("reopen %d: %v", l, err)
	}
	if !bytes.Equal(g.GroupContext(), c.g.GroupContext()) || !bytes.Equal(epochAuth(g), epochAuth(c.g)) || len(g.props) != len(c.g.props) || (g.pending == nil) != (c.g.pending == nil) {
		w.t.Fatalf("reopened member %d differs", l)
	}
	c.g = g
}

// forge returns a Commit from member sender with content changed by edit,
// signed with key (nil: the sender's) and with a valid membership tag.
func (w *world) forge(sender uint32, commit *message.Commit, edit func(c *message.FramedContent), key ed25519.PrivateKey) []byte {
	w.t.Helper()
	g := w.members[sender].g
	s := g.s
	c := &message.FramedContent{GroupID: s.ctx.GroupID, Epoch: s.ctx.Epoch, Sender: message.Sender{Type: message.SenderMember, Index: sender}, ContentType: message.ContentCommit, Commit: commit}
	if edit != nil {
		edit(c)
	}
	return w.seal(g, c, key, bytes.Repeat([]byte{1}, suite.Nh))
}

func (w *world) seal(g *Group, c *message.FramedContent, key ed25519.PrivateKey, tag []byte) []byte {
	w.t.Helper()
	s := g.s
	if key == nil {
		key = s.sig
	}
	sig, err := framing.Sign(key, message.WirePublic, c, s.ctxBytes)
	if err != nil {
		w.t.Fatal(err)
	}
	ac := &message.AuthenticatedContent{WireFormat: message.WirePublic, Content: c, Auth: message.AuthData{Signature: sig}}
	if c.ContentType == message.ContentCommit {
		ac.Auth.ConfirmationTag = tag
	}
	pm, err := framing.ProtectPublic(ac, s.secrets.Membership, s.ctxBytes)
	if err != nil {
		w.t.Fatal(err)
	}
	b, err := (&message.MLSMessage{WireFormat: message.WirePublic, Public: pm}).Marshal()
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

// edit decodes the Commit message msg of member sender, lets f change it,
// and signs it again; the confirmation tag is kept.
func (w *world) edit(sender uint32, msg []byte, f func(c *message.FramedContent)) []byte {
	w.t.Helper()
	m, err := message.UnmarshalMLSMessage(msg)
	if err != nil {
		w.t.Fatal(err)
	}
	c := m.Public.Content
	f(c)
	return w.seal(w.members[sender].g, c, nil, m.Public.Auth.ConfirmationTag)
}

// wantErr fails unless err wraps want and its text holds reason.
func wantErr(t testing.TB, err, want error, reason string) {
	t.Helper()
	if !errors.Is(err, want) || !strings.Contains(fmt.Sprint(err), reason) {
		t.Fatalf("error = %v; want %v with %q", err, want, reason)
	}
}

// unchanged fails unless g still has the GroupContext and secrets of before.
func unchanged(t testing.TB, g *Group, ctx, auth []byte) {
	t.Helper()
	if !bytes.Equal(g.GroupContext(), ctx) || !bytes.Equal(epochAuth(g), auth) {
		t.Fatal("a refused message changed the group")
	}
}

// keyPackageFor returns a KeyPackage for a new client with the given
// identity and signature key.
func keyPackageFor(t testing.TB, id []byte, sig ed25519.PrivateKey, change func(o *KeyPackageOptions)) (*client, []byte) {
	t.Helper()
	c := newClient(t)
	c.id, c.sig = id, sig
	o := KeyPackageOptions{Credential: tree.Credential{Type: tree.CredentialBasic, Identity: id}, SignatureKey: sig}
	if change != nil {
		change(&o)
	}
	kp, err := NewKeyPackage(c.st, o)
	if err != nil {
		t.Fatal(err)
	}
	return c, kp
}

func pskID(id string) *schedule.PSKID {
	return &schedule.PSKID{Type: schedule.PSKExternal, ID: []byte(id), Nonce: bytes.Repeat([]byte{7}, suite.Nh)}
}

// each calls f with every key and value of s; f must not change them.
func (s *MemStore) each(f func(key, value []byte)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		f([]byte(k), v)
	}
}

// epochAuth returns the epoch authenticator of g, nil when g cannot give it.
func epochAuth(g *Group) []byte {
	b, _ := g.EpochAuthenticator()
	return b
}
