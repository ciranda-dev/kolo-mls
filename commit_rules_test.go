package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

func byValue(ps ...*message.Proposal) *message.Commit {
	c := &message.Commit{}
	for _, p := range ps {
		c.Proposals = append(c.Proposals, message.ProposalOrRef{Type: message.ByValue, Proposal: p})
	}
	return c
}

func removeP(l uint32) *message.Proposal {
	return &message.Proposal{Type: message.ProposalRemove, Removed: l}
}

func addP(t testing.TB, kp []byte) *message.Proposal {
	k, err := decodeKeyPackage(kp)
	if err != nil {
		t.Fatal(err)
	}
	return &message.Proposal{Type: message.ProposalAdd, KeyPackage: k}
}

func pskP(id string) *message.Proposal {
	return &message.Proposal{Type: message.ProposalPSK, PSK: pskID(id)}
}

func gceP(exts ...tls.Extension) *message.Proposal {
	return &message.Proposal{Type: message.ProposalGroupContextExtensions, Extensions: exts}
}

// refused checks that member 1 refuses msg with want and reason and keeps
// its state.
func refused(t *testing.T, w *world, msg []byte, want error, reason string) {
	t.Helper()
	g := w.members[1].g
	ctx, auth := g.GroupContext(), epochAuth(g)
	_, err := g.Process(msg)
	wantErr(t, err, want, reason)
	unchanged(t, g, ctx, auth)
}

// TestListRules runs the proposal list rules C0 to C12 (RFC
// 9420 section 12.2) on Commits that member 0 forges and member 1 receives.
func TestListRules(t *testing.T) {
	w := newWorld(t, 4)
	other := newClient(t)
	_, sameA := keyPackageFor(t, []byte("twin"), other.sig, nil)
	_, sameB := keyPackageFor(t, []byte("twin"), newClient(t).sig, nil)
	_, existing := keyPackageFor(t, w.members[2].id, newClient(t).sig, nil)
	_, stolenKey := keyPackageFor(t, []byte("thief"), w.members[2].sig, nil)
	_, oneKeyA := keyPackageFor(t, []byte("one"), other.sig, nil)
	for _, c := range []struct {
		rule   string
		commit *message.Commit
		want   error
		reason string
	}{
		{"C0", &message.Commit{Proposals: []message.ProposalOrRef{{Type: message.ByReference, Ref: bytes.Repeat([]byte{1}, 32)}}}, errs.ErrUnknownProposal, "unknown proposal"},
		{"C1", byValue(removeP(9)), errs.ErrInvalidProposal, "Remove of blank leaf 9"},
		{"C2", byValue(&message.Proposal{Type: message.ProposalUpdate, LeafNode: w.members[0].g.s.tree.Leaf(0)}), errs.ErrInvalidCommit, "an Update by the committer"},
		{"C3", byValue(removeP(0)), errs.ErrInvalidCommit, "a Remove of the committer"},
		{"C4", byValue(removeP(2), removeP(2)), errs.ErrInvalidCommit, "two Updates or Removes for leaf 2"},
		{"C5", byValue(addP(t, sameA), addP(t, sameB)), errs.ErrInvalidCommit, "two Adds of the same client"},
		{"C6", byValue(addP(t, existing)), errs.ErrInvalidCommit, "an Add of a client already in the group"},
		{"C7", byValue(pskP("a"), pskP("a")), errs.ErrInvalidCommit, "the same PreSharedKeyID"},
		{"C8", byValue(gceP(), gceP()), errs.ErrInvalidCommit, "two GroupContextExtensions"},
		{"C9", byValue(&message.Proposal{Type: message.ProposalReInit, ReInit: &message.ReInit{Version: 1, CipherSuite: 1}}, removeP(2)), errs.ErrInvalidCommit, "a ReInit proposal together with other proposals"},
		{"C10", byValue(&message.Proposal{Type: message.ProposalExternalInit, KEMOutput: []byte{1}}), errs.ErrInvalidCommit, "an ExternalInit proposal in a regular Commit"},
		{"C12", byValue(addP(t, stolenKey)), errs.ErrInvalidCommit, "signature key of leaf"},
		{"C12 two Adds with one signature key", byValue(addP(t, sameA), addP(t, oneKeyA)), errs.ErrInvalidCommit, "signature key of leaf"},
	} {
		t.Run(c.rule, func(t *testing.T) {
			refused(t, w, w.forge(0, c.commit, nil, nil), c.want, c.reason)
		})
	}
	t.Run("C6 with a Remove of the same client", func(t *testing.T) {
		// RFC 9420 section 12.2 allows the Add of a client the list removes.
		if err := w.cfg.checkList(w.members[1].g.s, 0, []item{{p: removeP(2)}, {p: addP(t, existing)}}, nil, false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("C9 ReInit alone", func(t *testing.T) {
		refused(t, w, w.forge(0, byValue(&message.Proposal{Type: message.ProposalReInit, ReInit: &message.ReInit{Version: 1, CipherSuite: 1}}), nil, nil), errs.ErrUnsupported, "ReInit")
	})
	t.Run("C11", func(t *testing.T) {
		// The decoder refuses unknown proposal types, so the check is reached
		// only with a list built in memory.
		err := w.cfg.checkList(w.members[1].g.s, 0, []item{{p: &message.Proposal{Type: 8}}}, nil, false)
		wantErr(t, err, errs.ErrInvalidCommit, "proposal type 0x0008 that members do not support")
	})
}

// TestCreateListRules checks that a committer refuses the same lists.
func TestCreateListRules(t *testing.T) {
	w := newWorld(t, 3)
	a := w.members[0].g
	_, existing := keyPackageFor(t, w.members[2].id, newClient(t).sig, nil)
	_, twin := keyPackageFor(t, []byte("twin"), newClient(t).sig, nil)
	for name, c := range map[string]struct {
		o      CommitOptions
		want   error
		reason string
	}{
		"remove self":       {CommitOptions{Remove: []uint32{0}}, errs.ErrInvalidCommit, "a Remove of the committer"},
		"remove twice":      {CommitOptions{Remove: []uint32{1, 1}}, errs.ErrInvalidCommit, "two Updates or Removes"},
		"add existing":      {CommitOptions{Add: [][]byte{existing}}, errs.ErrInvalidCommit, "already in the group"},
		"add twice":         {CommitOptions{Add: [][]byte{twin, twin}}, errs.ErrInvalidCommit, "two Adds of the same client"},
		"psk twice":         {CommitOptions{PSKs: []*schedule.PSKID{pskID("a"), pskID("a")}}, errs.ErrInvalidCommit, "the same PreSharedKeyID"},
		"psk missing":       {CommitOptions{PSKs: []*schedule.PSKID{pskID("a")}}, errs.ErrPSKNotFound, "pre-shared key not found"},
		"no path on remove": {CommitOptions{Remove: []uint32{1}, NoPath: true}, errs.ErrInvalidArgument, "need a path"},
		"unknown reference": {CommitOptions{References: [][]byte{{1}}}, errs.ErrUnknownProposal, "unknown"},
		"remove blank":      {CommitOptions{Remove: []uint32{7}}, errs.ErrInvalidProposal, "blank leaf 7"},
	} {
		ctx, auth := a.GroupContext(), epochAuth(a)
		_, err := a.Commit(c.o)
		if !errors.Is(err, c.want) || !bytes.Contains([]byte(err.Error()), []byte(c.reason)) {
			t.Errorf("%s: error = %v; want %v with %q", name, err, c.want, c.reason)
		}
		unchanged(t, a, ctx, auth)
		if a.Pending() != nil {
			t.Fatalf("%s: a refused Commit is pending", name)
		}
	}
	// An Update proposal of the committer itself cannot be committed by it.
	msg, err := a.ProposeUpdate(nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := message.UnmarshalMLSMessage(msg)
	ref, _ := (&message.AuthenticatedContent{WireFormat: message.WirePublic, Content: m.Public.Content, Auth: m.Public.Auth}).ProposalRef()
	_, err = a.Commit(CommitOptions{References: [][]byte{ref}})
	wantErr(t, err, errs.ErrInvalidCommit, "an Update by the committer")
}

// commitBy returns a valid Commit message of member l with o, leaving l's
// state unchanged.
func commitBy(t testing.TB, w *world, l uint32, o CommitOptions) []byte {
	t.Helper()
	g := w.members[l].g
	pc, err := g.Commit(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.DiscardPending(); err != nil {
		t.Fatal(err)
	}
	return pc.Commit()
}

// TestProcessRules runs the Commit processing rules K1 to K12
// (RFC 9420 section 12.4.2).
func TestProcessRules(t *testing.T) {
	w := newWorld(t, 4)
	a := w.members[0].g
	t.Run("K1", func(t *testing.T) {
		refused(t, w, w.forge(0, byValue(), func(c *message.FramedContent) { c.Epoch-- }, nil), errs.ErrWrongEpoch, "past epoch")
		refused(t, w, w.forge(0, byValue(), func(c *message.FramedContent) { c.Epoch++ }, nil), errs.ErrFutureEpoch, "future epoch")
		refused(t, w, w.forge(0, byValue(), func(c *message.FramedContent) { c.GroupID = []byte("other") }, nil), errs.ErrWrongGroup, "another group")
	})
	t.Run("K2", func(t *testing.T) {
		msg := commitBy(t, w, 0, CommitOptions{})
		msg[len(msg)-1] ^= 1
		refused(t, w, msg, errs.ErrMembershipTag, "membership tag")
	})
	t.Run("K3", func(t *testing.T) {
		_, key, _ := ed25519.GenerateKey(nil)
		refused(t, w, w.forge(0, byValue(), nil, key), errs.ErrSignature, "signature")
	})
	t.Run("K4", func(t *testing.T) {
		g := w.members[1].g
		g.cfg.Policy = refusePolicy{}
		defer func() { g.cfg.Policy = rfcPolicy{} }()
		refused(t, w, commitBy(t, w, 0, CommitOptions{}), errs.ErrPolicy, "refused by policy")
	})
	t.Run("K5", func(t *testing.T) {
		refused(t, w, w.forge(0, byValue(pskP("absent")), nil, nil), errs.ErrPSKNotFound, "pre-shared key not found")
	})
	t.Run("K6", func(t *testing.T) {
		// Removes apply before Adds, so the new member takes the freed leaf;
		// the new extensions apply to the Adds of the same list.
		v := newWorld(t, 4)
		j := newClient(t)
		pc := v.commit(0, CommitOptions{Remove: []uint32{1}, Add: [][]byte{j.keyPackage(t)}})
		if got := v.join(0, pc, []*client{j}); got[0] != 1 {
			t.Fatalf("the new member took leaf %d, want 1", got[0])
		}
		rc, _ := (&message.RequiredCapabilities{Extensions: []uint16{0xf00a}}).Marshal()
		_, err := v.members[0].g.Commit(CommitOptions{SetExtensions: true, Extensions: []tls.Extension{{Type: message.ExtRequiredCapabilities, Data: rc}}, Add: [][]byte{newClient(t).keyPackage(t)}})
		wantErr(t, err, errs.ErrInvalidLeaf, "required extension 0xf00a not supported")
	})
	t.Run("K7", func(t *testing.T) {
		refused(t, w, w.forge(0, byValue(removeP(2)), nil, nil), errs.ErrInvalidCommit, "path missing")
		refused(t, w, w.forge(0, byValue(), nil, nil), errs.ErrInvalidCommit, "path missing")
		refused(t, w, w.forge(0, byValue(gceP()), nil, nil), errs.ErrInvalidCommit, "path missing")
	})
	resign := func(f func(l *tree.LeafNode)) []byte {
		return w.edit(0, commitBy(t, w, 0, CommitOptions{}), func(c *message.FramedContent) {
			l := c.Commit.Path.Leaf
			f(l)
			if err := l.Sign(a.s.sig, a.s.ctx.GroupID, 0); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("K8", func(t *testing.T) {
		refused(t, w, resign(func(l *tree.LeafNode) { l.Source = tree.SourceUpdate }), errs.ErrInvalidLeaf, "leaf_node_source 2, want 3")
		msg := w.edit(0, commitBy(t, w, 0, CommitOptions{}), func(c *message.FramedContent) { c.Commit.Path.Leaf.Signature[0] ^= 1 })
		refused(t, w, msg, errs.ErrInvalidLeaf, "signature")
	})
	t.Run("K9", func(t *testing.T) {
		refused(t, w, resign(func(l *tree.LeafNode) { l.EncryptionKey = a.s.tree.Leaf(0).EncryptionKey }), errs.ErrInvalidCommit, "keeps the committer's encryption key")
	})
	t.Run("K10", func(t *testing.T) {
		msg := w.edit(0, commitBy(t, w, 0, CommitOptions{}), func(c *message.FramedContent) {
			c.Commit.Path.Nodes[0].EncryptionKey = a.s.tree.Leaf(3).EncryptionKey
		})
		refused(t, w, msg, errs.ErrInvalidCommit, "already in the tree")
	})
	t.Run("K11", func(t *testing.T) {
		refused(t, w, resign(func(l *tree.LeafNode) { l.ParentHash = bytes.Repeat([]byte{1}, 32) }), errs.ErrInvalidCommit, "parent_hash")
		// The ciphertext member 1 decrypts holds another path secret.
		pc, err := a.Commit(CommitOptions{})
		if err != nil {
			t.Fatal(err)
		}
		next := pc.next.ctx
		if err := a.DiscardPending(); err != nil {
			t.Fatal(err)
		}
		prov := *next
		prov.ConfirmedTranscriptHash = a.s.ctx.ConfirmedTranscriptHash
		pb, _ := prov.Marshal()
		msg := w.edit(0, pc.Commit(), func(c *message.FramedContent) {
			kem, ct, err := suite.EncryptWithLabel(w.members[1].g.s.tree.Leaf(1).EncryptionKey, "UpdatePathNode", pb, bytes.Repeat([]byte{5}, 32))
			if err != nil {
				t.Fatal(err)
			}
			c.Commit.Path.Nodes[0].Secrets[0] = tree.HPKECiphertext{KEMOutput: kem, Ciphertext: ct}
		})
		refused(t, w, msg, errs.ErrInvalidCommit, "does not derive the key")
	})
	t.Run("K12", func(t *testing.T) {
		msg := commitBy(t, w, 0, CommitOptions{})
		m, _ := message.UnmarshalMLSMessage(msg)
		tag := bytes.Clone(m.Public.Auth.ConfirmationTag)
		tag[0] ^= 1
		refused(t, w, w.seal(a, m.Public.Content, nil, tag), errs.ErrConfirmationTag, "confirmation tag")
	})
	// The untouched Commit is still accepted after every refusal.
	pc := commitBy(t, w, 0, CommitOptions{})
	if _, err := w.members[1].g.Process(pc); err != nil {
		t.Fatal(err)
	}
}

type refusePolicy struct{}

var errRefused = errors.New("refused")

func (refusePolicy) CheckProposal(ProposalView) error { return errRefused }
func (refusePolicy) CheckCommit(CommitView) error     { return errRefused }
func (refusePolicy) CheckJoin(JoinView) error         { return errRefused }
