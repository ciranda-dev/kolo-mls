package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// leafFixture is a signed key_package leaf and the GroupContext it is
// checked against.
func leafFixture(t *testing.T, change func(n *tree.LeafNode)) (*tree.LeafNode, *schedule.GroupContext) {
	t.Helper()
	pub, sig, _ := ed25519.GenerateKey(nil)
	_, enc, _ := suite.GenerateKeyPair()
	now := uint64(time.Now().Unix())
	n := &tree.LeafNode{
		EncryptionKey: enc, SignatureKey: pub,
		Credential:   tree.Credential{Type: tree.CredentialBasic, Identity: []byte("x")},
		Capabilities: tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}, Credentials: []uint16{1}},
		Source:       tree.SourceKeyPackage, NotBefore: now - 10, NotAfter: now + 3600,
	}
	if change != nil {
		change(n)
	}
	if err := n.Sign(sig, nil, 0); err != nil {
		t.Fatal(err)
	}
	return n, &schedule.GroupContext{CipherSuite: suite.ID, GroupID: []byte("g")}
}

// TestLeafRules runs the leaf checks LN1 to LN11, the LeafNode rules (RFC 9420
// section 7.3).
func TestLeafRules(t *testing.T) {
	cfg := testConfig()
	sending := leafRule{source: tree.SourceKeyPackage, sending: true}
	ok, ctx := leafFixture(t, nil)
	if err := cfg.checkLeaf(ok, sending, ctx); err != nil {
		t.Fatal(err)
	}
	rc, _ := (&message.RequiredCapabilities{Extensions: []uint16{0xf00a}}).Marshal()
	for _, c := range []struct {
		rule   string
		change func(n *tree.LeafNode)
		tamper func(n *tree.LeafNode)
		leaf   *leafRule
		ctx    func(c *schedule.GroupContext)
		want   error
		reason string
	}{
		{"LN1", func(n *tree.LeafNode) {
			n.Credential = tree.Credential{Type: tree.CredentialX509, Certificates: x509(t, []byte{1})}
			n.Capabilities.Credentials = []uint16{2}
		}, nil, nil, nil, errs.ErrCredential, "credential type 0x0002"},
		{"LN2", nil, func(n *tree.LeafNode) { n.Signature[0] ^= 1 }, &leafRule{source: tree.SourceKeyPackage, skipSignature: false}, nil, errs.ErrInvalidLeaf, "signature"},
		{"LN3", nil, nil, nil, func(c *schedule.GroupContext) {
			c.Extensions = []tls.Extension{{Type: message.ExtRequiredCapabilities, Data: rc}}
		}, errs.ErrInvalidLeaf, "required extension 0xf00a not supported"},
		{"LN5", func(n *tree.LeafNode) { n.NotBefore, n.NotAfter = 1, 2 }, nil, nil, nil, errs.ErrInvalidLeaf, "not valid now"},
		{"LN6", func(n *tree.LeafNode) { n.Extensions = []tls.Extension{{Type: 0xf00b}} }, nil, nil, nil, errs.ErrInvalidLeaf, "leaf extension 0xf00b not in its capabilities"},
		{"LN7", nil, nil, &leafRule{source: tree.SourceUpdate}, nil, errs.ErrInvalidLeaf, "leaf_node_source 1, want 2"},
		{"LN9", func(n *tree.LeafNode) { n.NotAfter = n.NotBefore + 85*24*3600 }, nil, nil, nil, errs.ErrInvalidLeaf, "lifetime longer than"},
		{"LN9 reversed", func(n *tree.LeafNode) { n.NotAfter = n.NotBefore - 1 }, nil, nil, nil, errs.ErrInvalidLeaf, "ends before it starts"},
		{"LN10", func(n *tree.LeafNode) { n.Capabilities.CipherSuites = []uint16{2} }, nil, nil, nil, errs.ErrInvalidLeaf, "lack the group's version or cipher suite"},
		{"LN10 version", func(n *tree.LeafNode) { n.Capabilities.Versions = []uint16{2} }, nil, nil, nil, errs.ErrInvalidLeaf, "lack the group's version or cipher suite"},
		{"LN11", nil, nil, nil, func(c *schedule.GroupContext) { c.Extensions = []tls.Extension{{Type: 0xf00a}} }, errs.ErrInvalidLeaf, "GroupContext extension 0xf00a not supported"},
		{"own credential type", func(n *tree.LeafNode) { n.Capabilities.Credentials = []uint16{0xf001} }, nil, nil, nil, errs.ErrInvalidLeaf, "own credential type"},
		{"encryption key", func(n *tree.LeafNode) { n.EncryptionKey = make([]byte, 32) }, nil, nil, nil, errs.ErrInvalidLeaf, "low order"},
		{"signature key size", func(n *tree.LeafNode) { n.SignatureKey = n.SignatureKey[:31] }, nil, nil, nil, errs.ErrInvalidLeaf, "signature key of 31 bytes"},
	} {
		t.Run(c.rule, func(t *testing.T) {
			n, ctx := leafFixture(t, c.change)
			r := sending
			if c.leaf != nil {
				r = *c.leaf
			}
			if c.tamper != nil {
				c.tamper(n)
			}
			if c.ctx != nil {
				c.ctx(ctx)
			}
			wantErr(t, cfg.checkLeaf(n, r, ctx), c.want, c.reason)
		})
	}
	t.Run("LN5 receiving", func(t *testing.T) {
		// Kolo policy: a received leaf is never refused for expiry.
		n, ctx := leafFixture(t, func(n *tree.LeafNode) { n.NotBefore, n.NotAfter = 1, 2 })
		if err := cfg.checkLeaf(n, leafRule{source: tree.SourceKeyPackage}, ctx); err != nil {
			t.Fatal(err)
		}
		c := cfg
		c.Now = func() time.Time { return time.Unix(2, 0) }
		if err := c.checkLeaf(n, sending, ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("LN9 unbounded", func(t *testing.T) {
		n, ctx := leafFixture(t, func(n *tree.LeafNode) { n.NotBefore, n.NotAfter = 0, 1<<64-1 })
		c := cfg
		c.MaxLeafLifetime, c.Now = -1, func() time.Time { return time.Unix(1000, 0) }
		if err := c.checkLeaf(n, sending, ctx); err != nil {
			t.Fatal(err)
		}
		c.MaxLeafLifetime = time.Hour
		wantErr(t, c.checkLeaf(n, sending, ctx), errs.ErrInvalidLeaf, "lifetime longer than 1h0m0s")
	})
	t.Run("LN5 boundaries", func(t *testing.T) {
		now := time.Unix(1000, 0)
		c := cfg
		c.Now = func() time.Time { return now }
		for _, b := range []struct {
			nb, na uint64
			ok     bool
		}{{1000, 1000, true}, {1001, 2000, false}, {0, 999, false}, {999, 1001, true}} {
			n, ctx := leafFixture(t, func(n *tree.LeafNode) { n.NotBefore, n.NotAfter = b.nb, b.na })
			err := c.checkLeaf(n, sending, ctx)
			if (err == nil) != b.ok {
				t.Errorf("lifetime %d to %d at 1000: %v", b.nb, b.na, err)
			}
		}
	})
	t.Run("default extensions are not listed", func(t *testing.T) {
		n, ctx := leafFixture(t, func(n *tree.LeafNode) { n.Extensions = []tls.Extension{{Type: message.ExtApplicationID}} })
		ctx.Extensions = []tls.Extension{{Type: message.ExtExternalSenders}}
		if err := cfg.checkLeaf(n, sending, ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("required capabilities", func(t *testing.T) {
		for _, c := range []struct {
			rc     message.RequiredCapabilities
			change func(n *tree.LeafNode)
			reason string
		}{
			{message.RequiredCapabilities{Proposals: []uint16{0xf00c}}, nil, "required proposal type 0xf00c"},
			{message.RequiredCapabilities{Credentials: []uint16{0xf001}}, nil, "required credential type 0xf001"},
			{message.RequiredCapabilities{Extensions: []uint16{3}, Proposals: []uint16{1}, Credentials: []uint16{1}}, nil, ""},
			{message.RequiredCapabilities{Extensions: []uint16{0xf00a}, Proposals: []uint16{0xf00c}}, func(n *tree.LeafNode) {
				n.Capabilities.Extensions, n.Capabilities.Proposals = []uint16{0xf00a}, []uint16{0xf00c}
			}, ""},
		} {
			n, ctx := leafFixture(t, c.change)
			b, _ := c.rc.Marshal()
			ctx.Extensions = []tls.Extension{{Type: message.ExtRequiredCapabilities, Data: b}}
			err := cfg.checkLeaf(n, sending, ctx)
			if c.reason == "" {
				if err != nil {
					t.Error(err)
				}
				continue
			}
			wantErr(t, err, errs.ErrInvalidLeaf, c.reason)
		}
		n, ctx := leafFixture(t, nil)
		ctx.Extensions = []tls.Extension{{Type: message.ExtRequiredCapabilities, Data: []byte{1}}}
		wantErr(t, cfg.checkLeaf(n, sending, ctx), errs.ErrInvalidLeaf, "required_capabilities")
	})
}

// TestMemberRules runs the checks across members: LN4 and LN8.
func TestMemberRules(t *testing.T) {
	w := newWorld(t, 3)
	s := w.members[0].g.s
	if err := checkMembers(s.tree, s.ctx, true); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		rule   string
		change func(n *tree.LeafNode)
		want   error
		reason string
	}{
		{"LN4", func(n *tree.LeafNode) {
			n.Credential = tree.Credential{Type: 0xf001}
			n.Capabilities.Credentials = []uint16{1, 0xf001}
		}, errs.ErrInvalidLeaf, "does not support credential type 0xf001"},
		{"LN4 new leaf", func(n *tree.LeafNode) { n.Capabilities.Credentials = []uint16{0xf001} }, errs.ErrInvalidLeaf, "does not support credential type 0x0001"},
		{"LN8 signature key", func(n *tree.LeafNode) { n.SignatureKey = s.tree.Leaf(1).SignatureKey }, errs.ErrInvalidLeaf, "signature key of leaf"},
		{"LN8 encryption key", func(n *tree.LeafNode) { n.EncryptionKey = s.tree.Leaf(1).EncryptionKey }, errs.ErrInvalidLeaf, "encryption key of leaf"},
		{"LN8 parent key", func(n *tree.LeafNode) { n.EncryptionKey = s.tree.Node(s.tree.NonBlank()[1]).Parent.EncryptionKey }, errs.ErrInvalidLeaf, "not unique"},
	} {
		t.Run(c.rule, func(t *testing.T) {
			tr := s.tree.Clone()
			n := tr.Leaf(2).Clone()
			c.change(n)
			if err := tr.UpdateLeaf(2, n); err != nil {
				t.Fatal(err)
			}
			if c.rule == "LN8 parent key" {
				// Updating blanks the direct path; keep a parent of another leaf.
				tr = s.tree.Clone()
				leaf := tr.Leaf(0).Clone()
				c.change(leaf)
				if _, err := tr.AddLeaf(leaf); err != nil {
					t.Fatal(err)
				}
			}
			wantErr(t, checkMembers(tr, s.ctx, false), c.want, c.reason)
		})
	}
	t.Run("P-GCE", func(t *testing.T) {
		ctx := *s.ctx
		ctx.Extensions = []tls.Extension{{Type: 0xf00a}}
		wantErr(t, checkMembers(s.tree, &ctx, true), errs.ErrInvalidLeaf, "GroupContext extension 0xf00a not supported")
		if err := checkMembers(s.tree, &ctx, false); err != nil {
			t.Fatal(err)
		}
	})
}

// TestKeyPackageRules runs the KeyPackage checks K-KP1 to K-KP5
// (RFC 9420 section 10.1).
func TestKeyPackageRules(t *testing.T) {
	cfg := testConfig()
	ctx := &schedule.GroupContext{CipherSuite: suite.ID, GroupID: []byte("g")}
	c := newClient(t)
	b := c.keyPackage(t)
	kp, _ := decodeKeyPackage(b)
	if err := cfg.checkKeyPackage(kp, ctx, EventKeyPackage, true); err != nil {
		t.Fatal(err)
	}
	resign := func(k *message.KeyPackage) {
		tbs, _ := k.TBS()
		k.Signature, _ = suite.SignWithLabel(c.sig, "KeyPackageTBS", tbs)
	}
	for _, x := range []struct {
		rule   string
		change func(k *message.KeyPackage)
		reason string
	}{
		{"K-KP1 version", func(k *message.KeyPackage) { k.Version = 2; resign(k) }, "version 2"},
		{"K-KP1 suite", func(k *message.KeyPackage) { k.CipherSuite = 3; resign(k) }, "cipher suite 0x0003"},
		{"K-KP2", func(k *message.KeyPackage) { k.LeafNode.Source = tree.SourceUpdate; resign(k) }, "leaf_node_source"},
		{"K-KP3", func(k *message.KeyPackage) { k.Signature[0] ^= 1 }, "signature"},
		{"K-KP4", func(k *message.KeyPackage) { k.InitKey = k.LeafNode.EncryptionKey; resign(k) }, "init key equals the leaf encryption key"},
		{"K-KP5", func(k *message.KeyPackage) { k.Extensions = []tls.Extension{{Type: 0xf00a}}; resign(k) }, "extension 0xf00a not in the leaf's capabilities"},
		{"init key", func(k *message.KeyPackage) { k.InitKey = make([]byte, 32); resign(k) }, "init key"},
	} {
		t.Run(x.rule, func(t *testing.T) {
			k, _ := decodeKeyPackage(b)
			x.change(k)
			wantErr(t, cfg.checkKeyPackage(k, ctx, EventKeyPackage, true), errs.ErrInvalidKeyPackage, x.reason)
		})
	}
	k, _ := decodeKeyPackage(b)
	k.Extensions = []tls.Extension{{Type: message.ExtApplicationID}}
	resign(k)
	if err := cfg.checkKeyPackage(k, ctx, EventKeyPackage, true); err != nil {
		t.Fatalf("default extension in a KeyPackage: %v", err)
	}
}

// TestProposalRules runs the proposal checks of RFC 9420 section 12.1 and
// the framing checks on proposals member 1 receives from member 0.
func TestProposalRules(t *testing.T) {
	w := newWorld(t, 3)
	a := w.members[0].g
	leaf := func(change func(n *tree.LeafNode)) *tree.LeafNode {
		n := a.s.tree.Leaf(0).Clone()
		_, n.EncryptionKey, _ = suite.GenerateKeyPair()
		n.Source, n.NotBefore, n.NotAfter = tree.SourceUpdate, 0, 0
		change(n)
		if err := n.Sign(a.s.sig, a.s.ctx.GroupID, 0); err != nil {
			t.Fatal(err)
		}
		return n
	}
	send := func(p *message.Proposal, edit func(c *message.FramedContent)) []byte {
		c := &message.FramedContent{GroupID: a.s.ctx.GroupID, Epoch: a.s.ctx.Epoch, Sender: message.Sender{Type: message.SenderMember, Index: 0}, ContentType: message.ContentProposal, Proposal: p}
		if edit != nil {
			edit(c)
		}
		return w.seal(a, c, nil, nil)
	}
	other := newClient(t)
	_, other.sig, _ = ed25519.GenerateKey(nil)
	for _, c := range []struct {
		rule   string
		msg    []byte
		want   error
		reason string
	}{
		{"P-Add", send(addP(t, func() []byte {
			_, kp := keyPackageFor(t, []byte("y"), other.sig, func(o *KeyPackageOptions) { o.Capabilities.CipherSuites = []uint16{1, 2} })
			k, _ := decodeKeyPackage(kp)
			k.Signature[0] ^= 1
			b, _ := (&message.MLSMessage{WireFormat: message.WireKeyPackage, KeyPackage: k}).Marshal()
			return b
		}()), nil), errs.ErrInvalidKeyPackage, "signature"},
		{"P-Update", send(&message.Proposal{Type: message.ProposalUpdate, LeafNode: leaf(func(n *tree.LeafNode) { n.EncryptionKey = a.s.tree.Leaf(0).EncryptionKey })}, nil), errs.ErrInvalidProposal, "keeps the encryption key"},
		{"P-Update source", send(&message.Proposal{Type: message.ProposalUpdate, LeafNode: leaf(func(n *tree.LeafNode) { n.Source = tree.SourceCommit })}, nil), errs.ErrInvalidLeaf, "leaf_node_source 3, want 2"},
		{"P-Remove", send(removeP(5), nil), errs.ErrInvalidProposal, "Remove of blank leaf 5"},
		{"P-PSK nonce", send(&message.Proposal{Type: message.ProposalPSK, PSK: &schedule.PSKID{Type: schedule.PSKExternal, ID: []byte{1}, Nonce: make([]byte, 33)}}, nil), errs.ErrInvalidProposal, "psk_nonce of 33 bytes"},
		{"P-PSK short nonce", send(&message.Proposal{Type: message.ProposalPSK, PSK: &schedule.PSKID{Type: schedule.PSKExternal, ID: []byte{1}, Nonce: []byte{1}}}, nil), errs.ErrMalformed, "psk_nonce of 1 bytes"},
		{"P-PSK branch", send(&message.Proposal{Type: message.ProposalPSK, PSK: &schedule.PSKID{Type: schedule.PSKResumption, Usage: schedule.UsageBranch, Nonce: make([]byte, 32)}}, nil), errs.ErrInvalidProposal, "usage 3 outside"},
		{"P-PSK reinit", send(&message.Proposal{Type: message.ProposalPSK, PSK: &schedule.PSKID{Type: schedule.PSKResumption, Usage: schedule.UsageReinit, Nonce: make([]byte, 32)}}, nil), errs.ErrInvalidProposal, "usage 2 outside"},
		{"P-ReInit", send(&message.Proposal{Type: message.ProposalReInit, ReInit: &message.ReInit{Version: 0}}, nil), errs.ErrInvalidProposal, "ReInit to version 0"},
		{"P-ReInit refused", send(&message.Proposal{Type: message.ProposalReInit, ReInit: &message.ReInit{Version: 1}}, nil), errs.ErrUnsupported, "ReInit proposals"},
		{"P-ExternalInit", send(&message.Proposal{Type: message.ProposalExternalInit, KEMOutput: []byte{1}}, nil), errs.ErrUnsupported, "ExternalInit proposals"},
		{"F3 epoch", send(removeP(2), func(c *message.FramedContent) { c.Epoch++ }), errs.ErrFutureEpoch, "future"},
		{"F4 external sender", send(removeP(2), func(c *message.FramedContent) { c.Sender = message.Sender{Type: message.SenderExternal} }), errs.ErrUnsupported, "sender type 2"},
		{"F4 new member", send(removeP(2), func(c *message.FramedContent) { c.Sender = message.Sender{Type: message.SenderNewMemberProposal} }), errs.ErrUnsupported, "sender type 3"},
		{"blank sender", send(removeP(2), func(c *message.FramedContent) { c.Sender.Index = 7 }), errs.ErrUnknownSender, "sender leaf 7 is blank"},
	} {
		t.Run(c.rule, func(t *testing.T) {
			refused(t, w, c.msg, c.want, c.reason)
		})
	}
	t.Run("policy", func(t *testing.T) {
		g := w.members[1].g
		g.cfg.Policy = refusePolicy{}
		defer func() { g.cfg.Policy = rfcPolicy{} }()
		refused(t, w, send(removeP(2), nil), errs.ErrPolicy, "refused by policy")
	})
	t.Run("not a group message", func(t *testing.T) {
		refused(t, w, newClient(t).keyPackage(t), errs.ErrInvalidArgument, "is not a group message")
	})
	t.Run("PrivateMessage", func(t *testing.T) {
		m := &message.MLSMessage{WireFormat: message.WirePrivate, Private: &message.PrivateMessage{GroupID: a.GroupID(), Epoch: a.Epoch(), ContentType: message.ContentProposal,
			EncryptedSenderData: make([]byte, 32), Ciphertext: make([]byte, 32)}}
		b, _ := m.Marshal()
		refused(t, w, b, errs.ErrDecrypt, "decryption failed")
	})
	t.Run("hostile bytes", func(t *testing.T) {
		msg := send(removeP(2), nil)
		refused(t, w, msg[:len(msg)-1], errs.ErrMalformed, "truncated")
		refused(t, w, append(bytes.Clone(msg), 0), errs.ErrMalformed, "trailing bytes")
		refused(t, w, nil, errs.ErrMalformed, "truncated")
	})
	// A valid proposal is cached once, and a duplicate is not cached again.
	msg := send(removeP(2), nil)
	g := w.members[1].g
	r1, err := g.Process(msg)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := g.Process(msg)
	if err != nil || !bytes.Equal(r1.ProposalRef, r2.ProposalRef) || len(g.props) != 1 {
		t.Fatalf("duplicate proposal: %v, %d cached", err, len(g.props))
	}
}

// TestRemovedMember covers a Commit that removes the receiver and Commits
// from a removed member.
func TestRemovedMember(t *testing.T) {
	w := newWorld(t, 4)
	old := w.members[3].g
	stale := commitBy(t, w, 3, CommitOptions{})
	w.commit(0, CommitOptions{Remove: []uint32{3}})
	if _, ok := w.members[3]; ok {
		t.Fatal("the removed member is still in the world")
	}
	if err := old.live(); !errors.Is(err, errs.ErrRemoved) {
		t.Fatalf("removed group: %v", err)
	}
	if _, err := old.Process(stale); !errors.Is(err, errs.ErrRemoved) {
		t.Fatalf("Process after removal: %v", err)
	}
	keys := 0
	old.st().each(func(k, _ []byte) {
		if bytes.HasPrefix(k, groupKey(old.GroupID(), "")) {
			keys++
		}
	})
	if keys != 0 {
		t.Fatalf("%d records of the group kept after removal", keys)
	}
	// Its Commit of the old epoch is for a past epoch now.
	refused(t, w, stale, errs.ErrWrongEpoch, "past epoch")
	// A Commit in the new epoch names its blank leaf.
	refused(t, w, w.forge(0, byValue(), func(c *message.FramedContent) { c.Sender.Index = 3 }, nil), errs.ErrUnknownSender, "sender leaf 3 is blank")
}

// x509 encodes an x509 chain for a test.
func x509(t testing.TB, certs ...[]byte) []byte {
	t.Helper()
	b, err := tree.Chain(certs...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
