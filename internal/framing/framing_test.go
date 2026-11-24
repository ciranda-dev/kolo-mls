package framing

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
)

type protectionVector struct {
	CipherSuite             uint16      `json:"cipher_suite"`
	GroupID                 testvec.Hex `json:"group_id"`
	Epoch                   uint64      `json:"epoch"`
	TreeHash                testvec.Hex `json:"tree_hash"`
	ConfirmedTranscriptHash testvec.Hex `json:"confirmed_transcript_hash"`
	SignaturePriv           testvec.Hex `json:"signature_priv"`
	SignaturePub            testvec.Hex `json:"signature_pub"`
	EncryptionSecret        testvec.Hex `json:"encryption_secret"`
	SenderDataSecret        testvec.Hex `json:"sender_data_secret"`
	MembershipKey           testvec.Hex `json:"membership_key"`
	Proposal                testvec.Hex `json:"proposal"`
	ProposalPub             testvec.Hex `json:"proposal_pub"`
	ProposalPriv            testvec.Hex `json:"proposal_priv"`
	Commit                  testvec.Hex `json:"commit"`
	CommitPub               testvec.Hex `json:"commit_pub"`
	CommitPriv              testvec.Hex `json:"commit_priv"`
	Application             testvec.Hex `json:"application"`
	ApplicationPriv         testvec.Hex `json:"application_priv"`
}

// fixture is one vector entry's group, as test-vectors.md describes it: two
// members, leaf 1 sending.
type fixture struct {
	t       testing.TB
	v       *protectionVector
	context []byte
	sig     ed25519.PrivateKey
}

func newFixture(t testing.TB, v *protectionVector) *fixture {
	gc := schedule.GroupContext{CipherSuite: v.CipherSuite, GroupID: v.GroupID, Epoch: v.Epoch, TreeHash: v.TreeHash, ConfirmedTranscriptHash: v.ConfirmedTranscriptHash}
	b, err := gc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.SignaturePriv) != ed25519.SeedSize {
		t.Fatalf("signature_priv of %d bytes", len(v.SignaturePriv))
	}
	sig := ed25519.NewKeyFromSeed(v.SignaturePriv)
	if !bytes.Equal(sig.Public().(ed25519.PublicKey), v.SignaturePub) {
		t.Fatal("signature_priv does not match signature_pub")
	}
	return &fixture{t: t, v: v, context: b, sig: sig}
}

func (f *fixture) secretTree() *secrettree.Tree {
	st, err := secrettree.New(f.v.EncryptionSecret, 2, secrettree.Options{})
	if err != nil {
		f.t.Fatal(err)
	}
	return st
}

func member(l uint32) bool { return l < 2 }

// content returns signed content of the given type for wire format wf.
func (f *fixture) content(wf uint16, c *message.FramedContent) *message.AuthenticatedContent {
	c.GroupID, c.Epoch, c.Sender = f.v.GroupID, f.v.Epoch, message.Sender{Type: message.SenderMember, Index: 1}
	sig, err := Sign(f.sig, wf, c, f.context)
	if err != nil {
		f.t.Fatal(err)
	}
	ac := &message.AuthenticatedContent{WireFormat: wf, Content: c, Auth: message.AuthData{Signature: sig}}
	if c.ContentType == message.ContentCommit {
		// The receiver here does not check the confirmation tag.
		ac.Auth.ConfirmationTag = bytes.Repeat([]byte{7}, suite.Nh)
	}
	return ac
}

func (f *fixture) unprotectPublic(b []byte) *message.AuthenticatedContent {
	m, err := message.UnmarshalMLSMessage(b)
	if err != nil {
		f.t.Fatal(err)
	}
	if m.WireFormat != message.WirePublic {
		f.t.Fatalf("wire format %d", m.WireFormat)
	}
	ac, err := UnprotectPublic(m.Public, f.v.MembershipKey, f.context)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := Verify(f.v.SignaturePub, ac, f.context); err != nil {
		f.t.Fatal(err)
	}
	return ac
}

// unprotectPrivate decrypts b with keys, checks its signature and only then
// commits the key, as a receiver must.
func (f *fixture) unprotectPrivate(b []byte, keys *secrettree.Tree) *message.AuthenticatedContent {
	m, err := message.UnmarshalMLSMessage(b)
	if err != nil {
		f.t.Fatal(err)
	}
	if m.WireFormat != message.WirePrivate {
		f.t.Fatalf("wire format %d", m.WireFormat)
	}
	ac, lk, err := UnprotectPrivate(m.Private, f.v.SenderDataSecret, keys, member)
	if err != nil {
		f.t.Fatal(err)
	}
	defer lk.Discard()
	if err := Verify(f.v.SignaturePub, ac, f.context); err != nil {
		f.t.Fatal(err)
	}
	if err := keys.Commit(lk); err != nil {
		f.t.Fatal(err)
	}
	return ac
}

// next returns the sender's next key of kind k in keys.
func (f *fixture) next(keys *secrettree.Tree, k secrettree.Kind) *secrettree.Lookup {
	lk, err := keys.PeekNext(1, k)
	if err != nil {
		f.t.Fatal(err)
	}
	return lk
}

func (f *fixture) protectPrivate(ac *message.AuthenticatedContent, keys *secrettree.Tree) []byte {
	lk := f.next(keys, RatchetKind(ac.Content.ContentType))
	defer lk.Discard()
	pm, err := ProtectPrivate(ac, f.v.SenderDataSecret, lk)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := keys.Commit(lk); err != nil {
		f.t.Fatal(err)
	}
	b, err := (&message.MLSMessage{WireFormat: message.WirePrivate, Private: pm}).Marshal()
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func marshalProposal(t *testing.T, p *message.Proposal) []byte {
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func marshalCommit(t *testing.T, c *message.Commit) []byte {
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMessageProtectionVectors runs message-protection.json as
// test-vectors.md describes, for the handshake and application messages.
func TestMessageProtectionVectors(t *testing.T) {
	var v []protectionVector
	testvec.Load(t, "message-protection.json", &v)
	checked, skipped, cases := 0, 0, 0
	for i := range v {
		e := &v[i]
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		checked++
		f := newFixture(t, e)

		proposal, err := message.UnmarshalProposal(e.Proposal)
		if err != nil {
			t.Fatal(err)
		}
		commit, err := message.UnmarshalCommit(e.Commit)
		if err != nil {
			t.Fatal(err)
		}
		handshakes := []struct {
			pub, priv []byte
			body      func(*message.FramedContent) []byte
			fresh     func() *message.FramedContent
			raw       []byte
		}{
			{e.ProposalPub, e.ProposalPriv, func(c *message.FramedContent) []byte { return marshalProposal(t, c.Proposal) },
				func() *message.FramedContent {
					return &message.FramedContent{ContentType: message.ContentProposal, Proposal: proposal}
				}, e.Proposal},
			{e.CommitPub, e.CommitPriv, func(c *message.FramedContent) []byte { return marshalCommit(t, c.Commit) },
				func() *message.FramedContent {
					return &message.FramedContent{ContentType: message.ContentCommit, Commit: commit}
				}, e.Commit},
		}
		for _, h := range handshakes {
			if got := h.body(f.unprotectPublic(h.pub).Content); !bytes.Equal(got, h.raw) {
				t.Fatal("PublicMessage gives other content")
			}
			pm, err := ProtectPublic(f.content(message.WirePublic, h.fresh()), e.MembershipKey, f.context)
			if err != nil {
				t.Fatal(err)
			}
			b, err := (&message.MLSMessage{WireFormat: message.WirePublic, Public: pm}).Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if got := h.body(f.unprotectPublic(b).Content); !bytes.Equal(got, h.raw) {
				t.Fatal("protected PublicMessage gives other content")
			}
			if got := h.body(f.unprotectPrivate(h.priv, f.secretTree()).Content); !bytes.Equal(got, h.raw) {
				t.Fatal("PrivateMessage gives other content")
			}
			b = f.protectPrivate(f.content(message.WirePrivate, h.fresh()), f.secretTree())
			if got := h.body(f.unprotectPrivate(b, f.secretTree()).Content); !bytes.Equal(got, h.raw) {
				t.Fatal("protected PrivateMessage gives other content")
			}
			cases += 4
		}

		app := func() *message.FramedContent {
			return &message.FramedContent{ContentType: message.ContentApplication, ApplicationData: e.Application}
		}
		if _, err := ProtectPublic(f.content(message.WirePublic, app()), e.MembershipKey, f.context); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Fatalf("application data as a PublicMessage: error = %v", err)
		}
		if got := f.unprotectPrivate(e.ApplicationPriv, f.secretTree()).Content.ApplicationData; !bytes.Equal(got, e.Application) {
			t.Fatal("application PrivateMessage gives other data")
		}
		b := f.protectPrivate(f.content(message.WirePrivate, app()), f.secretTree())
		if got := f.unprotectPrivate(b, f.secretTree()).Content.ApplicationData; !bytes.Equal(got, e.Application) {
			t.Fatal("protected application PrivateMessage gives other data")
		}
		cases += 3
	}
	if checked != 1 || skipped != 6 || cases != 11 {
		t.Fatalf("message-protection.json: %d suite 1 entries, %d skipped, %d cases; want 1, 6, 11", checked, skipped, cases)
	}
}
