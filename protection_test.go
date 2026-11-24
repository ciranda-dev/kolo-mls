package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/framing"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
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

// vectorGroups opens the two members of a message-protection.json entry as Groups from their
// own MemStores: leaf 0 a fresh client, leaf 1 the vector's sender with signature_priv. The
// secrets the entry does not give are random and the same for both.
func vectorGroups(t *testing.T, e *protectionVector, cfg Config) (receiver, sender *Group) {
	t.Helper()
	c0 := newClient(t)
	rec0 := c0.keyPackageRecord(t, c0.keyPackage(t))
	c1, kp1 := keyPackageFor(t, []byte("vector sender"), ed25519.NewKeyFromSeed(e.SignaturePriv), nil)
	rec1 := c1.keyPackageRecord(t, kp1)
	if !bytes.Equal(rec1.kp.LeafNode.SignatureKey, e.SignaturePub) {
		t.Fatal("signature_priv does not match signature_pub")
	}
	ctx := &schedule.GroupContext{CipherSuite: e.CipherSuite, GroupID: e.GroupID, Epoch: e.Epoch, TreeHash: e.TreeHash, ConfirmedTranscriptHash: e.ConfirmedTranscriptHash}
	random := func() []byte {
		b := make([]byte, suite.Nh)
		rand.Read(b)
		return b
	}
	common := [][]byte{random(), random(), random(), random(), random()}
	open := func(c *client, rec *keyPackageRecord, own uint32) *Group {
		tr, err := tree.FromNodes(3, map[uint64]tree.Node{0: {Leaf: rec0.kp.LeafNode}, 2: {Leaf: rec1.kp.LeafNode}})
		if err != nil {
			t.Fatal(err)
		}
		secrets := &schedule.Secrets{SenderData: bytes.Clone(e.SenderDataSecret), Encryption: bytes.Clone(e.EncryptionSecret), Membership: bytes.Clone(e.MembershipKey),
			Exporter: bytes.Clone(common[0]), Resumption: bytes.Clone(common[1]), EpochAuthenticator: bytes.Clone(common[2]), Init: bytes.Clone(common[3])}
		s := &state{tree: tr, sig: rec.sig, secrets: secrets, interim: bytes.Clone(common[4]),
			priv: &tree.Private{Leaf: own, Keys: map[uint64][]byte{2 * uint64(own): bytes.Clone(rec.encPriv)}}}
		if err := s.setContext(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.startKeys(cfg.keyOptions()); err != nil {
			t.Fatal(err)
		}
		var b Batch
		if err := writeState(&b, nil, s, nil); err != nil {
			t.Fatal(err)
		}
		if err := writeBatch(c.st, b); err != nil {
			t.Fatal(err)
		}
		g, err := Open(c.st, e.GroupID, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	return open(c0, rec0, 0), open(c1, rec1, 1)
}

// TestMessageProtectionGroups runs message-protection.json through Groups opened from their
// Stores, and has the receiver and the framing layer read the sender's own messages.
func TestMessageProtectionGroups(t *testing.T) {
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
		// The entry's proposal removes leaf 2 and its Commit injects an
		// external PSK no member holds: both are refused, but only after the
		// message decrypted and its signature verified.
		for _, c := range []struct {
			msg     []byte
			private bool
			want    error
		}{
			{e.ProposalPub, false, errs.ErrInvalidProposal},
			{e.ProposalPriv, true, errs.ErrInvalidProposal},
			{e.CommitPub, false, errs.ErrPSKNotFound},
			{e.CommitPriv, true, errs.ErrPSKNotFound},
			{e.ApplicationPriv, true, nil},
		} {
			g, _ := vectorGroups(t, e, vectorConfig(nil))
			r, err := g.Process(c.msg)
			if !errors.Is(err, c.want) {
				t.Fatalf("entry message: %v, want %v", err, c.want)
			}
			if c.want == nil && (r.Sender != 1 || !bytes.Equal(r.Application, e.Application)) {
				t.Fatal("application data differs")
			}
			storeMatches(t, g)
			// An authentic proposal or application message uses its key; a
			// Commit keeps it until Apply and is refused the same way again.
			again := errs.ErrReplay
			if c.want == errs.ErrPSKNotFound {
				again = c.want
			}
			if _, err := g.Process(c.msg); c.private && !errors.Is(err, again) {
				t.Fatalf("the same message again: %v, want %v", err, again)
			}
			cases++
		}
		for _, private := range []bool{false, true} {
			cfg := vectorConfig(nil)
			cfg.PrivateHandshakes = private
			recv, send := vectorGroups(t, e, cfg)
			msg, err := send.Encrypt(e.Application, nil)
			if err != nil {
				t.Fatal(err)
			}
			if r, err := recv.Process(msg); err != nil || !bytes.Equal(r.Application, e.Application) {
				t.Fatalf("own application message: %v", err)
			}
			readByVector(t, e, msg, true)
			if msg, err = send.ProposeRemove(0); err != nil {
				t.Fatal(err)
			}
			if r, err := recv.Process(msg); err != nil || r.ProposalRef == nil {
				t.Fatalf("own proposal: %v", err)
			}
			readByVector(t, e, msg, private)
			// The Commit leaves the proposal out; the new epoch drops it.
			pc, err := send.Commit(CommitOptions{})
			if err != nil {
				t.Fatal(err)
			}
			readByVector(t, e, pc.Commit(), private)
			r, err := recv.Process(pc.Commit())
			if err != nil {
				t.Fatal(err)
			}
			if err := recv.Apply(r.Commit); err != nil {
				t.Fatal(err)
			}
			if err := send.ApplyPending(); err != nil {
				t.Fatal(err)
			}
			if recv.Epoch() != e.Epoch+1 || !bytes.Equal(epochAuth(recv), epochAuth(send)) {
				t.Fatal("the two members differ after the Commit")
			}
			storeMatches(t, recv)
			storeMatches(t, send)
			cases += 3
		}
	}
	if checked != 1 || skipped != 6 || cases != 11 {
		t.Fatalf("message-protection.json: %d suite 1 entries, %d skipped, %d cases; want 1, 6, 11", checked, skipped, cases)
	}
}

// readByVector decrypts a PrivateMessage of leaf 1 with the entry's secrets
// alone and checks its signature with signature_pub; a PublicMessage is
// checked with membership_key.
func readByVector(t *testing.T, e *protectionVector, msg []byte, private bool) {
	t.Helper()
	m, err := message.UnmarshalMLSMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	gc := schedule.GroupContext{CipherSuite: e.CipherSuite, GroupID: e.GroupID, Epoch: e.Epoch, TreeHash: e.TreeHash, ConfirmedTranscriptHash: e.ConfirmedTranscriptHash}
	ctx, _ := gc.Marshal()
	var ac *message.AuthenticatedContent
	if private {
		if m.WireFormat != message.WirePrivate {
			t.Fatal("not a PrivateMessage")
		}
		keys, err := secrettree.New(e.EncryptionSecret, 2, secrettree.Options{})
		if err != nil {
			t.Fatal(err)
		}
		var lk *secrettree.Lookup
		if ac, lk, err = framing.UnprotectPrivate(m.Private, e.SenderDataSecret, keys, func(l uint32) bool { return l < 2 }); err != nil {
			t.Fatal(err)
		}
		lk.Discard()
	} else {
		if m.WireFormat != message.WirePublic {
			t.Fatal("not a PublicMessage")
		}
		if ac, err = framing.UnprotectPublic(m.Public, e.MembershipKey, ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := framing.Verify(e.SignaturePub, ac, ctx); err != nil {
		t.Fatal(err)
	}
}
