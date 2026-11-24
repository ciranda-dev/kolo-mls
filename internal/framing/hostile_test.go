package framing

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
)

// synthetic returns a fixture with fresh keys, independent of the vectors.
func synthetic(t testing.TB) *fixture {
	pub, priv, _ := ed25519.GenerateKey(nil)
	v := &protectionVector{
		CipherSuite:      suite.ID,
		GroupID:          []byte("group"),
		Epoch:            3,
		TreeHash:         bytes.Repeat([]byte{1}, 32),
		SignaturePriv:    priv.Seed(),
		SignaturePub:     []byte(pub),
		EncryptionSecret: bytes.Repeat([]byte{2}, 32),
		SenderDataSecret: bytes.Repeat([]byte{3}, 32),
		MembershipKey:    bytes.Repeat([]byte{4}, 32),
	}
	return newFixture(t, v)
}

func remove() *message.FramedContent {
	return &message.FramedContent{ContentType: message.ContentProposal, Proposal: &message.Proposal{Type: message.ProposalRemove, Removed: 0}}
}

func TestPublicMessageForgeries(t *testing.T) {
	f := synthetic(t)
	ac := f.content(message.WirePublic, remove())
	pm, err := ProtectPublic(ac, f.v.MembershipKey, f.context)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnprotectPublic(pm, f.v.MembershipKey, f.context); err != nil {
		t.Fatal(err)
	}
	tag := pm.MembershipTag
	pm.MembershipTag = bytes.Clone(tag)
	pm.MembershipTag[0] ^= 1
	if _, err := UnprotectPublic(pm, f.v.MembershipKey, f.context); !errors.Is(err, errs.ErrMembershipTag) {
		t.Fatalf("forged membership tag: %v", err)
	}
	pm.MembershipTag = tag
	if _, err := UnprotectPublic(pm, bytes.Repeat([]byte{5}, 32), f.context); !errors.Is(err, errs.ErrMembershipTag) {
		t.Fatalf("other membership key: %v", err)
	}
	ctx := bytes.Clone(f.context)
	ctx[len(ctx)-1] ^= 1
	if _, err := UnprotectPublic(pm, f.v.MembershipKey, ctx); !errors.Is(err, errs.ErrMembershipTag) {
		t.Fatalf("other GroupContext: %v", err)
	}
	ac.Auth.Signature = bytes.Clone(ac.Auth.Signature)
	ac.Auth.Signature[0] ^= 1
	if err := Verify(f.v.SignaturePub, ac, f.context); !errors.Is(err, errs.ErrSignature) {
		t.Fatalf("forged signature: %v", err)
	}
	ac.Auth.Signature[0] ^= 1
	if err := Verify(f.v.SignaturePub, ac, ctx); !errors.Is(err, errs.ErrSignature) {
		t.Fatalf("signature over another GroupContext: %v", err)
	}
	if err := Verify(f.v.SignaturePub[:31], ac, f.context); !errors.Is(err, errs.ErrSignature) {
		t.Fatalf("short signature key: %v", err)
	}
	app := f.content(message.WirePublic, &message.FramedContent{ContentType: message.ContentApplication, ApplicationData: []byte("x")})
	if _, err := UnprotectPublic(&message.PublicMessage{Content: app.Content, Auth: app.Auth}, f.v.MembershipKey, f.context); !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("application PublicMessage received: %v", err)
	}
	if _, err := ProtectPublic(f.content(message.WirePrivate, remove()), f.v.MembershipKey, f.context); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("private wire format as a PublicMessage: %v", err)
	}
}

func TestPrivateMessageForgeries(t *testing.T) {
	f := synthetic(t)
	protect := func() *message.PrivateMessage {
		pm, err := ProtectPrivate(f.content(message.WirePrivate, remove()), f.v.SenderDataSecret, f.next(f.secretTree(), secrettree.Handshake))
		if err != nil {
			t.Fatal(err)
		}
		return pm
	}
	if _, _, err := UnprotectPrivate(protect(), f.v.SenderDataSecret, f.secretTree(), member); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		change func(pm *message.PrivateMessage)
		keys   func() *secrettree.Tree
		member func(uint32) bool
		want   error
	}{
		"ciphertext":         {func(pm *message.PrivateMessage) { pm.Ciphertext[len(pm.Ciphertext)-1] ^= 1 }, nil, nil, errs.ErrDecrypt},
		"sender data":        {func(pm *message.PrivateMessage) { pm.EncryptedSenderData[0] ^= 1 }, nil, nil, errs.ErrDecrypt},
		"authenticated data": {func(pm *message.PrivateMessage) { pm.AuthenticatedData = []byte{1} }, nil, nil, errs.ErrDecrypt},
		"epoch":              {func(pm *message.PrivateMessage) { pm.Epoch++ }, nil, nil, errs.ErrDecrypt},
		"group id":           {func(pm *message.PrivateMessage) { pm.GroupID = []byte("other") }, nil, nil, errs.ErrDecrypt},
		"content type":       {func(pm *message.PrivateMessage) { pm.ContentType = message.ContentCommit }, nil, nil, errs.ErrDecrypt},
		"blank sender leaf":  {nil, nil, func(uint32) bool { return false }, errs.ErrUnknownSender},
		"other secret tree": {nil, func() *secrettree.Tree {
			st, _ := secrettree.New(bytes.Repeat([]byte{9}, 32), 2, secrettree.Options{})
			return st
		}, nil, errs.ErrDecrypt},
	} {
		pm := protect()
		if c.change != nil {
			c.change(pm)
		}
		keys := f.secretTree()
		if c.keys != nil {
			keys = c.keys()
		}
		m := c.member
		if m == nil {
			m = member
		}
		if _, _, err := UnprotectPrivate(pm, f.v.SenderDataSecret, keys, m); !errors.Is(err, c.want) {
			t.Errorf("%s: error = %v, want %v", name, err, c.want)
		}
	}
	// A replayed message finds its key consumed once committed.
	st := f.secretTree()
	pm := protect()
	_, lk, err := UnprotectPrivate(pm, f.v.SenderDataSecret, st, member)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(lk); err != nil {
		t.Fatal(err)
	}
	if _, _, err := UnprotectPrivate(pm, f.v.SenderDataSecret, st, member); !errors.Is(err, errs.ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := ProtectPrivate(f.content(message.WirePublic, remove()), f.v.SenderDataSecret, f.next(f.secretTree(), secrettree.Handshake)); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("public wire format as a PrivateMessage: %v", err)
	}
	for _, lk := range []*secrettree.Lookup{f.next(f.secretTree(), secrettree.Application), func() *secrettree.Lookup {
		lk, _ := f.secretTree().PeekNext(0, secrettree.Handshake)
		return lk
	}()} {
		if _, err := ProtectPrivate(f.content(message.WirePrivate, remove()), f.v.SenderDataSecret, lk); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Fatalf("key of another ratchet: %v", err)
		}
	}
}

// TestRefusedPrivateConsumesNothing: a PrivateMessage refused at any step
// leaves the receiver's secret tree as it was, so the real message of that
// generation still decrypts afterwards.
// TestOpenSenderData: the leaf and generation come out of the sender data,
// and another sender data secret does not open it.
func TestOpenSenderData(t *testing.T) {
	f := synthetic(t)
	lk := f.next(f.secretTree(), secrettree.Handshake)
	ac := f.content(message.WirePrivate, remove())
	pm, err := ProtectPrivate(ac, f.v.SenderDataSecret, lk)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := OpenSenderData(pm, f.v.SenderDataSecret)
	if err != nil || sd.Leaf != ac.Content.Sender.Index || sd.Generation != lk.Generation() {
		t.Fatalf("leaf %d generation %d: %v", sd.Leaf, sd.Generation, err)
	}
	if _, err := OpenSenderData(pm, bytes.Repeat([]byte{9}, 32)); err == nil {
		t.Fatal("opened with another secret")
	}
}

func TestRefusedPrivateConsumesNothing(t *testing.T) {
	f := synthetic(t)
	sender := f.secretTree()
	lk := f.next(sender, secrettree.Handshake)
	pm, err := ProtectPrivate(f.content(message.WirePrivate, remove()), f.v.SenderDataSecret, lk)
	if err != nil {
		t.Fatal(err)
	}
	st := f.secretTree()
	before, _ := st.Records()
	for name, change := range map[string]func(pm *message.PrivateMessage){
		"ciphertext":     func(pm *message.PrivateMessage) { pm.Ciphertext[len(pm.Ciphertext)-1] ^= 1 },
		"content type":   func(pm *message.PrivateMessage) { pm.ContentType = message.ContentApplication },
		"authentic data": func(pm *message.PrivateMessage) { pm.AuthenticatedData = []byte{1} },
		"uncommitted":    nil,
	} {
		c := *pm
		c.Ciphertext = bytes.Clone(pm.Ciphertext)
		if change != nil {
			change(&c)
		}
		_, lk, err := UnprotectPrivate(&c, f.v.SenderDataSecret, st, member)
		if change != nil && err == nil {
			t.Fatalf("%s: accepted", name)
		}
		lk.Discard()
		after, _ := st.Records()
		if len(after) != len(before) || !bytes.Equal(after[0].Value, before[0].Value) {
			t.Fatalf("%s: the secret tree changed", name)
		}
	}
	ac, lk, err := UnprotectPrivate(pm, f.v.SenderDataSecret, st, member)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(f.v.SignaturePub, ac, f.context); err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(lk); err != nil {
		t.Fatal(err)
	}
}

// The padding of a PrivateMessage must be zero (RFC 9420 section 6.3.1); a
// sender that pads with other bytes is refused.
func TestPrivateMessagePadding(t *testing.T) {
	f := synthetic(t)
	ac := f.content(message.WirePrivate, remove())
	pt, err := message.MarshalPrivateContent(ac.Content, &ac.Auth, 0)
	if err != nil {
		t.Fatal(err)
	}
	pt = append(pt, 0, 0, 1)
	pm := &message.PrivateMessage{GroupID: f.v.GroupID, Epoch: f.v.Epoch, ContentType: message.ContentProposal}
	aad, _ := pm.ContentAAD()
	st := f.secretTree()
	lk := f.next(st, secrettree.Handshake)
	key, nonce, gen := lk.Key(), lk.Nonce(), lk.Generation()
	sd := message.SenderData{Leaf: 1, Generation: gen}
	pm.Ciphertext, _ = suite.Seal(key, nonce, aad, pt)
	sdKey, sdNonce, _ := senderDataKey(f.v.SenderDataSecret, pm.Ciphertext)
	sdb, _ := sd.Marshal()
	sdAAD, _ := pm.SenderDataAAD()
	pm.EncryptedSenderData, _ = suite.Seal(sdKey, sdNonce, sdAAD, sdb)
	if _, _, err := UnprotectPrivate(pm, f.v.SenderDataSecret, f.secretTree(), member); !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("non-zero padding: %v", err)
	}
}

// A ciphertext shorter than Nh bytes samples the whole ciphertext for the
// sender data key (RFC 9420 section 6.3.2).
func TestSenderDataShortSample(t *testing.T) {
	k1, n1, err := senderDataKey(bytes.Repeat([]byte{3}, 32), []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := suite.ExpandWithLabel(bytes.Repeat([]byte{3}, 32), "key", []byte{1, 2, 3}, suite.Nk)
	wantN, _ := suite.ExpandWithLabel(bytes.Repeat([]byte{3}, 32), "nonce", []byte{1, 2, 3}, suite.Nn)
	if !bytes.Equal(k1, want) || !bytes.Equal(n1, wantN) {
		t.Fatal("short sample")
	}
	long := bytes.Repeat([]byte{8}, 40)
	k2, _, _ := senderDataKey(bytes.Repeat([]byte{3}, 32), long)
	want2, _ := suite.ExpandWithLabel(bytes.Repeat([]byte{3}, 32), "key", long[:32], suite.Nk)
	if !bytes.Equal(k2, want2) {
		t.Fatal("sample of a long ciphertext is not its first Nh bytes")
	}
}

// TestPadding: the content of a PrivateMessage is padded with zeros to its
// Padmé length.
func TestPadding(t *testing.T) {
	for n, want := range map[int]int{0: 0, 1: 1, 9: 10, 100: 104, 1000: 1024, 70000: 71680} {
		if got := padme(n); got != want {
			t.Fatalf("padme(%d) = %d, want %d", n, got, want)
		}
	}
	f := synthetic(t)
	padded := 0
	for _, size := range []int{0, 1, 33, 500, 5000} {
		ac := f.content(message.WirePrivate, &message.FramedContent{ContentType: message.ContentApplication, ApplicationData: make([]byte, size)})
		pm, err := ProtectPrivate(ac, f.v.SenderDataSecret, f.next(f.secretTree(), secrettree.Application))
		if err != nil {
			t.Fatal(err)
		}
		pt, _ := message.MarshalPrivateContent(ac.Content, &ac.Auth, 0)
		if got := len(pm.Ciphertext) - 16; got != padme(len(pt)) {
			t.Fatalf("content of %d bytes sent as %d, want %d", len(pt), got, padme(len(pt)))
		}
		if padme(len(pt)) > len(pt) {
			padded++
		}
		_, lk, err := UnprotectPrivate(pm, f.v.SenderDataSecret, f.secretTree(), member)
		if err != nil {
			t.Fatal(err)
		}
		lk.Discard()
	}
	if padded == 0 {
		t.Fatal("no size needed padding")
	}
}
