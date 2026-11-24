// Package framing signs, authenticates and encrypts MLS content: the
// FramedContentTBS signature, the PublicMessage membership tag and the
// PrivateMessage encryption of RFC 9420 sections 6.1 to 6.3.
package framing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math/bits"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
)

// Sign returns the signature of content as sent with wireFormat; context is
// the encoded GroupContext of the epoch (RFC 9420 section 6.1).
func Sign(priv ed25519.PrivateKey, wireFormat uint16, c *message.FramedContent, context []byte) ([]byte, error) {
	tbs, err := message.TBS(wireFormat, c, context)
	if err != nil {
		return nil, err
	}
	return suite.SignWithLabel(priv, "FramedContentTBS", tbs)
}

// Verify checks the signature of ac with the sender's signature key.
func Verify(pub []byte, ac *message.AuthenticatedContent, context []byte) error {
	tbs, err := message.TBS(ac.WireFormat, ac.Content, context)
	if err != nil {
		return err
	}
	if !suite.VerifyWithLabel(pub, "FramedContentTBS", tbs, ac.Auth.Signature) {
		return errs.ErrSignature
	}
	return nil
}

// tbm returns AuthenticatedContentTBM, the input of the membership tag.
func tbm(ac *message.AuthenticatedContent, context []byte) ([]byte, error) {
	tbs, err := message.TBS(message.WirePublic, ac.Content, context)
	if err != nil {
		return nil, err
	}
	return message.TBM(tbs, ac.Content, &ac.Auth)
}

// ProtectPublic returns the PublicMessage of ac with the membership tag of
// a member sender (RFC 9420 section 6.2). Application data is refused: it
// must be sent as a PrivateMessage (RFC 9420 section 6).
func ProtectPublic(ac *message.AuthenticatedContent, membershipKey, context []byte) (*message.PublicMessage, error) {
	if ac.WireFormat != message.WirePublic {
		return nil, fmt.Errorf("%w: wire format %d for a PublicMessage", errs.ErrInvalidArgument, ac.WireFormat)
	}
	if ac.Content.ContentType == message.ContentApplication {
		return nil, fmt.Errorf("%w: application data must be sent as a PrivateMessage", errs.ErrInvalidArgument)
	}
	pm := &message.PublicMessage{Content: ac.Content, Auth: ac.Auth}
	if ac.Content.Sender.Type == message.SenderMember {
		in, err := tbm(ac, context)
		if err != nil {
			return nil, err
		}
		pm.MembershipTag = suite.MAC(membershipKey, in)
	}
	return pm, nil
}

// UnprotectPublic checks the membership tag of a member's PublicMessage and
// returns its AuthenticatedContent; the signature is the caller's to check.
func UnprotectPublic(pm *message.PublicMessage, membershipKey, context []byte) (*message.AuthenticatedContent, error) {
	ac := &message.AuthenticatedContent{WireFormat: message.WirePublic, Content: pm.Content, Auth: pm.Auth}
	if pm.Content.ContentType == message.ContentApplication {
		return nil, fmt.Errorf("%w: application data in a PublicMessage", errs.ErrMalformed)
	}
	if pm.Content.Sender.Type == message.SenderMember {
		in, err := tbm(ac, context)
		if err != nil {
			return nil, err
		}
		if !suite.VerifyMAC(membershipKey, in, pm.MembershipTag) {
			return nil, errs.ErrMembershipTag
		}
	}
	return ac, nil
}

// RatchetKind returns the ratchet of a content type: application or
// handshake (RFC 9420 section 9).
func RatchetKind(contentType uint8) secrettree.Kind {
	if contentType == message.ContentApplication {
		return secrettree.Application
	}
	return secrettree.Handshake
}

// padme returns the Padmé length of n (Nikitin et al., "PURBs: Padded
// Uniform Random Blobs", PETS 2019): at most about 12% more than n.
func padme(n int) int {
	if n < 2 {
		return n
	}
	e := bits.Len(uint(n)) - 1
	mask := 1<<(e-bits.Len(uint(e))) - 1
	return (n + mask) &^ mask
}

// senderDataKey derives the key and nonce of the sender data from the first
// Nh bytes of the content ciphertext (RFC 9420 section 6.3.2).
func senderDataKey(senderDataSecret, ciphertext []byte) (key, nonce []byte, err error) {
	sample := ciphertext[:min(len(ciphertext), suite.Nh)]
	if key, err = suite.ExpandWithLabel(senderDataSecret, "key", sample, suite.Nk); err != nil {
		return nil, nil, err
	}
	if nonce, err = suite.ExpandWithLabel(senderDataSecret, "nonce", sample, suite.Nn); err != nil {
		clear(key)
		return nil, nil, err
	}
	return key, nonce, nil
}

// guarded returns nonce with its first four bytes XORed with the reuse guard
// (RFC 9420 section 6.3.1).
func guarded(nonce []byte, guard [4]byte) []byte {
	out := bytes.Clone(nonce)
	for i, g := range guard {
		out[i] ^= g
	}
	return out
}

// ProtectPrivate encrypts ac, signed by a member for the PrivateMessage wire
// format, with the key of lk, the sender's next generation, and pads the
// content with zeros to its Padmé length (RFC 9420 sections 6.3 and 15.1);
// the caller commits lk once the message is kept.
func ProtectPrivate(ac *message.AuthenticatedContent, senderDataSecret []byte, lk *secrettree.Lookup) (*message.PrivateMessage, error) {
	c := ac.Content
	if ac.WireFormat != message.WirePrivate || c.Sender.Type != message.SenderMember {
		return nil, fmt.Errorf("%w: a PrivateMessage needs a member sender and the private wire format", errs.ErrInvalidArgument)
	}
	if lk.Leaf() != c.Sender.Index || lk.Kind() != RatchetKind(c.ContentType) {
		return nil, fmt.Errorf("%w: the key is of another ratchet", errs.ErrInvalidArgument)
	}
	content, err := message.MarshalPrivateContent(c, &ac.Auth, 0)
	if err != nil {
		return nil, err
	}
	// The padding is zero bytes after the content (RFC 9420 section 6.3.1).
	pt := make([]byte, padme(len(content)))
	copy(pt, content)
	clear(content)
	defer clear(pt)
	pm := &message.PrivateMessage{GroupID: c.GroupID, Epoch: c.Epoch, ContentType: c.ContentType, AuthenticatedData: c.AuthenticatedData}
	aad, err := pm.ContentAAD()
	if err != nil {
		return nil, err
	}
	sd := message.SenderData{Leaf: c.Sender.Index, Generation: lk.Generation()}
	rand.Read(sd.ReuseGuard[:]) // crypto/rand.Read never fails since Go 1.24
	key, nonce := lk.Key(), lk.Nonce()
	n := guarded(nonce, sd.ReuseGuard)
	pm.Ciphertext, err = suite.Seal(key, n, aad, pt)
	clear(key)
	clear(nonce)
	clear(n)
	if err != nil {
		return nil, err
	}
	sdKey, sdNonce, err := senderDataKey(senderDataSecret, pm.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(sdKey)
	sdb, err := sd.Marshal()
	if err != nil {
		return nil, err
	}
	sdAAD, err := pm.SenderDataAAD()
	if err != nil {
		return nil, err
	}
	if pm.EncryptedSenderData, err = suite.Seal(sdKey, sdNonce, sdAAD, sdb); err != nil {
		return nil, err
	}
	return pm, nil
}

// OpenSenderData decrypts the sender data of pm (RFC 9420 section 6.3.2); it
// uses up no key.
func OpenSenderData(pm *message.PrivateMessage, senderDataSecret []byte) (*message.SenderData, error) {
	sdKey, sdNonce, err := senderDataKey(senderDataSecret, pm.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(sdKey)
	sdAAD, err := pm.SenderDataAAD()
	if err != nil {
		return nil, err
	}
	sdb, err := suite.Open(sdKey, sdNonce, sdAAD, pm.EncryptedSenderData)
	if err != nil {
		return nil, err
	}
	return message.UnmarshalSenderData(sdb)
}

// UnprotectPrivate decrypts pm and returns its AuthenticatedContent and the
// Lookup of its key, uncommitted; member reports whether a leaf index names
// a non-blank leaf. The caller checks the signature, commits the Lookup only
// then (RFC 9420 section 9.2: a key is consumed by a successful decryption)
// and discards it either way.
func UnprotectPrivate(pm *message.PrivateMessage, senderDataSecret []byte, keys *secrettree.Tree, member func(leaf uint32) bool) (*message.AuthenticatedContent, *secrettree.Lookup, error) {
	sd, err := OpenSenderData(pm, senderDataSecret)
	if err != nil {
		return nil, nil, err
	}
	if !member(sd.Leaf) {
		return nil, nil, fmt.Errorf("%w: sender data names blank leaf %d", errs.ErrUnknownSender, sd.Leaf)
	}
	lk, err := keys.Peek(sd.Leaf, RatchetKind(pm.ContentType), sd.Generation)
	if err != nil {
		return nil, nil, err
	}
	key, nonce := lk.Key(), lk.Nonce()
	n := guarded(nonce, sd.ReuseGuard)
	aad, err := pm.ContentAAD()
	var pt []byte
	if err == nil {
		pt, err = suite.Open(key, n, aad, pm.Ciphertext)
	}
	clear(key)
	clear(nonce)
	clear(n)
	if err != nil {
		lk.Discard()
		return nil, nil, err
	}
	defer clear(pt)
	c := &message.FramedContent{
		GroupID:           pm.GroupID,
		Epoch:             pm.Epoch,
		Sender:            message.Sender{Type: message.SenderMember, Index: sd.Leaf},
		AuthenticatedData: pm.AuthenticatedData,
		ContentType:       pm.ContentType,
	}
	auth, err := message.UnmarshalPrivateContent(pt, c)
	if err != nil {
		lk.Discard()
		return nil, nil, err
	}
	return &message.AuthenticatedContent{WireFormat: message.WirePrivate, Content: c, Auth: auth}, lk, nil
}
