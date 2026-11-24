// Package schedule implements the MLS key schedule of RFC 9420 section 8:
// the GroupContext, epoch secrets, transcript hashes, PSKs and the exporter.
package schedule

import (
	"fmt"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// MLS10 is the ProtocolVersion value of mls10.
const MLS10 uint16 = 1

// GroupContext is the GroupContext of RFC 9420 section 8.1; version is mls10.
type GroupContext struct {
	CipherSuite             uint16
	GroupID                 []byte
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
	Extensions              []tls.Extension
}

// Write appends the encoding of g to w.
func (g *GroupContext) Write(w *tls.Writer) {
	w.U16(MLS10)
	w.U16(g.CipherSuite)
	w.Opaque(g.GroupID)
	w.U64(g.Epoch)
	w.Opaque(g.TreeHash)
	w.Opaque(g.ConfirmedTranscriptHash)
	tls.WriteExtensions(w, g.Extensions)
}

// Marshal returns the encoding of g.
func (g *GroupContext) Marshal() ([]byte, error) {
	var w tls.Writer
	g.Write(&w)
	return w.Bytes()
}

// ReadGroupContext reads a GroupContext and refuses versions other than mls10.
func ReadGroupContext(r *tls.Reader) (*GroupContext, error) {
	v, err := r.U16()
	if err != nil {
		return nil, err
	}
	if v != MLS10 {
		return nil, fmt.Errorf("%w: protocol version %d", errs.ErrUnsupported, v)
	}
	var g GroupContext
	if g.CipherSuite, err = r.U16(); err != nil {
		return nil, err
	}
	if g.GroupID, err = r.Opaque(); err != nil {
		return nil, err
	}
	if g.Epoch, err = r.U64(); err != nil {
		return nil, err
	}
	if g.TreeHash, err = r.Opaque(); err != nil {
		return nil, err
	}
	if g.ConfirmedTranscriptHash, err = r.Opaque(); err != nil {
		return nil, err
	}
	if g.Extensions, err = tls.ReadExtensions(r); err != nil {
		return nil, err
	}
	return &g, nil
}

// Secrets holds the epoch-derived secrets of RFC 9420 section 8, Table 4,
// and the next epoch's init_secret. external_secret is left out: no group
// keeps it, since external joins are refused.
type Secrets struct {
	SenderData         []byte
	Encryption         []byte
	Exporter           []byte
	Confirmation       []byte
	Membership         []byte
	Resumption         []byte
	EpochAuthenticator []byte
	Init               []byte
}

func checkSecret(name string, s []byte) error {
	if len(s) != suite.Nh {
		return fmt.Errorf("%w: %s is %d bytes, want %d", errs.ErrInvalidArgument, name, len(s), suite.Nh)
	}
	return nil
}

// JoinerSecret computes joiner_secret from init_secret[n-1], commit_secret
// and the encoded GroupContext[n].
func JoinerSecret(initSecret, commitSecret, groupContext []byte) ([]byte, error) {
	if err := checkSecret("init_secret", initSecret); err != nil {
		return nil, err
	}
	if err := checkSecret("commit_secret", commitSecret); err != nil {
		return nil, err
	}
	prk, err := suite.Extract(initSecret, commitSecret)
	if err != nil {
		return nil, err
	}
	defer clear(prk)
	return suite.ExpandWithLabel(prk, "joiner", groupContext, suite.Nh)
}

// Epoch computes welcome_secret and the secrets of epoch n from
// joiner_secret, psk_secret and the encoded GroupContext[n].
func Epoch(joinerSecret, pskSecret, groupContext []byte) (welcomeSecret []byte, s *Secrets, err error) {
	if err := checkSecret("joiner_secret", joinerSecret); err != nil {
		return nil, nil, err
	}
	if err := checkSecret("psk_secret", pskSecret); err != nil {
		return nil, nil, err
	}
	member, err := suite.Extract(joinerSecret, pskSecret)
	if err != nil {
		return nil, nil, err
	}
	defer clear(member)
	if welcomeSecret, err = suite.DeriveSecret(member, "welcome"); err != nil {
		return nil, nil, err
	}
	epochSecret, err := suite.ExpandWithLabel(member, "epoch", groupContext, suite.Nh)
	if err != nil {
		clear(welcomeSecret)
		return nil, nil, err
	}
	defer clear(epochSecret)
	if s, err = FromEpochSecret(epochSecret); err != nil {
		clear(welcomeSecret)
		return nil, nil, err
	}
	return welcomeSecret, s, nil
}

// WelcomeSecret computes welcome_secret from joiner_secret and psk_secret, as
// a joiner needs it before it knows the GroupContext (RFC 9420 section 12.4.3.1).
func WelcomeSecret(joinerSecret, pskSecret []byte) ([]byte, error) {
	if err := checkSecret("joiner_secret", joinerSecret); err != nil {
		return nil, err
	}
	if err := checkSecret("psk_secret", pskSecret); err != nil {
		return nil, err
	}
	member, err := suite.Extract(joinerSecret, pskSecret)
	if err != nil {
		return nil, err
	}
	defer clear(member)
	return suite.DeriveSecret(member, "welcome")
}

// FromEpochSecret derives the secrets of Table 4 and init_secret from
// epoch_secret; group creation calls it with a random epoch_secret (section 11).
func FromEpochSecret(epochSecret []byte) (*Secrets, error) {
	if err := checkSecret("epoch_secret", epochSecret); err != nil {
		return nil, err
	}
	var s Secrets
	for _, d := range []struct {
		label string
		out   *[]byte
	}{
		{"sender data", &s.SenderData},
		{"encryption", &s.Encryption},
		{"exporter", &s.Exporter},
		{"confirm", &s.Confirmation},
		{"membership", &s.Membership},
		{"resumption", &s.Resumption},
		{"authentication", &s.EpochAuthenticator},
		{"init", &s.Init},
	} {
		v, err := suite.DeriveSecret(epochSecret, d.label)
		if err != nil {
			return nil, err
		}
		*d.out = v
	}
	return &s, nil
}

// Clear zeroes every secret of s.
func (s *Secrets) Clear() {
	for _, b := range [][]byte{s.SenderData, s.Encryption, s.Exporter, s.Confirmation, s.Membership, s.Resumption, s.EpochAuthenticator, s.Init} {
		clear(b)
	}
}

// ExternalPub returns external_pub, the public key of
// KEM.DeriveKeyPair(external_secret) (RFC 9420 section 8).
func ExternalPub(externalSecret []byte) ([]byte, error) {
	priv, pub, err := suite.DeriveKeyPair(externalSecret)
	if err != nil {
		return nil, err
	}
	clear(priv)
	return pub, nil
}

// Export computes MLS-Exporter(label, context, length) from exporter_secret
// (RFC 9420 section 8.5).
func Export(exporterSecret []byte, label string, context []byte, length int) ([]byte, error) {
	s, err := suite.DeriveSecret(exporterSecret, label)
	if err != nil {
		return nil, err
	}
	defer clear(s)
	return suite.ExpandWithLabel(s, "exported", suite.Hash(context), length)
}

// ConfirmedTranscriptHash computes confirmed_transcript_hash[n] from
// interim_transcript_hash[n-1] and the encoded ConfirmedTranscriptHashInput
// (RFC 9420 section 8.2).
func ConfirmedTranscriptHash(interimBefore, input []byte) []byte {
	return suite.Hash(append(append([]byte{}, interimBefore...), input...))
}

// InterimTranscriptHash computes interim_transcript_hash[n] from
// confirmed_transcript_hash[n] and the Commit's confirmation_tag.
func InterimTranscriptHash(confirmed, confirmationTag []byte) ([]byte, error) {
	var w tls.Writer
	w.Fixed(confirmed)
	w.Opaque(confirmationTag)
	b, err := w.Bytes()
	if err != nil {
		return nil, err
	}
	return suite.Hash(b), nil
}
