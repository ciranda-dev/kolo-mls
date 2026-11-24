// Package cred is the Kolo credential of an MLS leaf: credential type 0xF001
// with a kolo-id device certificate and the device's signature over the
// leaf's MLS signature key, and the Authenticator that checks it (RFC 9420
// section 5.3).
package cred

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// Type is the credential type 0xF001 of a Kolo device, from the private-use
// range of RFC 9420 section 17.5.
const Type = tree.CredentialKoloDevice

// LeafKeyContext is the context of the device's signature over a leaf's MLS
// signature key.
const LeafKeyContext = "kolo-mls/leaf-key/v0"

// maxCert is the largest kolo-id certificate encoding, with an approver
// parent.
const maxCert = 514

// MaxBody is the largest credential body: version, the certificate with its
// length and the signature.
const MaxBody = 1 + 2 + maxCert + ed25519.SignatureSize

// ErrCredential reports a Kolo credential that does not decode or verify;
// kolo-id's errors are wrapped.
var ErrCredential = errors.New("kolomls: invalid Kolo credential")

// Credential is a decoded Kolo credential.
type Credential struct {
	// Cert is the device certificate; trusted only after Validate.
	Cert *koloid.DeviceCert
	// Signature is the device's signature over the binding.
	Signature []byte
}

// Device returns the certified device key, nil without a certificate.
func (c *Credential) Device() ed25519.PublicKey {
	if c == nil {
		return nil
	}
	return c.Cert.Device()
}

// Person returns the person key the certificate names, an unverified
// claim; nil without a certificate.
func (c *Credential) Person() ed25519.PublicKey {
	if c == nil {
		return nil
	}
	return c.Cert.Person()
}

// Encode returns c as an MLS Credential, an empty one without a
// certificate.
func (c *Credential) Encode() kolomls.Credential {
	if c == nil || c.Cert == nil {
		return kolomls.Credential{Type: Type}
	}
	var e kolocodec.Encoder
	e.PutUvarint(0)
	e.PutBytes(c.Cert.Encode())
	e.PutFixed(c.Signature)
	return kolomls.Credential{Type: Type, Identity: e.Bytes()}
}

// Binding returns the bytes the device signs for a leaf: the version, the
// cipher suite, the MLS signature key and the hash of the certificate, so a
// signature cannot move to another certificate of the same device key.
func Binding(signatureKey []byte, cert *koloid.DeviceCert) []byte {
	h := sha256.Sum256(cert.Encode())
	var e kolocodec.Encoder
	e.PutUvarint(0)
	e.PutUvarint(uint64(suite.ID))
	e.PutFixed(signatureKey)
	e.PutFixed(h[:])
	return e.Bytes()
}

// New returns the credential of device, certified by cert, for a leaf with
// signatureKey, signed by the device key.
func New(device *koloid.Identity, cert *koloid.DeviceCert, signatureKey ed25519.PublicKey) (kolomls.Credential, error) {
	if cert == nil || !bytes.Equal(cert.Device(), device.PublicKey()) {
		return kolomls.Credential{}, fmt.Errorf("%w: the certificate is for another device", ErrCredential)
	}
	if len(signatureKey) != ed25519.PublicKeySize {
		return kolomls.Credential{}, fmt.Errorf("%w: signature key of %d bytes", ErrCredential, len(signatureKey))
	}
	sig, err := device.Sign(LeafKeyContext, Binding(signatureKey, cert))
	if err != nil {
		return kolomls.Credential{}, fmt.Errorf("%w: %w", ErrCredential, err)
	}
	return (&Credential{Cert: cert, Signature: sig}).Encode(), nil
}

// Decode decodes a Kolo credential, checking its structure but no
// signature.
func Decode(c kolomls.Credential) (*Credential, error) {
	if c.Type != Type {
		return nil, fmt.Errorf("%w: credential type %#04x", ErrCredential, c.Type)
	}
	if len(c.Identity) > MaxBody {
		return nil, fmt.Errorf("%w: %d bytes", ErrCredential, len(c.Identity))
	}
	d := kolocodec.NewDecoder(c.Identity)
	v, err := d.Uvarint()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCredential, err)
	}
	if v != 0 {
		return nil, fmt.Errorf("%w: version %d", ErrCredential, v)
	}
	cb, err := d.Bytes(maxCert)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCredential, err)
	}
	sig, err := d.Fixed(ed25519.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCredential, err)
	}
	if err := d.Done(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCredential, err)
	}
	cert, err := koloid.DecodeDeviceCert(cb)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCredential, err)
	}
	return &Credential{Cert: cert, Signature: sig}, nil
}

// unixEpoch is the time receivers check certificates at: every expiry is
// after it, since members accept leaves with expired certificates (RFC 9420
// section 5.3.2), and the answer is the same on every member.
var unixEpoch = time.Unix(0, 0)

// DefaultMaxCached is the default bound on the client ids an Authenticator
// caches: more than the leaves of the largest tree a joiner accepts by
// default (kolomls.DefaultMaxTreeBytes over the smallest Kolo leaf, measured
// by TestCacheBound).
const DefaultMaxCached = 1 << 19

// Authenticator checks Kolo credentials for the core (RFC 9420 section
// 5.3.1). Its fields are set before first use; it is safe for concurrent
// use.
type Authenticator struct {
	// Expect is the application's check of the person and device a leaf
	// presents (the reference identifier of RFC 9420 section 5.3.1); nil
	// accepts any person. It must answer the same on every member.
	Expect func(person, device ed25519.PublicKey, ev kolomls.Event) error
	// Revocations returns the revocations held for device of person, checked
	// when this member adds a KeyPackage (kolomls.EventKeyPackage); nil holds
	// none. Receivers do not check them in Validate, so that every member
	// decides alike; see Revoked.
	Revocations func(person, device ed25519.PublicKey) []*koloid.Revocation
	// Now is the clock of the expiry check when this member adds a
	// KeyPackage; required for that check.
	Now func() time.Time
	// MaxCached bounds the client ids kept; zero means DefaultMaxCached. The
	// cache is emptied when it is full.
	MaxCached int

	mu  sync.Mutex
	ids map[[32]byte][32]byte
}

// Validate checks that c is a Kolo credential of a valid certificate chain
// whose device signed signatureKey for this cipher suite, and asks Expect.
func (a *Authenticator) Validate(c kolomls.Credential, signatureKey []byte, ev kolomls.Event) error {
	cr, err := Decode(c)
	if err != nil {
		return err
	}
	if len(signatureKey) != ed25519.PublicKeySize || smallOrder(signatureKey) {
		return fmt.Errorf("%w: MLS signature key", ErrCredential)
	}
	person := cr.Person()
	opts := &koloid.VerifyOptions{Person: person, Now: unixEpoch}
	if ev == kolomls.EventKeyPackage {
		if a.Now == nil {
			return fmt.Errorf("%w: an Authenticator needs a clock to check a KeyPackage", ErrCredential)
		}
		opts.Now = a.Now()
		if a.Revocations != nil {
			opts.Revocations = a.Revocations(person, cr.Device())
		}
	}
	if err := koloid.VerifyDevice(cr.Cert, opts, LeafKeyContext, Binding(signatureKey, cr.Cert), cr.Signature); err != nil {
		return fmt.Errorf("%w: %w", ErrCredential, err)
	}
	if a.Expect != nil {
		if err := a.Expect(person, cr.Device(), ev); err != nil {
			return fmt.Errorf("%w: %w", ErrCredential, err)
		}
	}
	a.remember(c.Identity, cr.Device())
	return nil
}

// Successor checks that next keeps the person and the device of prev; the
// certificate and the MLS signature key may change (RFC 9420 section 5.3.1).
func (a *Authenticator) Successor(prev, next kolomls.Credential) error {
	p, err := Decode(prev)
	if err != nil {
		return err
	}
	n, err := Decode(next)
	if err != nil {
		return err
	}
	if !bytes.Equal(p.Person(), n.Person()) || !bytes.Equal(p.Device(), n.Device()) {
		return fmt.Errorf("%w: a leaf keeps its person and device", ErrCredential)
	}
	return nil
}

// ClientID returns the device key: two leaves of one device are the same
// client.
func (a *Authenticator) ClientID(c kolomls.Credential) ([]byte, error) {
	h := sha256.Sum256(c.Identity)
	a.mu.Lock()
	d, ok := a.ids[h]
	a.mu.Unlock()
	if ok && c.Type == Type {
		return bytes.Clone(d[:]), nil
	}
	cr, err := Decode(c)
	if err != nil {
		return nil, err
	}
	a.remember(c.Identity, cr.Device())
	return cr.Device(), nil
}

func (a *Authenticator) remember(body []byte, device ed25519.PublicKey) {
	h := sha256.Sum256(body)
	max := a.MaxCached
	if max <= 0 {
		max = DefaultMaxCached
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ids == nil || len(a.ids) >= max {
		a.ids = map[[32]byte][32]byte{}
	}
	a.ids[h] = [32]byte(device)
}

// Revoked returns an error wrapping koloid.ErrCertRevoked when one of revs
// covers the certificate chain of c, nil otherwise; it does not check
// expiry. Settlers call it with the revocations at a settled position, so
// they decide alike (RFC 9750 section 6.5).
func Revoked(c kolomls.Credential, revs []*koloid.Revocation) error {
	cr, err := Decode(c)
	if err != nil {
		return err
	}
	if err := cr.Cert.Verify(&koloid.VerifyOptions{Person: cr.Person(), Now: unixEpoch, Revocations: revs}); err != nil {
		return fmt.Errorf("%w: %w", ErrCredential, err)
	}
	return nil
}

// smallOrderY holds the y coordinates (little-endian, sign bit clear) of
// the Ed25519 points of order 1, 2, 4 and 8, canonical and not (RFC 8032
// section 5.1): a key at one of them lets anyone forge its signatures.
var smallOrderY = [7][32]byte{
	{0x00},
	{0x01},
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

func smallOrder(pub []byte) bool {
	for _, y := range smallOrderY {
		if bytes.Equal(pub[:31], y[:31]) && pub[31]&0x7f == y[31] {
			return true
		}
	}
	return false
}
