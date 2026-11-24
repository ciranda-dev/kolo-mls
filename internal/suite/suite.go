// Package suite implements the primitives of cipher suite 0x0001,
// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (RFC 9420 sections 5.1, 5.2, 8).
package suite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"fmt"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// ID is the cipher suite value of MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
const ID uint16 = 0x0001

// Sizes in bytes (RFC 9180 sections 7.1 to 7.3).
const (
	Nh = 32 // hash and KDF output
	Nk = 16 // AEAD key
	Nn = 12 // AEAD nonce
)

var kem = hpke.DHKEM(ecdh.X25519())

const labelPrefix = "MLS 1.0 "

// wrap prefixes an error of the standard library, which never holds a secret.
func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("kolomls: %s: %w", op, err)
}

// Hash returns SHA-256 of b.
func Hash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// RefHash computes RefHash(label, value) (RFC 9420 section 5.2).
func RefHash(label string, value []byte) ([]byte, error) {
	var w tls.Writer
	w.Opaque([]byte(label))
	w.Opaque(value)
	b, err := w.Bytes()
	if err != nil {
		return nil, err
	}
	return Hash(b), nil
}

// Extract computes KDF.Extract(salt, ikm). The parameters follow the RFC's
// order; crypto/hkdf takes them the other way round.
func Extract(salt, ikm []byte) ([]byte, error) {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	return prk, wrap("hkdf extract", err)
}

// Expand computes KDF.Expand(prk, info, n); n is at most 255 * Nh.
func Expand(prk, info []byte, n int) ([]byte, error) {
	if n < 0 || n > 255*Nh {
		return nil, fmt.Errorf("%w: expand length %d", errs.ErrInvalidArgument, n)
	}
	out, err := hkdf.Expand(sha256.New, prk, string(info), n)
	return out, wrap("hkdf expand", err)
}

// ExpandWithLabel computes ExpandWithLabel(secret, label, context, length)
// (RFC 9420 section 8).
func ExpandWithLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// Expand refuses any length above 255 * Nh, so the uint16 never truncates.
	var w tls.Writer
	w.U16(uint16(length))
	w.Opaque([]byte(labelPrefix + label))
	w.Opaque(context)
	info, err := w.Bytes()
	if err != nil {
		return nil, err
	}
	return Expand(secret, info, length)
}

// DeriveSecret computes DeriveSecret(secret, label) (RFC 9420 section 8).
func DeriveSecret(secret []byte, label string) ([]byte, error) {
	return ExpandWithLabel(secret, label, nil, Nh)
}

// DeriveTreeSecret computes DeriveTreeSecret(secret, label, generation, length)
// (RFC 9420 section 9.1).
func DeriveTreeSecret(secret []byte, label string, generation uint32, length int) ([]byte, error) {
	var w tls.Writer
	w.U32(generation)
	ctx, _ := w.Bytes()
	return ExpandWithLabel(secret, label, ctx, length)
}

func labeled(label string, content []byte) ([]byte, error) {
	var w tls.Writer
	w.Opaque([]byte(labelPrefix + label))
	w.Opaque(content)
	return w.Bytes()
}

// SignWithLabel computes SignWithLabel (RFC 9420 section 5.1.2) with an
// Ed25519 private key of ed25519.PrivateKeySize bytes.
func SignWithLabel(priv ed25519.PrivateKey, label string, content []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signature private key size", errs.ErrInvalidArgument)
	}
	m, err := labeled(label, content)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, m), nil
}

// VerifyWithLabel reports whether sig is a valid SignWithLabel signature;
// keys and signatures of the wrong size are invalid.
func VerifyWithLabel(pub []byte, label string, content, sig []byte) bool {
	// ed25519.Verify panics on a public key of the wrong size.
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	m, err := labeled(label, content)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), m, sig)
}

// EncryptWithLabel computes EncryptWithLabel (RFC 9420 section 5.1.3) and
// returns kem_output and ciphertext separately, as MLS keeps them.
func EncryptWithLabel(pub []byte, label string, context, plaintext []byte) (kemOutput, ciphertext []byte, err error) {
	pk, err := kem.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: HPKE public key", errs.ErrInvalidArgument)
	}
	info, err := labeled(label, context)
	if err != nil {
		return nil, nil, err
	}
	enc, s, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: HPKE public key", errs.ErrInvalidArgument)
	}
	ct, err := s.Seal(nil, plaintext)
	if err != nil {
		return nil, nil, wrap("hpke seal", err)
	}
	return enc, ct, nil
}

// DecryptWithLabel computes DecryptWithLabel (RFC 9420 section 5.1.3) with
// a serialized X25519 private key.
func DecryptWithLabel(priv []byte, label string, context, kemOutput, ciphertext []byte) ([]byte, error) {
	sk, err := kem.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: HPKE private key", errs.ErrInvalidArgument)
	}
	info, err := labeled(label, context)
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(kemOutput, sk, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
	if err != nil {
		return nil, errs.ErrDecrypt
	}
	pt, err := r.Open(nil, ciphertext)
	if err != nil {
		return nil, errs.ErrDecrypt
	}
	return pt, nil
}

// DeriveKeyPair computes KEM.DeriveKeyPair(ikm) (RFC 9180 section 7.1.3) and
// returns the serialized private and public keys.
func DeriveKeyPair(ikm []byte) (priv, pub []byte, err error) {
	sk, err := kem.DeriveKeyPair(ikm)
	if err != nil {
		return nil, nil, wrap("hpke derive key pair", err)
	}
	return keyPair(sk)
}

// GenerateKeyPair returns a fresh serialized X25519 key pair from crypto/rand.
func GenerateKeyPair() (priv, pub []byte, err error) {
	sk, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, wrap("hpke generate key", err)
	}
	return keyPair(sk)
}

// probe is a fixed X25519 key: its shared secret with a low-order point is
// all zero, which crypto/ecdh refuses (RFC 9180 section 7.1.4).
var probe = func() *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	if err != nil {
		panic(err)
	}
	return k
}()

// CheckPublicKey reports an error unless b is a 32-byte X25519 public key of
// large order, one that HPKE can encrypt to.
func CheckPublicKey(b []byte) error {
	pk, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return fmt.Errorf("%w: HPKE public key size", errs.ErrInvalidArgument)
	}
	if _, err := probe.ECDH(pk); err != nil {
		return fmt.Errorf("%w: HPKE public key of low order", errs.ErrInvalidArgument)
	}
	return nil
}

// PublicKey returns the serialized X25519 public key of a serialized private key.
func PublicKey(priv []byte) ([]byte, error) {
	sk, err := kem.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: HPKE private key", errs.ErrInvalidArgument)
	}
	return sk.PublicKey().Bytes(), nil
}

func keyPair(sk hpke.PrivateKey) (priv, pub []byte, err error) {
	priv, err = sk.Bytes()
	if err != nil {
		return nil, nil, wrap("hpke private key", err)
	}
	return priv, sk.PublicKey().Bytes(), nil
}

// MAC computes HMAC-SHA256(key, data).
func MAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// VerifyMAC reports in constant time whether tag is MAC(key, data).
func VerifyMAC(key, data, tag []byte) bool {
	return hmac.Equal(MAC(key, data), tag)
}

func gcm(key, nonce []byte) (cipher.AEAD, error) {
	if len(key) != Nk || len(nonce) != Nn {
		return nil, fmt.Errorf("%w: AEAD key or nonce size", errs.ErrInvalidArgument)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, wrap("aes", err)
	}
	a, err := cipher.NewGCM(b)
	return a, wrap("gcm", err)
}

// Seal encrypts plaintext with AES-128-GCM.
func Seal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	a, err := gcm(key, nonce)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts and authenticates ciphertext with AES-128-GCM.
func Open(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	a, err := gcm(key, nonce)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errs.ErrDecrypt
	}
	return pt, nil
}
