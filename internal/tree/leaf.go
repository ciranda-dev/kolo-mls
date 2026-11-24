// Package tree implements the MLS ratchet tree and TreeKEM of RFC 9420
// sections 4 and 7: nodes and their encoding, resolutions, tree and parent
// hashes, tree validation and UpdatePath creation and processing.
package tree

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"slices"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// Credential types (RFC 9420 section 17.5); KoloDevice is the private-use
// type of the Kolo credential.
const (
	CredentialBasic      uint16 = 1
	CredentialX509       uint16 = 2
	CredentialKoloDevice uint16 = 0xF001
)

// Credential is an MLS Credential (RFC 9420 section 5.3). Identity holds the
// basic identity or the Kolo device credential; Certificates the encoded x509
// chain, each certificate an opaque<V>, kept whole so that a chain of tiny
// certificates costs no more memory than its encoding.
type Credential struct {
	Type         uint16
	Identity     []byte
	Certificates []byte
}

// Chain encodes certificates as the content of an x509 Credential.
func Chain(certs ...[]byte) ([]byte, error) {
	var w tls.Writer
	for _, c := range certs {
		w.Opaque(c)
	}
	return w.Bytes()
}

// CertificateList returns the certificates of an x509 Credential.
func (c *Credential) CertificateList() ([][]byte, error) {
	var out [][]byte
	r := tls.NewReader(c.Certificates)
	for r.Len() > 0 {
		cert, err := r.Opaque()
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	return out, nil
}

func (c *Credential) write(w *tls.Writer) {
	w.U16(c.Type)
	if c.Type == CredentialX509 {
		w.Opaque(c.Certificates)
		return
	}
	w.Opaque(c.Identity)
}

// A credential type has a select arm with no length, so an unknown type
// cannot be skipped and is malformed (RFC 9420 section 13.5).
func readCredential(r *tls.Reader) (Credential, error) {
	var c Credential
	var err error
	if c.Type, err = r.U16(); err != nil {
		return c, err
	}
	switch c.Type {
	case CredentialBasic, CredentialKoloDevice:
		c.Identity, err = r.Opaque()
	case CredentialX509:
		if c.Certificates, err = r.Opaque(); err != nil {
			return c, err
		}
		chain := tls.NewReader(c.Certificates)
		for chain.Len() > 0 && err == nil {
			var n uint32
			if n, err = chain.Varint(); err == nil {
				err = chain.Skip(int(n))
			}
		}
	default:
		err = fmt.Errorf("%w: credential type %#04x", errs.ErrMalformed, c.Type)
	}
	return c, err
}

// Capabilities lists what a client supports (RFC 9420 section 7.2).
type Capabilities struct {
	Versions     []uint16
	CipherSuites []uint16
	Extensions   []uint16
	Proposals    []uint16
	Credentials  []uint16
}

func (c *Capabilities) lists() []*[]uint16 {
	return []*[]uint16{&c.Versions, &c.CipherSuites, &c.Extensions, &c.Proposals, &c.Credentials}
}

func (c *Capabilities) write(w *tls.Writer) {
	for _, l := range c.lists() {
		w.Vector(func(w *tls.Writer) {
			for _, v := range *l {
				w.U16(v)
			}
		})
	}
}

func readCapabilities(r *tls.Reader) (Capabilities, error) {
	var c Capabilities
	for _, l := range c.lists() {
		err := r.Vector(func(r *tls.Reader) error {
			v, err := r.U16()
			*l = append(*l, v)
			return err
		})
		if err != nil {
			return c, err
		}
	}
	return c, nil
}

// LeafNodeSource values (RFC 9420 section 7.2).
const (
	SourceKeyPackage uint8 = 1
	SourceUpdate     uint8 = 2
	SourceCommit     uint8 = 3
)

// LeafNode is an MLS LeafNode (RFC 9420 section 7.2). NotBefore and NotAfter
// are set for source key_package; ParentHash for source commit.
type LeafNode struct {
	EncryptionKey []byte
	SignatureKey  []byte
	Credential    Credential
	Capabilities  Capabilities
	Source        uint8
	NotBefore     uint64
	NotAfter      uint64
	ParentHash    []byte
	Extensions    []tls.Extension
	Signature     []byte
}

func (n *LeafNode) writeContent(w *tls.Writer) {
	w.Opaque(n.EncryptionKey)
	w.Opaque(n.SignatureKey)
	n.Credential.write(w)
	n.Capabilities.write(w)
	w.U8(n.Source)
	switch n.Source {
	case SourceKeyPackage:
		w.U64(n.NotBefore)
		w.U64(n.NotAfter)
	case SourceCommit:
		w.Opaque(n.ParentHash)
	}
	tls.WriteExtensions(w, n.Extensions)
}

// Write appends the encoding of n to w.
func (n *LeafNode) Write(w *tls.Writer) {
	n.writeContent(w)
	w.Opaque(n.Signature)
}

// ReadLeafNode reads a LeafNode.
func ReadLeafNode(r *tls.Reader) (*LeafNode, error) {
	var n LeafNode
	var err error
	if n.EncryptionKey, err = r.Opaque(); err != nil {
		return nil, err
	}
	if n.SignatureKey, err = r.Opaque(); err != nil {
		return nil, err
	}
	if n.Credential, err = readCredential(r); err != nil {
		return nil, err
	}
	if n.Capabilities, err = readCapabilities(r); err != nil {
		return nil, err
	}
	if n.Source, err = r.U8(); err != nil {
		return nil, err
	}
	switch n.Source {
	case SourceKeyPackage:
		if n.NotBefore, err = r.U64(); err != nil {
			return nil, err
		}
		if n.NotAfter, err = r.U64(); err != nil {
			return nil, err
		}
	case SourceUpdate:
	case SourceCommit:
		if n.ParentHash, err = r.Opaque(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: leaf_node_source %d", errs.ErrMalformed, n.Source)
	}
	if n.Extensions, err = tls.ReadExtensions(r); err != nil {
		return nil, err
	}
	if n.Signature, err = r.Opaque(); err != nil {
		return nil, err
	}
	return &n, nil
}

// tbs returns LeafNodeTBS; update and commit leaves bind the group and the
// leaf index (RFC 9420 section 7.2).
func (n *LeafNode) tbs(groupID []byte, leaf uint32) ([]byte, error) {
	var w tls.Writer
	n.writeContent(&w)
	if n.Source == SourceUpdate || n.Source == SourceCommit {
		w.Opaque(groupID)
		w.U32(leaf)
	}
	return w.Bytes()
}

// Sign sets the signature of n for the group and leaf index.
func (n *LeafNode) Sign(priv ed25519.PrivateKey, groupID []byte, leaf uint32) error {
	tbs, err := n.tbs(groupID, leaf)
	if err != nil {
		return err
	}
	sig, err := suite.SignWithLabel(priv, "LeafNodeTBS", tbs)
	if err != nil {
		return err
	}
	n.Signature = sig
	return nil
}

// VerifySignature reports whether the signature of n is valid with its
// signature_key for the group and leaf index.
func (n *LeafNode) VerifySignature(groupID []byte, leaf uint32) bool {
	tbs, err := n.tbs(groupID, leaf)
	if err != nil {
		return false
	}
	return suite.VerifyWithLabel(n.SignatureKey, "LeafNodeTBS", tbs, n.Signature)
}

// Clone returns a copy of n that shares no slice with it.
func (n *LeafNode) Clone() *LeafNode {
	c := *n
	c.EncryptionKey = bytes.Clone(n.EncryptionKey)
	c.SignatureKey = bytes.Clone(n.SignatureKey)
	c.Credential.Identity = bytes.Clone(n.Credential.Identity)
	c.Credential.Certificates = bytes.Clone(n.Credential.Certificates)
	caps, nc := c.Capabilities.lists(), n.Capabilities.lists()
	for i := range caps {
		*caps[i] = slices.Clone(*nc[i])
	}
	c.ParentHash = bytes.Clone(n.ParentHash)
	c.Extensions = nil
	for _, e := range n.Extensions {
		c.Extensions = append(c.Extensions, tls.Extension{Type: e.Type, Data: bytes.Clone(e.Data)})
	}
	c.Signature = bytes.Clone(n.Signature)
	return &c
}
