// Command basic creates an MLS group of two members in memory: alice creates it,
// adds bob with his KeyPackage and a Welcome, and sends him one message.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	kolomls "github.com/ciranda-dev/kolo-mls"
)

// directory is a small Authentication Service: it accepts a basic credential
// only with the signature key registered for its identity.
type directory map[string]ed25519.PublicKey

func (d directory) Validate(c kolomls.Credential, signatureKey []byte, _ kolomls.Event) error {
	key, ok := d[string(c.Identity)]
	if c.Type != kolomls.CredentialBasic || !ok || !bytes.Equal(key, signatureKey) {
		return errors.New("basic: unknown identity or signature key")
	}
	return nil
}

func (d directory) Successor(prev, next kolomls.Credential) error {
	if !bytes.Equal(prev.Identity, next.Identity) {
		return errors.New("basic: identity changed")
	}
	return nil
}

func (d directory) ClientID(c kolomls.Credential) ([]byte, error) { return c.Identity, nil }

// generation binds the generation of each PrivateMessage into its signed
// authenticated data, so a member cannot replay another member's message
// under a later generation (RFC 9750 section 8.6). Kolo groups use
// settle.Envelope.
type generation struct{}

func (generation) Wrap(gen uint32, aad []byte) ([]byte, error) {
	return append(binary.BigEndian.AppendUint32(nil, gen), aad...), nil
}

func (generation) Unwrap(gen uint32, ad []byte) ([]byte, error) {
	if len(ad) < 4 || binary.BigEndian.Uint32(ad) != gen {
		return nil, errors.New("basic: authenticated data of another generation")
	}
	return ad[4:], nil
}

// rfcOnly adds no rule to those of RFC 9420.
type rfcOnly struct{}

func (rfcOnly) CheckProposal(kolomls.ProposalView) error { return nil }
func (rfcOnly) CheckCommit(kolomls.CommitView) error     { return nil }
func (rfcOnly) CheckJoin(kolomls.JoinView) error         { return nil }

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// keyPackage registers a new signature key for name in d, which binds a
// name to one key, and returns a KeyPackage whose private keys go in st.
func keyPackage(st kolomls.Store, d directory, name string) ([]byte, error) {
	if _, ok := d[name]; ok {
		return nil, fmt.Errorf("basic: %s is already registered", name)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	d[name] = pub
	c := kolomls.Credential{Type: kolomls.CredentialBasic, Identity: []byte(name)}
	return kolomls.NewKeyPackage(st, kolomls.KeyPackageOptions{Credential: c, SignatureKey: priv})
}

// config is the Config of the groups, with d as their Authentication
// Service.
func config(d directory) kolomls.Config {
	return kolomls.Config{Authenticator: d, Policy: rfcOnly{}, Envelope: generation{}}
}

func run(w io.Writer) error {
	d := directory{}
	cfg := config(d)
	aliceStore, bobStore := kolomls.NewMemStore(), kolomls.NewMemStore()

	aliceKP, err := keyPackage(aliceStore, d, "alice")
	if err != nil {
		return err
	}
	alice, err := kolomls.Create(aliceStore, kolomls.CreateOptions{Config: cfg, KeyPackage: aliceKP})
	if err != nil {
		return err
	}
	defer alice.Close()

	bobKP, err := keyPackage(bobStore, d, "bob")
	if err != nil {
		return err
	}
	pc, err := alice.Commit(kolomls.CommitOptions{Add: [][]byte{bobKP}})
	if err != nil {
		return err
	}
	tree, err := pc.RatchetTree()
	if err != nil {
		return err
	}
	if err := alice.ApplyPending(); err != nil {
		return err
	}
	bob, err := kolomls.Join(bobStore, pc.Welcome(), tree, kolomls.JoinOptions{Config: cfg})
	if err != nil {
		return err
	}
	defer bob.Close()

	msg, err := alice.Encrypt([]byte("hello, bob"), nil)
	if err != nil {
		return err
	}
	res, err := bob.Process(msg)
	if err != nil {
		return err
	}
	ea, err := alice.EpochAuthenticator()
	if err != nil {
		return err
	}
	eb, err := bob.EpochAuthenticator()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "bob read %q in epoch %d\n", res.Application, res.Epoch)
	fmt.Fprintf(w, "members: %d\n", len(bob.Tree().Members()))
	fmt.Fprintf(w, "same epoch authenticator: %t\n", bytes.Equal(ea, eb))
	return nil
}
