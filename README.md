# kolo-mls

Group end-to-end encryption by the MLS standard (RFC 9420).

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

kolo-mls encrypts the messages of a group so that only the current members can read them. When someone is removed, they cannot read what is sent after the removal reaches the group. It implements the Messaging Layer Security protocol ([RFC 9420](https://www.rfc-editor.org/info/rfc9420), with the architecture of [RFC 9750](https://www.rfc-editor.org/info/rfc9750)) for the mandatory cipher suite 0x0001 (X25519, AES-128-GCM, SHA-256, Ed25519), written on the Go standard library only: pure Go, no cgo, nothing to install.

The root package `kolomls` is the MLS core: groups, KeyPackages, Welcomes, proposals, Commits and application messages, with the state kept in a `Store` you provide. It checks no identity by itself: you give it an `Authenticator` and a `Policy`, as RFC 9750 asks of an application.

Kolo groups add four packages. `cred` is the credential of a [kolo-id](https://github.com/ciranda-dev/kolo-id) device, so every device is one member of the group. `settle` holds the rules of a member device: a Commit is applied only with signatures from a quorum of settlers. `braid` is the admins' side over [kolo-braid](https://github.com/ciranda-dev/kolo-braid), which decides each epoch's one Commit; the application carries the Commits (for example over [kolo-gossip](https://github.com/ciranda-dev/kolo-gossip)) and keeps them on pins. `backendstore` keeps groups in a [kolo-store](https://github.com/ciranda-dev/kolo-store) backend.

## Install

```sh
go get github.com/ciranda-dev/kolo-mls
```

The root package imports the standard library only. `cred`, `settle`, `braid` and `backendstore` also pull Kolo modules (kolo-id, kolo-codec, kolo-braid, kolo-store). Build with `CGO_ENABLED=0` for a binary with no C code; kolo-store's on-disk backend links a C zstd library when cgo is enabled.

## Quick start

Two members in memory: alice creates a group with a KeyPackage of her own, adds bob with his KeyPackage, the ratchet tree goes to him next to the Welcome, and she sends him one message. Credentials are basic and checked by a small directory that binds each name to one key, an envelope binds each message's generation into its authenticated data (RFC 9750 section 8.6), and no rule beyond RFC 9420 applies. Kolo groups use `cred`, `settle` and `braid` instead, as [docs/guide.md](docs/guide.md) shows. The program is [examples/basic](examples/basic/main.go); run it with `go run ./examples/basic` in a clone of this repository.

```go
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
```

```text
$ go run ./examples/basic
bob read "hello, bob" in epoch 1
members: 2
same epoch authenticator: true
```

## API

Root package `kolomls`:

| Symbol | What it does |
|---|---|
| `NewKeyPackage`, `DeleteKeyPackage` | Make a KeyPackage whose private keys go in the Store; delete an unused one |
| `Create`, `Join`, `Open`, `Group.Close` | Start a group from a KeyPackage, join with a Welcome, open a stored group, zero the secrets in memory |
| `Group.Commit`, `PendingCommit`, `ApplyPending`, `DiscardPending`, `Pending` | Make a Commit and its Welcome, keep it apart until the Delivery Service chooses, then apply or drop it |
| `Group.Process`, `Result`, `StagedCommit`, `Apply` | Verify a received message: cache a proposal, stage a Commit until `Apply`, or return application data |
| `ProposeAdd`, `ProposeRemove`, `ProposeUpdate`, `ProposePSK`, `ProposeGroupContextExtensions`, `CachedProposals` | Make proposals and list the cached ones, to commit by reference |
| `Encrypt`, `PeekSender`, `ExpirePastEpoch` | Protect application data; read the leaf and generation a message names, without using up a key; end the previous epoch's window and return when the next one ends |
| `Export`, `EpochAuthenticator`, `RatchetTree`, `PendingCommit.RatchetTree`, `Tree`, `TreeView` | Exporter secret, epoch authenticator, the encoded tree, and a read-only view of its leaves |
| `Store`, `Batch`, `MemStore`, `backendstore.New` | The atomic storage contract, an in-memory Store, a Store on a kolo-store backend |
| `Config`, `Authenticator`, `Policy`, `Envelope`, `PSKStore` | The parameters and the application's checks: credentials, rules, the generation envelope, pre-shared keys |

`cred`:

| Symbol | What it does |
|---|---|
| `New`, `Decode`, `Credential` | Make the credential of a device for a leaf's signature key; decode one |
| `Authenticator` | The kolomls `Authenticator` for Kolo credentials, with the application's person check, revocations and a clock |
| `Revoked`, `Binding` | Check a credential against revocations; the bytes the device signs for a leaf |

`settle` (a member device):

| Symbol | What it does |
|---|---|
| `NewConfig`, `Policy`, `Envelope`, `Capabilities` | The configuration, commit rule and envelope of a Kolo group |
| `Roles`, `NewRoles`, `GroupExtensions`, `RolesExtension` | The admins, settlers and quorum of a group, as a GroupContext extension (0xF002) |
| `CreateMember`, `JoinMember`, `OpenMember`, `Member` | Create, join or open a group as a device; `Member` wraps a Group |
| `Member.Receive`, `ApplySettled`, `CatchUp` | Read application data and proposals; apply a settled Commit; catch up from pins, each sender's messages in order |
| `Member.AppliedLeaves` | The credentials and signature keys of the leaves the last applied Commit added or replaced |
| `Settled`, `TBS`, `Share` | The SettledCommit and the settler signatures it holds |
| `Pins`, `SealTree`, `OpenTree` | What devices fetch from pins (put, get, delete, list in pages), and the ratchet tree encrypted for a joiner |
| `Member.Leave`, `SelfUpdate`, `BranchPSK`, `PredecessorOf` | A device's own removal request, key update and the successor group's branch key |

`braid` (an admin device):

| Symbol | What it does |
|---|---|
| `NewAdmin`, `Admin.Commit`, `Refer`, `Reference` | Run an admin, make a Commit and write its reference into the braid |
| `Admin.Step`, `NextDeadline` | Do what the settled order asks (vote, sign, assemble, apply) and say when to step again |
| `Admin.ReleaseWelcome` | Tell the admin a Welcome is used or dropped, so its tree can leave pins |
| `Admin.Succeed`, `SucceedOptions` | Start the successor group when the settlers are lost for good |
| `Order`, `NewBraidOrder`, `NewIndex` | The admins' braid as the Admin reads it, and the index its apply function keeps |
| `Decide`, `Decision`, `Sign`, `Assemble` | The decision of an epoch from the settled order, a settler's signature, the SettledCommit |

`backendstore`: `New` returns a `Store` on a kolo-store `Backend` under a key prefix.

Errors work with `errors.Is`; the root exports every sentinel of the core (`ErrDecrypt`, `ErrWrongEpoch`, `ErrPendingProposals`, ...) and each package has its own. Messages start with `kolomls:`.

## Formats

- MLS messages use the RFC 9420 wire format, not kolo-codec, so the official test vectors and other implementations apply. Only cipher suite 0x0001 is implemented; external commits, external proposals and ReInit are refused.
- The Kolo credential is type 0xF001: a kolo-id device certificate and the device's signature over the leaf's signature key, under the context `kolo-mls/leaf-key/v0`.
- The roles extension is type 0xF002: the braid's id, the quorum rule, the admins and the settlers.
- Braid entries, written in kolo-codec: a commit reference, a vote and a signature share, each with its writer's device certificate.
- A SettledCommit is the signed bytes (group, epoch, Commit hash, the contexts before and after, braid, reference position) and one signature per settler, under the context `kolo-mls/commit-settled/v0`.
- The sealed tree is the ratchet tree encrypted with AES-128-GCM under a key exported from the new epoch for one admin device, with the group id and epoch as additional data.

The design, the reasons and the references are in [docs/design.md](docs/design.md).

## Documentation

- [docs/guide.md](docs/guide.md): groups and the Store, the Authentication Service, KeyPackages, Commits and Welcomes, receiving, application messages, Kolo groups and errors.
- [docs/design.md](docs/design.md): the design, how the keys are handled and what MLS does not give.
- [docs/limits.md](docs/limits.md): every bound with its default, source and setting. Every bound is configurable; the defaults include an out-of-order window of 5, a forward distance of 1,000, a key package lifetime of 84 days, a previous epoch kept for 10 seconds, a joined tree of at most 128 MiB, a next-epoch buffer of 16 MiB and a catch-up heap bound of 16 MiB per pass.
- [docs/security.md](docs/security.md): what the library guarantees, what it expects of its caller, and how to report a vulnerability.
- [SECURITY.md](SECURITY.md): security policy.

## Status

Experimental. The API may change before v1.0.0.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
