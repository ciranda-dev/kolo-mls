# Guide

How to use kolo-mls. The fragments use the real API; every error is returned and checked in a program (as [examples/basic](../examples/basic/main.go) does) and left out here.

## 1. Groups, epochs and the Store

A group is a chain of epochs. A Commit moves it to the next epoch and gives fresh secrets to the members of that epoch only. A `Group` is one member's view of it.

State lives in a `Store`, a key-value interface with an atomic, durable `Apply(Batch)`. Every change of a group is one batch, and each consumed secret is deleted in the batch that records the advance. Use `kolomls.NewMemStore()` for tests and examples, and `backendstore.New(backend, prefix)` for a kolo-store backend (no other user of the backend may write keys under the prefix).

```go
st := backendstore.New(backend, []byte("mls/"))
g, err := kolomls.Open(st, gid, cfg) // a stored group, after a restart
```

- A `Group` is not safe for concurrent use, and at most one `Group` per group id may be open on a Store. `Create`, `Join` and `Open` of one group id must not run at the same time, nor `Create` and `Join` that use one KeyPackage: each reads the KeyPackage's keys before the write that deletes them, so both would use one leaf key in two groups.
- If a write fails, the Group refuses every later call, since the write may have happened. Open the group again to read what the Store holds.
- `Close` zeroes the secrets in memory; later calls that use a secret return `ErrClosed`.

## 2. The Authentication Service

MLS does not say who a credential belongs to; your `Authenticator` does (RFC 9420 section 5.3.1, RFC 9750 section 6.5). It must answer the same on every member.

```go
type Authenticator interface {
	Validate(c Credential, signatureKey []byte, ev Event) error
	Successor(prev, next Credential) error
	ClientID(c Credential) ([]byte, error)
}
```

`Validate` checks the credential and that it binds the leaf's signature key, at the moment `ev` names (`EventKeyPackage`, `EventJoin`, `EventAdd`, `EventUpdate`, `EventCommitPath`). `Successor` says whether a member may replace one credential with another. `ClientID` says which leaves are the same client.

The examples/basic program uses a directory that binds each name to one signature key, with basic credentials. For Kolo groups use `cred.Authenticator`: it verifies the kolo-id certificate chain and the device's signature over the leaf key, and asks your `Expect(person, device, event)` whether that person may be here. `Expect` is where your application checks the person: nil, or an `Expect` that returns nil for everyone, accepts any person with a valid certificate chain.

```go
auth := &cred.Authenticator{Now: time.Now, Expect: func(person, device ed25519.PublicKey, ev kolomls.Event) error {
	if !invited(person) { // your list of the people of this group
		return errNotInvited
	}
	return nil
}}
```

## 3. KeyPackages and Create

A KeyPackage is what a client publishes so that others can add it. `NewKeyPackage` makes one and stores its private keys in the Store; the result is an encoded MLSMessage.

```go
c := kolomls.Credential{Type: kolomls.CredentialBasic, Identity: []byte("alice")}
kp, err := kolomls.NewKeyPackage(st, kolomls.KeyPackageOptions{Credential: c, SignatureKey: priv})
g, err := kolomls.Create(st, kolomls.CreateOptions{Config: cfg, KeyPackage: kp})
```

`Create` takes a KeyPackage made on the same Store, uses its leaf for the creator and deletes its private keys. A KeyPackage lives 84 days by default (`KeyPackageOptions.Lifetime`). `DeleteKeyPackage` removes the private keys of one that is not needed. A KeyPackage is used once: `Join` deletes it, and a second `Create` or `Join` with it returns `ErrKeyPackageNotFound`.

`Config` holds the Authenticator and the Policy (both required) and the bounds of [limits.md](limits.md).

## 4. Adding and removing

`Commit` makes a Commit and, when it adds members, their Welcome. The group does not change yet: the Commit is kept as a `PendingCommit`, since the Delivery Service decides which Commit of an epoch wins (RFC 9420 section 14).

```go
pc, err := g.Commit(kolomls.CommitOptions{Add: [][]byte{bobKP}})   // or Remove: []uint32{leaf}
tree, err := pc.RatchetTree() // the tree of the new epoch, before ApplyPending
err = g.ApplyPending()        // the Delivery Service chose this Commit
// err = g.DiscardPending()   // it chose another one
```

`pc.Commit()` is the message for the other members and `pc.Welcome()` the Welcome for the added ones. A pending Commit survives a restart: `g.Pending()` returns it after `Open`.

The joiner needs the ratchet tree. It comes from the `ratchet_tree` extension of the GroupInfo (set `CommitOptions.RatchetTree`), or out of band (RFC 9420 section 12.4.3.3) as the `ratchetTree` argument:

```go
bob, err := kolomls.Join(bobStore, pc.Welcome(), tree, kolomls.JoinOptions{Config: cfg})
```

`JoinOptions.MaxTreeBytes` bounds the tree (128 MiB by default). `JoinOptions.Tree` is a callback for a tree that is kept encrypted under a secret of the new epoch; it receives the epoch's exporter. `Join` checks every rule of RFC 9420 section 12.4.3.1, asks the Authenticator about every leaf and the Policy about the group, and deletes the KeyPackage it used.

`CommitOptions` also takes `PSKs`, `SetExtensions` with `Extensions`, `References` to cached proposals, `NoPath`, a new `Leaf` and `AuthenticatedData`. External commits, external proposals and ReInit are refused.

## 5. Receiving

`Process` verifies one message of the current epoch and returns a `Result`:

```go
res, err := g.Process(msg)
switch {
case res.Commit != nil:
	err = g.Apply(res.Commit) // or res.Commit.Discard()
case res.ProposalRef != nil:
	// a proposal now cached, named by res.ProposalRef
default:
	use(res.Application, res.AuthenticatedData)
}
```

A proposal is cached until the next Commit. `StagedCommit` tells what the Commit does (`Added`, `Removed`, `Leaves`, `Committer`, `RemovesSelf`) before `Apply`. A Commit that removes this member deletes the group's records: `Apply` returns nil, `Removed` reports true and every later call returns `ErrRemoved`.

A member that holds cached proposals must commit them before it sends application data: `Encrypt` returns `ErrPendingProposals` until it does (RFC 9420 section 12.4). `CachedProposals` lists their references, to put in `CommitOptions.References`; a Commit that names a proposal this member does not hold returns `ErrUnknownProposal`.

Proposals come from `ProposeAdd`, `ProposeRemove`, `ProposeUpdate`, `ProposePSK` and `ProposeGroupContextExtensions`; each returns the message to send.

## 6. Application messages

```go
msg, err := g.Encrypt([]byte("hello"), aad)
```

Handshakes (proposals and Commits) go as PrivateMessage when `Config.PrivateHandshakes` is set, and as PublicMessage otherwise; application data is always encrypted. Messages are padded to the Padme length.

- Envelope. A signature does not cover the generation of a PrivateMessage, so a member could replay another member's content under a later generation and use it up (RFC 9750 section 8.6). `Config.Envelope` binds the generation into the signed authenticated data; `settle.Envelope{}` is one, and examples/basic writes another in a few lines. With a nil Envelope the replay works, so set one.
- Out of order. A receiver keeps a window of `OutOfOrderTolerance` generations per sender (5), the newest read included, and accepts a message at most `MaxForwardDistance` generations ahead (1,000). Outside them `Process` returns `ErrTooOld` or `ErrTooFarAhead`; a generation read twice returns `ErrReplay`.
- Previous epoch. After a Commit is applied, application messages of the previous epoch stay readable for `PastEpochWindow` (10 seconds). The library has no timers: call `ExpirePastEpoch` and call it again at the time it returns.

```go
next, err := g.ExpirePastEpoch() // the zero time when no previous epoch is kept
```

Messages of other epochs return `ErrWrongEpoch` or `ErrFutureEpoch`; keeping a future message until its Commit arrives is the caller's job (`settle.Member` does it for Kolo groups).

## 7. Exporter and epoch authenticator

`Export(label, context, length)` derives a secret of the current epoch (RFC 9420 section 8.5), at most 8,160 bytes. `EpochAuthenticator` returns the value members compare out of band to check they share the epoch (section 8.7). The library gives no way to read the epoch's own secrets.

## 8. Policy

`Policy` holds your rules on top of RFC 9420 (section 12.2). It sees a copy of each proposal, Commit and Welcome before the core accepts it, and must decide the same on every member.

```go
type Policy interface {
	CheckProposal(v ProposalView) error
	CheckCommit(v CommitView) error
	CheckJoin(v JoinView) error
}
```

`ProposalView.Cached` and `FromSender` let a Policy bound the proposal cache. The core adds no bound of its own there.

## 9. Kolo groups

A Kolo group has admin devices and settler devices (the settlers are among the admins), and ordinary member devices. A member applies a Commit only with signatures from a quorum of settlers, so one admin cannot split the group. The roles live in a GroupContext extension (0xF002) that only admins change. The roles have no cap on admins or settlers; an application that wants one sets `settle.Limits.MaxAdmins` or `MaxSettlers` in its `Policy`.

Roles and creation:

```go
roles, err := settle.NewRoles(order.ID(), settle.Majority, admins, settlers, settle.Limits{})
exts, err := settle.GroupExtensions(roles)
cfg := settle.NewConfig(auth, &settle.Policy{}, time.Now)
cert, sig := ... // the device's certificate and a new MLS signature key
c, err := cred.New(device, cert, sig.Public().(ed25519.PublicKey))
kp, err := kolomls.NewKeyPackage(st, kolomls.KeyPackageOptions{Credential: c, SignatureKey: sig, Capabilities: settle.Capabilities()})
m, err := settle.CreateMember(st, kolomls.CreateOptions{Config: cfg, KeyPackage: kp, Extensions: exts}, settle.MemberOptions{})
```

The member loop of a device:

```go
res, err := m.Receive(msg)                 // application data and proposals; a next-epoch message waits (ErrBuffered)
results, err := m.ApplySettled(settled, commit) // a Commit with its SettledCommit, in epoch order
results, err = m.CatchUp(ctx, pins)        // after being away: settled Commits and each epoch's archive from pins
next, err := m.ExpirePastEpoch()
```

`CatchUp` reads each sender's archived messages of an epoch in the order sent, however many there are: the keys sort by hash, and a receiver keeps only a window of generations per sender, so `CatchUp` reads the sender data of each message first (`Group.PeekSender`, which uses up no key) and applies them by leaf and generation. An epoch of any size is read in passes within `MemberOptions.MaxCatchUpBytes` of heap (16 MiB by default; the Results it returns are not counted); a pass costs one read of every message of the epoch, so a smaller bound means more passes. Archived messages it could not read (a value that does not open, does not match its key or is past the bound, or a listing that pins got wrong) are counted in `ErrCatchUp`, never the epoch. A message of this device, one below a sender's ratchet head (read live before, or passed over) and handshakes are not reported.

`CatchUp` leaves the member in the last epoch only, so a caller that needs something each epoch holds, such as a key from `Export` or `EpochAuthenticator`, sets `MemberOptions.OnEpoch`: it is called with the member after each epoch `CatchUp` applies, in order, and an error from it stops `CatchUp` there and is returned wrapped (`errors.Is` finds it); the next `CatchUp` goes on from that epoch. It is not called for the epoch that removes the device, and it must not call `CatchUp` or `ApplySettled`. The epoch the member was in before `CatchUp` is not passed to it. `ApplySettled` and `Receive` do not call it.

`Member.AppliedLeaves` returns copies of the leaves that the Commit applied last added or replaced: the added devices' credentials and signature keys, and the committer's new leaf. A device that joins in epoch J cannot learn the credentials of devices that were added and removed before J: Commits are PrivateMessages, readable only with the keys of their epoch, and the ratchet tree it joins with holds only the leaves of J. So each device records what it needs of a leaf (for example the person and device of an author) in `OnEpoch` or right after `ApplySettled`, while the epoch is the current one; the value is not kept across `OpenMember`, and it holds public data only (no keys of the group). The committer reads the same leaves of its own Commit once `ApplySettled` applies it, and `Member.PendingLeaves` before.

`CatchUp` reads one SettledCommit for each epoch (`SettledKey`) and stops when pins hold none or it does not apply. An application whose epochs may have several admins' values for one epoch reads them itself and applies each epoch with `ApplySettled`, trying the next value when one fails.

`Pins` is the interface you implement over kolo-pin or any store: `Put`, `Get`, `Delete`, and `List(ctx, prefix, after, max)`, which returns up to `max` keys that start with `prefix` and sort after `after`, so a caller reads on from the last key until the list is empty. `settle.ObjectKey`, `SettledKey`, `TreeKey` and `ArchiveKey` name the values. Commits, SettledCommits and archived messages stay for the life of the group; the admins delete the encrypted trees they no longer need, as below.

A new device joins with the Welcome, the SettledCommit of its Commit and the epoch's encrypted tree:

```go
m, err := settle.JoinMember(st, welcome, settled, func(gid []byte, epoch uint64, max int) ([]byte, error) {
	return pins.Get(ctx, settle.TreeKey(gid, epoch), max)
}, kolomls.JoinOptions{Config: cfg}, settle.MemberOptions{})
```

The admin side runs on a kolo-braid braid whose apply function feeds the `braid.Index` and the devices roster:

```go
roster, err := devices.New([]byte("devices/"), nil)
idx := braid.NewIndex([]byte("mls/"), roster)
apply := func(tx *kolobraid.Tx, e *kolobraid.Entry) error {
	if ok, err := idx.Apply(tx, e); ok || err != nil {
		return err
	}
	_, err := roster.Apply(tx, e)
	return err
}
order := braid.NewBraidOrder(b, idx, roster) // b is the braid made with Options{Apply: apply}
admin, err := braid.NewAdmin(device, order, m, braid.Options{Pins: pins, Now: time.Now})
```

`NewAdmin` and `Step` return `braid.ErrRoster` for an order that is not the braid the group's roles name.

The admin loop:

```go
welcome, err := admin.Commit(ctx, kolomls.CommitOptions{Add: kps}) // writes the reference to the braid
ap, err := admin.Step(ctx) // vote, sign, assemble and apply what the settled order asks
// ap.Settled and ap.Commit go to the members; ap is nil until the epoch is decided
```

Call `Step` after each braid event and again at `admin.NextDeadline()`, which is the zero time while the settler waits for no Commit on pins. Each epoch's Commit is decided from the braid's settled order alone: the first reference not yet decided wins with a quorum of accept votes, or loses with enough reject votes. A settler votes against a Commit it could not fetch from pins within `braid.Options.FetchTimeout` (60 seconds), and against a reference to anything but a Commit, which it refuses before processing it. `ApproveRoles` is your decision on a roles change that adds a settler, changes the quorum or drops a device that is not revoked; nil refuses all of them. A Welcome is delivered only with the SettledCommit of its Commit. Each Commit that adds members marks its Welcome as unused on pins, which keeps the epoch's tree there; call `admin.ReleaseWelcome(ctx, epoch)`, with the epoch the Commit was sent in, once the Welcome is used or will not be (also when its Commit was not decided). `Step` keeps the new epoch's tree and deletes the previous one unless an unused Welcome names it, so pins hold the latest tree and those of unused Welcomes only.

When the settlers are lost for good, an admin starts a successor group with `Admin.Succeed`; a member accepts it only when its `settle.Policy.Predecessor` is set from `settle.PredecessorOf`, which the application does once the old quorum is known to be lost.

The caller contract is in [security.md](security.md).

## 10. Errors

Errors work with `errors.Is`, and every message starts with `kolomls:`. No message holds input bytes or a secret.

| Package | Sentinels |
|---|---|
| `kolomls` | `ErrMalformed`, `ErrTooLong`, `ErrInvalidArgument`, `ErrUnsupported`, `ErrDecrypt`, `ErrSignature`, `ErrMembershipTag`, `ErrConfirmationTag`, `ErrInvalidTree`, `ErrInvalidCommit`, `ErrInvalidLeaf`, `ErrInvalidKeyPackage`, `ErrInvalidProposal`, `ErrInvalidWelcome`, `ErrUnknownProposal`, `ErrPSKNotFound`, `ErrKeyPackageNotFound`, `ErrCredential`, `ErrPolicy`, `ErrWrongGroup`, `ErrWrongEpoch`, `ErrFutureEpoch`, `ErrTooFarAhead`, `ErrTooOld`, `ErrReplay`, `ErrGenerationExhausted`, `ErrPendingProposals`, `ErrPendingCommit`, `ErrRemoved`, `ErrNotFound`, `ErrStore`, `ErrGroupExists`, `ErrUnknownSender`, `ErrClosed` |
| `cred` | `ErrCredential` (wraps kolo-id's errors) |
| `settle` | `ErrNotSettled`, `ErrSettledMismatch`, `ErrEquivocation`, `ErrEnvelope`, `ErrRule`, `ErrRoles`, `ErrBuffered`, `ErrRevokedSender`, `ErrHalted`, `ErrCatchUp`, `ErrNotHeld`, `ErrMissing`, `ErrPinTooLarge`, `ErrSealedTree` |
| `braid` | `ErrRoster`, `ErrNotApproved`, `ErrDecision`, `ErrEntry` |

## 11. Formats and references

MLS messages use the RFC 9420 encoding; the Kolo credential, roles extension, braid entries, SettledCommit and sealed tree are described in the [README](../README.md#formats) and in [design.md](design.md). The references are:

- [RFC 9420](https://www.rfc-editor.org/info/rfc9420), The Messaging Layer Security (MLS) Protocol.
- [RFC 9750](https://www.rfc-editor.org/info/rfc9750), The Messaging Layer Security (MLS) Architecture.
