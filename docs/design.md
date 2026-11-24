# Design

Status: experimental; the API may change before v1.0.0. The core is the root package `kolomls`, and the Kolo layer is the packages `cred`, `settle`, `braid` and `backendstore`. This page summarizes the design so that readers know what the library is, and what it is not.

## What it is for

A group of people, on several devices each, needs to read the group's messages while they are members and to stop reading new ones once they are removed. kolo-mls gives Kolo that by implementing the Messaging Layer Security protocol (RFC 9420, with the architecture in RFC 9750).

## Why MLS

The history of a group is a chain of epochs. Each new epoch starts with a commit that gives fresh secrets only to the members of that epoch, so a removed member cannot compute the secrets of any later epoch. The cost of a commit grows with the logarithm of the group size, not with its size, which is what makes large groups practical.

## How it is built

- We write it ourselves from the RFC, on the Go standard library only: `crypto/hpke`, `crypto/ecdh`, `crypto/hkdf`, `crypto/ed25519`, `crypto/aes`, `crypto/cipher`, `crypto/sha256` and `crypto/hmac`. No new primitive, no cgo, no native dependency, so it builds wherever Go 1.26 builds.
- Cipher suite 0x0001 is the only one implemented: DHKEM(X25519, HKDF-SHA256), AES-128-GCM, SHA-256 and Ed25519.
- MLS messages use the RFC's own wire format. This is an approved exception to the rule that Kolo's network formats use kolo-codec: the official test vectors and other implementations require the RFC encoding. Kolo's own envelopes around MLS messages use kolo-codec.
- Key packages, their leaves and welcomes carry random GREASE values (RFC 9420 section 13.5), so peers that refuse unknown values show up early; unknown values received are ignored where section 13.4 says so.
- Some implementations refuse a GREASE extension in a leaf, a KeyPackage or a GroupInfo, contrary to RFC 9420 sections 13.4, 13.5 and 17.3; kolo-mls follows the RFC.
- Correctness is shown, not claimed: every official test vector file of the MLS working group must pass; the library is cross-checked against independent implementations in a throwaway setup; every decoder is fuzzed; every validation rule has a test that fails when the rule is removed.
- A release is made only after the internal security review rounds of the project have nothing open, with every finding fixed; there has been no external audit.

## Message keys

- In Kolo groups proposals, commits and application messages all travel encrypted (MLS PrivateMessage). The core can also send proposals and commits in the clear (PublicMessage), as the RFC allows; application data is always encrypted.
- A received message uses up its key only after its signature checks out. A member can build a valid ciphertext under another member's key, since every member derives every key of the epoch, but cannot sign as that member. A commit keeps its key until it is applied, so a device that stops in between can read the commit again.
- Kolo binds the message's generation into the signed part of each encrypted message, so an insider cannot replay another member's signed message under a later generation and use up that generation (RFC 9750 section 8.6). The core leaves this binding to the application, and Kolo groups always set it: without it, that replay works.
- Each key is deleted in the same storage write that records it as used, and an epoch's keys are deleted with the epoch, except that the previous epoch stays readable for 10 seconds after a commit, for late application messages of members that stay. The application's clock ends that window: the library has no timers. A receiver keeps a window of 5 generations per sender, the newest one read included, so a message may arrive up to 4 generations behind the newest; one message may move a sender at most 1,000 generations ahead. Both are configurable up to 65,536.
- If a storage write fails, the group refuses every call until it is opened again from storage, since the write may have happened.
- Encrypted messages are padded to the Padmé length, at most about 12% longer.
- A member that holds proposals commits them before it sends application data (RFC 9420 section 12.4).

## Identity

- One device is one leaf of the group's tree.
- The credential is a Kolo credential: the kolo-id device certificate chain plus the device's signature over the leaf's MLS signature key, under the context `kolo-mls/leaf-key/v0`. The device key never signs MLS bytes itself; each leaf has its own MLS signature key.
- The leaf check verifies the certificate chain for the person the certificate names, and then the application decides whether that person may be here; with no such check of its own, any person is accepted (the admins chose to add the device and the settlers signed the commit).
- A new device of the same person joins as a new leaf. A revoked device is removed from the group by a commit. Removing a person removes every device of that person in one commit.

## One model for every group

The same rules apply to a group of three and a group of thirty thousand:

- The group's braid (kolo-braid) holds only the admin devices, and the settlers are among them. Ordinary members are never braid members.
- The settled order of the braid decides each epoch's one commit. The braid holds only a small reference to the commit (group, epoch and the hash of the commit bytes).
- Admins commit membership and group changes. A member commits only its own key update, and asks to leave with a proposal of its own removal, which an admin commits.
- A member applies a commit only with signatures from a quorum of settlers, under the context `kolo-mls/commit-settled/v0`. The settler set is carried inside the group itself, in a group context extension that only admins may change.
- The application sends the commit bytes, which carry their proposals by value, and the settler signatures (for example over kolo-gossip) and keeps them on pins, so that a device that was offline can catch up from them.
- A welcome for a new member is sent only after the settler signatures exist.

This signature scheme is Kolo's own design and is not in any RFC. It has been through internal security review rounds of the project, with every finding fixed; it has had no external audit.

## The Kolo layer

The rules above are built on the core in three parts, each with its own tests and fuzz targets: packages `cred`, `settle` and `braid`.

- Credential: type 0xF001 carries the device certificate and the device's signature over the leaf's MLS signature key, the cipher suite and the certificate's hash. The check verifies the chain for the person the certificate names, refuses a small-order signature key, and then asks the application's own check of that person. Only the admin that adds a device checks the certificate's expiry and its revocations; settlers check revocations against the braid's device roster as it stood right after the commit reference's settled position, whenever they read it, so they decide alike; a member that holds a revocation drops that device's messages but still applies settled commits. Every receiver accepts an expired certificate, as RFC 9420 section 5.3.2 recommends.
- Member side: the roles extension 0xF002 (the braid, the quorum rule, the admins and the settlers, in increasing key order), the commit rule, the envelope that binds each message's generation, and the settled commit. A member applies a commit only with signatures from a quorum of the epoch's settlers that are members, after it checked the group, epoch, braid, the context before, the commit's hash and the context the commit leads to. A member proposes only its own removal; only admins hold such a request, at most one per member, since a held proposal stops a device from sending until a commit (RFC 9420 section 12.4); an admin commits it by value, and a commit that names any proposal by reference is refused, so every device holds what a commit needs whatever proposals it read. A second settled commit for the epoch it left stops the member for good, also after a restart. Messages of the next epoch wait until its commit, the oldest dropped first past 16 MiB; a device that was away applies the settled commits and reads each epoch's archive one epoch at a time, in each sender's order, within 16 MiB of heap per pass, so an epoch of any size is read in passes; what it could not read is reported, never the epoch. Every read from pins asks for a bound, so hostile pins cannot hand a device more.
- Admin side: three small entries in the admins' braid, a commit reference, a vote and a signature share. Each epoch's commit is decided from the braid's settled order alone: the first reference not yet decided wins with a quorum q of accept votes, or loses with s - q + 1 reject votes, so the group goes on when settlers disagree about whether a commit was available. An admin's next reference counts only after its previous one was rejected, so one admin delays the group at most one fetch timeout at a time. A settler votes against a commit it could not fetch within a minute (on any fetch error). It accepts a change of the roles only when it names the braid's own admins, settler seats and quorum, and, since one admin can change the braid alone, only with its own application's approval when the change adds a settler, changes the quorum rule or drops an admin or settler that is not revoked; adding an admin or dropping a revoked device needs none. A settler that the commit removes checks the roles too, as its vote counts. Every entry carries its writer's device certificate, and the braid's apply rejects an entry whose writer the devices roster revokes at that entry's own position (the device's revocations and its issuer's), so a revoked admin or settler loses its references, votes and shares at one position for every peer, with no braid removal needed, and the decision stays a function of the settled order; an entry whose certificate is not the writer's leaf credential in the epoch does not count. A settler checks the leaves a commit brings against the roster right after the reference's settled position, read once per certificate and epoch. A settler records each vote, share and first failed fetch before it writes, so a restart never casts a different vote or resets the timeout, and once it signed for an epoch it never votes or signs again in it. After each commit an admin keeps the ratchet tree on pins, encrypted under a key exported from the new epoch for that admin's device, with the group id and epoch bound in, and deletes the previous epoch's tree unless a Welcome that is not used yet names it (the admin that made the Welcome marks it on pins until the application releases it).
- What this design does not stop: s - q + 1 settlers that vote against everything stop every commit, their own removal included (with four settlers under the majority rule, two); an admin whose reference is ordered first can win epochs with commits that change nothing, until another admin removes it from the braid; an admin can remove honest settlers from the braid and stall the group; with one or two settlers, a stolen settler device can stall the group until a new group is made.
- A member device needs only the core, kolo-id and kolo-codec. The admin side runs on kolo-braid, and the Store on a kolo-store backend; both bring kolo-store's on-disk backend, which builds with `CGO_ENABLED=0` (with cgo on it links a C compression library).
- When the settlers are lost for good, a settler of the last epoch starts a successor group whose first commit carries a branch key of that epoch (RFC 9420 section 11.3); a member joins it only when its creator was a settler of the old group, is not revoked as far as the member knows, and every device in it was a member there. The application lets a member accept a successor only once the old quorum is known to be lost.
- The library has no timers: the application calls the member's expiry of the previous epoch and the admin's step again at the times they return.

## History

- A person who joins a group later reads only the messages from the moment they joined. There is no history for them, and no history interface in the library.
- A person's own new device does get the history, by transfer from another device of the same person, outside MLS and over an authenticated, encrypted channel proven by the person's certificate chain. kolo-mls has no such transfer; a new device reads only from the moment it joins unless the application moves the history itself. If all of a person's devices are lost, the recovery phrase restores the identity, not the messages.
- Devices that were in the group but offline catch up from pins: they fetch the commits after their last epoch with their settler signatures, and the archived ciphertext of each epoch they belonged to, and move forward one epoch at a time.

## Idle devices

An idle device is never removed automatically. A device that is offline for a long time stays a member and catches up when it returns. The application can show an inactive devices list so that a person or an admin can remove a device by hand.

This has costs: a forgotten device keeps its old key in the tree and keeps receiving new secrets, so if it is stolen later its holder can read what was sent after its last update until it is removed; its disk keeps the secrets of its last epoch; and every commit of the group must stay available on pins for as long as the group lives.

## What the guarantee is

When someone is removed from a group, they can still read what was said while they were a member, because their device already received it. They cannot read anything sent after the removal reaches the group, even if they get hold of the encrypted copies. For a short time while the removal spreads (how long depends on how fast the settled commit reaches each device, and the library does not bound it), a device that has not yet seen it may still send a message the removed person can read; devices that have seen it wait. Someone who joins later reads only messages from the moment they joined. If one of your devices is stolen, remove it: from then on it reads nothing new. A device you stop using is not removed by itself: it stays in your groups and can read new messages when it comes back, so remove devices you no longer use from the inactive devices list. Keys are deleted after use, so a device that is later stolen cannot unlock old encrypted copies with the app's keys (a full copy of the disk may still hold deleted bytes; [security.md](security.md) says how far this goes). Kolo cannot take back what a person already saw, cannot stop a member from copying messages, and does not hide who is in a group from the other members.

## What MLS does not give

- No history for people who join later, and no way to read again what a device already consumed and deleted.
- No protection of what a removed member already has.
- No protection against a compromised authentication service. In Kolo that is the recovery phrase and the approver devices.
- No delivery guarantee: whoever carries the messages can delay or drop them.
- No protection against replay by insiders within an epoch, unless the application sets an `Envelope`, which binds each message's generation; Kolo groups set it.
- No built-in defense against a malicious commit that only some members can detect. A member that cannot follow a settled commit keeps its state and reports it; reporting is built, re-adding such members is not.
- No protection against denial of service.
- Group id, epoch and timing are visible on every message, and the transport shows which device sent it. Device linkability is accepted.
- Removal waits when fewer than a quorum of settlers are online. The docs advise at least two admin devices.

## With the other Kolo libraries

| Library | What it does with kolo-mls |
|---|---|
| kolo-id | Device certificates are the credentials of the leaves. |
| kolo-braid | Orders each epoch's commit through the admin devices. |
| kolo-gossip | Can carry commits, proposals, settler signatures and encrypted messages to every member device; not wired by kolo-mls. |
| kolo-pin | Keeps the commits and the archived ciphertext of each epoch for members who were offline. |
| kolo-invite | Not wired: the application delivers the Welcome. |
| kolo-store, kolo-kv | Can hold the group state; consumed secrets are deleted in the same write, and [security.md](security.md) says what a disk image can still reveal. |

## Plan

0. Read the RFCs in full and write the design note and the threat model: a removed member, a stolen device, a malicious admin, a malicious settler, a malicious carrier, a malformed commit, a long-offline device and a disk image.
1. Primitives and key schedule.
2. Tree and TreeKEM, with measurements of commit size and time at 64, 1,024, 10,000 and 100,000 members.
3. Messages, proposals, commits and welcomes.
4. Secret tree and application messages, with the deletion schedule.
5. Identity and the delivery design, tested with the same tests for three members and for hundreds.
6. Interoperation with independent implementations, long fuzz runs and mutation tests.
7. Security review rounds.
8. Docs and release.

Every stage ends with its official test vectors passing, fuzzing of every new decoder and review by the project reviewers. Sizes and times for very large groups are measured, not assumed; where no measurement exists, none is claimed.

## References

- [RFC 9420, The Messaging Layer Security (MLS) Protocol](https://www.rfc-editor.org/info/rfc9420) (Proposed Standard, July 2023). The protocol this library implements: framing, ratchet tree, TreeKEM, key schedule, proposals, commits, Welcome and the code points.
- [RFC 9750, The Messaging Layer Security (MLS) Architecture](https://www.rfc-editor.org/info/rfc9750) (Informational, April 2025). The roles of the Authentication Service and the Delivery Service and the security considerations that shape the design.
- [RFC 9180, Hybrid Public Key Encryption](https://www.rfc-editor.org/info/rfc9180) (Informational, February 2022). The HPKE scheme RFC 9420 uses to encrypt secrets to a member's key.
- [RFC 9846, The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/info/rfc9846), section 3, "Presentation Language" (Proposed Standard, July 2026; obsoletes RFC 8446). RFC 9420 was written against RFC 8446, whose section 3 defines the same language. The notation and encoding of every MLS structure.
- [MLS working group test vectors](https://github.com/mlswg/mls-implementations/tree/2034fe72e0c805a683ba76165660c834f2a8142a), repository `mlswg/mls-implementations` at commit `2034fe72e0c805a683ba76165660c834f2a8142a`. The official test vectors that must pass. The repository has no license file, so the vectors are fetched for testing and never copied into this repository.

Cipher suite: only 0x0001, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.

Wire format: MLS messages use the encoding of RFC 9420, not kolo-codec. This is an approved exception, because the official test vectors and other implementations require the RFC encoding. Kolo's own envelopes around MLS messages use kolo-codec.

Not implemented in v0.1: external commits, external proposals and ReInit. They are parsed and validated for syntax, and refused by policy with a typed error.
