# Security

What kolo-mls guarantees, what it does not, and what it expects of the program that uses it. The library is experimental: read [limits.md](limits.md) and [design.md](design.md) with this page.

## The guarantee

- When someone is removed from a group, they can still read what was said while they were a member, because their device already received it. They cannot read anything sent after the removal reaches the group, even if they get hold of the encrypted copies.
- While the removal spreads, a device that has not applied it yet may still send a message the removed person can read. How long that takes depends on how fast the settled Commit reaches each device; the library does not bound it.
- Someone who joins later reads only the messages from the moment they joined. There is no history for them and no history interface.
- A group changes only when a Commit is applied. In a Kolo group a device applies a Commit only with signatures from a quorum of the group's settler devices, so one admin device alone cannot split the group or change its members.
- If one of your devices is stolen, remove it: from then on it reads nothing new. A device you stop using is not removed by itself: it stays in the group and can read new messages when it comes back, so remove devices you no longer use.
- Keys are deleted after use, in the same write that records them as used (except the 4 older generations per sender kept for late messages and the previous epoch kept for 10 seconds), so a device that is stolen later cannot unlock old encrypted copies with the library's keys. A copy of the whole disk may still hold deleted bytes (see Key handling).
- A message uses up its key only after its signature checks out. With the Kolo envelope, a member cannot replay another member's signed message under a later generation to use that generation up.

The library does not take back what a person already saw, does not stop a member from copying messages, and does not hide who is in a group from the other members.

## What MLS does not give

- No history for people who join later, and no way to read again what a device already consumed and deleted.
- No protection of what a removed member already has.
- No protection against a compromised Authentication Service. In Kolo that is the recovery phrase and the approver devices of kolo-id.
- No delivery guarantee: whoever carries the messages can delay or drop them.
- No protection against replay by insiders within an epoch, unless the application sets an `Envelope`, as Kolo groups do.
- No defense against a malicious Commit that only some members can detect. A member that cannot follow a settled Commit keeps its state and reports `ErrSettledMismatch`.
- No protection against denial of service. Settlers that vote against everything stop every commit, and an admin can remove honest settlers from the braid and stall the group; with one or two settlers a stolen settler device can stall the group until a successor group is made.
- Group id, epoch and timing are visible on every message, and the transport shows which device sent it.
- Removal waits while fewer than a quorum of settlers are online. Keep at least two admin devices.

## What the library expects of its caller

- One `Group` (or `settle.Member`) per group id at a time on a Store, and never two copies of one device's state: two would write diverging secret trees. `Create`, `Join` and `Open` of one group id do not run at the same time.
- A `Store` whose `Apply` is atomic and durable, and safe for concurrent use when shared. A failed write makes the Group refuse every call until it is opened again.
- A clock. The Kolo layer refuses to run without one; the core falls back to the system clock. The library has no timers: call `ExpirePastEpoch` and `braid.Admin.Step` again at the times they return (`Admin.NextDeadline`).
- An `Authenticator` and a `Policy` that decide the same way on every member. Members that decide differently split the group (RFC 9750 section 6.5).
- Deliver Commits to `Process` in epoch order, one per epoch, and in a Kolo group only with their SettledCommit (`settle.Member.ApplySettled`).
- Deliver referenced proposals before the Commit that names them.
- Deliver a Welcome only after its Commit is settled and signed.
- Keep every message of a future epoch and deliver it again after catching up (`settle.Member` buffers within a bound).
- Keep every Commit and its SettledCommit on pins for the life of the group, and each epoch's archived messages while a member of that epoch may be behind. Pins also hold the encrypted tree of the latest epoch and of each epoch an unused Welcome names; call `braid.Admin.ReleaseWelcome` when a Welcome is used or dropped, or its tree stays.
- Call `ApplyPending` or `DiscardPending` once the Delivery Service has chosen the Commit for the epoch.
- In a Kolo group, run the member loop (`Receive`, `ApplySettled`, `CatchUp`, `ExpirePastEpoch`) on every device and the admin loop (`Step` after each braid event and at `NextDeadline`) on every admin device, and decide roles changes in `braid.Options.ApproveRoles`.

## Key handling

- Each consumed secret is deleted in the same atomic write that records the advance (RFC 9420 section 9.2). An epoch's keys are deleted with the epoch, except that the previous epoch stays readable for `PastEpochWindow` (10 seconds) for late application messages.
- No API returns an epoch secret. `Export` derives a secret for a label, and `EpochAuthenticator` returns the epoch authenticator. `Close` zeroes the secrets held in memory.
- Private keys, seeds and epoch secrets are never logged and never put in an error message.
- The Store holds private keys and epoch secrets as given, unencrypted; protecting the disk is up to the application.
- Deleting from disk is best effort: `backendstore` removes the keys in the batch, but backups, snapshots and freed blocks may keep their bytes. A disk image taken before a deletion holds what it held then.
- A device that stays idle keeps the secrets of its last epoch on disk.

## Reporting a vulnerability

Report it privately, as [SECURITY.md](../SECURITY.md) describes: open a private security advisory on GitHub, not a public issue.
