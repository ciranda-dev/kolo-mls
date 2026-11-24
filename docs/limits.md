# Limits

Every bound below is enforced by the code. Where a setting is named, zero means the default; what a negative value does (no bound, none kept, or refused) is in the doc comment of that setting, and the identity cache takes any value of zero or less as the default. The roles limits take zero or less as no cap. Sizes are checked before any allocation, and no allocation is sized from an untrusted length.

## Policy

- No unnecessary limits. The library does not cap the size of a group, the number of members per person or the number of groups.
- Only protective bounds. A bound exists only to stop a hostile or broken peer from making memory, CPU or disk grow without limit, or to keep a cryptographic counter from wrapping.
- Every bound is configurable, except the ones the format itself fixes.
- Every default has a written source: the RFC, a published specification, or a measurement we made. A default is never taken from memory and never set to what a test needs.

## Defaults

| Bound | Protects | Default | Source | Setting |
|---|---|---|---|---|
| Window of generations kept per sender, for out-of-order delivery | Memory, forward secrecy within an epoch | 5 per sender and kind of message, the newest generation read included, so 4 older ones stay readable | default of a published MLS implementation | `Config.OutOfOrderTolerance` |
| Ratchet steps forward for one message | CPU against a hostile generation number | 1,000 | default of the same implementation | `Config.MaxForwardDistance` |
| Largest window or forward distance that can be configured | CPU per received message | 65,536 | measured: one message that moves a ratchet that far and keeps every key costs about 0.15 s of CPU | fixed |
| Previous epoch kept for late messages | Forward secrecy against late delivery | 10 seconds after a commit is applied, the previous epoch only, for application messages of members that stay; the caller's clock ends the window | a published group media protocol keeps previous-epoch keys for 10 s | `Config.PastEpochWindow`; negative keeps none |
| Lifetime of a key package | Stale join keys | 84 days, starting one hour before creation for clock skew; leaves whose lifetime is longer than 84 days and one hour are refused | default of a published MLS implementation; RFC 9420 section 7.2 requires a maximum | `KeyPackageOptions.Lifetime` for a new key package, `Config.MaxLeafLifetime` for the bound a receiver checks |
| Update interval of an online device | Post-compromise security | None in the library (RFC 9420 section 3.2 gives one a day as an example); the application calls `SelfUpdate` | the example in RFC 9420 section 3.2 | the application's policy |
| Messages per sender per epoch | Nonce space | 2^32 - 1, the generation counter | RFC 9420 section 6.3.2 | fixed |
| Size of an MLS message | Memory, hostile input | Follows the carrier library | the carrier's own bound | the carrier's |
| Size of a welcome | Memory | Follows the carrier the application uses | the carrier's own bound | the carrier's |
| Ratchet tree bytes accepted when joining | Memory | 128 MiB | measured: a group of 100,000 members with large credentials needs about 83 MB, and the costliest hostile tree measured holds about 7 bytes of memory per byte received, so the default bounds a join near 0.9 GiB | `JoinOptions.MaxTreeBytes` |
| Resumption keys of past epochs kept | Forward secrecy of past epochs | None: only the current epoch's | RFC 9420 section 8.6 asks for a defined limit | `Config.ResumptionPSKs` |
| Proposals cached in an epoch | Memory | The core leaves the bound to the application's policy, which sees the number already cached and the sender's. Kolo groups cache only a member's own removal, at admins only, at most one per member and fewer than the group has members; Kolo commits carry their proposals by value | the Kolo commit rule | `Policy.CheckProposal` of the application's Policy |
| Kolo credential | Decoding | 581 bytes: the largest device certificate with its approver parent (514), its length, a version and the device's signature | the format's own maximum | fixed |
| Admins in a group's roles | Memory | None: a count past the keys the extension holds (32 bytes each) is refused, and the carrier bounds the extension | the format: 32 bytes per key | `settle.Policy.Limits.MaxAdmins`, an application's cap |
| Settlers in a group's roles | Memory | None, as for admins; signature work per commit is at most one check per settler | the format: 32 bytes per key | `settle.Policy.Limits.MaxSettlers`, an application's cap |
| Signatures in a settled commit | Signature work per commit | At most one per settler of the group's roles (those of the epoch just left too, for its evidence) | the format's own maximum | follows the settlers of the roles |
| Client identities cached | Memory | 524,288: more than the leaves of the largest tree a joiner accepts by default (the smallest Kolo leaf, measured at 471 bytes, gives at most 284,359 in 128 MiB); the cache is emptied when full | measured: the smallest Kolo leaf | `cred.Authenticator.MaxCached` |
| Messages of the next epoch kept for later | Memory | 16 MiB, oldest dropped first; later epochs are fetched again after catching up | the admins' braid bound on waiting entries | `settle.MemberOptions.MaxBufferedBytes`; negative keeps none |
| Heap held while reading one epoch's archive, and the size of one archived message | Memory | 16 MiB. It bounds the memory of a pass, not the epoch: a pass lists keys in pages and keeps the next messages in (leaf, generation) order, which costs a key (about 86 bytes of prefix, 64 of hash, 16 of string header) and two 40-byte index entries per message, a quarter more for allocator rounding, about 307 bytes, so 54,000 messages per pass at 16 MiB. An epoch with more is read in more passes, none skipped; each pass reads every message of the epoch. A value past the bound, one that does not match its key or does not open, and a listing that pins got wrong are reported with ErrCatchUp while the epoch is still applied. The Results returned are not counted | the admins' braid bound on waiting entries; measured: a pass over 200,000 archived messages in one epoch held 14.3 MB of live heap, under this bound (`TestCatchUpLargeEpoch`) | `settle.MemberOptions.MaxCatchUpBytes`; negative no bound |
| References of one admin | Liveness | One candidate at a time: an admin's next reference counts only after its previous one was rejected | the commit decision rule | fixed |
| Wait for a commit on pins before a settler votes against it | Liveness of the group | 60 seconds, on any fetch error; the caller's clock, kept across restarts | the message timeout of the stream layer the braid syncs on | `braid.Options.FetchTimeout`; a negative value is refused |
| Roster reads at a reference's position | CPU, storage | One per candidate leaf certificate and epoch, kept for the epoch: each read replays the braid from its last such read (kolo-braid SettledAt), and reads run one at a time | the braid's one replay at a time | fixed |
| Commit read from pins | Memory | 128 MiB, the tree bound: the KeyPackages a Commit adds become the tree's leaves | the tree bound | `settle.MemberOptions.MaxCommitBytes`; negative no bound |
| SettledCommit read from pins | Memory | 512 bytes plus 96 per settler of the group's roles | measured: the encoding of a SettledCommit | follows the settlers of the roles |
| Encrypted tree read from pins | Memory | The joiner's tree bound plus 48 bytes (the sealer's key and the AEAD tag), asked of pins before the blob is read | the tree bound | follows `JoinOptions.MaxTreeBytes` |

## Not limits

Group size, members per person and the number of groups are not limits of the library.

## Choices that are policy, not limits

- Idle devices are never removed automatically. An optional policy, off by default, can list or propose their removal after a period the group chooses.
- Commits are kept on pins for as long as the group lives, because no device is evicted for being idle.
- Encrypted trees are not: pins hold the latest epoch's tree and the trees that a Welcome not yet used names, and each admin deletes the others (`Pins.Delete`) when it applies the next epoch or when the application releases the Welcome (`braid.Admin.ReleaseWelcome`). A tree is 14.5 MB at 30,000 members, so one per epoch would not be kept for the life of the group.

- `settle.Member.AppliedLeaves` adds no bound: it holds copies of the leaves of one Commit, which is already bounded by `MaxCommitBytes`, and it is replaced by the next Commit.
- `settle.Member.CatchUp` reads one SettledCommit for each epoch. An application with several admins that may each hold a value for an epoch applies the epochs itself with `ApplySettled`.
- `settle.MemberOptions.OnEpoch` adds no bound: `CatchUp` calls it once per epoch it applies, so the work in it is the caller's, and the number of epochs is that of the Commits on pins.

## Clocks

The Kolo layer takes the application's clock and refuses to run without one. The core uses `Config.Now` for the lifetime of the leaves it sends and the previous-epoch window, and falls back to the system clock when it is not set. The library has no timers: the application calls the previous-epoch expiry (`Group.ExpirePastEpoch`, `settle.Member.ExpirePastEpoch`) and the admin's step (`braid.Admin.Step`, again at `Admin.NextDeadline`) at the times they return.
