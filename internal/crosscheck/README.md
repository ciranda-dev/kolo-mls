# internal/crosscheck

The kolo-mls side of the interoperability cross-check (stage 6): a driver
that answers the operations of the IETF MLS working group's interop client
interface for kolo-mls, cipher suite 0x0001, basic credentials, and no rule
beyond RFC 9420. The other implementations, the working group's test
runner, the RPC front end and the scripts that build and run them live in a
throwaway directory outside this repository; their names, pinned versions,
checksums and URLs are in the Kolo roadmap notes
(`kolo-roadmap/design-mls/stage6-crosscheck.md`), not here.

## Driver

```sh
GOWORK=off go build -o /tmp/kolo-driver ./internal/crosscheck/driver
```

The driver reads one JSON object per line on standard input,
`{"id":1,"method":"CreateGroup","params":{...}}`, and writes
`{"id":1,"result":{...}}` or `{"id":1,"error":"..."}`. Methods and field
names are those of the interop interface (`CreateGroup`, `CreateKeyPackage`,
`JoinGroup`, `StateAuth`, `Export`, `Protect`, `Unprotect`, `StorePSK`, the
proposal methods, `Commit`, `HandleCommit`, `HandlePendingCommit`,
`CreateBranch`, `HandleBranch`, `Free`), with bytes as base64. One extra
method, `GroupState`, returns the encoded GroupContext and ratchet tree for
the comparisons. External joins, reinitialization and external senders are
out of scope and answer `unsupported operation`.

Settings every member uses (RFC 9420 leaves them to the application):
a maximum leaf lifetime of 365 days and one hour, the longest default
KeyPackage lifetime among the implementations compared; 32 past resumption
PSKs; handshakes as PrivateMessage when `encrypt_handshake` is set. A branch
joiner checks that every member of the new group is a member of the old one
(RFC 9420 section 11.3).

## Tests

All tests skip unless `KOLO_MLS_CROSSCHECK=1`.

```sh
KOLO_MLS_CROSSCHECK=1 GOWORK=off go test -run 'TestScenario|TestServe' ./internal/crosscheck/
```

`TestScenario` runs every in-scope operation between two driver clients in
both handshake modes. `TestServe` checks the line protocol.

```sh
KOLO_MLS_CROSSCHECK=1 KOLO_MLS_CROSSCHECK_DIR=/path/to/throwaway \
  GOWORK=off go test -run TestPeers -v ./internal/crosscheck/
```

`TestPeers` builds the driver and runs the throwaway directory's
`run-pairwise.sh` with it: groups of 2, 3, 5, 17, 100 and 256 members whose
members alternate between kolo-mls and one other implementation, and the
two other implementations together as the control, both handshake modes,
both creators. It needs that directory built (its `run-all.sh`).
