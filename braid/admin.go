package braid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// DefaultFetchTimeout is how long a settler waits for a candidate Commit on
// pins before it votes reject: 60 s, the message timeout of the stream layer
// the braid syncs on.
const DefaultFetchTimeout = 60 * time.Second

var (
	// ErrRoster reports a roles change that does not match the braid's
	// settled admins, settlers and quorum.
	ErrRoster = errors.New("kolomls: roles do not match the braid")
	// ErrNotApproved reports a roles change that adds a settler, changes
	// the quorum rule or drops a device that is not revoked, without the
	// application's approval.
	ErrNotApproved = errors.New("kolomls: roles change not approved")
	// ErrDecision reports a settled order whose decision is not the one
	// this settler signed for the epoch.
	ErrDecision = errors.New("kolomls: decision differs from the signed one")
)

// Order is the admins' braid as an Admin uses it. The read methods read
// local state and do not block.
type Order interface {
	// ID returns the braid's group id, which the roles name.
	ID() [32]byte
	// Append writes body as this admin's next entry.
	Append(ctx context.Context, body []byte) error
	// Entries returns the settled kolo-mls entries of group gid and epoch
	// in the braid's order.
	Entries(gid []byte, epoch uint64) ([]Ref, []Vote, []Sig, error)
	// Own returns this admin's votes and shares of group gid and epoch in
	// the order, settled or not.
	Own(gid []byte, epoch uint64) ([]Vote, []Sig, error)
	// Revocations returns what voids cert in the settled roster.
	Revocations(cert *koloid.DeviceCert) ([]*koloid.Revocation, error)
	// RevocationsAt returns what voids cert in the roster right after the
	// settled entry at position.
	RevocationsAt(ctx context.Context, position uint64, cert *koloid.DeviceCert) ([]*koloid.Revocation, error)
	// Roster returns the settled admins and settler seats, each in
	// increasing order, and the settlers' quorum.
	Roster() (admins, settlers [][32]byte, q int, err error)
}

// Options are an Admin's choices.
type Options struct {
	// Pins keeps Commits, SettledCommits and trees; required.
	Pins settle.Pins
	// FetchTimeout is how long a settler waits for a candidate on pins;
	// zero means DefaultFetchTimeout, a negative value is refused.
	FetchTimeout time.Duration
	// Now is the clock of FetchTimeout; required.
	Now func() time.Time
	// ApproveRoles is this settler's application deciding a roles change
	// that adds a settler, changes the quorum rule or drops an admin or
	// settler that is not revoked; nil refuses every such change.
	ApproveRoles func(current, next *settle.Roles) bool
}

// Admin runs an admin device of a Kolo group over the admins' braid
// (docs/design.md, "The Kolo layer"). It is not safe for concurrent use.
type Admin struct {
	id *koloid.Identity
	b  Order
	m  *settle.Member
	o  Options

	gid []byte
	// epoch is the epoch Step last ran in; started is false before.
	epoch    uint64
	started  bool
	evidence map[[32]byte]bool
	// revsAt keeps the revocations read at a reference's position, by
	// position and certificate hash, for the current epoch.
	revsAt map[revKey][]*koloid.Revocation
}

type revKey struct {
	position uint64
	cert     [32]byte
}

// Applied is the epoch change an Admin made.
type Applied struct {
	// Epoch is the epoch the Commit was sent in.
	Epoch uint64
	// Settled and Commit are what members apply with ApplySettled.
	Settled, Commit []byte
	// Results are the kept messages of the new epoch, now read.
	Results []*kolomls.Result
}

// NewAdmin runs the admin device id, the device of m's own leaf, over b;
// votes and shares are recorded in m's Store before they are written.
func NewAdmin(id *koloid.Identity, b Order, m *settle.Member, o Options) (*Admin, error) {
	if id == nil || b == nil || m == nil || o.Pins == nil || o.Now == nil || o.FetchTimeout < 0 {
		return nil, fmt.Errorf("%w: an Admin needs an identity, an Order, a Member, Pins, a clock and a timeout not below zero", errs.ErrInvalidArgument)
	}
	d, err := m.Device()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(d[:], id.PublicKey()) {
		return nil, fmt.Errorf("%w: the identity is not the device of the own leaf", errs.ErrInvalidArgument)
	}
	roles, err := settle.RolesOf(m.Extensions(), m.Limits())
	if err != nil {
		return nil, err
	}
	if roles.Braid != b.ID() {
		return nil, fmt.Errorf("%w: the Order is not the braid the roles name", ErrRoster)
	}
	return &Admin{id: id, b: b, m: m, o: o, gid: m.GroupID(), evidence: map[[32]byte]bool{}, revsAt: map[revKey][]*koloid.Revocation{}}, nil
}

// Member returns the admin's Member.
func (a *Admin) Member() *settle.Member { return a.m }

func (a *Admin) timeout() time.Duration {
	if a.o.FetchTimeout == 0 {
		return DefaultFetchTimeout
	}
	return a.o.FetchTimeout
}

// Commit creates this admin's Commit of o, keeps it on pins and writes its
// reference. It returns the Welcome of the members it adds, to deliver with
// the SettledCommit once pins hold one for this Commit (RFC 9750 section
// 5.2.3). A failed write keeps the Commit pending: call Reference again.
func (a *Admin) Commit(ctx context.Context, o kolomls.CommitOptions) ([]byte, error) {
	if o.SetExtensions {
		if err := a.checkRoles(o.Extensions); err != nil {
			return nil, err
		}
	}
	pc, err := a.m.Commit(o)
	if err != nil {
		return nil, err
	}
	return pc.Welcome(), a.Reference(ctx)
}

// Reference writes the reference of this admin's pending Commit again; a
// second reference to one Commit counts once. A Commit that adds members
// first marks its Welcome as unused on pins, which keeps the tree it names
// there (ReleaseWelcome).
func (a *Admin) Reference(ctx context.Context) error {
	pc := a.m.Pending()
	if pc == nil {
		return errs.ErrPendingCommit
	}
	if len(pc.Welcome()) > 0 {
		if err := a.o.Pins.Put(ctx, a.welcomeKey(a.m.Epoch()), []byte{1}); err != nil {
			return err
		}
	}
	return a.refer(ctx, a.m.Epoch(), pc.Commit())
}

// welcomeKey is the key of the mark that the Welcome of this admin's Commit
// sent in epoch is unused.
func (a *Admin) welcomeKey(epoch uint64) string {
	return a.welcomePrefix(epoch) + hex.EncodeToString(a.id.PublicKey())
}

func (a *Admin) welcomePrefix(epoch uint64) string {
	return "kolo-mls/welcome/" + hex.EncodeToString(a.gid) + "/" + strconv.FormatUint(epoch, 10) + "/"
}

// ReleaseWelcome reports that the Welcome of this admin's Commit sent in
// epoch is used or will not be: the tree it names leaves pins unless it is
// the latest or another admin's unused Welcome names it. Call it for a Commit
// that was not decided too.
func (a *Admin) ReleaseWelcome(ctx context.Context, epoch uint64) error {
	if err := a.o.Pins.Delete(ctx, a.welcomeKey(epoch)); err != nil {
		return err
	}
	return a.dropTree(ctx, epoch+1)
}

// dropTree deletes the tree of epoch from pins unless it is the current
// epoch's or an unused Welcome of the Commit before it names it. Every admin
// keeps the tree of each epoch it applies, so one that applies the next epoch
// drops the previous one.
func (a *Admin) dropTree(ctx context.Context, epoch uint64) error {
	if epoch == 0 || epoch >= a.m.Epoch() {
		return nil
	}
	held, err := a.o.Pins.List(ctx, a.welcomePrefix(epoch-1), "", 1)
	if err != nil || len(held) > 0 {
		return err
	}
	return a.o.Pins.Delete(ctx, settle.TreeKey(a.gid, epoch))
}

// Refer keeps a member's own key update, an empty Commit with a path of the
// current epoch, on pins and writes its reference.
func (a *Admin) Refer(ctx context.Context, commit []byte) error {
	return a.refer(ctx, a.m.Epoch(), commit)
}

func (a *Admin) refer(ctx context.Context, epoch uint64, commit []byte) error {
	h, err := settle.PutObject(ctx, a.o.Pins, commit)
	if err != nil {
		return err
	}
	cert, err := a.ownCert()
	if err != nil {
		return err
	}
	return a.b.Append(ctx, refBody(cert, a.gid, epoch, h))
}

// checkRoles checks the GroupContext extensions a Commit leads to: changed
// roles must name the braid's settled admins, settler seats and quorum, and
// a change other than adding admins or dropping revoked devices needs the
// application's approval, since one admin can change the braid alone.
func (a *Admin) checkRoles(exts []kolomls.Extension) error {
	next, err := settle.RolesOf(exts, a.m.Limits())
	if err != nil {
		return err
	}
	cur, err := settle.RolesOf(a.m.Extensions(), a.m.Limits())
	if err != nil {
		return err
	}
	if bytes.Equal(next.Encode(), cur.Encode()) {
		return nil
	}
	admins, settlers, q, err := a.b.Roster()
	if err != nil {
		return err
	}
	if !slices.Equal(next.Admins, admins) || !slices.Equal(next.Settlers, settlers) || next.Q() != q {
		return ErrRoster
	}
	plain, err := a.mechanical(cur, next)
	if err != nil || plain {
		return err
	}
	if a.o.ApproveRoles != nil && a.o.ApproveRoles(cur, next) {
		return nil
	}
	return ErrNotApproved
}

// mechanical reports a roles change that only adds admins or drops devices
// the settled roster revokes.
func (a *Admin) mechanical(cur, next *settle.Roles) (bool, error) {
	if next.Quorum != cur.Quorum {
		return false, nil
	}
	for _, k := range next.Settlers {
		if !cur.Settler(k[:]) {
			return false, nil
		}
	}
	for _, k := range cur.Admins {
		if next.Admin(k[:]) && (next.Settler(k[:]) || !cur.Settler(k[:])) {
			continue
		}
		bad, err := a.revoked(k)
		if err != nil || !bad {
			return false, err
		}
	}
	return true, nil
}

func (a *Admin) revoked(d [32]byte) (bool, error) {
	t := a.m.Tree()
	for _, l := range t.Members() {
		n := t.Leaf(l)
		c, err := cred.Decode(n.Credential)
		if err != nil {
			return false, err
		}
		if [32]byte(c.Device()) != d {
			continue
		}
		revs, err := a.b.Revocations(c.Cert)
		if err != nil {
			return false, err
		}
		return cred.Revoked(n.Credential, revs) != nil, nil
	}
	return false, nil
}

// ownCert returns the encoded device certificate of this admin's own leaf,
// which its entries carry.
func (a *Admin) ownCert() ([]byte, error) {
	c, err := cred.Decode(a.m.Tree().Leaf(a.m.OwnLeaf()).Credential)
	if err != nil {
		return nil, err
	}
	return c.Cert.Encode(), nil
}

// leafCerts returns the SHA-256 of each member device's certificate in the
// epoch's tree.
func (a *Admin) leafCerts() (map[[32]byte][32]byte, error) {
	t := a.m.Tree()
	out := map[[32]byte][32]byte{}
	for _, l := range t.Members() {
		c, err := cred.Decode(t.Leaf(l).Credential)
		if err != nil {
			return nil, err
		}
		out[[32]byte(c.Device())] = sha256.Sum256(c.Cert.Encode())
	}
	return out, nil
}

// ofLeaves keeps the entries whose certificate is their writer's leaf
// credential in the epoch, a function of the epoch alone.
func ofLeaves(refs []Ref, votes []Vote, sigs []Sig, certs map[[32]byte][32]byte) ([]Ref, []Vote, []Sig) {
	ok := func(w, c [32]byte) bool {
		h, in := certs[w]
		return in && h == c
	}
	refs = slices.DeleteFunc(refs, func(x Ref) bool { return !ok(x.Writer, x.Cert) })
	votes = slices.DeleteFunc(votes, func(x Vote) bool { return !ok(x.Writer, x.Cert) })
	sigs = slices.DeleteFunc(sigs, func(x Sig) bool { return !ok(x.Writer, x.Cert) })
	return refs, votes, sigs
}

// Evidence returns the settlers this admin saw vote twice on one Commit or
// sign two TBS for one epoch, in key order.
func (a *Admin) Evidence() [][32]byte {
	return slices.SortedFunc(maps.Keys(a.evidence), func(x, y [32]byte) int { return bytes.Compare(x[:], y[:]) })
}

// recordKey names a record of this admin in the Store; each holds one
// epoch's, so a group has at most three.
func recordKey(gid []byte, name string) []byte {
	return []byte("s/" + hex.EncodeToString(gid) + "/" + name)
}

var recordNames = []string{"vote", "sig", "seen"}

func (a *Admin) enter(n uint64) error {
	if a.started && a.epoch == n {
		return nil
	}
	st := a.m.Store()
	var b kolomls.Batch
	for _, name := range recordNames {
		rec, err := st.Get(recordKey(a.gid, name))
		if errors.Is(err, errs.ErrNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: %w", errs.ErrStore, err)
		}
		if len(rec) < 8 || binary.BigEndian.Uint64(rec) < n {
			b.Delete = append(b.Delete, recordKey(a.gid, name))
		}
	}
	if len(b.Delete) > 0 {
		if err := st.Apply(b); err != nil {
			return fmt.Errorf("%w: %w", errs.ErrStore, err)
		}
	}
	clear(a.revsAt)
	a.epoch, a.started = n, true
	return nil
}

func (a *Admin) deleteRecords() error {
	var b kolomls.Batch
	for _, name := range recordNames {
		b.Delete = append(b.Delete, recordKey(a.gid, name))
	}
	if err := a.m.Store().Apply(b); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrStore, err)
	}
	return nil
}

// record returns the value of a record for epoch n, nil when it holds
// another epoch's.
func (a *Admin) record(name string, n uint64) ([]byte, error) {
	rec, err := a.m.Store().Get(recordKey(a.gid, name))
	if errors.Is(err, errs.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errs.ErrStore, err)
	}
	if len(rec) < 8 {
		return nil, fmt.Errorf("%w: %s record", errs.ErrMalformed, name)
	}
	if binary.BigEndian.Uint64(rec) != n {
		return nil, nil
	}
	return rec[8:], nil
}

func (a *Admin) putRecord(name string, n uint64, v []byte) error {
	rec := binary.BigEndian.AppendUint64(nil, n)
	if err := a.m.Store().Apply(kolomls.Batch{Put: []kolomls.KV{{Key: recordKey(a.gid, name), Value: append(rec, v...)}}}); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrStore, err)
	}
	return nil
}

// Step does what the braid's settled order asks of this admin in the current
// epoch (vote, sign, assemble and apply) and returns the change once applied.
// After an epoch change it keeps the new tree on pins and drops the previous
// one; if only that drop failed it returns the change with the error.
func (a *Admin) Step(ctx context.Context) (*Applied, error) {
	m := a.m
	if err := m.Halted(); err != nil {
		return nil, err
	}
	if m.Removed() {
		if err := a.deleteRecords(); err != nil {
			return nil, err
		}
		return nil, errs.ErrRemoved
	}
	n := m.Epoch()
	if err := a.enter(n); err != nil {
		return nil, err
	}
	r, err := a.round(n)
	if err != nil {
		return nil, err
	}
	roles, before, sigs, d := r.roles, r.before, r.sigs, r.d
	for _, k := range d.Equivocators {
		a.evidence[k] = true
	}
	// This admin's own Commit, once rejected, is dropped so it can commit
	// again.
	if pc := m.Pending(); pc != nil && slices.Contains(d.Rejected, sha256.Sum256(pc.Commit())) {
		if err := m.DiscardPending(); err != nil {
			return nil, err
		}
	}
	// A settler that signed for the epoch never signs or votes on anything
	// else in it.
	if rec, err := a.record("sig", n); err != nil {
		return nil, err
	} else if rec != nil {
		t, err := settle.DecodeTBS(rec)
		if err != nil {
			return nil, err
		}
		if d.Decided == nil || d.Decided.Commit != t.Commit || d.Decided.Position != t.RefPosition {
			return nil, fmt.Errorf("%w: epoch %d", ErrDecision, n)
		}
	}
	me := [32]byte(a.id.PublicKey())
	if d.Decided != nil {
		if roles.Settler(me[:]) {
			if err := a.share(ctx, n, d.Decided, before, roles); err != nil {
				return nil, err
			}
		}
		return a.assemble(ctx, n, d.Decided, sigs, before, roles)
	}
	if d.Candidate != nil && roles.Settler(me[:]) && !d.Voted[me] {
		return nil, a.vote(ctx, n, d.Candidate, before)
	}
	return nil, nil
}

// round is the settled state of an epoch as this admin reads it.
type round struct {
	roles  *settle.Roles
	before [32]byte
	sigs   []Sig
	d      Decision
}

// round reads the roles and the settled entries of the current epoch n and
// decides it over the entries of the epoch's leaves.
func (a *Admin) round(n uint64) (*round, error) {
	m := a.m
	roles, err := settle.RolesOf(m.Extensions(), m.Limits())
	if err != nil {
		return nil, err
	}
	if roles.Braid != a.b.ID() {
		return nil, fmt.Errorf("%w: the Order is not the braid the roles name", ErrRoster)
	}
	before := sha256.Sum256(m.GroupContext())
	refs, votes, sigs, err := a.b.Entries(a.gid, n)
	if err != nil {
		return nil, err
	}
	certs, err := a.leafCerts()
	if err != nil {
		return nil, err
	}
	refs, votes, sigs = ofLeaves(refs, votes, sigs, certs)
	return &round{roles: roles, before: before, sigs: sigs, d: Decide(refs, votes, roles, before)}, nil
}

// vote casts this settler's vote on the candidate once: recorded in the
// Store first, written again after a restart while the order lacks it.
func (a *Admin) vote(ctx context.Context, n uint64, cand *Ref, before [32]byte) error {
	rec, err := a.record("vote", n)
	if err != nil {
		return err
	}
	// The record holds one vote per Commit of the epoch: hash, accept, reason.
	recorded, err := readVotes(rec)
	if err != nil {
		return err
	}
	v, ok := recorded[cand.Commit]
	if !ok {
		accept, reason, decided, err := a.validate(ctx, n, cand)
		if err != nil || !decided {
			return err
		}
		v = Vote{Commit: cand.Commit, Accept: accept, Reason: reason}
		recorded[cand.Commit] = v
		if err := a.putRecord("vote", n, writeVotes(recorded)); err != nil {
			return err
		}
	}
	mine, _, err := a.b.Own(a.gid, n)
	if err != nil {
		return err
	}
	for _, m := range mine {
		if m.Commit == cand.Commit {
			return nil
		}
	}
	cert, err := a.ownCert()
	if err != nil {
		return err
	}
	return a.b.Append(ctx, voteBody(cert, a.gid, n, cand.Commit, before, v.Accept, v.Reason))
}

func readVotes(b []byte) (map[[32]byte]Vote, error) {
	out := map[[32]byte]Vote{}
	if len(b)%34 != 0 {
		return nil, fmt.Errorf("%w: vote record", errs.ErrMalformed)
	}
	for i := 0; i < len(b); i += 34 {
		h := [32]byte(b[i : i+32])
		out[h] = Vote{Commit: h, Accept: b[i+32] == 1, Reason: Reason(b[i+33])}
	}
	return out, nil
}

func writeVotes(vs map[[32]byte]Vote) []byte {
	var out []byte
	for h, v := range vs {
		a := byte(0)
		if v.Accept {
			a = 1
		}
		out = append(append(out, h[:]...), a, byte(v.Reason))
	}
	return out
}

// firstSight returns when this settler first saw candidate h fail to
// fetch, recording now when it is the first time; kept in the Store, so a
// restart keeps the clock.
func (a *Admin) firstSight(n uint64, h [32]byte) (time.Time, error) {
	rec, err := a.record("seen", n)
	if err != nil {
		return time.Time{}, err
	}
	if t, ok, err := seenAt(rec, h); err != nil || ok {
		return t, err
	}
	now := a.o.Now()
	rec = binary.BigEndian.AppendUint64(append(rec, h[:]...), uint64(now.UnixNano()))
	return now, a.putRecord("seen", n, rec)
}

// seenAt returns when candidate h first failed to fetch, from the seen
// record.
func seenAt(rec []byte, h [32]byte) (time.Time, bool, error) {
	if len(rec)%40 != 0 {
		return time.Time{}, false, fmt.Errorf("%w: seen record", errs.ErrMalformed)
	}
	for i := 0; i < len(rec); i += 40 {
		if [32]byte(rec[i:i+32]) == h {
			return time.Unix(0, int64(binary.BigEndian.Uint64(rec[i+32:]))), true, nil
		}
	}
	return time.Time{}, false, nil
}

// NextDeadline returns when the candidate this settler waits for on pins
// times out, the zero time when it waits for none; the caller calls Step
// then, also on an idle braid.
func (a *Admin) NextDeadline() (time.Time, error) {
	n := a.m.Epoch()
	seen, err := a.record("seen", n)
	if err != nil || seen == nil {
		return time.Time{}, err
	}
	r, err := a.round(n)
	if err != nil {
		return time.Time{}, err
	}
	// Only the candidate this settler has not voted on yet is awaited; its
	// vote is recorded before it is written.
	c := r.d.Candidate
	if c == nil {
		return time.Time{}, nil
	}
	rec, err := a.record("vote", n)
	if err != nil {
		return time.Time{}, err
	}
	recorded, err := readVotes(rec)
	if err != nil {
		return time.Time{}, err
	}
	if _, ok := recorded[c.Commit]; ok {
		return time.Time{}, nil
	}
	first, ok, err := seenAt(seen, c.Commit)
	if err != nil || !ok {
		return time.Time{}, err
	}
	return first.Add(a.timeout()), nil
}

// validate checks a candidate as a member of the epoch: its bytes on pins
// (within FetchTimeout), MLS processing with the Kolo Policy, no leaf it
// brings revoked, and a roles change that matches the braid. decided is
// false while the bytes are still awaited.
func (a *Admin) validate(ctx context.Context, n uint64, cand *Ref) (accept bool, reason Reason, decided bool, err error) {
	m := a.m
	if pc := m.Pending(); pc != nil && sha256.Sum256(pc.Commit()) == cand.Commit {
		bad, err := a.anyRevoked(ctx, cand.Position, m.PendingLeaves())
		if err != nil {
			return false, 0, false, err
		}
		if bad {
			return false, ReasonInvalid, true, nil
		}
		if err := a.contextRoles(pc.GroupContext()); err != nil {
			return false, ReasonInvalid, true, nil
		}
		return true, ReasonNone, true, nil
	}
	commit, err := a.fetch(ctx, cand)
	if err != nil {
		// Whatever failed (missing, a pin error, a pin that hangs), the
		// candidate is unavailable once the timeout passed.
		first, serr := a.firstSight(n, cand.Commit)
		if serr != nil {
			return false, 0, false, serr
		}
		if a.o.Now().Sub(first) < a.timeout() {
			return false, 0, false, nil
		}
		return false, ReasonUnavailable, true, nil
	}
	sc, err := m.Stage(commit)
	if err != nil {
		if errors.Is(err, errs.ErrStore) || errors.Is(err, errs.ErrClosed) {
			return false, 0, false, err
		}
		return false, ReasonInvalid, true, nil
	}
	defer sc.Discard()
	bad, err := a.anyRevoked(ctx, cand.Position, sc.Leaves())
	if err != nil {
		return false, 0, false, err
	}
	if bad {
		return false, ReasonInvalid, true, nil
	}
	// Also a settler that the Commit removes checks the roles it sets: its
	// accept counts toward q.
	if err := a.checkRoles(sc.Extensions()); err != nil {
		return false, ReasonInvalid, true, nil
	}
	return true, ReasonNone, true, nil
}

// anyRevoked reports whether the roster right after the reference's
// settled position revokes one of leaves (design 7.5); a leaf whose
// credential does not decode counts as revoked. Each answer is kept for the
// epoch, as every read replays the braid to that position.
func (a *Admin) anyRevoked(ctx context.Context, position uint64, leaves []*kolomls.LeafNode) (bool, error) {
	for _, n := range leaves {
		c, err := cred.Decode(n.Credential)
		if err != nil {
			return true, nil
		}
		k := revKey{position, sha256.Sum256(c.Cert.Encode())}
		revs, ok := a.revsAt[k]
		if !ok {
			if revs, err = a.b.RevocationsAt(ctx, position, c.Cert); err != nil {
				return false, err
			}
			a.revsAt[k] = revs
		}
		if cred.Revoked(n.Credential, revs) != nil {
			return true, nil
		}
	}
	return false, nil
}

func (a *Admin) contextRoles(ctx []byte) error {
	var gc *kolomls.GroupContext
	if err := tls.Decode(ctx, func(r *tls.Reader) (err error) {
		gc, err = schedule.ReadGroupContext(r)
		return err
	}); err != nil {
		return err
	}
	return a.checkRoles(gc.Extensions)
}

// fetch returns a referenced Commit from pins, within the fetch timeout of
// real time.
func (a *Admin) fetch(ctx context.Context, ref *Ref) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout())
	defer cancel()
	return settle.GetObject(ctx, a.o.Pins, ref.Commit, a.m.MaxCommitBytes())
}

// share signs the decided Commit once as a settler: the TBS is recorded in
// the Store first and the share written again while the order lacks it.
func (a *Admin) share(ctx context.Context, n uint64, dec *Ref, before [32]byte, roles *settle.Roles) error {
	rec, err := a.record("sig", n)
	if err != nil {
		return err
	}
	var t *settle.TBS
	if rec != nil {
		if t, err = settle.DecodeTBS(rec); err != nil {
			return err
		}
	} else {
		after, err := a.contextAfter(ctx, dec)
		if err != nil || after == nil {
			return err
		}
		t = &settle.TBS{GroupID: a.gid, Epoch: n, Commit: dec.Commit, ContextBefore: before, ContextAfter: sha256.Sum256(after), Braid: roles.Braid, RefPosition: dec.Position}
		if err := a.putRecord("sig", n, t.Encode()); err != nil {
			return err
		}
	}
	_, mine, err := a.b.Own(a.gid, n)
	if err != nil {
		return err
	}
	for _, s := range mine {
		if bytes.Equal(s.TBS.Encode(), t.Encode()) {
			return nil
		}
	}
	sig, err := Sign(a.id, t)
	if err != nil {
		return err
	}
	cert, err := a.ownCert()
	if err != nil {
		return err
	}
	return a.b.Append(ctx, sigBody(cert, t, sig))
}

// contextAfter returns the encoded GroupContext the decided Commit leads
// to, nil when it removes this admin, which then cannot sign.
func (a *Admin) contextAfter(ctx context.Context, dec *Ref) ([]byte, error) {
	m := a.m
	if pc := m.Pending(); pc != nil && sha256.Sum256(pc.Commit()) == dec.Commit {
		return pc.GroupContext(), nil
	}
	commit, err := a.fetch(ctx, dec)
	if err != nil {
		return nil, err
	}
	sc, err := m.Stage(commit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", settle.ErrSettledMismatch, err)
	}
	defer sc.Discard()
	if sc.RemovesSelf() {
		return nil, nil
	}
	return sc.GroupContext(), nil
}

// assemble builds the SettledCommit of the decided Commit once q settlers
// signed one TBS for it, keeps it on pins, applies it and serves the tree.
func (a *Admin) assemble(ctx context.Context, n uint64, dec *Ref, sigs []Sig, before [32]byte, roles *settle.Roles) (*Applied, error) {
	byTBS := map[string][]settle.Share{}
	tbs := map[string]settle.TBS{}
	signed := map[[32]byte]string{}
	for _, s := range sigs {
		t := s.TBS
		k := string(t.Encode())
		// A settler that signs two TBS for one epoch is evidence.
		if prev, ok := signed[s.Writer]; ok && prev != k && roles.Settler(s.Writer[:]) {
			a.evidence[s.Writer] = true
		}
		signed[s.Writer] = k
		if t.Commit != dec.Commit || t.RefPosition != dec.Position || t.ContextBefore != before || t.Braid != roles.Braid || t.Epoch != n || !bytes.Equal(t.GroupID, a.gid) {
			continue
		}
		byTBS[k] = append(byTBS[k], settle.Share{Signer: s.Writer, Signature: s.Signature})
		tbs[k] = t
	}
	var settled *settle.Settled
	for _, k := range slices.Sorted(maps.Keys(byTBS)) {
		t := tbs[k]
		s := Assemble(&t, byTBS[k], roles)
		if len(s.Shares) >= roles.Q() {
			settled = s
			break
		}
	}
	if settled == nil {
		return nil, nil
	}
	m := a.m
	var commit []byte
	if pc := m.Pending(); pc != nil && sha256.Sum256(pc.Commit()) == dec.Commit {
		commit = pc.Commit()
	} else {
		var err error
		if commit, err = a.fetch(ctx, dec); err != nil {
			return nil, err
		}
	}
	sb := settled.Encode()
	if err := a.o.Pins.Put(ctx, settle.SettledKey(a.gid, n), sb); err != nil {
		return nil, err
	}
	results, err := m.ApplySettled(sb, commit)
	if err != nil {
		return nil, err
	}
	applied := &Applied{Epoch: n, Settled: sb, Commit: commit, Results: results}
	if m.Removed() {
		return applied, nil
	}
	sealed, err := settle.SealTree(m)
	if err != nil {
		return nil, err
	}
	if err := a.o.Pins.Put(ctx, settle.TreeKey(a.gid, m.Epoch()), sealed); err != nil {
		return nil, err
	}
	return applied, a.dropTree(ctx, n)
}

// SucceedOptions are the parts of a successor group that its creator gives.
type SucceedOptions struct {
	// Create is the creator's group options, with Create.KeyPackage made on the
	// Store given to Succeed; its Extensions and Config.PSKs are set by Succeed
	// and must be empty.
	Create kolomls.CreateOptions
	// KeyPackages are the members' fresh KeyPackages.
	KeyPackages [][]byte
	// Member and Admin are the new group's options.
	Member settle.MemberOptions
	Admin  Options
}

// Succeed starts the successor of a's group once its settlers are lost for
// good (RFC 9420 section 11.3), under nb with this admin as its only admin
// and settler, on st. It returns the new Admin, whose Step settles the first
// Commit, and that Commit's Welcome.
func (a *Admin) Succeed(ctx context.Context, nb Order, st kolomls.Store, so SucceedOptions) (*Admin, []byte, error) {
	if so.Create.Extensions != nil || so.Create.Config.PSKs != nil {
		return nil, nil, fmt.Errorf("%w: Succeed sets the extensions and the PSKs", errs.ErrInvalidArgument)
	}
	old, err := settle.RolesOf(a.m.Extensions(), a.m.Limits())
	if err != nil {
		return nil, nil, err
	}
	psk, err := a.m.BranchPSK()
	if err != nil {
		return nil, nil, err
	}
	me := []ed25519.PublicKey{a.id.PublicKey()}
	roles, err := settle.NewRoles(nb.ID(), old.Quorum, me, me, a.m.Limits())
	if err != nil {
		return nil, nil, err
	}
	co := so.Create
	if co.Extensions, err = settle.GroupExtensions(roles); err != nil {
		return nil, nil, err
	}
	co.Config.PSKs = psk
	m, err := settle.CreateMember(st, co, so.Member)
	if err != nil {
		return nil, nil, err
	}
	na, err := NewAdmin(a.id, nb, m, so.Admin)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	welcome, err := na.Commit(ctx, kolomls.CommitOptions{Add: so.KeyPackages, PSKs: []*kolomls.PSKID{psk.ID()}})
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	// The old group's records are not needed again.
	if err := a.deleteRecords(); err != nil {
		return nil, nil, err
	}
	return na, welcome, nil
}
