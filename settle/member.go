package settle

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
)

// Default bounds of a Member: 16 MiB, the bound the admins' braid puts on
// entries that wait for an earlier one; a Commit at most the tree bound,
// since the KeyPackages it adds become the tree's leaves.
const (
	DefaultMaxBufferedBytes = 16 << 20
	DefaultMaxCatchUpBytes  = 16 << 20
	DefaultMaxCommitBytes   = kolomls.DefaultMaxTreeBytes
)

var (
	// ErrBuffered reports a message of the next epoch, kept until the
	// Commit that starts that epoch is applied.
	ErrBuffered = errors.New("kolomls: message of the next epoch kept for later")
	// ErrRevokedSender reports an application message of a leaf whose
	// certificate this device holds a revocation for; it is dropped.
	ErrRevokedSender = errors.New("kolomls: message of a revoked device dropped")
	// ErrHalted reports a Member that stopped on an equivocation; it stays
	// stopped after it is opened again.
	ErrHalted = errors.New("kolomls: member halted")
	// ErrCatchUp reports archived messages of an epoch that catch-up could
	// not read: a value past the bound, one that does not match its key or
	// does not open, or a listing that pins got wrong. The epoch is still
	// applied.
	ErrCatchUp = errors.New("kolomls: epoch archive refused")
	// ErrNotHeld reports a leave request received by a device that is not
	// an admin; it is dropped, as only admins commit it.
	ErrNotHeld = errors.New("kolomls: leave requests are held by admins only")
)

// MemberOptions are a Member's choices.
type MemberOptions struct {
	// MaxBufferedBytes bounds the next-epoch messages kept, the oldest
	// dropped first; zero means DefaultMaxBufferedBytes and a negative value
	// keeps none.
	MaxBufferedBytes int
	// MaxCatchUpBytes bounds the memory that reading one epoch's archive
	// holds, not the epoch: it sets the keys listed and indexed at a time
	// (the bytes of a key and of its index entry, at least one) and the
	// size of one message, and an epoch with more messages is read in
	// several passes. The Results CatchUp returns are not counted. Zero
	// means DefaultMaxCatchUpBytes and a negative value no bound.
	MaxCatchUpBytes int
	// OnEpoch is called by CatchUp after each epoch it applies, with the
	// Member in the new epoch, so the caller can read what only that epoch
	// holds (Export, EpochAuthenticator). An error stops CatchUp and is
	// returned wrapped. It is not called for the epoch that removes this
	// device, and it must not call CatchUp or ApplySettled. Nil does nothing.
	OnEpoch func(*Member) error
	// MaxCommitBytes bounds a Commit read from pins; zero means
	// DefaultMaxCommitBytes and a negative value no bound.
	MaxCommitBytes int
	// Revocations returns the revocations this device holds for device of
	// person: messages of such leaves are dropped and RevokedLeaves lists
	// them; settled Commits are still applied (RFC 9750 section 6.5).
	Revocations func(person, device ed25519.PublicKey) []*koloid.Revocation
}

// last is the epoch a Member left: its Commit and roles, to recognize a
// second settled Commit for it.
type last struct {
	epoch  uint64
	commit [32]byte
	roles  *Roles
}

// Member is one device's side of a Kolo group: it applies only settled
// Commits (docs/design.md, "The Kolo layer"). It is not safe for concurrent
// use.
type Member struct {
	st     kolomls.Store
	gid    []byte
	cfg    kolomls.Config
	auth   *cred.Authenticator
	policy *Policy
	o      MemberOptions
	g      *kolomls.Group

	devices  map[[32]byte]bool
	buffered [][]byte
	bufBytes int
	prev     *last
	applied  []*kolomls.LeafNode
	halted   error
}

func newMember(st kolomls.Store, cfg kolomls.Config, o MemberOptions) (*Member, error) {
	a, ok := cfg.Authenticator.(*cred.Authenticator)
	if !ok {
		return nil, fmt.Errorf("%w: a Kolo group needs the Kolo Authenticator", errs.ErrInvalidArgument)
	}
	p, ok := cfg.Policy.(*Policy)
	if !ok || p.auth != a {
		return nil, fmt.Errorf("%w: a Kolo group needs the Kolo Policy of NewConfig", errs.ErrInvalidArgument)
	}
	if !cfg.PrivateHandshakes || cfg.Envelope == nil || cfg.Now == nil {
		return nil, fmt.Errorf("%w: a Kolo group sends handshakes as PrivateMessage with the envelope and a clock", errs.ErrInvalidArgument)
	}
	return &Member{st: st, cfg: cfg, auth: a, policy: p, o: o}, nil
}

// OpenMember opens the stored group gid with a configuration made by
// NewConfig; a Member that halted is refused with ErrHalted.
func OpenMember(st kolomls.Store, gid []byte, cfg kolomls.Config, o MemberOptions) (*Member, error) {
	m, err := newMember(st, cfg, o)
	if err != nil {
		return nil, err
	}
	if m.g, err = kolomls.Open(st, gid, cfg); err != nil {
		return nil, err
	}
	m.gid = m.g.GroupID()
	if err := m.loadRecords(); err != nil {
		m.g.Close()
		return nil, err
	}
	if err := m.bind(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Member) bind() error {
	if m.g.Removed() {
		return nil
	}
	d, err := m.device()
	if err != nil {
		m.g.Close()
		return err
	}
	m.policy.self = &d
	return nil
}

// CreateMember creates a Kolo group; co.KeyPackage is made on st and
// co.Extensions must be GroupExtensions of the group's roles.
func CreateMember(st kolomls.Store, co kolomls.CreateOptions, mo MemberOptions) (*Member, error) {
	m, err := newMember(st, co.Config, mo)
	if err != nil {
		return nil, err
	}
	if _, err := checkGroupExtensions(co.Extensions, m.limits()); err != nil {
		return nil, err
	}
	if m.g, err = kolomls.Create(st, co); err != nil {
		return nil, err
	}
	m.gid = m.g.GroupID()
	if err := m.bind(); err != nil {
		return nil, err
	}
	return m, nil
}

// JoinMember joins with a Welcome and the SettledCommit of its Commit;
// sealedTree returns the epoch's encrypted tree (SealTree).
func JoinMember(st kolomls.Store, welcome, settled []byte, sealedTree func(gid []byte, epoch uint64, max int) ([]byte, error), o kolomls.JoinOptions, mo MemberOptions) (*Member, error) {
	m, err := newMember(st, o.Config, mo)
	if err != nil {
		return nil, err
	}
	s, err := DecodeSettled(settled, m.limits().MaxSettlers)
	if err != nil {
		return nil, err
	}
	pw := *m.policy
	pw.welcome = s
	o.Policy = &pw
	max := o.MaxTreeBytes
	if max == 0 {
		max = kolomls.DefaultMaxTreeBytes
	}
	o.Tree = func(export func(string, []byte, int) ([]byte, error)) ([]byte, error) {
		// The tree bound applies before decryption.
		bound := 0
		if max > 0 {
			bound = max + sealedOverhead
		}
		sealed, err := sealedTree(s.TBS.GroupID, s.TBS.Epoch+1, bound)
		if err != nil {
			return nil, err
		}
		if bound > 0 && len(sealed) > bound {
			return nil, fmt.Errorf("%w: encrypted tree of %d bytes", errs.ErrInvalidTree, len(sealed))
		}
		return OpenTree(export, s.TBS.GroupID, s.TBS.Epoch+1, sealed)
	}
	g, err := kolomls.Join(st, welcome, nil, o)
	if err != nil {
		return nil, err
	}
	m.gid = g.GroupID()
	g.Close()
	if m.g, err = kolomls.Open(st, m.gid, m.cfg); err != nil {
		return nil, err
	}
	if err := m.bind(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Member) limits() Limits { return m.policy.Limits }

// Limits returns the roles bounds of the group's Policy.
func (m *Member) Limits() Limits { return m.policy.Limits }

// Store returns the Store the group lives in.
func (m *Member) Store() kolomls.Store { return m.st }

// GroupID returns the group id.
func (m *Member) GroupID() []byte { return bytes.Clone(m.gid) }

// Epoch returns the current epoch.
func (m *Member) Epoch() uint64 { return m.g.Epoch() }

// OwnLeaf returns this device's leaf index.
func (m *Member) OwnLeaf() uint32 { return m.g.OwnLeaf() }

// Removed reports whether a settled Commit removed this device.
func (m *Member) Removed() bool { return m.g.Removed() }

// GroupContext returns the encoded GroupContext of the current epoch.
func (m *Member) GroupContext() []byte { return m.g.GroupContext() }

// Extensions returns the GroupContext extensions of the current epoch.
func (m *Member) Extensions() []kolomls.Extension { return m.g.Extensions() }

// Tree returns a read-only view of the current tree.
func (m *Member) Tree() kolomls.TreeView { return m.g.Tree() }

// EpochAuthenticator returns the epoch authenticator (RFC 9420 section 8.7).
func (m *Member) EpochAuthenticator() ([]byte, error) { return m.g.EpochAuthenticator() }

// Export derives an exported secret (RFC 9420 section 8.5).
func (m *Member) Export(label string, context []byte, length int) ([]byte, error) {
	return m.g.Export(label, context, length)
}

// Encrypt protects application data for the current epoch.
func (m *Member) Encrypt(data, aad []byte) ([]byte, error) {
	if m.halted != nil {
		return nil, m.halted
	}
	msg, err := m.g.Encrypt(data, aad)
	return msg, m.fix(err)
}

// Leave returns this device's proposal to remove itself; an admin commits
// the removal by value.
func (m *Member) Leave() ([]byte, error) {
	if m.halted != nil {
		return nil, m.halted
	}
	msg, err := m.g.ProposeRemove(m.g.OwnLeaf())
	return msg, m.fix(err)
}

// SelfUpdate makes this device's key update, an empty Commit with a path,
// kept pending until a settled Commit decides the epoch; an admin
// references it with Admin.Refer.
func (m *Member) SelfUpdate() ([]byte, error) {
	pc, err := m.Commit(kolomls.CommitOptions{})
	if err != nil {
		return nil, err
	}
	return pc.Commit(), nil
}

// Commit makes a pending Commit of o; Kolo Welcomes never carry the tree.
func (m *Member) Commit(o kolomls.CommitOptions) (*kolomls.PendingCommit, error) {
	if m.halted != nil {
		return nil, m.halted
	}
	if o.RatchetTree {
		return nil, fmt.Errorf("%w: a Kolo Welcome does not carry the tree", errs.ErrInvalidArgument)
	}
	pc, err := m.g.Commit(o)
	return pc, m.fix(err)
}

// Pending returns this device's pending Commit, nil when there is none.
func (m *Member) Pending() *kolomls.PendingCommit { return m.g.Pending() }

// DiscardPending drops this device's pending Commit.
func (m *Member) DiscardPending() error { return m.fix(m.g.DiscardPending()) }

// BranchPSK returns the branch PSK of the current epoch for a successor
// group (RFC 9420 section 11.3).
func (m *Member) BranchPSK() (*BranchPSK, error) {
	id, v, err := m.g.BranchPSK()
	if err != nil {
		return nil, err
	}
	return &BranchPSK{GroupID: id.GroupID, Epoch: id.Epoch, Value: v, id: id}, nil
}

// AppliedLeaves returns copies of the leaves that the Commit this Member
// applied last added or replaced, with their credentials and signature keys;
// it is nil before the first Commit and when that Commit removed this device.
// A Commit is a PrivateMessage, so these leaves can be read only while their
// epoch is the current one (in OnEpoch or right after ApplySettled) and are
// not kept across OpenMember.
func (m *Member) AppliedLeaves() []*kolomls.LeafNode {
	if m.applied == nil {
		return nil
	}
	out := make([]*kolomls.LeafNode, len(m.applied))
	for i, l := range m.applied {
		out[i] = l.Clone()
	}
	return out
}

// Stage processes a Commit without applying it, for a settler's check; the
// caller discards the result.
func (m *Member) Stage(commit []byte) (*kolomls.StagedCommit, error) {
	if m.halted != nil {
		return nil, m.halted
	}
	// Kolo handshakes are PrivateMessages, whose content_type is in the
	// clear (RFC 9420 section 6.3): anything else is refused before Process,
	// which would use up an application message's key or cache a proposal.
	if contentType(commit) != message.ContentCommit {
		return nil, fmt.Errorf("%w: not a Commit", errs.ErrInvalidArgument)
	}
	r, err := m.g.Process(commit)
	if err != nil {
		return nil, m.fix(err)
	}
	if r.Commit == nil {
		return nil, fmt.Errorf("%w: not a Commit", errs.ErrInvalidArgument)
	}
	return r.Commit, nil
}

// MaxCommitBytes returns the bound on a Commit read from pins.
func (m *Member) MaxCommitBytes() int {
	if m.o.MaxCommitBytes == 0 {
		return DefaultMaxCommitBytes
	}
	return m.o.MaxCommitBytes
}

// shareBound is the most signatures a SettledCommit may carry: the settlers
// of the current roles, or of the epoch just left, whose evidence is still read.
func (m *Member) shareBound() (int, error) {
	roles, err := RolesOf(m.g.Extensions(), m.limits())
	if err != nil {
		return 0, err
	}
	n := len(roles.Settlers)
	if m.prev != nil {
		n = max(n, len(m.prev.roles.Settlers))
	}
	return n, nil
}

// maxSettledBytes bounds an encoded SettledCommit of at most n shares: the
// signed bytes take under 512.
func maxSettledBytes(n int) int { return 512 + 96*n }

// PendingLeaves returns the leaves that this device's pending Commit adds
// or replaces.
func (m *Member) PendingLeaves() []*kolomls.LeafNode { return m.g.PendingLeaves() }

// Halted returns the error that stopped this Member for good, nil while it
// runs.
func (m *Member) Halted() error { return m.halted }

// ExpirePastEpoch deletes the previous epoch once its window ended and
// returns when the window still kept ends, the zero time when none is;
// the caller calls it again then.
func (m *Member) ExpirePastEpoch() (time.Time, error) {
	t, err := m.g.ExpirePastEpoch()
	return t, m.fix(err)
}

// Close closes the group.
func (m *Member) Close() { m.g.Close() }

func (m *Member) device() ([32]byte, error) {
	n := m.g.Tree().Leaf(m.g.OwnLeaf())
	if n == nil {
		return [32]byte{}, errs.ErrRemoved
	}
	d, err := m.auth.ClientID(n.Credential)
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(d), nil
}

// Device returns this device's key, as its own leaf names it.
func (m *Member) Device() ([32]byte, error) { return m.device() }

// fix opens the Group again when err says a write failed, and returns err.
func (m *Member) fix(err error) error {
	if errors.Is(err, errs.ErrStore) && !m.g.Removed() {
		gid := m.g.GroupID()
		m.g.Close()
		g, rerr := kolomls.Open(m.st, gid, m.cfg)
		if rerr != nil {
			return errors.Join(err, rerr)
		}
		m.g, m.devices = g, nil
	}
	return err
}

// leafDevices returns the device keys of the current leaves, cached for the
// epoch.
func (m *Member) leafDevices() (map[[32]byte]bool, error) {
	if m.devices != nil {
		return m.devices, nil
	}
	out := map[[32]byte]bool{}
	t := m.g.Tree()
	for _, leaf := range t.Members() {
		d, err := m.auth.ClientID(t.Leaf(leaf).Credential)
		if err != nil {
			return nil, err
		}
		out[[32]byte(d)] = true
	}
	m.devices = out
	return out, nil
}

// Receive processes an application message or a proposal. A message of the
// next epoch is kept (ErrBuffered) until ApplySettled starts that epoch; a
// Commit is refused.
func (m *Member) Receive(msg []byte) (*kolomls.Result, error) {
	if m.halted != nil {
		return nil, m.halted
	}
	r, err := m.g.Process(msg)
	if errors.Is(err, errs.ErrFutureEpoch) {
		return nil, m.buffer(msg)
	}
	if err != nil {
		return nil, m.fix(err)
	}
	if r.Commit != nil {
		r.Commit.Discard()
		return nil, fmt.Errorf("%w: a Commit is applied with its SettledCommit", ErrNotSettled)
	}
	if r.Application != nil && m.revoked(r.Sender) {
		return nil, ErrRevokedSender
	}
	return r, nil
}

// buffer keeps a message of the next epoch, dropping the oldest kept ones
// when the bound is reached: anyone can send bytes that look like the next
// epoch, and the newest are the likeliest to be real.
func (m *Member) buffer(msg []byte) error {
	max := m.o.MaxBufferedBytes
	if max == 0 {
		max = DefaultMaxBufferedBytes
	}
	if !m.nextEpoch(msg) || len(msg) > max {
		return errs.ErrFutureEpoch
	}
	for m.bufBytes+len(msg) > max {
		m.bufBytes -= len(m.buffered[0])
		m.buffered = m.buffered[1:]
	}
	m.buffered = append(m.buffered, bytes.Clone(msg))
	m.bufBytes += len(msg)
	return ErrBuffered
}

// nextEpoch reports whether msg is a message of the epoch after the current
// one: later ones are read from pins after catching up.
func (m *Member) nextEpoch(msg []byte) bool {
	e, ok := messageEpoch(msg)
	return ok && e == m.g.Epoch()+1
}

func (m *Member) revoked(l uint32) bool {
	if m.o.Revocations == nil {
		return false
	}
	n := m.g.Tree().Leaf(l)
	if n == nil {
		return false
	}
	c, err := cred.Decode(n.Credential)
	if err != nil {
		return false
	}
	return errors.Is(cred.Revoked(n.Credential, m.o.Revocations(c.Person(), c.Device())), koloid.ErrCertRevoked)
}

// RevokedLeaves returns the leaves this device holds a revocation for, so
// the application asks an admin to commit their removal.
func (m *Member) RevokedLeaves() []uint32 {
	var out []uint32
	for _, l := range m.g.Tree().Members() {
		if m.revoked(l) {
			out = append(out, l)
		}
	}
	return out
}

// ApplySettled applies the Commit that settled names for the current epoch
// (docs/design.md, "The Kolo layer") and returns the kept messages of the
// new epoch, now read.
func (m *Member) ApplySettled(settled, commit []byte) ([]*kolomls.Result, error) {
	n, err := m.shareBound()
	if err != nil {
		return nil, err
	}
	s, err := DecodeSettled(settled, n)
	if err != nil {
		return nil, err
	}
	return m.applySettled(s, commit)
}

func (m *Member) applySettled(s *Settled, commit []byte) ([]*kolomls.Result, error) {
	if m.halted != nil {
		return nil, m.halted
	}
	t := &s.TBS
	if !bytes.Equal(t.GroupID, m.gid) {
		return nil, fmt.Errorf("%w: another group", ErrNotSettled)
	}
	g := m.g
	if p := m.prev; p != nil && t.Epoch == p.epoch {
		// Evidence needs q signatures of that epoch's settlers.
		if t.Commit != p.commit && s.Valid(p.roles, func([32]byte) bool { return true }) >= p.roles.Q() {
			return nil, m.halt()
		}
		return nil, nil
	}
	// The epoch just left, with no record of it (a write lost before the
	// record): nothing to do.
	if t.Epoch+1 == g.Epoch() && m.prev == nil {
		return nil, nil
	}
	if t.Epoch < g.Epoch() {
		return nil, fmt.Errorf("%w: a SettledCommit of epoch %d", errs.ErrWrongEpoch, t.Epoch)
	}
	if t.Epoch > g.Epoch() {
		return nil, errs.ErrFutureEpoch
	}
	roles, err := RolesOf(g.Extensions(), m.limits())
	if err != nil {
		return nil, err
	}
	devices, err := m.leafDevices()
	if err != nil {
		return nil, err
	}
	if err := s.Check(g.GroupContext(), commit, m.gid, g.Epoch(), roles, func(d [32]byte) bool { return devices[d] }); err != nil {
		return nil, err
	}
	if err := m.applyChecked(s, commit); err != nil {
		return nil, err
	}
	m.devices = nil
	if m.g.Removed() {
		return nil, m.deleteRecords()
	}
	m.prev = &last{epoch: t.Epoch, commit: t.Commit, roles: roles}
	if err := m.putLast(); err != nil {
		return nil, err
	}
	return m.redeliver(), nil
}

func (m *Member) applyChecked(s *Settled, commit []byte) error {
	g := m.g
	if pc := g.Pending(); pc != nil {
		if sha256.Sum256(pc.Commit()) == s.TBS.Commit {
			if sha256.Sum256(pc.GroupContext()) != s.TBS.ContextAfter {
				return fmt.Errorf("%w: own Commit leads to another GroupContext", ErrSettledMismatch)
			}
			leaves := g.PendingLeaves()
			if err := m.fix(g.ApplyPending()); err != nil {
				return err
			}
			m.applied = leaves
			return nil
		}
		if err := g.DiscardPending(); err != nil {
			return m.fix(err)
		}
	}
	r, err := g.Process(commit)
	if err != nil {
		if errors.Is(err, errs.ErrUnknownProposal) || errors.Is(err, errs.ErrStore) || errors.Is(err, errs.ErrClosed) {
			return m.fix(err)
		}
		return fmt.Errorf("%w: %w", ErrSettledMismatch, err)
	}
	sc := r.Commit
	if sc == nil {
		return fmt.Errorf("%w: not a Commit", ErrSettledMismatch)
	}
	// A removed member cannot build the next GroupContext (RFC 9420 section
	// 12.4.2); the settler signatures are what it checked.
	if !sc.RemovesSelf() && sha256.Sum256(sc.GroupContext()) != s.TBS.ContextAfter {
		sc.Discard()
		return fmt.Errorf("%w: the Commit leads to another GroupContext", ErrSettledMismatch)
	}
	leaves := sc.Leaves()
	if err := m.fix(g.Apply(sc)); err != nil {
		return err
	}
	m.applied = leaves
	return nil
}

// redeliver processes the kept messages of the new epoch and returns what
// they gave; messages still ahead stay kept.
func (m *Member) redeliver() []*kolomls.Result {
	msgs := m.buffered
	m.buffered, m.bufBytes = nil, 0
	var out []*kolomls.Result
	for _, msg := range msgs {
		r, err := m.Receive(msg)
		if err == nil {
			out = append(out, r)
		}
	}
	return out
}

// CatchUp applies, one epoch at a time, the settled Commits pins hold after
// the current epoch, reading each epoch's archive before its Commit, each
// sender's messages in order; archived messages it could not read are
// reported with ErrCatchUp at the end. MemberOptions.OnEpoch is called after
// each epoch.
func (m *Member) CatchUp(ctx context.Context, pins Pins) ([]*kolomls.Result, error) {
	var out []*kolomls.Result
	var lost error
	for !m.g.Removed() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if pins == nil {
			return out, fmt.Errorf("%w: no Pins", errs.ErrInvalidArgument)
		}
		e := m.g.Epoch()
		n, err := m.shareBound()
		if err != nil {
			return out, err
		}
		sb, err := pins.Get(ctx, SettledKey(m.gid, e), maxSettledBytes(n))
		if errors.Is(err, ErrMissing) {
			return out, lost
		}
		if err != nil {
			return out, err
		}
		s, err := DecodeSettled(sb, n)
		if err != nil {
			return out, err
		}
		if s.TBS.Epoch != e || !bytes.Equal(s.TBS.GroupID, m.gid) {
			return out, fmt.Errorf("%w: pins hold another epoch's SettledCommit under epoch %d", ErrNotSettled, e)
		}
		// A hostile member can flood the archive, so a full archive costs
		// messages, never the epoch.
		rs, err := m.readArchive(ctx, pins, e)
		out = append(out, rs...)
		if errors.Is(err, ErrCatchUp) {
			lost = errors.Join(lost, err)
		} else if err != nil {
			return out, err
		}
		commit, err := GetObject(ctx, pins, s.TBS.Commit, m.MaxCommitBytes())
		if err != nil {
			return out, err
		}
		rs, err = m.applySettled(s, commit)
		out = append(out, rs...)
		if err != nil {
			return out, err
		}
		if m.g.Epoch() == e && !m.g.Removed() {
			return out, fmt.Errorf("%w: epoch %d did not advance", ErrNotSettled, e)
		}
		if m.o.OnEpoch != nil && !m.g.Removed() {
			if err := m.o.OnEpoch(m); err != nil {
				return out, fmt.Errorf("kolomls: OnEpoch at epoch %d: %w", m.g.Epoch(), err)
			}
		}
	}
	return out, lost
}

// archived is an archived application message named by its sender data;
// messages are read by leaf, then generation, then hash.
type archived struct {
	leaf, generation uint32
	hash             [32]byte
}

func (a archived) compare(b archived) int {
	return cmp.Or(cmp.Compare(a.leaf, b.leaf), cmp.Compare(a.generation, b.generation), bytes.Compare(a.hash[:], b.hash[:]))
}

// archivedSize is the bytes of an index entry and headerSize that of a
// string header. A pass holds n keys and up to 2n entries; each costs a
// quarter more than its size, for the allocator's size classes and the room
// append leaves.
const (
	archivedSize = 40
	headerSize   = 16
)

// readArchive reads the application messages archived in epoch e, each
// sender's in generation order, which the ratchet window needs (RFC 9420
// section 15.3), whatever order the keys sort in. Each pass lists the keys,
// indexes the next n messages in that order and reads them, so an epoch of
// any size is read in passes and the heap holds about n keys and index
// entries. Proposals are not needed, Kolo Commits carry them by value.
func (m *Member) readArchive(ctx context.Context, pins Pins, e uint64) ([]*kolomls.Result, error) {
	if m.halted != nil {
		return nil, m.halted
	}
	limit := m.o.MaxCatchUpBytes
	if limit == 0 {
		limit = DefaultMaxCatchUpBytes
	}
	prefix := ArchivePrefix(m.gid, e)
	n := 0
	if limit > 0 {
		n = max(limit/((len(prefix)+hex.EncodedLen(sha256.Size)+headerSize+2*archivedSize)*5/4), 1)
	}
	var out []*kolomls.Result
	var after *archived
	lost := 0
	for first := true; ; first = false {
		batch, more, unread, err := m.indexArchive(ctx, pins, prefix, limit, n, after)
		if err != nil {
			return out, err
		}
		if first {
			lost += unread
		}
		for _, a := range batch {
			msg, err := pins.Get(ctx, prefix+hex.EncodeToString(a.hash[:]), limit)
			if err != nil && !errors.Is(err, ErrMissing) && !errors.Is(err, ErrPinTooLarge) {
				return out, err
			}
			if err != nil || sha256.Sum256(msg) != a.hash {
				lost++
				continue
			}
			r, err := m.Receive(msg)
			switch {
			case err == nil:
				out = append(out, r)
			case errors.Is(err, errs.ErrStore) || errors.Is(err, errs.ErrClosed) || errors.Is(err, ErrHalted):
				return out, err
			// Below the sender's ratchet head: read live before, or passed
			// over then; reading in order never passes one over.
			case errors.Is(err, errs.ErrReplay) || errors.Is(err, errs.ErrTooOld) || errors.Is(err, ErrRevokedSender):
			default:
				lost++
			}
		}
		if !more {
			break
		}
		after = &batch[len(batch)-1]
	}
	if lost > 0 {
		return out, fmt.Errorf("%w: %d archived messages of epoch %d not read", ErrCatchUp, lost, e)
	}
	return out, nil
}

// indexArchive lists epoch's archive and returns the n smallest messages
// after the one given (all when n is 0), in order, whether more follow, and
// how many listed values it could not index.
func (m *Member) indexArchive(ctx context.Context, pins Pins, prefix string, limit, n int, after *archived) (kept []archived, more bool, unread int, err error) {
	var from string
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, 0, err
		}
		keys, err := pins.List(ctx, prefix, from, n)
		if err != nil {
			return nil, false, 0, err
		}
		if len(keys) == 0 {
			break
		}
		for _, k := range keys {
			if k <= from || !strings.HasPrefix(k, prefix) {
				return nil, false, 0, fmt.Errorf("%w: pins listed %q out of order or outside the epoch", ErrCatchUp, k)
			}
			from = k
			msg, err := pins.Get(ctx, k, limit)
			if err != nil && !errors.Is(err, ErrMissing) && !errors.Is(err, ErrPinTooLarge) {
				return nil, false, 0, err
			}
			h := sha256.Sum256(msg)
			if err != nil || k[len(prefix):] != hex.EncodeToString(h[:]) {
				unread++
				continue
			}
			if ct := contentType(msg); ct == message.ContentProposal || ct == message.ContentCommit {
				continue
			}
			leaf, gen, err := m.g.PeekSender(msg)
			if errors.Is(err, errs.ErrStore) || errors.Is(err, errs.ErrClosed) {
				return nil, false, 0, err
			}
			if err != nil {
				unread++
				continue
			}
			if leaf == m.g.OwnLeaf() {
				continue
			}
			a := archived{leaf: leaf, generation: gen, hash: h}
			if after != nil && a.compare(*after) <= 0 {
				continue
			}
			if kept = append(kept, a); n > 0 && len(kept) == 2*n {
				slices.SortFunc(kept, archived.compare)
				kept, more = kept[:n], true
			}
		}
	}
	slices.SortFunc(kept, archived.compare)
	if n > 0 && len(kept) > n {
		kept, more = kept[:n], true
	}
	return kept, more, unread, nil
}

// Records of a Member in its Store, beside the group's.
func (m *Member) recordKey(name string) []byte {
	return []byte("s/" + hex.EncodeToString(m.gid) + "/" + name)
}

// halt stops the Member for good: the halt is stored, so opening the group
// again returns ErrHalted.
func (m *Member) halt() error {
	m.halted = fmt.Errorf("%w: %w", ErrHalted, ErrEquivocation)
	if err := m.st.Apply(kolomls.Batch{Put: []kolomls.KV{{Key: m.recordKey("halt"), Value: []byte{1}}}}); err != nil {
		return errors.Join(m.halted, fmt.Errorf("%w: %w", errs.ErrStore, err))
	}
	return m.halted
}

// putLast stores the epoch just left: epoch, Commit hash, roles.
func (m *Member) putLast() error {
	v := binary.BigEndian.AppendUint64(nil, m.prev.epoch)
	v = append(append(v, m.prev.commit[:]...), m.prev.roles.Encode()...)
	if err := m.st.Apply(kolomls.Batch{Put: []kolomls.KV{{Key: m.recordKey("last"), Value: v}}}); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrStore, err)
	}
	return nil
}

func (m *Member) loadRecords() error {
	if _, err := m.st.Get(m.recordKey("halt")); err == nil {
		return fmt.Errorf("%w: %w", ErrHalted, ErrEquivocation)
	} else if !errors.Is(err, errs.ErrNotFound) {
		return fmt.Errorf("%w: %w", errs.ErrStore, err)
	}
	v, err := m.st.Get(m.recordKey("last"))
	if errors.Is(err, errs.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %w", errs.ErrStore, err)
	}
	m.prev, err = parseLast(v, m.limits())
	return err
}

func parseLast(v []byte, l Limits) (*last, error) {
	if len(v) < 40 {
		return nil, fmt.Errorf("%w: stored last epoch", errs.ErrMalformed)
	}
	r, err := DecodeRoles(v[40:], l)
	if err != nil {
		return nil, err
	}
	return &last{epoch: binary.BigEndian.Uint64(v), commit: [32]byte(v[8:40]), roles: r}, nil
}

func (m *Member) deleteRecords() error {
	if err := m.st.Apply(kolomls.Batch{Delete: [][]byte{m.recordKey("halt"), m.recordKey("last")}}); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrStore, err)
	}
	return nil
}

func messageEpoch(msg []byte) (uint64, bool) {
	m, err := message.UnmarshalMLSMessage(msg)
	if err != nil {
		return 0, false
	}
	switch m.WireFormat {
	case message.WirePrivate:
		return m.Private.Epoch, true
	case message.WirePublic:
		return m.Public.Content.Epoch, true
	}
	return 0, false
}

// contentType returns the content type of a PrivateMessage, in the clear
// (RFC 9420 section 6.3), zero for anything else.
func contentType(msg []byte) uint8 {
	m, err := message.UnmarshalMLSMessage(msg)
	if err != nil || m.WireFormat != message.WirePrivate {
		return 0
	}
	return m.Private.ContentType
}
