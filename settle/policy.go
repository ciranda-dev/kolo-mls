package settle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
)

// ErrRule reports a proposal, Commit or Welcome that breaks a rule of Kolo
// groups (RFC 9420 section 12.2: "An application may extend the above
// procedure by additional rules").
var ErrRule = errors.New("kolomls: Kolo group rule")

// Predecessor describes the group a successor group branches from (RFC 9420
// section 11.3), as a member of it saw its last epoch.
type Predecessor struct {
	// GroupID and Epoch name the old group's last epoch.
	GroupID []byte
	Epoch   uint64
	// Devices are the device keys of the old group's leaves.
	Devices map[[32]byte]bool
	// Roles are the old group's roles in that epoch.
	Roles *Roles
	// Braid is the group id of the successor braid; zero, for a device that
	// is not in the braid, is not checked.
	Braid [32]byte
	// Revocations returns the revocations this device holds for device of
	// person; a creator they cover is refused. Nil holds none.
	Revocations func(person, device ed25519.PublicKey) []*koloid.Revocation
}

// PredecessorOf describes m's current epoch for a successor group whose
// braid is braid. Set it in a Policy only once the old group's settler
// quorum is known to be lost for good.
func PredecessorOf(m *Member, braid [32]byte) (*Predecessor, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: no Member", errs.ErrInvalidArgument)
	}
	r, err := RolesOf(m.Extensions(), m.limits())
	if err != nil {
		return nil, err
	}
	p := &Predecessor{GroupID: m.GroupID(), Epoch: m.Epoch(), Devices: map[[32]byte]bool{}, Roles: r, Braid: braid, Revocations: m.o.Revocations}
	t := m.Tree()
	for _, leaf := range t.Members() {
		d, err := m.auth.ClientID(t.Leaf(leaf).Credential)
		if err != nil {
			return nil, err
		}
		p.Devices[[32]byte(d)] = true
	}
	return p, nil
}

// Policy is the commit rule of Kolo groups (docs/design.md, "The Kolo
// layer"); NewConfig puts it in a group's Config. One Policy serves one group.
type Policy struct {
	// Limits bound the roles extension; the Member and the Admin of the
	// group use these.
	Limits Limits
	// Predecessor, when set, allows joining a successor group of it with a
	// branch PSK; nil refuses every branch.
	Predecessor *Predecessor

	auth *cred.Authenticator
	// self is this device, set once the Member opened the group.
	self *[32]byte
	// welcome is the SettledCommit of the Welcome being joined (RFC 9750
	// section 5.2.3), set by JoinMember.
	welcome *Settled
}

func (p *Policy) device(n *kolomls.LeafNode) ([]byte, error) {
	if n == nil {
		return nil, fmt.Errorf("%w: blank leaf", ErrRule)
	}
	if p.auth == nil {
		return nil, fmt.Errorf("%w: a Policy is used through NewConfig", errs.ErrInvalidArgument)
	}
	return p.auth.ClientID(n.Credential)
}

// CheckProposal accepts only a member's own Remove, at most one cached per
// member, and only at admins, which commit the removal by value.
func (p *Policy) CheckProposal(v kolomls.ProposalView) error {
	if v.Proposal.Type != message.ProposalRemove || v.Proposal.Removed != v.Sender {
		return fmt.Errorf("%w: a member proposes only its own Remove", ErrRule)
	}
	// A proposal held stops this device from sending until a Commit (RFC
	// 9420 section 12.4), and only admins commit it.
	if p.self != nil {
		roles, err := RolesOf(v.Extensions, p.Limits)
		if err != nil {
			return err
		}
		d, err := p.device(v.SenderLeaf)
		if err != nil {
			return err
		}
		if !roles.Admin(p.self[:]) && !bytes.Equal(d, p.self[:]) {
			return ErrNotHeld
		}
	}
	if v.FromSender > 0 {
		return fmt.Errorf("%w: a member's own Remove is already cached", ErrRule)
	}
	if v.Cached >= len(v.Tree.Members()) {
		return fmt.Errorf("%w: proposal cache full", ErrRule)
	}
	return nil
}

// CheckCommit applies the commit rule.
func (p *Policy) CheckCommit(v kolomls.CommitView) error {
	roles, err := checkGroupExtensions(v.Context.Extensions, p.Limits)
	if err != nil {
		return err
	}
	if v.Path == nil {
		return fmt.Errorf("%w: a Commit carries a path", ErrRule)
	}
	committer, err := p.device(v.CommitterLeaf)
	if err != nil {
		return err
	}
	if !roles.Admin(committer) {
		if len(v.Proposals) > 0 {
			return fmt.Errorf("%w: a member that is not an admin commits only its own key update", ErrRule)
		}
		return nil
	}
	var adds, gce bool
	var next *Roles
	removed := map[uint32]bool{}
	for _, pv := range v.Proposals {
		// Every device then holds what a Commit needs, whatever proposals
		// it read or refused.
		if pv.ByReference {
			return fmt.Errorf("%w: Kolo Commits carry their proposals by value", ErrRule)
		}
		switch pv.Proposal.Type {
		case message.ProposalAdd:
			adds = true
		case message.ProposalRemove:
			removed[pv.Proposal.Removed] = true
		case message.ProposalGroupContextExtensions:
			gce = true
			if next, err = checkGroupExtensions(pv.Proposal.Extensions, p.Limits); err != nil {
				return err
			}
		case message.ProposalPSK:
			// Only the branch PSK of a successor group's first Commit
			// (RFC 9420 section 11.3).
			id := pv.Proposal.PSK
			if v.Context.Epoch != 0 || id.Type != schedule.PSKResumption || id.Usage != schedule.UsageBranch {
				return fmt.Errorf("%w: pre-shared keys are not used in Kolo groups", ErrRule)
			}
		default:
			return fmt.Errorf("%w: proposal type %d", ErrRule, pv.Proposal.Type)
		}
	}
	// The settlers that sign an Add Commit are the ones a joiner sees.
	if adds && gce {
		return fmt.Errorf("%w: Adds and GroupContextExtensions in one Commit", ErrRule)
	}
	staying := map[[32]byte]bool{}
	gone := 0
	for _, leaf := range v.Tree.Members() {
		d, err := p.device(v.Tree.Leaf(leaf))
		if err != nil {
			return err
		}
		if removed[leaf] {
			if roles.Admin(d) && (next == nil || next.Admin(d)) {
				return fmt.Errorf("%w: removing an admin or settler device needs roles without it", ErrRule)
			}
			if roles.Settler(d) {
				gone++
			}
			continue
		}
		staying[[32]byte(d)] = true
	}
	// A removed settler cannot build the next GroupContext, so it cannot
	// sign: q settlers must stay to settle this Commit.
	if len(roles.Settlers)-gone < roles.Q() {
		return fmt.Errorf("%w: fewer than q settlers stay to settle the Commit", ErrRule)
	}
	if next != nil {
		if next.Braid != roles.Braid {
			return fmt.Errorf("%w: the braid of a group does not change", ErrRule)
		}
		for _, k := range next.Admins {
			if !staying[k] {
				return fmt.Errorf("%w: an admin that is not a member after the Commit", ErrRule)
			}
		}
	}
	return nil
}

// CheckJoin checks a Welcome's SettledCommit and extensions, and allows a
// branch PSK only for a successor of Predecessor.
func (p *Policy) CheckJoin(v kolomls.JoinView) error {
	roles, err := checkGroupExtensions(v.Context.Extensions, p.Limits)
	if err != nil {
		return err
	}
	for _, e := range v.InfoExtensions {
		if e.Type == message.ExtRatchetTree || e.Type == message.ExtExternalPub {
			return fmt.Errorf("%w: GroupInfo extension %d", ErrRule, e.Type)
		}
	}
	if len(v.Context.GroupID) != suite.Nh {
		return fmt.Errorf("%w: group id of %d bytes", ErrRule, len(v.Context.GroupID))
	}
	if err := p.checkWelcome(v, roles); err != nil {
		return err
	}
	if len(v.PSKs) == 0 {
		return nil
	}
	if len(v.PSKs) != 1 || v.PSKs[0].Type != schedule.PSKResumption || v.PSKs[0].Usage != schedule.UsageBranch {
		return fmt.Errorf("%w: pre-shared keys are not used in Kolo groups", ErrRule)
	}
	old := p.Predecessor
	id := v.PSKs[0]
	if old == nil || old.Roles == nil || !bytes.Equal(id.GroupID, old.GroupID) || id.Epoch != old.Epoch {
		return fmt.Errorf("%w: a branch of a group this member does not follow", ErrRule)
	}
	if old.Braid != ([32]byte{}) && roles.Braid != old.Braid {
		return fmt.Errorf("%w: a successor group names the successor braid", ErrRule)
	}
	signer, err := p.device(v.Tree.Leaf(v.Signer))
	if err != nil {
		return err
	}
	if !old.Roles.Settler(signer) {
		return fmt.Errorf("%w: a successor group is created by a settler of the old one", ErrRule)
	}
	if old.Revocations != nil {
		c, err := cred.Decode(v.Tree.Leaf(v.Signer).Credential)
		if err != nil {
			return err
		}
		if cred.Revoked(v.Tree.Leaf(v.Signer).Credential, old.Revocations(c.Person(), c.Device())) != nil {
			return fmt.Errorf("%w: the successor's creator is revoked", ErrRule)
		}
	}
	for _, leaf := range v.Tree.Members() {
		d, err := p.device(v.Tree.Leaf(leaf))
		if err != nil {
			return err
		}
		if !old.Devices[[32]byte(d)] {
			return fmt.Errorf("%w: a leaf of the successor group was not in the old one", ErrRule)
		}
	}
	return nil
}

// checkWelcome verifies the SettledCommit of a Welcome: it settles the
// Commit that made the joined epoch, with q signatures of settlers that the
// joined GroupContext lists and that are leaves of its tree.
func (p *Policy) checkWelcome(v kolomls.JoinView, roles *Roles) error {
	w := p.welcome
	if w == nil {
		return fmt.Errorf("%w: a Welcome needs its SettledCommit", ErrNotSettled)
	}
	ctx, err := v.Context.Marshal()
	if err != nil {
		return err
	}
	if t := &w.TBS; !bytes.Equal(t.GroupID, v.Context.GroupID) || t.Epoch+1 != v.Context.Epoch || t.Braid != roles.Braid || t.ContextAfter != sha256.Sum256(ctx) {
		return fmt.Errorf("%w: the SettledCommit is not for the joined epoch", ErrNotSettled)
	}
	if len(w.Shares) > len(roles.Settlers) {
		return fmt.Errorf("%w: more signatures than settlers", ErrNotSettled)
	}
	devices, err := p.devices(v.Tree)
	if err != nil {
		return err
	}
	if w.Valid(roles, func(d [32]byte) bool { return devices[d] }) < roles.Q() {
		return fmt.Errorf("%w: fewer than %d settler signatures", ErrNotSettled, roles.Q())
	}
	return nil
}

func (p *Policy) devices(t kolomls.TreeView) (map[[32]byte]bool, error) {
	out := map[[32]byte]bool{}
	for _, leaf := range t.Members() {
		d, err := p.device(t.Leaf(leaf))
		if err != nil {
			return nil, err
		}
		out[[32]byte(d)] = true
	}
	return out, nil
}

// NewConfig returns the configuration of a Kolo group with a and p: the Kolo
// credential and Policy, handshakes as PrivateMessage, the envelope, and the
// clock now, which the Kolo layer requires.
func NewConfig(a *cred.Authenticator, p *Policy, now func() time.Time) kolomls.Config {
	if p == nil {
		p = &Policy{}
	}
	p.auth = a
	return kolomls.Config{Authenticator: a, Policy: p, PrivateHandshakes: true, Envelope: Envelope{}, Now: now}
}

// BranchPSK serves the resumption PSK of a group's last epoch, with usage
// branch, to the first Commit of its successor group and to its joiners
// (RFC 9420 section 11.3).
type BranchPSK struct {
	GroupID []byte
	Epoch   uint64
	Value   []byte

	id *kolomls.PSKID
}

// ID returns the PSK id with its nonce, for the successor's first Commit;
// nil for a BranchPSK not made by Member.BranchPSK.
func (b *BranchPSK) ID() *kolomls.PSKID { return b.id }

// PSK returns a copy of the value for the branch PSK of GroupID and Epoch.
func (b *BranchPSK) PSK(id *kolomls.PSKID) ([]byte, error) {
	if b == nil || id == nil || id.Type != schedule.PSKResumption || id.Usage != schedule.UsageBranch || !bytes.Equal(id.GroupID, b.GroupID) || id.Epoch != b.Epoch {
		return nil, errs.ErrNotFound
	}
	return bytes.Clone(b.Value), nil
}
