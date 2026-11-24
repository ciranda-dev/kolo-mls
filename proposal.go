package kolomls

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// cached is a proposal received or sent in the current epoch, kept for
// Commits that include it by reference (RFC 9420 section 12.1).
type cached struct {
	ref []byte
	ac  *message.AuthenticatedContent
	// leafPriv is the private key of the new leaf of this member's own Update.
	leafPriv []byte
}

func (c *cached) proposal() *Proposal {
	return c.ac.Content.Proposal
}

func (c *cached) sender() uint32 {
	return c.ac.Content.Sender.Index
}

func (c *cached) marshal() ([]byte, error) {
	ac, err := c.ac.Marshal()
	if err != nil {
		return nil, err
	}
	var w tls.Writer
	w.Opaque(ac)
	w.Optional(c.leafPriv != nil)
	if c.leafPriv != nil {
		w.Opaque(c.leafPriv)
	}
	return w.Bytes()
}

func unmarshalCached(ref, b []byte) (*cached, error) {
	c := &cached{ref: ref}
	err := tls.Decode(b, func(r *tls.Reader) error {
		acb, err := r.Opaque()
		if err != nil {
			return err
		}
		if c.ac, err = message.UnmarshalAuthenticatedContent(acb); err != nil {
			return err
		}
		if c.ac.Content.ContentType != message.ContentProposal || c.ac.Content.Sender.Type != message.SenderMember {
			return fmt.Errorf("%w: stored proposal", errs.ErrMalformed)
		}
		present, err := r.Optional()
		if err != nil || !present {
			return err
		}
		c.leafPriv, err = r.Opaque()
		return err
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func invalidProposal(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errs.ErrInvalidProposal, fmt.Sprintf(format, a...))
}

// checkProposal runs the checks of RFC 9420 section 12.1 on p from member
// sender; ReInit and ExternalInit are refused with ErrUnsupported after
// their own checks, since this library does not run those flows.
func (c *Config) checkProposal(s *state, p *Proposal, sender uint32, sending bool) error {
	switch p.Type {
	case message.ProposalAdd:
		ev := EventAdd
		if sending {
			ev = EventKeyPackage
		}
		if err := c.checkKeyPackage(p.KeyPackage, s.ctx, ev, sending); err != nil {
			return fmt.Errorf("%w: %w", errs.ErrInvalidProposal, err)
		}
	case message.ProposalUpdate:
		old := s.tree.Leaf(sender)
		if old == nil {
			return invalidProposal("Update from blank leaf %d", sender)
		}
		if err := c.checkLeaf(p.LeafNode, leafRule{source: tree.SourceUpdate, index: sender, event: EventUpdate, sending: sending}, s.ctx); err != nil {
			return fmt.Errorf("%w: %w", errs.ErrInvalidProposal, err)
		}
		if bytes.Equal(p.LeafNode.EncryptionKey, old.EncryptionKey) {
			return invalidProposal("Update keeps the encryption key of the leaf it replaces")
		}
		if err := c.successor(old, p.LeafNode); err != nil {
			return fmt.Errorf("%w: %w", errs.ErrInvalidProposal, err)
		}
	case message.ProposalRemove:
		if s.tree.Leaf(p.Removed) == nil {
			return invalidProposal("Remove of blank leaf %d", p.Removed)
		}
	case message.ProposalPSK:
		if err := checkPSKID(p.PSK, s.ctx); err != nil {
			return err
		}
	case message.ProposalReInit:
		if p.ReInit.Version < schedule.MLS10 {
			return invalidProposal("ReInit to version %d, below the group's", p.ReInit.Version)
		}
		return fmt.Errorf("%w: ReInit proposals", errs.ErrUnsupported)
	case message.ProposalExternalInit:
		return fmt.Errorf("%w: ExternalInit proposals", errs.ErrUnsupported)
	case message.ProposalGroupContextExtensions:
		// Validity depends on the whole Commit (RFC 9420 section 12.1.7):
		// checkMembers runs it on the tree after the Commit.
	default:
		return invalidProposal("proposal type %#04x", p.Type)
	}
	return nil
}

// checkPSKID runs the PreSharedKey checks of RFC 9420 section 12.1.4 in a
// group with GroupContext ctx. A branch PSK is part of branching only in
// the first Commit of a new group, from another group (section 11.3).
func checkPSKID(id *PSKID, ctx *GroupContext) error {
	if len(id.Nonce) != suite.Nh {
		return invalidProposal("psk_nonce of %d bytes", len(id.Nonce))
	}
	branch := id.Usage == schedule.UsageBranch && ctx.Epoch == 0 && !bytes.Equal(id.GroupID, ctx.GroupID)
	if id.Type == schedule.PSKResumption && id.Usage != schedule.UsageApplication && !branch {
		return invalidProposal("resumption PSK with usage %d outside reinitialization or branching", id.Usage)
	}
	return nil
}

// successor checks a leaf that replaces old with the Authenticator when its
// credential changes (RFC 9420 section 5.3.1).
func (c *Config) successor(old, next *LeafNode) error {
	if old.Credential.Type == next.Credential.Type && bytes.Equal(old.Credential.Identity, next.Credential.Identity) && bytes.Equal(old.Credential.Certificates, next.Credential.Certificates) {
		return nil
	}
	if err := c.Authenticator.Successor(old.Credential, next.Credential); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrCredential, err)
	}
	return nil
}

type item struct {
	p      *Proposal
	sender uint32
	// ref is set for a proposal included by reference.
	ref      []byte
	leafPriv []byte
}

func proposalView(s *state, sender uint32, p *Proposal, byRef bool) (ProposalView, error) {
	b, err := p.Marshal()
	if err != nil {
		return ProposalView{}, err
	}
	cp, err := message.UnmarshalProposal(b)
	if err != nil {
		return ProposalView{}, err
	}
	return ProposalView{Sender: sender, SenderLeaf: cloneLeaf(s.tree.Leaf(sender)), Proposal: cp, ByReference: byRef, Tree: TreeView{s.tree}, Extensions: cloneExtensions(s.ctx.Extensions)}, nil
}

func cloneLeaf(n *LeafNode) *LeafNode {
	if n == nil {
		return nil
	}
	return n.Clone()
}

func cloneContext(ctx *GroupContext) (*GroupContext, error) {
	b, err := ctx.Marshal()
	if err != nil {
		return nil, err
	}
	var c *GroupContext
	err = tls.Decode(b, func(r *tls.Reader) (err error) {
		c, err = schedule.ReadGroupContext(r)
		return err
	})
	return c, err
}

func invalidCommit(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errs.ErrInvalidCommit, fmt.Sprintf(format, a...))
}

// checkList runs the list checks of RFC 9420 section 12.2 for a regular
// Commit by committer, then the Policy.
func (c *Config) checkList(s *state, committer uint32, items []item, path *LeafNode, sending bool) error {
	touched := map[uint32]bool{}
	removed := map[uint32]bool{}
	adds := map[string]bool{}
	psks := map[string]bool{}
	gce, reinit := 0, 0
	for _, it := range items {
		p := it.p
		if !isDefaultProposal(p.Type) {
			return invalidCommit("proposal type %#04x that members do not support", p.Type)
		}
		switch p.Type {
		case message.ProposalUpdate:
			if it.sender == committer {
				return invalidCommit("an Update by the committer")
			}
			if touched[it.sender] {
				return invalidCommit("two Updates or Removes for leaf %d", it.sender)
			}
			touched[it.sender] = true
		case message.ProposalRemove:
			if p.Removed == committer {
				return invalidCommit("a Remove of the committer")
			}
			if touched[p.Removed] {
				return invalidCommit("two Updates or Removes for leaf %d", p.Removed)
			}
			touched[p.Removed] = true
			removed[p.Removed] = true
		case message.ProposalAdd:
			id, err := c.Authenticator.ClientID(p.KeyPackage.LeafNode.Credential)
			if err != nil {
				return fmt.Errorf("%w: %w", errs.ErrCredential, err)
			}
			if adds[string(id)] {
				return invalidCommit("two Adds of the same client")
			}
			adds[string(id)] = true
		case message.ProposalPSK:
			var w tls.Writer
			p.PSK.Write(&w)
			b, err := w.Bytes()
			if err != nil {
				return err
			}
			if psks[string(b)] {
				return invalidCommit("two PreSharedKey proposals with the same PreSharedKeyID")
			}
			psks[string(b)] = true
		case message.ProposalGroupContextExtensions:
			gce++
			if gce > 1 {
				return invalidCommit("two GroupContextExtensions proposals")
			}
		case message.ProposalReInit:
			reinit++
		case message.ProposalExternalInit:
			return invalidCommit("an ExternalInit proposal in a regular Commit")
		}
	}
	if reinit > 0 && len(items) > 1 {
		return invalidCommit("a ReInit proposal together with other proposals")
	}
	if len(adds) > 0 {
		for _, x := range s.tree.NonBlank() {
			l := uint32(x / 2)
			n := s.tree.Node(x).Leaf
			if n == nil || removed[l] {
				continue
			}
			id, err := c.Authenticator.ClientID(n.Credential)
			if err != nil {
				return fmt.Errorf("%w: %w", errs.ErrCredential, err)
			}
			if adds[string(id)] {
				return invalidCommit("an Add of a client already in the group")
			}
		}
	}
	// The new extensions apply to the other proposals of the list (RFC 9420
	// section 12.3), and a committer checks the lifetime of every Add it
	// includes, by value or by reference, as RFC 9420 section 7.3 asks of a
	// client that sends a leaf.
	eff := s
	for _, it := range items {
		if it.p.Type == message.ProposalGroupContextExtensions {
			ctx := *s.ctx
			ctx.Extensions = it.p.Extensions
			eff = &state{ctx: &ctx, tree: s.tree}
		}
	}
	for _, it := range items {
		if err := c.checkProposal(eff, it.p, it.sender, sending); err != nil {
			return err
		}
	}
	ctx, err := cloneContext(s.ctx)
	if err != nil {
		return err
	}
	v := CommitView{Committer: committer, CommitterLeaf: cloneLeaf(s.tree.Leaf(committer)), Path: cloneLeaf(path), Context: ctx, Tree: TreeView{s.tree}}
	for _, it := range items {
		pv, err := proposalView(s, it.sender, it.p, it.ref != nil)
		if err != nil {
			return err
		}
		v.Proposals = append(v.Proposals, pv)
	}
	if err := c.Policy.CheckCommit(v); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrPolicy, err)
	}
	return nil
}

// pathRequired reports whether a Commit with these proposals needs a path
// (RFC 9420 section 12.4).
func pathRequired(items []item) bool {
	if len(items) == 0 {
		return true
	}
	for _, it := range items {
		switch it.p.Type {
		case message.ProposalUpdate, message.ProposalRemove, message.ProposalExternalInit, message.ProposalGroupContextExtensions:
			return true
		}
	}
	return false
}

type applied struct {
	tree       *tree.Tree
	extensions []Extension
	gce        bool
	// added holds the leaf index of each Add, in list order.
	added    []uint32
	addedKPs []*message.KeyPackage
	removed  map[uint32]bool
	updated  map[uint32][]byte
}

// applyList applies items to a copy of the tree of s in the order of RFC
// 9420 section 12.3.
func applyList(s *state, items []item) (*applied, error) {
	a := &applied{tree: s.tree.Clone(), extensions: s.ctx.Extensions, removed: map[uint32]bool{}, updated: map[uint32][]byte{}}
	for _, it := range items {
		if it.p.Type == message.ProposalGroupContextExtensions {
			a.extensions, a.gce = it.p.Extensions, true
		}
	}
	for _, it := range items {
		if it.p.Type == message.ProposalUpdate {
			if err := a.tree.UpdateLeaf(it.sender, it.p.LeafNode.Clone()); err != nil {
				return nil, err
			}
			a.updated[it.sender] = it.leafPriv
		}
	}
	var removes []uint32
	for _, it := range items {
		if it.p.Type == message.ProposalRemove {
			removes = append(removes, it.p.Removed)
			a.removed[it.p.Removed] = true
		}
	}
	if len(removes) > 0 {
		if err := a.tree.RemoveLeaves(removes); err != nil {
			return nil, err
		}
	}
	var leaves []*LeafNode
	for _, it := range items {
		switch it.p.Type {
		case message.ProposalAdd:
			leaves = append(leaves, it.p.KeyPackage.LeafNode.Clone())
			a.addedKPs = append(a.addedKPs, it.p.KeyPackage)
		}
	}
	if len(leaves) > 0 {
		added, err := a.tree.AddLeaves(leaves)
		if err != nil {
			return nil, err
		}
		a.added = added
	}
	return a, nil
}

// resumptionPSK returns a copy of this group's resumption PSK for id, nil
// when id names another group or an epoch whose PSK is not kept.
func (s *state) resumptionPSK(id *PSKID) []byte {
	if s == nil || id.Type != schedule.PSKResumption || id.Usage != schedule.UsageApplication || !bytes.Equal(id.GroupID, s.ctx.GroupID) {
		return nil
	}
	if id.Epoch == s.ctx.Epoch {
		return bytes.Clone(s.secrets.Resumption)
	}
	for _, p := range s.past {
		if p.epoch == id.Epoch {
			return bytes.Clone(p.psk)
		}
	}
	return nil
}

// pskValues returns the value of each PSK: this group's kept resumption
// PSKs, or the PSKStore's (RFC 9420 section 12.4.2: "Verify that
// all PreSharedKey proposals in the proposals vector are available").
func (c *Config) pskValues(s *state, ids []*PSKID) ([][]byte, error) {
	out := make([][]byte, len(ids))
	for i, id := range ids {
		if v := s.resumptionPSK(id); v != nil {
			out[i] = v
			continue
		}
		if c.PSKs == nil {
			clearAll(out)
			return nil, errs.ErrPSKNotFound
		}
		v, err := c.PSKs.PSK(id)
		switch {
		case errors.Is(err, errs.ErrNotFound):
			err = fmt.Errorf("%w: %w", errs.ErrPSKNotFound, err)
		case err != nil:
			err = fmt.Errorf("%w: PSKStore: %w", errs.ErrStore, err)
		}
		if err != nil {
			clearAll(out)
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
