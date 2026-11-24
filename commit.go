package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"maps"
	"slices"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// StagedCommit is another member's verified Commit; nothing changes until
// Apply (RFC 9420 section 14).
type StagedCommit struct {
	g    *Group
	base *state
	// next is the state of the new epoch, nil when this member is removed
	// or the Commit was discarded.
	next        *state
	removesSelf bool
	extensions  []Extension
	committer   uint32
	added       []uint32
	removed     []uint32
}

// Discard zeroes the secrets of a Commit that will not be applied.
func (sc *StagedCommit) Discard() {
	if sc.next != nil {
		sc.next.clear()
		sc.next = nil
	}
	sc.base = nil
}

// RemovesSelf reports whether the Commit removes this member.
func (sc *StagedCommit) RemovesSelf() bool {
	return sc.removesSelf
}

// Committer returns the committer's leaf index.
func (sc *StagedCommit) Committer() uint32 {
	return sc.committer
}

// Added returns the leaf indices the Commit adds.
func (sc *StagedCommit) Added() []uint32 {
	return append([]uint32(nil), sc.added...)
}

// Removed returns the leaf indices the Commit removes, in increasing order.
func (sc *StagedCommit) Removed() []uint32 {
	return append([]uint32(nil), sc.removed...)
}

// Leaves returns copies of the leaves of the new tree that the Commit adds
// or replaces, nil when it removes this member.
func (sc *StagedCommit) Leaves() []*LeafNode {
	if sc.next == nil || sc.base == nil {
		return nil
	}
	var out []*LeafNode
	for _, x := range sc.next.tree.NonBlank() {
		if x%2 != 0 {
			continue
		}
		// Leaves are never changed in place: a new pointer is a new leaf.
		if n := sc.next.tree.Leaf(uint32(x / 2)); n != sc.base.tree.Leaf(uint32(x/2)) {
			out = append(out, n.Clone())
		}
	}
	return out
}

// Extensions returns the GroupContext extensions of the new epoch, also when
// the Commit removes this member.
func (sc *StagedCommit) Extensions() []Extension {
	return cloneExtensions(sc.extensions)
}

// GroupContext returns the encoded GroupContext of the new epoch, nil when
// this member is removed.
func (sc *StagedCommit) GroupContext() []byte {
	if sc.next == nil {
		return nil
	}
	return bytes.Clone(sc.next.ctxBytes)
}

// resolve returns the proposals of commit, looking up references in the
// cache (erratum 8815: an unknown reference makes the Commit invalid).
func (g *Group) resolve(commit *message.Commit, committer uint32) ([]item, error) {
	items := make([]item, 0, len(commit.Proposals))
	for _, por := range commit.Proposals {
		if por.Type == message.ByValue {
			items = append(items, item{p: por.Proposal, sender: committer})
			continue
		}
		it, err := g.refItem(por.Ref)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, nil
}

func (g *Group) refItem(ref []byte) (item, error) {
	c := g.cachedProposal(ref)
	if c == nil {
		return item{}, unknownRef(ref)
	}
	return item{p: c.proposal(), sender: c.sender(), ref: c.ref, leafPriv: c.leafPriv}, nil
}

func (g *Group) cachedProposal(ref []byte) *cached {
	return g.byRef[string(ref)]
}

func (g *Group) setProps(props []*cached) {
	g.props = props
	g.byRef = make(map[string]*cached, len(props))
	for _, c := range props {
		g.byRef[string(c.ref)] = c
	}
}

// unknownRef reports a missing proposal; the reference is named only when it
// has the size of a ProposalRef, so hostile bytes stay out of the text.
func unknownRef(ref []byte) error {
	if len(ref) != suite.Nh {
		return fmt.Errorf("%w: reference of %d bytes", errs.ErrUnknownProposal, len(ref))
	}
	return fmt.Errorf("%w: %x", errs.ErrUnknownProposal, ref)
}

func pskIDs(items []item) []*PSKID {
	var ids []*PSKID
	for _, it := range items {
		if it.p.Type == message.ProposalPSK {
			ids = append(ids, it.p.PSK)
		}
	}
	return ids
}

// provisional returns the GroupContext of the new epoch before its
// confirmed transcript hash is known (RFC 9420 section 12.4.1).
func provisional(s *state, a *applied) *GroupContext {
	return &GroupContext{
		CipherSuite:             s.ctx.CipherSuite,
		GroupID:                 s.ctx.GroupID,
		Epoch:                   s.ctx.Epoch + 1,
		ConfirmedTranscriptHash: s.ctx.ConfirmedTranscriptHash,
		Extensions:              a.extensions,
	}
}

// keyed holds a new epoch's context with its confirmed transcript hash, its
// secrets, and the secrets a Welcome needs.
type keyed struct {
	ctx     *GroupContext
	secrets *schedule.Secrets
	welcome []byte
	joiner  []byte
	psk     []byte
}

func (k *keyed) clear() {
	clear(k.welcome)
	clear(k.joiner)
	clear(k.psk)
}

// deriveEpoch completes ctx with the confirmed transcript hash of the
// Commit ac and derives the new epoch's secrets (RFC 9420 sections 8, 8.2).
func deriveEpoch(s *state, ctx *GroupContext, ac *message.AuthenticatedContent, commitSecret []byte, ids []*PSKID, psks [][]byte) (*keyed, error) {
	in, err := ac.ConfirmedTranscriptHashInput()
	if err != nil {
		return nil, err
	}
	ctx.ConfirmedTranscriptHash = schedule.ConfirmedTranscriptHash(s.interim, in)
	gc, err := ctx.Marshal()
	if err != nil {
		return nil, err
	}
	k := &keyed{ctx: ctx}
	if k.joiner, err = schedule.JoinerSecret(s.secrets.Init, commitSecret, gc); err != nil {
		return nil, err
	}
	if k.psk, err = schedule.PSKSecret(ids, psks); err != nil {
		k.clear()
		return nil, err
	}
	if k.welcome, k.secrets, err = schedule.Epoch(k.joiner, k.psk, gc); err != nil {
		k.clear()
		return nil, err
	}
	return k, nil
}

// stage verifies a Commit of another member and returns the new epoch's
// state (RFC 9420 section 12.4.2); the epoch, membership tag and signature
// were checked by Process.
func (g *Group) stage(ac *message.AuthenticatedContent) (*StagedCommit, error) {
	s := g.s
	committer := ac.Content.Sender.Index
	if committer == s.own() {
		return nil, fmt.Errorf("%w: this member's own Commit is applied with ApplyPending", errs.ErrInvalidArgument)
	}
	commit := ac.Content.Commit
	items, err := g.resolve(commit, committer)
	if err != nil {
		return nil, err
	}
	var pathLeaf *LeafNode
	if commit.Path != nil {
		pathLeaf = commit.Path.Leaf
	}
	if err := g.cfg.checkList(s, committer, items, pathLeaf, false); err != nil {
		return nil, err
	}
	ids := pskIDs(items)
	psks, err := g.cfg.pskValues(s, ids)
	if err != nil {
		return nil, err
	}
	defer clearAll(psks)
	a, err := applyList(s, items)
	if err != nil {
		return nil, err
	}
	if commit.Path == nil && pathRequired(items) {
		return nil, invalidCommit("path missing where RFC 9420 section 12.4 requires it")
	}
	ctx := provisional(s, a)
	removed := a.removed[s.own()]
	sc := &StagedCommit{g: g, base: s, committer: committer, added: a.added, removesSelf: removed, extensions: cloneExtensions(a.extensions), removed: slices.Sorted(maps.Keys(a.removed))}

	base := s.priv.Clone()
	defer base.Clear()
	if k, ok := a.updated[s.own()]; ok {
		clear(base.Keys[2*uint64(s.own())])
		base.Keys[2*uint64(s.own())] = bytes.Clone(k)
	}
	commitSecret := make([]byte, suite.Nh)
	defer func() { clear(commitSecret) }()
	var next *tree.Private
	defer func() {
		if sc.next == nil && next != nil {
			next.Clear()
		}
	}()
	if commit.Path != nil {
		rule := leafRule{source: tree.SourceCommit, index: committer, event: EventCommitPath}
		if err := g.cfg.checkLeaf(commit.Path.Leaf, rule, ctx); err != nil {
			return nil, fmt.Errorf("%w: %w", errs.ErrInvalidCommit, err)
		}
		if err := g.cfg.successor(s.tree.Leaf(committer), commit.Path.Leaf); err != nil {
			return nil, fmt.Errorf("%w: %w", errs.ErrInvalidCommit, err)
		}
		if err := a.tree.Merge(committer, commit.Path); err != nil {
			return nil, err
		}
		th, err := a.tree.TreeHash()
		if err != nil {
			return nil, err
		}
		ctx.TreeHash = th
		excluded := map[uint32]bool{}
		for _, l := range a.added {
			excluded[l] = true
		}
		if removed {
			// The removed member cannot decrypt, but checks what every
			// member checks before it deletes its state.
			if err := a.tree.CheckPathCiphertexts(committer, commit.Path, excluded); err != nil {
				return nil, err
			}
		} else {
			pc, err := ctx.Marshal()
			if err != nil {
				return nil, err
			}
			ps, cs, n, err := a.tree.DecryptPath(committer, commit.Path, excluded, pc, base)
			if err != nil {
				return nil, err
			}
			clear(ps)
			commitSecret, next = cs, n
		}
	} else {
		th, err := a.tree.TreeHash()
		if err != nil {
			return nil, err
		}
		ctx.TreeHash = th
		next = base.Clone()
	}
	if err := checkMembers(a.tree, ctx, a.gce); err != nil {
		return nil, fmt.Errorf("%w: %w", errs.ErrInvalidCommit, err)
	}
	if removed {
		// Without a path secret the removed member cannot derive the new
		// epoch or check the confirmation tag (RFC 9420 section 12.4.2).
		return sc, nil
	}
	next.Prune(a.tree)
	if err := next.Check(a.tree); err != nil {
		return nil, fmt.Errorf("%w: %w", errs.ErrInvalidCommit, err)
	}
	k, err := deriveEpoch(s, ctx, ac, commitSecret, ids, psks)
	if err != nil {
		return nil, err
	}
	defer k.clear()
	if !suite.VerifyMAC(k.secrets.Confirmation, k.ctx.ConfirmedTranscriptHash, ac.Auth.ConfirmationTag) {
		k.secrets.Clear()
		return nil, errs.ErrConfirmationTag
	}
	clear(k.secrets.Confirmation)
	interim, err := schedule.InterimTranscriptHash(k.ctx.ConfirmedTranscriptHash, ac.Auth.ConfirmationTag)
	if err != nil {
		k.secrets.Clear()
		return nil, err
	}
	ns := &state{tree: a.tree, priv: next, sig: bytes.Clone(s.sig), secrets: k.secrets, interim: interim, past: s.nextPast(g.cfg.ResumptionPSKs)}
	if err := ns.setContext(k.ctx); err != nil {
		ns.clear()
		return nil, err
	}
	sc.next = ns
	return sc, nil
}

func clearAll(bs [][]byte) {
	for _, b := range bs {
		clear(b)
	}
}

// Apply makes a staged Commit the current epoch in one Store batch that also
// deletes the old epoch and any pending Commit (RFC 9420 sections 9.2, 14).
// A Commit that removes this member deletes the group's records instead:
// Apply returns nil, Removed reports true and every later call returns
// ErrRemoved. A Commit that is not applied is discarded.
func (g *Group) Apply(sc *StagedCommit) error {
	if err := g.live(); err != nil {
		sc.Discard()
		return err
	}
	if sc.g != g || sc.base != g.s {
		sc.Discard()
		return fmt.Errorf("%w: the Commit was staged for another state", errs.ErrInvalidArgument)
	}
	if sc.removesSelf {
		var b Batch
		if err := deleteGroup(&b, g.s, g.prev, g.props); err != nil {
			return err
		}
		if err := g.write(b); err != nil {
			return err
		}
		g.drop()
		g.err = errs.ErrRemoved
		return nil
	}
	if err := g.advance(sc.next); err != nil {
		sc.Discard()
		return err
	}
	sc.base, sc.next = nil, nil
	return nil
}

// advance makes next the current epoch in one Store batch that deletes the
// old epoch, the epoch's proposals and any pending Commit (RFC 9420
// sections 9.2, 14).
func (g *Group) advance(next *state) error {
	if err := next.startKeys(g.cfg.keyOptions()); err != nil {
		return err
	}
	p, err := g.newPast(g.s, next)
	if err != nil {
		return err
	}
	written := false
	defer func() {
		if !written {
			p.clear()
		}
	}()
	gid := g.s.ctx.GroupID
	var b Batch
	defer b.zero()
	if err := writeState(&b, g.s, next, nil); err != nil {
		return err
	}
	// The old epoch's secret tree stays for the window; the epoch before it
	// goes now, since only the previous epoch is kept.
	if p == nil {
		if err := deleteKeys(&b, gid, g.s.ctx.Epoch, g.s.keys); err != nil {
			return err
		}
	} else {
		pb, err := p.marshal()
		if err != nil {
			return err
		}
		b.put(groupKey(gid, "prev"), pb)
	}
	if err := writePastDelete(&b, gid, g.prev, p != nil); err != nil {
		return err
	}
	if err := writeProps(&b, gid, g.props, nil); err != nil {
		return err
	}
	if g.pending != nil {
		b.del(groupKey(gid, "pending"))
	}
	if err := g.write(b); err != nil {
		return err
	}
	written = true
	if g.pending != nil && g.pending.next == next {
		g.pending = nil
	}
	if p != nil {
		p.keys, g.s.keys = g.s.keys, nil
	}
	g.drop()
	g.s = next
	g.prev = p
	return nil
}

func (g *Group) drop() {
	g.s.clear()
	g.prev.clear()
	g.prev = nil
	for _, c := range g.props {
		clear(c.leafPriv)
	}
	g.setProps(nil)
	if g.pending != nil {
		g.pending.next.clear()
		g.pending = nil
	}
}

// Commit creates a Commit of o and its Welcome (RFC 9420 section 12.4.1),
// stored apart until ApplyPending or DiscardPending; the group's state does
// not change.
func (g *Group) Commit(o CommitOptions) (*PendingCommit, error) {
	if err := g.live(); err != nil {
		return nil, err
	}
	if g.pending != nil {
		return nil, errs.ErrPendingCommit
	}
	s := g.s
	own := s.own()
	items, ors, err := g.commitItems(o)
	if err != nil {
		return nil, err
	}
	template, sigKey, err := g.pathTemplate(o)
	if err != nil {
		return nil, err
	}
	doPath := !o.NoPath
	if o.NoPath && pathRequired(items) {
		return nil, fmt.Errorf("%w: these proposals need a path", errs.ErrInvalidArgument)
	}
	// Without a path the Welcome key depends only on the Commit, so a second
	// attempt after DiscardPending would reuse it for another GroupInfo.
	if o.NoPath && len(o.Add) > 0 {
		return nil, fmt.Errorf("%w: a Commit that adds members carries a path", errs.ErrInvalidArgument)
	}
	var policyLeaf *LeafNode
	if doPath {
		policyLeaf = template
	}
	if err := g.cfg.checkList(s, own, items, policyLeaf, true); err != nil {
		return nil, err
	}
	ids := pskIDs(items)
	psks, err := g.cfg.pskValues(s, ids)
	if err != nil {
		return nil, err
	}
	defer clearAll(psks)
	a, err := applyList(s, items)
	if err != nil {
		return nil, err
	}
	ctx := provisional(s, a)
	commitSecret := make([]byte, suite.Nh)
	var path *tree.Path
	var next *tree.Private
	var ns *state
	ok := false
	defer func() {
		switch {
		case ok:
		case ns != nil:
			ns.clear()
		case next != nil:
			next.Clear()
		}
	}()
	if doPath {
		excluded := map[uint32]bool{}
		for _, l := range a.added {
			excluded[l] = true
		}
		context := func(th []byte) ([]byte, error) {
			ctx.TreeHash = th
			return ctx.Marshal()
		}
		if path, err = a.tree.CreatePath(own, template, sigKey, s.ctx.GroupID, excluded, context); err != nil {
			return nil, err
		}
		next = path.Private
		defer func() {
			clearAll(path.PathSecrets)
			clear(path.CommitSecret)
		}()
		rule := leafRule{source: tree.SourceCommit, index: own, event: EventCommitPath, sending: true}
		if err := g.cfg.checkLeaf(path.UpdatePath.Leaf, rule, ctx); err != nil {
			return nil, err
		}
		if err := g.cfg.successor(s.tree.Leaf(own), path.UpdatePath.Leaf); err != nil {
			return nil, err
		}
		commitSecret = path.CommitSecret
	} else {
		next = s.priv.Clone()
		next.Prune(a.tree)
	}
	th, err := a.tree.TreeHash()
	if err != nil {
		return nil, err
	}
	ctx.TreeHash = th
	if err := checkMembers(a.tree, ctx, a.gce); err != nil {
		return nil, fmt.Errorf("%w: %w", errs.ErrInvalidCommit, err)
	}
	commit := &message.Commit{Proposals: ors}
	if path != nil {
		commit.Path = path.UpdatePath
	}
	content := &message.FramedContent{
		GroupID:           s.ctx.GroupID,
		Epoch:             s.ctx.Epoch,
		Sender:            message.Sender{Type: message.SenderMember, Index: own},
		AuthenticatedData: o.AuthenticatedData,
		ContentType:       message.ContentCommit,
		Commit:            commit,
	}
	wf, lk, err := g.prepare(content)
	if err != nil {
		return nil, err
	}
	defer lk.Discard()
	ac, err := g.sign(wf, content)
	if err != nil {
		return nil, err
	}
	k, err := deriveEpoch(s, ctx, ac, commitSecret, ids, psks)
	if err != nil {
		return nil, err
	}
	defer k.clear()
	ac.Auth.ConfirmationTag = suite.MAC(k.secrets.Confirmation, k.ctx.ConfirmedTranscriptHash)
	clear(k.secrets.Confirmation)
	ns = &state{tree: a.tree, priv: next, sig: bytes.Clone(sigKey), secrets: k.secrets, past: s.nextPast(g.cfg.ResumptionPSKs)}
	pc := &PendingCommit{next: ns}
	if ns.interim, err = schedule.InterimTranscriptHash(k.ctx.ConfirmedTranscriptHash, ac.Auth.ConfirmationTag); err != nil {
		return nil, err
	}
	if err := ns.setContext(k.ctx); err != nil {
		return nil, err
	}
	if pc.commit, err = g.seal(ac, lk); err != nil {
		return nil, err
	}
	if len(a.added) > 0 {
		if pc.welcome, err = welcome(ns, a, path, k, ac.Auth.ConfirmationTag, ids, o.RatchetTree); err != nil {
			return nil, err
		}
	}
	rec, err := pc.marshal(s)
	if err != nil {
		return nil, err
	}
	// A private Commit uses this member's next handshake key, consumed in the
	// same batch so a later Commit of the epoch never reuses it.
	if err := g.consume(lk, Batch{Put: []KV{{Key: groupKey(s.ctx.GroupID, "pending"), Value: rec}}}); err != nil {
		return nil, err
	}
	ok = true
	g.pending = pc
	return pc, nil
}

// commitItems resolves the references of o and adds its proposals by value
// in the order GroupContextExtensions, Removes, Adds, PreSharedKeys.
func (g *Group) commitItems(o CommitOptions) ([]item, []message.ProposalOrRef, error) {
	own := g.s.own()
	var items []item
	var ors []message.ProposalOrRef
	for _, ref := range o.References {
		it, err := g.refItem(ref)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, it)
		ors = append(ors, message.ProposalOrRef{Type: message.ByReference, Ref: bytes.Clone(it.ref)})
	}
	if err := uniqueExtensions(o.Extensions); err != nil {
		return nil, nil, err
	}
	var props []*Proposal
	if o.SetExtensions {
		props = append(props, &Proposal{Type: message.ProposalGroupContextExtensions, Extensions: o.Extensions})
	}
	for _, l := range o.Remove {
		props = append(props, &Proposal{Type: message.ProposalRemove, Removed: l})
	}
	for _, b := range o.Add {
		kp, err := decodeKeyPackage(b)
		if err != nil {
			return nil, nil, err
		}
		props = append(props, &Proposal{Type: message.ProposalAdd, KeyPackage: kp})
	}
	for _, id := range o.PSKs {
		id, err := withNonce(id)
		if err != nil {
			return nil, nil, err
		}
		props = append(props, &Proposal{Type: message.ProposalPSK, PSK: id})
	}
	for _, p := range props {
		items = append(items, item{p: p, sender: own})
		ors = append(ors, message.ProposalOrRef{Type: message.ByValue, Proposal: p})
	}
	return items, ors, nil
}

// pathTemplate returns the template of the committer's new leaf and the
// signature key it is signed with.
func (g *Group) pathTemplate(o CommitOptions) (*LeafNode, ed25519.PrivateKey, error) {
	s := g.s
	if o.NoPath && (o.Leaf != nil || o.SignatureKey != nil) {
		return nil, nil, fmt.Errorf("%w: a new leaf needs a path", errs.ErrInvalidArgument)
	}
	if o.Leaf == nil {
		if o.SignatureKey != nil {
			return nil, nil, fmt.Errorf("%w: a new signature key needs a leaf template", errs.ErrInvalidArgument)
		}
		return s.tree.Leaf(s.own()), s.sig, nil
	}
	if err := uniqueExtensions(o.Leaf.Extensions); err != nil {
		return nil, nil, err
	}
	key := s.sig
	if o.SignatureKey != nil {
		key = o.SignatureKey
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), o.Leaf.SignatureKey) {
		return nil, nil, fmt.Errorf("%w: the leaf template's signature key does not match its private key", errs.ErrInvalidArgument)
	}
	return o.Leaf, key, nil
}

// ApplyPending makes this member's pending Commit the current epoch, once
// the Delivery Service has chosen it (RFC 9420 section 14).
func (g *Group) ApplyPending() error {
	if err := g.live(); err != nil {
		return err
	}
	if g.pending == nil {
		return errs.ErrPendingCommit
	}
	return g.advance(g.pending.next)
}

// DiscardPending deletes this member's pending Commit, when the Delivery
// Service chose another one (RFC 9420 section 14).
func (g *Group) DiscardPending() error {
	if err := g.live(); err != nil {
		return err
	}
	if g.pending == nil {
		return errs.ErrPendingCommit
	}
	if err := g.write(Batch{Delete: [][]byte{groupKey(g.s.ctx.GroupID, "pending")}}); err != nil {
		return err
	}
	g.pending.next.clear()
	g.pending = nil
	return nil
}
