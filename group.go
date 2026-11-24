package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/framing"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// Group is one member's view of an MLS group. It is not safe for concurrent
// use, and at most one Group per group id may be open on a Store; every
// change is one Store batch.
type Group struct {
	cfg     Config
	store   Store
	s       *state
	props   []*cached
	byRef   map[string]*cached
	pending *PendingCommit
	// prev is the previous epoch inside its window, nil when none is kept.
	prev *past
	// err is set once the Group cannot be used: closed, removed, or a Store
	// write that failed.
	err error
}

// errBroken is returned by every call after a failed Store write, which
// may have been applied in part or in full.
var errBroken = fmt.Errorf("%w: an earlier write failed; open the group again", errs.ErrStore)

func (g *Group) live() error {
	return g.err
}

// write applies b to the Store; after an error the Group is unusable, since
// the Store may hold the batch or not.
func (g *Group) write(b Batch) error {
	if err := writeBatch(g.store, b); err != nil {
		g.drop()
		g.err = errBroken
		return err
	}
	return nil
}

// GroupID returns the group id.
func (g *Group) GroupID() []byte {
	return bytes.Clone(g.s.ctx.GroupID)
}

// Epoch returns the current epoch.
func (g *Group) Epoch() uint64 {
	return g.s.ctx.Epoch
}

// OwnLeaf returns this member's leaf index.
func (g *Group) OwnLeaf() uint32 {
	return g.s.own()
}

// GroupContext returns the encoded GroupContext of the current epoch.
func (g *Group) GroupContext() []byte {
	return bytes.Clone(g.s.ctxBytes)
}

// Extensions returns a copy of the GroupContext extensions of the current
// epoch.
func (g *Group) Extensions() []Extension {
	out := cloneExtensions(g.s.ctx.Extensions)
	if out == nil {
		out = []Extension{}
	}
	return out
}

func cloneExtensions(exts []Extension) []Extension {
	var out []Extension
	for _, e := range exts {
		out = append(out, Extension{Type: e.Type, Data: bytes.Clone(e.Data)})
	}
	return out
}

// Tree returns a read-only view of the ratchet tree of the current epoch.
func (g *Group) Tree() TreeView {
	return TreeView{g.s.tree}
}

// Removed reports whether an applied Commit removed this member.
func (g *Group) Removed() bool {
	return errors.Is(g.err, errs.ErrRemoved)
}

// EpochAuthenticator returns the epoch authenticator (RFC 9420 section 8.7).
func (g *Group) EpochAuthenticator() ([]byte, error) {
	if err := g.live(); err != nil {
		return nil, err
	}
	return bytes.Clone(g.s.secrets.EpochAuthenticator), nil
}

// RatchetTree returns the encoded ratchet tree of the current epoch.
func (g *Group) RatchetTree() ([]byte, error) {
	if err := g.live(); err != nil {
		return nil, err
	}
	return g.s.tree.Marshal()
}

// Export derives an exported secret (RFC 9420 section 8.5).
func (g *Group) Export(label string, context []byte, length int) ([]byte, error) {
	if err := g.live(); err != nil {
		return nil, err
	}
	return schedule.Export(g.s.secrets.Exporter, label, context, length)
}

// BranchPSK returns the id and value of the resumption PSK of the current
// epoch with usage branch and a fresh nonce, for the first Commit of a
// successor group and its joiners (RFC 9420 section 11.3).
func (g *Group) BranchPSK() (*PSKID, []byte, error) {
	if err := g.live(); err != nil {
		return nil, nil, err
	}
	id, err := withNonce(&PSKID{Type: schedule.PSKResumption, Usage: schedule.UsageBranch, GroupID: bytes.Clone(g.s.ctx.GroupID), Epoch: g.s.ctx.Epoch})
	if err != nil {
		return nil, nil, err
	}
	return id, bytes.Clone(g.s.secrets.Resumption), nil
}

// Create starts a group with this member alone at epoch 0 (RFC 9420
// section 11). Create of one group id must not run concurrently with
// another Create, Join or Open of it on the same Store, nor with a Create
// or Join that uses the same KeyPackage, or both may seed a group with it.
func Create(st Store, o CreateOptions) (*Group, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	if len(o.KeyPackage) == 0 {
		return nil, fmt.Errorf("%w: no KeyPackage", errs.ErrInvalidArgument)
	}
	kp, err := decodeKeyPackage(o.KeyPackage)
	if err != nil {
		return nil, err
	}
	ref, err := kp.Ref()
	if err != nil {
		return nil, err
	}
	key := keyPackageKey(ref)
	b, err := get(st, key)
	if errors.Is(err, errs.ErrNotFound) {
		return nil, errs.ErrKeyPackageNotFound
	}
	if err != nil {
		return nil, err
	}
	rec, err := unmarshalKeyPackageRecord(b)
	clear(b)
	if err != nil {
		return nil, err
	}
	defer rec.clear()
	return create(st, o, rec.kp.LeafNode, rec.encPriv, rec.sig, key)
}

// create starts the group of Create from the creator's leaf and its private
// keys; consumed, when set, is the key of the KeyPackage record to delete in
// the same batch.
func create(st Store, o CreateOptions, leaf *LeafNode, encPriv []byte, sig ed25519.PrivateKey, consumed []byte) (*Group, error) {
	if err := uniqueExtensions(o.Extensions, leaf.Extensions); err != nil {
		return nil, err
	}
	gid := o.GroupID
	if gid == nil {
		gid = make([]byte, suite.Nh)
		rand.Read(gid) // crypto/rand.Read never fails since Go 1.24
	}
	if _, err := get(st, groupKey(gid, "meta")); !errors.Is(err, errs.ErrNotFound) {
		if err == nil {
			err = errs.ErrGroupExists
		}
		return nil, err
	}
	if len(sig) != ed25519.PrivateKeySize || !bytes.Equal(sig.Public().(ed25519.PublicKey), leaf.SignatureKey) {
		return nil, fmt.Errorf("%w: signature key does not match the leaf", errs.ErrInvalidArgument)
	}
	if pub, err := suite.PublicKey(encPriv); err != nil || !bytes.Equal(pub, leaf.EncryptionKey) {
		return nil, fmt.Errorf("%w: encryption key does not match the leaf", errs.ErrInvalidArgument)
	}
	ctx := &GroupContext{CipherSuite: suite.ID, GroupID: bytes.Clone(gid), Extensions: o.Extensions}
	t := tree.New(leaf.Clone())
	if err := o.checkLeaf(leaf, leafRule{source: tree.SourceKeyPackage, sending: true, event: EventKeyPackage}, ctx); err != nil {
		return nil, err
	}
	th, err := t.TreeHash()
	if err != nil {
		return nil, err
	}
	ctx.TreeHash = th
	ctx.ConfirmedTranscriptHash = []byte{}
	epochSecret := make([]byte, suite.Nh)
	rand.Read(epochSecret)
	secrets, err := schedule.FromEpochSecret(epochSecret)
	clear(epochSecret)
	if err != nil {
		return nil, err
	}
	tag := suite.MAC(secrets.Confirmation, ctx.ConfirmedTranscriptHash)
	clear(secrets.Confirmation)
	s := &state{tree: t, sig: bytes.Clone(sig), secrets: secrets,
		priv: &tree.Private{Leaf: 0, Keys: map[uint64][]byte{0: bytes.Clone(encPriv)}}}
	ok := false
	defer func() {
		if !ok {
			s.clear()
		}
	}()
	if s.interim, err = schedule.InterimTranscriptHash(ctx.ConfirmedTranscriptHash, tag); err != nil {
		return nil, err
	}
	if err := s.setContext(ctx); err != nil {
		return nil, err
	}
	if err := s.startKeys(o.keyOptions()); err != nil {
		return nil, err
	}
	var b Batch
	defer b.zero()
	if err := writeState(&b, nil, s, nil); err != nil {
		return nil, err
	}
	if consumed != nil {
		b.del(consumed)
	}
	if err := writeBatch(st, b); err != nil {
		return nil, err
	}
	ok = true
	return &Group{cfg: o.Config, store: st, s: s}, nil
}

// Open loads group gid from st. Only one Group per group id may be open at
// a time; after a failed write, Open reads what the Store holds.
func Open(st Store, gid []byte, cfg Config) (*Group, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	s, m, pruned, err := loadState(st, gid, cfg.keyOptions())
	if err != nil {
		return nil, err
	}
	g := &Group{cfg: cfg, store: st, s: s}
	if err := g.load(m); err != nil {
		g.Close()
		return nil, err
	}
	p, prunedPast, err := loadPast(st, s, cfg.keyOptions())
	if err != nil {
		g.Close()
		return nil, err
	}
	g.prev = p
	// Keys outside a smaller window than the stored one are deleted now, and
	// so is a previous epoch whose window has ended.
	var b Batch
	writeKeys(&b, gid, s.ctx.Epoch, pruned)
	if p != nil {
		if g.cfg.now().Before(p.end) {
			writeKeys(&b, gid, p.epoch, prunedPast)
		} else {
			for _, r := range prunedPast {
				clear(r.Value)
			}
			if err := writePastDelete(&b, gid, p, false); err != nil {
				g.Close()
				return nil, err
			}
			p.clear()
			g.prev = nil
		}
	}
	if len(b.Put) > 0 || len(b.Delete) > 0 {
		if err := g.write(b); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func (g *Group) load(m *meta) error {
	gid := g.s.ctx.GroupID
	for _, ref := range m.props {
		b, err := getRecord(g.store, propKey(gid, ref))
		if err != nil {
			return err
		}
		c, err := unmarshalCached(ref, b)
		clear(b)
		if err != nil {
			return err
		}
		g.setProps(append(g.props, c))
	}
	pb, err := get(g.store, groupKey(gid, "pending"))
	switch {
	case errors.Is(err, errs.ErrNotFound):
	case err != nil:
		return err
	default:
		g.pending, err = loadPending(g.s, pb)
		clear(pb)
		return err
	}
	return nil
}

// Result is what Process found in a message: a cached proposal, a staged
// Commit or application data.
type Result struct {
	// Epoch is the epoch of the message: the current one, or the previous
	// one for a late application message read inside the window.
	Epoch uint64
	// Sender is the leaf index of the sender.
	Sender uint32
	// ProposalRef is the reference of a proposal now cached.
	ProposalRef []byte
	// Commit is a Commit ready to Apply.
	Commit *StagedCommit
	// Application is the data of an application message.
	Application []byte
	// AuthenticatedData is the authenticated data of an application
	// message, as the Envelope returns it when one is set.
	AuthenticatedData []byte
}

// expireDue deletes the previous epoch once its window has ended, so it
// never outlives the window by more than the next call.
func (g *Group) expireDue() error {
	if g.prev != nil && !g.cfg.now().Before(g.prev.end) {
		return g.expire()
	}
	return nil
}

// Process verifies a message of the current epoch: a proposal is cached, a
// Commit is staged and changes nothing until Apply, and application data is
// returned. A PrivateMessage uses up its key only once its signature and
// the Envelope accepted it, in the same Store batch as the proposal; a
// Commit's key is deleted with its epoch by Apply.
func (g *Group) Process(msg []byte) (*Result, error) {
	if err := g.live(); err != nil {
		return nil, err
	}
	if err := g.expireDue(); err != nil {
		return nil, err
	}
	m, err := message.UnmarshalMLSMessage(msg)
	if err != nil {
		return nil, err
	}
	var groupID []byte
	var epoch uint64
	switch m.WireFormat {
	case message.WirePublic:
		groupID, epoch = m.Public.Content.GroupID, m.Public.Content.Epoch
	case message.WirePrivate:
		groupID, epoch = m.Private.GroupID, m.Private.Epoch
	default:
		return nil, fmt.Errorf("%w: wire format %d is not a group message", errs.ErrInvalidArgument, m.WireFormat)
	}
	s := g.s
	if !bytes.Equal(groupID, s.ctx.GroupID) {
		return nil, errs.ErrWrongGroup
	}
	if epoch < s.ctx.Epoch {
		// Only application data of the previous epoch is read, inside the
		// window; content_type is in the clear (RFC 9420 section 6.3).
		if g.prev != nil && epoch == g.prev.epoch && m.WireFormat == message.WirePrivate && m.Private.ContentType == message.ContentApplication {
			return g.processPast(m.Private)
		}
		return nil, errs.ErrWrongEpoch
	}
	if epoch > s.ctx.Epoch {
		return nil, errs.ErrFutureEpoch
	}
	var ac *message.AuthenticatedContent
	var lk *secrettree.Lookup
	if m.WireFormat == message.WirePrivate {
		ac, lk, err = framing.UnprotectPrivate(m.Private, s.secrets.SenderData, s.keys, func(l uint32) bool { return s.tree.Leaf(l) != nil })
		if err != nil {
			return nil, err
		}
		defer lk.Discard()
	} else {
		if ac, err = g.unprotectPublic(m.Public); err != nil {
			return nil, err
		}
	}
	sender := ac.Content.Sender.Index
	if err := framing.Verify(s.tree.Leaf(sender).SignatureKey, ac, s.ctxBytes); err != nil {
		return nil, err
	}
	aad := ac.Content.AuthenticatedData
	if lk != nil && g.cfg.Envelope != nil {
		if aad, err = g.cfg.Envelope.Unwrap(lk.Generation(), aad); err != nil {
			return nil, fmt.Errorf("%w: authenticated data: %w", errs.ErrMalformed, err)
		}
	}
	switch ac.Content.ContentType {
	case message.ContentApplication:
		if err := g.consume(lk, Batch{}); err != nil {
			return nil, err
		}
		return &Result{Epoch: s.ctx.Epoch, Sender: sender, Application: bytes.Clone(ac.Content.ApplicationData), AuthenticatedData: bytes.Clone(aad)}, nil
	case message.ContentProposal:
		if err := g.checkProposalOf(sender, ac.Content.Proposal); err != nil {
			return nil, g.refuse(lk, err)
		}
		ref, err := g.cache(ac, nil, lk)
		if err != nil {
			return nil, err
		}
		return &Result{Epoch: s.ctx.Epoch, Sender: sender, ProposalRef: ref}, nil
	}
	// A Commit, the only content type left. Its key is not used up here:
	// the member may stop before Apply and must then read the Commit again,
	// and Apply deletes the epoch's whole secret tree.
	sc, err := g.stage(ac)
	if err != nil {
		return nil, err
	}
	return &Result{Epoch: s.ctx.Epoch, Sender: sender, Commit: sc}, nil
}

// PeekSender returns the sender's leaf and generation named in the sender
// data of a PrivateMessage of the current epoch, which uses up no key and
// proves nothing: anyone who holds the epoch's secrets can write it. Catch-up
// reads archived messages in this order.
func (g *Group) PeekSender(msg []byte) (leaf, generation uint32, err error) {
	if err := g.live(); err != nil {
		return 0, 0, err
	}
	m, err := message.UnmarshalMLSMessage(msg)
	if err != nil {
		return 0, 0, err
	}
	if m.WireFormat != message.WirePrivate {
		return 0, 0, fmt.Errorf("%w: not a PrivateMessage", errs.ErrInvalidArgument)
	}
	if !bytes.Equal(m.Private.GroupID, g.s.ctx.GroupID) {
		return 0, 0, errs.ErrWrongGroup
	}
	if m.Private.Epoch != g.s.ctx.Epoch {
		return 0, 0, errs.ErrWrongEpoch
	}
	sd, err := framing.OpenSenderData(m.Private, g.s.secrets.SenderData)
	if err != nil {
		return 0, 0, err
	}
	if g.s.tree.Leaf(sd.Leaf) == nil {
		return 0, 0, fmt.Errorf("%w: sender data names blank leaf %d", errs.ErrUnknownSender, sd.Leaf)
	}
	return sd.Leaf, sd.Generation, nil
}

// unprotectPublic checks a member's PublicMessage handshake and its
// membership tag.
func (g *Group) unprotectPublic(pm *message.PublicMessage) (*message.AuthenticatedContent, error) {
	s := g.s
	sender := pm.Content.Sender
	if sender.Type != message.SenderMember {
		return nil, fmt.Errorf("%w: sender type %d", errs.ErrUnsupported, sender.Type)
	}
	if g.cfg.PrivateHandshakes {
		return nil, fmt.Errorf("%w: a handshake sent as a PublicMessage", errs.ErrPolicy)
	}
	if s.tree.Leaf(sender.Index) == nil {
		return nil, fmt.Errorf("%w: sender leaf %d is blank", errs.ErrUnknownSender, sender.Index)
	}
	return framing.UnprotectPublic(pm, s.secrets.Membership, s.ctxBytes)
}

// consume writes b with the secret tree change of lk (nil for none) in one
// batch and then commits lk (RFC 9420 section 9.2).
func (g *Group) consume(lk *secrettree.Lookup, b Batch) error {
	defer b.zero()
	if lk != nil {
		rs, err := g.s.keys.Changes(lk)
		if err != nil {
			return err
		}
		writeKeys(&b, g.s.ctx.GroupID, g.s.ctx.Epoch, rs)
	}
	if len(b.Put) == 0 && len(b.Delete) == 0 {
		return nil
	}
	if err := g.write(b); err != nil {
		return err
	}
	if lk == nil {
		return nil
	}
	return g.s.keys.Commit(lk)
}

// refuse uses up the key lk of an authentic proposal that the rules refuse,
// since it was decrypted (RFC 9420 section 9.2), and returns err.
func (g *Group) refuse(lk *secrettree.Lookup, err error) error {
	if e := g.consume(lk, Batch{}); e != nil {
		return e
	}
	return err
}

// checkProposalOf runs the checks of RFC 9420 section 12.1 and the Policy
// on a proposal of sender.
func (g *Group) checkProposalOf(sender uint32, p *Proposal) error {
	s := g.s
	if err := g.cfg.checkProposal(s, p, sender, sender == s.own()); err != nil {
		return err
	}
	v, err := proposalView(s, sender, p, false)
	if err != nil {
		return err
	}
	v.Cached = len(g.props)
	for _, c := range g.props {
		if c.sender() == sender {
			v.FromSender++
		}
	}
	if err := g.cfg.Policy.CheckProposal(v); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrPolicy, err)
	}
	return nil
}

// cache stores a checked proposal with one Store write, which also uses up
// the key lk of a PrivateMessage (nil for none).
func (g *Group) cache(ac *message.AuthenticatedContent, leafPriv []byte, lk *secrettree.Lookup) ([]byte, error) {
	s := g.s
	ref, err := ac.ProposalRef()
	if err != nil {
		return nil, g.refuse(lk, err)
	}
	if g.cachedProposal(ref) != nil {
		return ref, g.consume(lk, Batch{})
	}
	c := &cached{ref: ref, ac: ac, leafPriv: leafPriv}
	props := append(append([]*cached(nil), g.props...), c)
	var b Batch
	if err := writeProps(&b, s.ctx.GroupID, g.props, props); err != nil {
		b.zero()
		return nil, g.refuse(lk, err)
	}
	if err := writeMeta(&b, s, props); err != nil {
		b.zero()
		return nil, g.refuse(lk, err)
	}
	if err := g.consume(lk, b); err != nil {
		return nil, err
	}
	g.setProps(props)
	return ref, nil
}

// propose checks, signs, protects and caches a proposal of this member;
// a proposal the rules refuse uses no key and writes nothing.
func (g *Group) propose(p *Proposal, leafPriv []byte) ([]byte, error) {
	if err := g.live(); err != nil {
		return nil, err
	}
	s := g.s
	if err := g.checkProposalOf(s.own(), p); err != nil {
		return nil, err
	}
	c := &message.FramedContent{
		GroupID:     s.ctx.GroupID,
		Epoch:       s.ctx.Epoch,
		Sender:      message.Sender{Type: message.SenderMember, Index: s.own()},
		ContentType: message.ContentProposal,
		Proposal:    p,
	}
	wf, lk, err := g.prepare(c)
	if err != nil {
		return nil, err
	}
	defer lk.Discard()
	ac, err := g.sign(wf, c)
	if err != nil {
		return nil, err
	}
	msg, err := g.seal(ac, lk)
	if err != nil {
		return nil, err
	}
	if _, err := g.cache(ac, leafPriv, lk); err != nil {
		return nil, err
	}
	return msg, nil
}

// prepare returns the wire format of content c and, for a PrivateMessage,
// the Lookup of this member's next key with the Envelope applied to the
// authenticated data of c.
func (g *Group) prepare(c *message.FramedContent) (uint16, *secrettree.Lookup, error) {
	if c.ContentType != message.ContentApplication && !g.cfg.PrivateHandshakes {
		return message.WirePublic, nil, nil
	}
	lk, err := g.s.keys.PeekNext(g.s.own(), framing.RatchetKind(c.ContentType))
	if err != nil {
		return 0, nil, err
	}
	if g.cfg.Envelope != nil {
		ad, err := g.cfg.Envelope.Wrap(lk.Generation(), c.AuthenticatedData)
		if err != nil {
			lk.Discard()
			return 0, nil, fmt.Errorf("%w: Envelope: %w", errs.ErrInvalidArgument, err)
		}
		c.AuthenticatedData = ad
	}
	return message.WirePrivate, lk, nil
}

func (g *Group) sign(wf uint16, c *message.FramedContent) (*message.AuthenticatedContent, error) {
	sig, err := framing.Sign(g.s.sig, wf, c, g.s.ctxBytes)
	if err != nil {
		return nil, err
	}
	return &message.AuthenticatedContent{WireFormat: wf, Content: c, Auth: message.AuthData{Signature: sig}}, nil
}

// seal returns ac as an MLSMessage: a PrivateMessage under lk, or a
// PublicMessage when lk is nil.
func (g *Group) seal(ac *message.AuthenticatedContent, lk *secrettree.Lookup) ([]byte, error) {
	s := g.s
	if lk == nil {
		pm, err := framing.ProtectPublic(ac, s.secrets.Membership, s.ctxBytes)
		if err != nil {
			return nil, err
		}
		return (&message.MLSMessage{WireFormat: message.WirePublic, Public: pm}).Marshal()
	}
	pm, err := framing.ProtectPrivate(ac, s.secrets.SenderData, lk)
	if err != nil {
		return nil, err
	}
	return (&message.MLSMessage{WireFormat: message.WirePrivate, Private: pm}).Marshal()
}

// Encrypt protects application data as a PrivateMessage of the current
// epoch, with aad as its authenticated data (RFC 9420 section 6.3). It is
// refused while proposals are cached: a Commit comes first (RFC 9420
// section 12.4).
func (g *Group) Encrypt(data, aad []byte) ([]byte, error) {
	if err := g.live(); err != nil {
		return nil, err
	}
	if err := g.expireDue(); err != nil {
		return nil, err
	}
	if len(g.props) > 0 {
		return nil, errs.ErrPendingProposals
	}
	s := g.s
	c := &message.FramedContent{
		GroupID:           s.ctx.GroupID,
		Epoch:             s.ctx.Epoch,
		Sender:            message.Sender{Type: message.SenderMember, Index: s.own()},
		AuthenticatedData: bytes.Clone(aad),
		ContentType:       message.ContentApplication,
		ApplicationData:   data,
	}
	wf, lk, err := g.prepare(c)
	if err != nil {
		return nil, err
	}
	defer lk.Discard()
	ac, err := g.sign(wf, c)
	if err != nil {
		return nil, err
	}
	msg, err := g.seal(ac, lk)
	if err != nil {
		return nil, err
	}
	if err := g.consume(lk, Batch{}); err != nil {
		return nil, err
	}
	return msg, nil
}

// CachedProposals returns the references of the proposals cached in this
// epoch, this member's own included, in the order they arrived.
func (g *Group) CachedProposals() [][]byte {
	out := make([][]byte, len(g.props))
	for i, c := range g.props {
		out[i] = bytes.Clone(c.ref)
	}
	return out
}

// ProposeAdd proposes to add the client of an encoded KeyPackage.
func (g *Group) ProposeAdd(keyPackage []byte) ([]byte, error) {
	kp, err := decodeKeyPackage(keyPackage)
	if err != nil {
		return nil, err
	}
	return g.propose(&Proposal{Type: message.ProposalAdd, KeyPackage: kp}, nil)
}

// ProposeRemove proposes to remove the member at leaf.
func (g *Group) ProposeRemove(leaf uint32) ([]byte, error) {
	return g.propose(&Proposal{Type: message.ProposalRemove, Removed: leaf}, nil)
}

// ProposePSK proposes to inject a pre-shared key; nonce nil means 32
// random bytes (RFC 9420 section 12.1.4).
func (g *Group) ProposePSK(id *PSKID) ([]byte, error) {
	id, err := withNonce(id)
	if err != nil {
		return nil, err
	}
	return g.propose(&Proposal{Type: message.ProposalPSK, PSK: id}, nil)
}

func withNonce(id *PSKID) (*PSKID, error) {
	if id == nil {
		return nil, fmt.Errorf("%w: no PSK id", errs.ErrInvalidArgument)
	}
	if id.Nonce != nil {
		return id, nil
	}
	c := *id
	c.Nonce = make([]byte, suite.Nh)
	rand.Read(c.Nonce)
	return &c, nil
}

// ProposeGroupContextExtensions proposes to replace the GroupContext extensions.
func (g *Group) ProposeGroupContextExtensions(exts []Extension) ([]byte, error) {
	if err := uniqueExtensions(exts); err != nil {
		return nil, err
	}
	return g.propose(&Proposal{Type: message.ProposalGroupContextExtensions, Extensions: exts}, nil)
}

// ProposeUpdate proposes to replace this member's leaf with a fresh
// encryption key; template, when not nil, gives a new credential,
// capabilities or extensions with the same signature key.
func (g *Group) ProposeUpdate(template *LeafNode) ([]byte, error) {
	if err := g.live(); err != nil {
		return nil, err
	}
	s := g.s
	if template == nil {
		template = s.tree.Leaf(s.own())
	}
	if !bytes.Equal(template.SignatureKey, s.tree.Leaf(s.own()).SignatureKey) {
		return nil, fmt.Errorf("%w: an Update keeps the signature key", errs.ErrInvalidArgument)
	}
	if err := uniqueExtensions(template.Extensions); err != nil {
		return nil, err
	}
	priv, pub, err := suite.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	leaf := template.Clone()
	leaf.EncryptionKey = pub
	leaf.Source, leaf.NotBefore, leaf.NotAfter, leaf.ParentHash = tree.SourceUpdate, 0, 0, nil
	if err := leaf.Sign(s.sig, s.ctx.GroupID, s.own()); err != nil {
		clear(priv)
		return nil, err
	}
	out, err := g.propose(&Proposal{Type: message.ProposalUpdate, LeafNode: leaf}, priv)
	if err != nil {
		clear(priv)
	}
	return out, err
}

func decodeKeyPackage(b []byte) (*message.KeyPackage, error) {
	m, err := message.UnmarshalMLSMessage(b)
	if err != nil {
		return nil, err
	}
	if m.WireFormat != message.WireKeyPackage {
		return nil, fmt.Errorf("%w: wire format %d is not a KeyPackage", errs.ErrInvalidArgument, m.WireFormat)
	}
	return m.KeyPackage, nil
}

// Close zeroes the secrets this Group holds in memory. Later calls that
// use a secret or change the group (Process, Apply, Commit, the Propose
// calls, Encrypt, Export, EpochAuthenticator, RatchetTree, ApplyPending,
// DiscardPending) return ErrClosed; GroupID, Epoch, OwnLeaf, GroupContext,
// Extensions and Tree, which hold no secret, keep returning the last
// epoch's values, CachedProposals is empty and Pending is nil.
func (g *Group) Close() {
	if g.err == nil {
		g.drop()
		g.err = errs.ErrClosed
	}
}
