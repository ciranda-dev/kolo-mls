package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
	"github.com/ciranda-dev/kolo-mls/internal/treemath"
)

// keyPackageRecord is a KeyPackage of this client with its private keys,
// stored until a Welcome uses it.
type keyPackageRecord struct {
	kp       *message.KeyPackage
	initPriv []byte
	encPriv  []byte
	sig      ed25519.PrivateKey
}

func (r *keyPackageRecord) clear() {
	clear(r.initPriv)
	clear(r.encPriv)
	clear(r.sig)
}

func (r *keyPackageRecord) marshal() ([]byte, error) {
	var w tls.Writer
	w.U8(stateVersion)
	r.kp.Write(&w)
	w.Opaque(r.initPriv)
	w.Opaque(r.encPriv)
	seed := r.sig.Seed()
	w.Opaque(seed)
	clear(seed)
	return w.Bytes()
}

func unmarshalKeyPackageRecord(b []byte) (*keyPackageRecord, error) {
	var r keyPackageRecord
	err := tls.Decode(b, func(rd *tls.Reader) error {
		v, err := rd.U8()
		if err != nil {
			return err
		}
		if v != stateVersion {
			return fmt.Errorf("%w: stored state version %d", errs.ErrUnsupported, v)
		}
		if r.kp, err = message.ReadKeyPackage(rd); err != nil {
			return err
		}
		if r.initPriv, err = rd.Opaque(); err != nil {
			return err
		}
		if r.encPriv, err = rd.Opaque(); err != nil {
			return err
		}
		seed, err := rd.Opaque()
		if err != nil {
			return err
		}
		defer clear(seed)
		if len(seed) != ed25519.SeedSize {
			return fmt.Errorf("%w: stored signature key", errs.ErrMalformed)
		}
		r.sig = ed25519.NewKeyFromSeed(seed)
		return nil
	})
	if err != nil {
		r.clear()
		return nil, err
	}
	return &r, nil
}

// storeKeyPackage stores kp with its private keys for a later Join and
// returns kp as an encoded MLSMessage.
func storeKeyPackage(st Store, r *keyPackageRecord) ([]byte, error) {
	ref, err := r.kp.Ref()
	if err != nil {
		return nil, err
	}
	rec, err := r.marshal()
	if err != nil {
		return nil, err
	}
	if err := writeBatch(st, Batch{Put: []KV{{Key: keyPackageKey(ref), Value: rec}}}); err != nil {
		return nil, err
	}
	return (&message.MLSMessage{WireFormat: message.WireKeyPackage, KeyPackage: r.kp}).Marshal()
}

// KeyPackageOptions are the parameters of NewKeyPackage.
type KeyPackageOptions struct {
	// Credential is the client's credential.
	Credential Credential
	// SignatureKey signs the KeyPackage; its public key goes in the leaf.
	SignatureKey ed25519.PrivateKey
	// Capabilities of the leaf; version mls10, the cipher suite and the
	// credential's type are added when missing.
	Capabilities Capabilities
	// LeafExtensions and Extensions are the leaf's and the KeyPackage's.
	LeafExtensions []Extension
	Extensions     []Extension
	// Lifetime is the time from now to the end of validity, which starts one
	// hour before now; zero means DefaultKeyPackageLifetime.
	Lifetime time.Duration
	// Now gives the current time; nil means time.Now.
	Now func() time.Time
}

func addMissing(l []uint16, v uint16) []uint16 {
	l = slices.Clone(l)
	if slices.Contains(l, v) {
		return l
	}
	return append(l, v)
}

// NewKeyPackage creates a KeyPackage with fresh init and leaf keys, stores
// its private keys in st for Join, and returns it as an encoded MLSMessage
// (RFC 9420 section 10). It seeds one group: Create and Join that use it
// must not run concurrently.
func NewKeyPackage(st Store, o KeyPackageOptions) ([]byte, error) {
	if len(o.SignatureKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signature key size", errs.ErrInvalidArgument)
	}
	if err := uniqueExtensions(o.LeafExtensions, o.Extensions); err != nil {
		return nil, err
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	life := o.Lifetime
	if life == 0 {
		life = DefaultKeyPackageLifetime
	}
	if life < 0 {
		return nil, fmt.Errorf("%w: negative lifetime", errs.ErrInvalidArgument)
	}
	t := now()
	initPriv, initPub, err := suite.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	encPriv, encPub, err := suite.GenerateKeyPair()
	if err != nil {
		clear(initPriv)
		return nil, err
	}
	caps := o.Capabilities
	caps.Versions = addMissing(caps.Versions, schedule.MLS10)
	caps.CipherSuites = addMissing(caps.CipherSuites, suite.ID)
	caps.Credentials = addMissing(caps.Credentials, o.Credential.Type)
	ext := greaseCapabilities(&caps)
	leaf := &LeafNode{
		EncryptionKey: encPub,
		SignatureKey:  o.SignatureKey.Public().(ed25519.PublicKey),
		Credential:    o.Credential,
		Capabilities:  caps,
		Source:        tree.SourceKeyPackage,
		NotBefore:     uint64(max(0, t.Add(-time.Hour).Unix())),
		NotAfter:      uint64(max(0, t.Add(life).Unix())),
		Extensions:    withGrease(o.LeafExtensions, ext),
	}
	r := &keyPackageRecord{initPriv: initPriv, encPriv: encPriv, sig: bytes.Clone(o.SignatureKey)}
	defer r.clear()
	if err := leaf.Sign(o.SignatureKey, nil, 0); err != nil {
		return nil, err
	}
	r.kp = &message.KeyPackage{Version: schedule.MLS10, CipherSuite: suite.ID, InitKey: initPub, LeafNode: leaf, Extensions: withGrease(o.Extensions, ext)}
	tbs, err := r.kp.TBS()
	if err != nil {
		return nil, err
	}
	if r.kp.Signature, err = suite.SignWithLabel(o.SignatureKey, "KeyPackageTBS", tbs); err != nil {
		return nil, err
	}
	return storeKeyPackage(st, r)
}

// DeleteKeyPackage deletes the private keys of an unused KeyPackage of this
// client, given as an encoded MLSMessage.
func DeleteKeyPackage(st Store, keyPackage []byte) error {
	kp, err := decodeKeyPackage(keyPackage)
	if err != nil {
		return err
	}
	ref, err := kp.Ref()
	if err != nil {
		return err
	}
	return writeBatch(st, Batch{Delete: [][]byte{keyPackageKey(ref)}})
}

func invalidWelcome(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errs.ErrInvalidWelcome, fmt.Sprintf(format, a...))
}

// Join processes a Welcome with this client's stored KeyPackage and joins
// the group (RFC 9420 section 12.4.3.1). ratchetTree is the encoded tree when
// the Welcome's GroupInfo does not carry it. Join of one group id must not
// run concurrently with another Create, Join or Open of it on the same
// Store, nor with a Create or Join that uses the same KeyPackage.
func Join(st Store, welcomeMsg, ratchetTree []byte, o JoinOptions) (*Group, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	m, err := message.UnmarshalMLSMessage(welcomeMsg)
	if err != nil {
		return nil, err
	}
	if m.WireFormat != message.WireWelcome {
		return nil, fmt.Errorf("%w: wire format %d is not a Welcome", errs.ErrInvalidArgument, m.WireFormat)
	}
	w := m.Welcome
	if w.CipherSuite != suite.ID {
		return nil, fmt.Errorf("%w: cipher suite %#04x", errs.ErrUnsupported, w.CipherSuite)
	}
	var rec *keyPackageRecord
	var entry message.EncryptedGroupSecrets
	for _, e := range w.Secrets {
		if len(e.NewMember) != suite.Nh {
			continue
		}
		b, err := get(st, keyPackageKey(e.NewMember))
		if errors.Is(err, errs.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		rec, err = unmarshalKeyPackageRecord(b)
		clear(b)
		if err != nil {
			return nil, err
		}
		entry = e
		break
	}
	if rec == nil {
		return nil, errs.ErrKeyPackageNotFound
	}
	defer rec.clear()
	if rec.kp.CipherSuite != w.CipherSuite {
		return nil, invalidWelcome("KeyPackage cipher suite differs from the Welcome's")
	}
	gsb, err := suite.DecryptWithLabel(rec.initPriv, "Welcome", w.EncryptedGroupInfo, entry.Secrets.KEMOutput, entry.Secrets.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: group secrets: %w", errs.ErrInvalidWelcome, err)
	}
	gs, err := message.UnmarshalGroupSecrets(gsb)
	clear(gsb)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errs.ErrInvalidWelcome, err)
	}
	defer gs.Clear()
	if len(gs.JoinerSecret) != suite.Nh || (gs.HasPathSecret && len(gs.PathSecret) != suite.Nh) {
		return nil, invalidWelcome("joiner or path secret size")
	}
	resumption := 0
	for _, id := range gs.PSKs {
		if id.Type != schedule.PSKResumption || id.Usage == schedule.UsageApplication {
			continue
		}
		resumption++
		if id.Usage == schedule.UsageReinit {
			return nil, fmt.Errorf("%w: reinitialization", errs.ErrUnsupported)
		}
		if id.Usage != schedule.UsageBranch {
			return nil, invalidWelcome("resumption PSK usage %d", id.Usage)
		}
	}
	if resumption > 1 {
		return nil, invalidWelcome("more than one reinit or branch PSK")
	}
	psks, err := o.pskValues(nil, gs.PSKs)
	if err != nil {
		return nil, err
	}
	pskSecret, err := schedule.PSKSecret(gs.PSKs, psks)
	clearAll(psks)
	if err != nil {
		return nil, err
	}
	defer clear(pskSecret)
	gi, err := decryptGroupInfo(w, gs.JoinerSecret, pskSecret)
	if err != nil {
		return nil, err
	}
	ctx := gi.GroupContext
	if resumption > 0 && ctx.Epoch != 1 {
		return nil, invalidWelcome("a branch PSK in a Welcome for epoch %d, not 1", ctx.Epoch)
	}
	if ctx.CipherSuite != rec.kp.CipherSuite {
		return nil, invalidWelcome("GroupInfo cipher suite differs from the KeyPackage's")
	}
	if _, err := get(st, groupKey(ctx.GroupID, "meta")); !errors.Is(err, errs.ErrNotFound) {
		if err == nil {
			err = errs.ErrGroupExists
		}
		return nil, err
	}
	// The key schedule needs no tree (RFC 9420 section 8), so a tree kept
	// under an exported key can be fetched now.
	s, err := joinState(ctx, gs.JoinerSecret, pskSecret)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			s.clear()
		}
	}()
	if ratchetTree == nil && o.Tree != nil && !hasTreeExtension(gi) {
		export := func(label string, context []byte, length int) ([]byte, error) {
			return schedule.Export(s.secrets.Exporter, label, context, length)
		}
		if ratchetTree, err = o.Tree(export); err != nil {
			return nil, err
		}
	}
	t, err := o.joinTree(gi, ratchetTree)
	if err != nil {
		return nil, err
	}
	signer := t.Leaf(gi.Signer)
	if signer == nil {
		return nil, invalidWelcome("GroupInfo signer %d is blank", gi.Signer)
	}
	tbs, err := gi.TBS()
	if err != nil {
		return nil, err
	}
	if !suite.VerifyWithLabel(signer.SignatureKey, "GroupInfoTBS", tbs, gi.Signature) {
		return nil, fmt.Errorf("%w: %w: GroupInfo", errs.ErrInvalidWelcome, errs.ErrSignature)
	}
	// The member checks cover this client's own leaf, so they also check
	// that it supports every GroupContext extension (RFC 9420 section 13.4).
	if err := o.checkJoinTree(t, ctx); err != nil {
		return nil, err
	}
	own, err := findLeaf(t, rec.kp.LeafNode)
	if err != nil {
		return nil, err
	}
	priv := &tree.Private{Leaf: own, Keys: map[uint64][]byte{2 * uint64(own): bytes.Clone(rec.encPriv)}}
	s.tree, s.priv, s.sig = t, priv, bytes.Clone(rec.sig)
	if err := setPathSecrets(t, priv, own, gi.Signer, gs); err != nil {
		return nil, err
	}
	if err := s.confirm(gi.ConfirmationTag); err != nil {
		return nil, err
	}
	jctx, err := cloneContext(ctx)
	if err != nil {
		return nil, err
	}
	var ids []*PSKID
	for _, id := range gs.PSKs {
		c := *id
		c.ID, c.GroupID, c.Nonce = bytes.Clone(id.ID), bytes.Clone(id.GroupID), bytes.Clone(id.Nonce)
		ids = append(ids, &c)
	}
	var infoExts []Extension
	for _, e := range gi.Extensions {
		infoExts = append(infoExts, Extension{Type: e.Type, Data: bytes.Clone(e.Data)})
	}
	if err := o.Policy.CheckJoin(JoinView{Context: jctx, Tree: TreeView{t}, Signer: gi.Signer, PSKs: ids, InfoExtensions: infoExts}); err != nil {
		return nil, fmt.Errorf("%w: %w", errs.ErrPolicy, err)
	}
	ref, err := rec.kp.Ref()
	if err != nil {
		return nil, err
	}
	if err := s.startKeys(o.keyOptions()); err != nil {
		return nil, err
	}
	var b Batch
	if err := writeState(&b, nil, s, nil); err != nil {
		return nil, err
	}
	// The KeyPackage's private keys go in the same write (RFC 9750 section 5.1).
	b.del(keyPackageKey(ref))
	if err := writeBatch(st, b); err != nil {
		return nil, err
	}
	ok = true
	return &Group{cfg: o.Config, store: st, s: s}, nil
}

func hasTreeExtension(gi *message.GroupInfo) bool {
	for _, e := range gi.Extensions {
		if e.Type == message.ExtRatchetTree {
			return true
		}
	}
	return false
}

// decryptGroupInfo decrypts the GroupInfo of a Welcome with the welcome key
// and nonce (RFC 9420 section 12.4.3.1).
func decryptGroupInfo(w *message.Welcome, joiner, pskSecret []byte) (*message.GroupInfo, error) {
	ws, err := schedule.WelcomeSecret(joiner, pskSecret)
	if err != nil {
		return nil, err
	}
	defer clear(ws)
	key, err := suite.ExpandWithLabel(ws, "key", nil, suite.Nk)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	nonce, err := suite.ExpandWithLabel(ws, "nonce", nil, suite.Nn)
	if err != nil {
		return nil, err
	}
	// welcome.json decrypts only with an empty AAD; RFC 9420 section
	// 12.4.3.1 names none.
	gib, err := suite.Open(key, nonce, nil, w.EncryptedGroupInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: GroupInfo: %w", errs.ErrInvalidWelcome, err)
	}
	gi, err := message.UnmarshalGroupInfo(gib)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errs.ErrInvalidWelcome, err)
	}
	return gi, nil
}

// joinTree returns the ratchet tree from the GroupInfo's ratchet_tree
// extension or from the caller, within MaxTreeBytes.
func (o *JoinOptions) joinTree(gi *message.GroupInfo, given []byte) (*tree.Tree, error) {
	enc := given
	for _, e := range gi.Extensions {
		if e.Type == message.ExtRatchetTree {
			if given != nil {
				return nil, fmt.Errorf("%w: a ratchet tree both in the Welcome and given", errs.ErrInvalidArgument)
			}
			enc = e.Data
		}
	}
	if enc == nil {
		return nil, fmt.Errorf("%w: no ratchet tree in the Welcome and none given", errs.ErrInvalidArgument)
	}
	limit := o.MaxTreeBytes
	if limit == 0 {
		limit = DefaultMaxTreeBytes
	}
	if limit > 0 && len(enc) > limit {
		return nil, fmt.Errorf("%w: ratchet tree of %d bytes, above MaxTreeBytes %d", errs.ErrInvalidTree, len(enc), limit)
	}
	return tree.UnmarshalTree(enc)
}

// checkJoinTree runs the tree checks of RFC 9420 section 12.4.3.1.
func (c *Config) checkJoinTree(t *tree.Tree, ctx *GroupContext) error {
	th, err := t.TreeHash()
	if err != nil {
		return err
	}
	if !bytes.Equal(th, ctx.TreeHash) {
		return fmt.Errorf("%w: tree hash differs from the GroupInfo's", errs.ErrInvalidTree)
	}
	if err := t.Verify(ctx.GroupID); err != nil {
		return err
	}
	for _, x := range t.NonBlank() {
		n := t.Node(x).Leaf
		if n == nil {
			continue
		}
		rule := leafRule{source: n.Source, index: uint32(x / 2), event: EventJoin, skipSignature: true}
		if err := c.checkLeaf(n, rule, ctx); err != nil {
			return fmt.Errorf("%w: leaf %d: %w", errs.ErrInvalidTree, x/2, err)
		}
	}
	if err := checkMembers(t, ctx, true); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrInvalidTree, err)
	}
	return nil
}

func findLeaf(t *tree.Tree, own *LeafNode) (uint32, error) {
	var w tls.Writer
	own.Write(&w)
	want, err := w.Bytes()
	if err != nil {
		return 0, err
	}
	for _, x := range t.NonBlank() {
		n := t.Node(x).Leaf
		if n == nil || !bytes.Equal(n.Signature, own.Signature) {
			continue
		}
		var w tls.Writer
		n.Write(&w)
		if got, err := w.Bytes(); err == nil && bytes.Equal(got, want) {
			return uint32(x / 2), nil
		}
	}
	return 0, invalidWelcome("no leaf is identical to the KeyPackage's")
}

// setPathSecrets derives one key per non-blank node from the common ancestor
// of own and signer to the root, as the committer's filtered direct path has
// them, and checks each against its node (RFC 9420 section 12.4.3.1).
func setPathSecrets(t *tree.Tree, priv *tree.Private, own, signer uint32, gs *message.GroupSecrets) error {
	if gs.HasPathSecret {
		x := treemath.CommonAncestor(2*uint64(own), 2*uint64(signer))
		if own == signer || t.Node(x).Blank() {
			return invalidWelcome("path secret for a blank or missing common ancestor")
		}
		d, err := treemath.DirectPath(2*uint64(own), t.Leaves())
		if err != nil {
			return err
		}
		k := slices.Index(d, x)
		if k < 0 {
			return invalidWelcome("common ancestor not on the direct path")
		}
		ps := bytes.Clone(gs.PathSecret)
		defer func() { clear(ps) }()
		for _, y := range d[k:] {
			if t.Node(y).Blank() {
				continue
			}
			if err := priv.SetPathSecret(y, ps); err != nil {
				return err
			}
			next, err := suite.DeriveSecret(ps, "path")
			if err != nil {
				return err
			}
			clear(ps)
			ps = next
		}
	}
	if err := priv.Check(t); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrInvalidWelcome, err)
	}
	return nil
}

// joinState derives the epoch secrets of a joiner; confirm checks them.
func joinState(ctx *GroupContext, joiner, pskSecret []byte) (*state, error) {
	s := &state{}
	if err := s.setContext(ctx); err != nil {
		return nil, err
	}
	ws, secrets, err := schedule.Epoch(joiner, pskSecret, s.ctxBytes)
	if err != nil {
		return nil, err
	}
	clear(ws)
	s.secrets = secrets
	return s, nil
}

// confirm checks the GroupInfo's confirmation tag of a joiner's state and
// computes the interim transcript hash.
func (s *state) confirm(tag []byte) error {
	if !suite.VerifyMAC(s.secrets.Confirmation, s.ctx.ConfirmedTranscriptHash, tag) {
		return fmt.Errorf("%w: %w", errs.ErrInvalidWelcome, errs.ErrConfirmationTag)
	}
	clear(s.secrets.Confirmation)
	var err error
	s.interim, err = schedule.InterimTranscriptHash(s.ctx.ConfirmedTranscriptHash, tag)
	return err
}
