// Package crosscheck drives kolo-mls for interoperability runs against other
// MLS implementations (RFC 9420, cipher suite 0x0001). A Client answers the
// operations of the MLS working group's interop client interface, one JSON
// object per line, with basic credentials and no rule beyond RFC 9420; an
// RPC front end outside this repository relays them.
package crosscheck

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"time"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// errUnsupported is returned for operations outside the cross-check scope
// (external joins, reinitialization, external senders).
var errUnsupported = errors.New("crosscheck: unsupported operation")

// resumptionPSKs is how many past epochs' resumption PSKs each member keeps.
const resumptionPSKs = 32

// maxLeafLifetime is the maximum leaf lifetime the members agree on (RFC 9420
// section 7.2 leaves it to the application): the longest default KeyPackage
// lifetime among the implementations compared, 365 days and one hour.
const maxLeafLifetime = 365*24*time.Hour + time.Hour

type auth struct{}

func (auth) Validate(c tree.Credential, _ []byte, _ kolomls.Event) error {
	if c.Type != tree.CredentialBasic {
		return fmt.Errorf("crosscheck: credential type %#04x", c.Type)
	}
	return nil
}

func (auth) Successor(prev, next tree.Credential) error { return nil }

func (auth) ClientID(c tree.Credential) ([]byte, error) { return c.Identity, nil }

type rfcPolicy struct{}

func (rfcPolicy) CheckProposal(kolomls.ProposalView) error { return nil }
func (rfcPolicy) CheckCommit(kolomls.CommitView) error     { return nil }
func (rfcPolicy) CheckJoin(kolomls.JoinView) error         { return nil }

// branchPolicy is rfcPolicy for joining a branch: every leaf of the new
// group must match a member of the old one by identity (RFC 9420 section
// 11.3).
type branchPolicy struct {
	rfcPolicy
	old map[string]bool
}

func (p branchPolicy) CheckJoin(v kolomls.JoinView) error {
	for _, l := range v.Tree.Members() {
		if !p.old[string(v.Tree.Leaf(l).Credential.Identity)] {
			return fmt.Errorf("crosscheck: branch member %q is not in the old group", v.Tree.Leaf(l).Credential.Identity)
		}
	}
	return nil
}

func identities(g *kolomls.Group) map[string]bool {
	ids := map[string]bool{}
	t := g.Tree()
	for _, l := range t.Members() {
		ids[string(t.Leaf(l).Credential.Identity)] = true
	}
	return ids
}

// psks serves external PSKs by id and resumption PSKs of other groups (the
// branch case) by group id and epoch; a group's own past resumption PSKs
// come from its state.
type psks struct {
	external   map[string][]byte
	resumption map[string][]byte
}

func newPSKs() *psks {
	return &psks{external: map[string][]byte{}, resumption: map[string][]byte{}}
}

func resumptionKey(gid []byte, epoch uint64) string {
	return hex.EncodeToString(gid) + "/" + strconv.FormatUint(epoch, 10)
}

func (p *psks) PSK(id *schedule.PSKID) ([]byte, error) {
	var v []byte
	var ok bool
	switch id.Type {
	case schedule.PSKExternal:
		v, ok = p.external[string(id.ID)]
	case schedule.PSKResumption:
		v, ok = p.resumption[resumptionKey(id.GroupID, id.Epoch)]
	}
	if !ok {
		return nil, errs.ErrNotFound
	}
	return bytes.Clone(v), nil
}

func (p *psks) clone() *psks {
	return &psks{external: maps.Clone(p.external), resumption: maps.Clone(p.resumption)}
}

// transaction is a KeyPackage waiting for a Welcome.
type transaction struct {
	st   *store
	sig  ed25519.PrivateKey
	id   []byte
	psks *psks
}

// member is one member's state in one group.
type member struct {
	g    *kolomls.Group
	st   *store
	sig  ed25519.PrivateKey
	id   []byte
	psks *psks
	cfg  kolomls.Config
	// sent maps this member's proposals of the epoch to their references,
	// since a member does not process its own messages.
	sent map[string][]byte
}

// Client holds every state and transaction of one interop client.
type Client struct {
	next  uint32
	txs   map[uint32]*transaction
	state map[uint32]*member
}

// NewClient returns an empty Client.
func NewClient() *Client {
	return &Client{txs: map[uint32]*transaction{}, state: map[uint32]*member{}}
}

func (c *Client) newID() uint32 {
	c.next++
	return c.next
}

func config(p *psks, encrypt bool) kolomls.Config {
	return kolomls.Config{
		Authenticator:     auth{},
		Policy:            rfcPolicy{},
		PSKs:              p,
		ResumptionPSKs:    resumptionPSKs,
		MaxLeafLifetime:   maxLeafLifetime,
		PrivateHandshakes: encrypt,
	}
}

func (c *Client) member(id uint32) (*member, error) {
	m, ok := c.state[id]
	if !ok {
		return nil, fmt.Errorf("crosscheck: unknown state %d", id)
	}
	return m, nil
}

func (c *Client) add(m *member) uint32 {
	m.sent = map[string][]byte{}
	id := c.newID()
	c.state[id] = m
	return id
}

func checkSuite(cs uint32) error {
	if cs != uint32(suite.ID) {
		return fmt.Errorf("%w: cipher suite %d", errUnsupported, cs)
	}
	return nil
}

func basic(id []byte) tree.Credential {
	return tree.Credential{Type: tree.CredentialBasic, Identity: bytes.Clone(id)}
}

func newSig() (ed25519.PrivateKey, error) {
	_, sig, err := ed25519.GenerateKey(nil)
	return sig, err
}

func (c *Client) newGroup(gid []byte, cs uint32, encrypt bool, identity []byte, exts []tls.Extension, p *psks, sig ed25519.PrivateKey) (*member, error) {
	if err := checkSuite(cs); err != nil {
		return nil, err
	}
	m := &member{st: newStore(), sig: sig, id: bytes.Clone(identity), psks: p, cfg: config(p, encrypt)}
	kp, err := kolomls.NewKeyPackage(m.st, kolomls.KeyPackageOptions{Credential: basic(identity), SignatureKey: sig})
	if err != nil {
		return nil, err
	}
	m.g, err = kolomls.Create(m.st, kolomls.CreateOptions{Config: m.cfg, GroupID: bytes.Clone(gid), KeyPackage: kp, Extensions: exts})
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Client) createGroup(r *createGroupRequest) (*createGroupResponse, error) {
	sig, err := newSig()
	if err != nil {
		return nil, err
	}
	m, err := c.newGroup(r.GroupID, r.CipherSuite, r.EncryptHandshake, r.Identity, nil, newPSKs(), sig)
	if err != nil {
		return nil, err
	}
	return &createGroupResponse{StateID: c.add(m)}, nil
}

// createKeyPackage makes a KeyPackage and returns its private keys, which
// the passive-client conversion of a transcript needs.
func (c *Client) createKeyPackage(r *createKeyPackageRequest) (*createKeyPackageResponse, error) {
	if err := checkSuite(r.CipherSuite); err != nil {
		return nil, err
	}
	sig, err := newSig()
	if err != nil {
		return nil, err
	}
	tx := &transaction{st: newStore(), sig: sig, id: bytes.Clone(r.Identity), psks: newPSKs()}
	kp, err := kolomls.NewKeyPackage(tx.st, kolomls.KeyPackageOptions{Credential: basic(r.Identity), SignatureKey: sig})
	if err != nil {
		return nil, err
	}
	initPriv, encPriv, err := tx.privateKeys(kp)
	if err != nil {
		return nil, err
	}
	id := c.newID()
	c.txs[id] = tx
	return &createKeyPackageResponse{TransactionID: id, KeyPackage: kp, InitPriv: initPriv, EncryptionPriv: encPriv, SignaturePriv: sig.Seed()}, nil
}

// privateKeys reads the init and encryption private keys of kp from the
// KeyPackage record kolomls stored (u8 version, KeyPackage,
// opaque init key, opaque encryption key, opaque seed).
func (tx *transaction) privateKeys(kp []byte) ([]byte, []byte, error) {
	m, err := message.UnmarshalMLSMessage(kp)
	if err != nil {
		return nil, nil, err
	}
	ref, err := m.KeyPackage.Ref()
	if err != nil {
		return nil, nil, err
	}
	rec, err := tx.st.Get([]byte("kp/" + hex.EncodeToString(ref)))
	if err != nil {
		return nil, nil, err
	}
	var initPriv, encPriv []byte
	err = tls.Decode(rec, func(rd *tls.Reader) error {
		if _, err := rd.U8(); err != nil {
			return err
		}
		if _, err := message.ReadKeyPackage(rd); err != nil {
			return err
		}
		if initPriv, err = rd.Opaque(); err != nil {
			return err
		}
		if encPriv, err = rd.Opaque(); err != nil {
			return err
		}
		_, err = rd.Opaque()
		return err
	})
	return initPriv, encPriv, err
}

func (c *Client) joinWith(tx *transaction, welcome, ratchetTree []byte, encrypt bool, p *psks, pol kolomls.Policy) (*member, error) {
	m := &member{st: tx.st, sig: tx.sig, id: tx.id, psks: p, cfg: config(p, encrypt)}
	// A tree given out of band is used only when the Welcome carries none.
	o := kolomls.JoinOptions{Config: m.cfg}
	o.Policy = pol
	if len(ratchetTree) > 0 {
		o.Tree = func(func(string, []byte, int) ([]byte, error)) ([]byte, error) { return ratchetTree, nil }
	}
	g, err := kolomls.Join(tx.st, welcome, nil, o)
	if err != nil {
		return nil, err
	}
	m.g = g
	return m, nil
}

func (c *Client) transaction(id uint32) (*transaction, error) {
	tx, ok := c.txs[id]
	if !ok {
		return nil, fmt.Errorf("crosscheck: unknown transaction %d", id)
	}
	return tx, nil
}

// joinGroup joins with a Welcome and the KeyPackage of a transaction.
func (c *Client) joinGroup(r *joinGroupRequest) (*joinGroupResponse, error) {
	tx, err := c.transaction(r.TransactionID)
	if err != nil {
		return nil, err
	}
	m, err := c.joinWith(tx, r.Welcome, r.RatchetTree, r.EncryptHandshake, tx.psks, rfcPolicy{})
	if err != nil {
		return nil, err
	}
	delete(c.txs, r.TransactionID)
	ea, err := m.g.EpochAuthenticator()
	if err != nil {
		return nil, err
	}
	return &joinGroupResponse{StateID: c.add(m), EpochAuthenticator: ea}, nil
}

func (c *Client) stateAuth(r *stateRequest) (*stateAuthResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	ea, err := m.g.EpochAuthenticator()
	if err != nil {
		return nil, err
	}
	return &stateAuthResponse{StateAuthSecret: ea}, nil
}

func (c *Client) export(r *exportRequest) (*exportResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	s, err := m.g.Export(r.Label, r.Context, int(r.KeyLength))
	if err != nil {
		return nil, err
	}
	return &exportResponse{ExportedSecret: s}, nil
}

func (c *Client) protect(r *protectRequest) (*protectResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	ct, err := m.g.Encrypt(r.Plaintext, r.AuthenticatedData)
	if err != nil {
		return nil, err
	}
	return &protectResponse{Ciphertext: ct}, nil
}

func (c *Client) unprotect(r *unprotectRequest) (*unprotectResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	res, err := m.g.Process(r.Ciphertext)
	if err != nil {
		return nil, err
	}
	if res.Commit != nil {
		res.Commit.Discard()
	}
	if res.Commit != nil || res.ProposalRef != nil {
		return nil, errors.New("crosscheck: not an application message")
	}
	return &unprotectResponse{AuthenticatedData: res.AuthenticatedData, Plaintext: res.Application}, nil
}

// storePSK installs an external PSK on a state or a transaction.
func (c *Client) storePSK(r *storePSKRequest) (*empty, error) {
	var p *psks
	if m, ok := c.state[r.StateOrTransactionID]; ok {
		p = m.psks
	} else if tx, ok := c.txs[r.StateOrTransactionID]; ok {
		p = tx.psks
	} else {
		return nil, fmt.Errorf("crosscheck: unknown state or transaction %d", r.StateOrTransactionID)
	}
	p.external[string(r.PSKID)] = bytes.Clone(r.PSKSecret)
	return &empty{}, nil
}

// propose sends a proposal of m and remembers its reference.
func (m *member) propose(f func(g *kolomls.Group) ([]byte, error)) (*proposalResponse, error) {
	msg, err := f(m.g)
	if err != nil {
		return nil, err
	}
	refs := m.g.CachedProposals()
	m.sent[string(msg)] = refs[len(refs)-1]
	return &proposalResponse{Proposal: msg}, nil
}

// leafOf returns the leaf of the member whose basic identity is id.
func (m *member) leafOf(id []byte) (uint32, error) {
	t := m.g.Tree()
	for _, l := range t.Members() {
		if bytes.Equal(t.Leaf(l).Credential.Identity, id) {
			return l, nil
		}
	}
	return 0, fmt.Errorf("crosscheck: no member %q", id)
}

func (c *Client) addProposal(r *addProposalRequest) (*proposalResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	return m.propose(func(g *kolomls.Group) ([]byte, error) { return g.ProposeAdd(r.KeyPackage) })
}

// updateProposal proposes a new leaf for this member.
func (c *Client) updateProposal(r *stateRequest) (*proposalResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	return m.propose(func(g *kolomls.Group) ([]byte, error) { return g.ProposeUpdate(nil) })
}

// removeProposal proposes to remove the member with a basic identity.
func (c *Client) removeProposal(r *removeProposalRequest) (*proposalResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	l, err := m.leafOf(r.RemovedID)
	if err != nil {
		return nil, err
	}
	return m.propose(func(g *kolomls.Group) ([]byte, error) { return g.ProposeRemove(l) })
}

func externalPSK(id []byte) *schedule.PSKID {
	return &schedule.PSKID{Type: schedule.PSKExternal, ID: bytes.Clone(id)}
}

func (m *member) resumptionPSK(epoch uint64) *schedule.PSKID {
	return &schedule.PSKID{Type: schedule.PSKResumption, Usage: schedule.UsageApplication, GroupID: m.g.GroupID(), Epoch: epoch}
}

// externalPSKProposal proposes an external PSK.
func (c *Client) externalPSKProposal(r *externalPSKProposalRequest) (*proposalResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	return m.propose(func(g *kolomls.Group) ([]byte, error) { return g.ProposePSK(externalPSK(r.PSKID)) })
}

// resumptionPSKProposal proposes this group's resumption PSK of an epoch.
func (c *Client) resumptionPSKProposal(r *resumptionPSKProposalRequest) (*proposalResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	return m.propose(func(g *kolomls.Group) ([]byte, error) { return g.ProposePSK(m.resumptionPSK(uint64(r.EpochID))) })
}

func extensions(in []extension) []tls.Extension {
	out := []tls.Extension{}
	for _, e := range in {
		out = append(out, tls.Extension{Type: uint16(e.ExtensionType), Data: bytes.Clone(e.ExtensionData)})
	}
	return out
}

// groupContextExtensionsProposal proposes new GroupContext extensions.
func (c *Client) groupContextExtensionsProposal(r *groupContextExtensionsProposalRequest) (*proposalResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	for _, e := range r.Extensions {
		if e.ExtensionType > 0xffff {
			return nil, fmt.Errorf("crosscheck: extension type %d", e.ExtensionType)
		}
	}
	return m.propose(func(g *kolomls.Group) ([]byte, error) {
		return g.ProposeGroupContextExtensions(extensions(r.Extensions))
	})
}

// cache makes sure every proposal in msgs is cached and returns their
// references in order.
func (m *member) cache(msgs [][]byte) ([][]byte, error) {
	var refs [][]byte
	for _, msg := range msgs {
		if ref, ok := m.sent[string(msg)]; ok {
			refs = append(refs, ref)
			continue
		}
		res, err := m.g.Process(msg)
		if err != nil {
			return nil, fmt.Errorf("proposal: %w", err)
		}
		if res.ProposalRef == nil {
			if res.Commit != nil {
				res.Commit.Discard()
			}
			return nil, errors.New("crosscheck: not a proposal")
		}
		m.sent[string(msg)] = res.ProposalRef
		refs = append(refs, res.ProposalRef)
	}
	return refs, nil
}

func (m *member) commitOptions(r *commitRequest) (kolomls.CommitOptions, error) {
	var o kolomls.CommitOptions
	refs, err := m.cache(r.ByReference)
	if err != nil {
		return o, err
	}
	o.References = refs
	for _, d := range r.ByValue {
		switch string(d.ProposalType) {
		case "add":
			o.Add = append(o.Add, d.KeyPackage)
		case "remove":
			l, err := m.leafOf(d.RemovedID)
			if err != nil {
				return o, err
			}
			o.Remove = append(o.Remove, l)
		case "externalPSK":
			o.PSKs = append(o.PSKs, externalPSK(d.PSKID))
		case "resumptionPSK":
			o.PSKs = append(o.PSKs, m.resumptionPSK(uint64(d.EpochID)))
		case "groupContextExtensions":
			if o.SetExtensions {
				return o, errors.New("crosscheck: two GroupContextExtensions by value")
			}
			o.SetExtensions = true
			o.Extensions = extensions(d.Extensions)
		default:
			return o, fmt.Errorf("%w: proposal %q", errUnsupported, d.ProposalType)
		}
	}
	o.RatchetTree = !r.ExternalTree
	o.NoPath = !r.ForcePath && len(o.Add) == 0
	return o, nil
}

// commit creates a Commit, without a path when force_path is unset and
// RFC 9420 section 12.4 allows it.
func (m *member) commit(o kolomls.CommitOptions) (*kolomls.PendingCommit, error) {
	pc, err := m.g.Commit(o)
	if err != nil && o.NoPath && errors.Is(err, errs.ErrInvalidArgument) {
		o.NoPath = false
		pc, err = m.g.Commit(o)
	}
	return pc, err
}

// commit commits proposals by reference and by value; the Commit waits for
// HandlePendingCommit.
func (c *Client) commit(r *commitRequest) (*commitResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	o, err := m.commitOptions(r)
	if err != nil {
		return nil, err
	}
	pc, err := m.commit(o)
	if err != nil {
		return nil, err
	}
	resp := &commitResponse{Commit: pc.Commit(), Welcome: pc.Welcome()}
	if r.ExternalTree {
		if resp.RatchetTree, err = pc.RatchetTree(); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (c *Client) advanced(id uint32, m *member) (*handleCommitResponse, error) {
	m.sent = map[string][]byte{}
	ea, err := m.g.EpochAuthenticator()
	if err != nil {
		return nil, err
	}
	return &handleCommitResponse{StateID: id, EpochAuthenticator: ea}, nil
}

// handleCommit processes and applies another member's Commit.
func (c *Client) handleCommit(r *handleCommitRequest) (*handleCommitResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	if _, err := m.cache(r.Proposal); err != nil {
		return nil, err
	}
	res, err := m.g.Process(r.Commit)
	if err != nil {
		return nil, err
	}
	if res.Commit == nil {
		return nil, errors.New("crosscheck: not a Commit")
	}
	if err := m.g.Apply(res.Commit); err != nil {
		return nil, err
	}
	if m.g.Removed() {
		delete(c.state, r.StateID)
		return &handleCommitResponse{StateID: r.StateID}, nil
	}
	return c.advanced(r.StateID, m)
}

// handlePendingCommit applies this member's pending Commit.
func (c *Client) handlePendingCommit(r *stateRequest) (*handleCommitResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	if err := m.g.ApplyPending(); err != nil {
		return nil, err
	}
	return c.advanced(r.StateID, m)
}

// createBranch starts a new group with the given members, its first Commit
// injecting the resumption PSK of this group's epoch with usage branch
// (RFC 9420 section 11.3).
func (c *Client) createBranch(r *createBranchRequest) (*createSubgroupResponse, error) {
	old, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	id, val, err := old.g.BranchPSK()
	if err != nil {
		return nil, err
	}
	p := old.psks.clone()
	p.resumption[resumptionKey(id.GroupID, id.Epoch)] = val
	m, err := c.newGroup(r.GroupID, uint32(suite.ID), old.cfg.PrivateHandshakes, old.id, extensions(r.Extensions), p, old.sig)
	if err != nil {
		return nil, err
	}
	o := kolomls.CommitOptions{Add: r.KeyPackages, PSKs: []*schedule.PSKID{id}, RatchetTree: !r.ExternalTree, NoPath: !r.ForcePath && len(r.KeyPackages) == 0}
	if _, err := m.commit(o); err != nil {
		return nil, err
	}
	pc := m.g.Pending()
	if err := m.g.ApplyPending(); err != nil {
		return nil, err
	}
	resp := &createSubgroupResponse{Welcome: pc.Welcome()}
	if r.ExternalTree {
		if resp.RatchetTree, err = m.g.RatchetTree(); err != nil {
			return nil, err
		}
	}
	if resp.EpochAuthenticator, err = m.g.EpochAuthenticator(); err != nil {
		return nil, err
	}
	resp.StateID = c.add(m)
	return resp, nil
}

// handleBranch joins a branch of the group of a state.
func (c *Client) handleBranch(r *handleBranchRequest) (*handleBranchResponse, error) {
	old, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	tx, err := c.transaction(r.TransactionID)
	if err != nil {
		return nil, err
	}
	id, val, err := old.g.BranchPSK()
	if err != nil {
		return nil, err
	}
	p := tx.psks.clone()
	p.resumption[resumptionKey(id.GroupID, id.Epoch)] = val
	m, err := c.joinWith(tx, r.Welcome, r.RatchetTree, old.cfg.PrivateHandshakes, p, branchPolicy{old: identities(old.g)})
	if err != nil {
		return nil, err
	}
	delete(c.txs, r.TransactionID)
	ea, err := m.g.EpochAuthenticator()
	if err != nil {
		return nil, err
	}
	return &handleBranchResponse{StateID: c.add(m), EpochAuthenticator: ea}, nil
}

// groupState returns the encoded GroupContext and ratchet tree of the
// current epoch, which the pairwise harness compares across members.
func (c *Client) groupState(r *stateRequest) (*groupStateResponse, error) {
	m, err := c.member(r.StateID)
	if err != nil {
		return nil, err
	}
	t, err := m.g.RatchetTree()
	if err != nil {
		return nil, err
	}
	return &groupStateResponse{GroupContext: m.g.GroupContext(), RatchetTree: t}, nil
}

func (c *Client) free(r *stateRequest) (*empty, error) {
	if m, ok := c.state[r.StateID]; ok {
		m.g.Close()
		delete(c.state, r.StateID)
	}
	return &empty{}, nil
}
