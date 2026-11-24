package kolomls

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// Event names the moment a credential is checked (RFC 9420 section 5.3.1).
type Event uint8

// Credential events.
const (
	// EventKeyPackage is a KeyPackage's leaf, checked before this member
	// adds it or creates a group with it.
	EventKeyPackage Event = iota + 1
	// EventJoin is a leaf of the tree of a group this member joins.
	EventJoin
	// EventAdd is a leaf added by another member's Commit.
	EventAdd
	// EventUpdate is a leaf in an Update proposal.
	EventUpdate
	// EventCommitPath is the leaf of a Commit's UpdatePath.
	EventCommitPath
)

// Authenticator is the application's Authentication Service (RFC 9420
// section 5.3.1). Its answers must be the same on every member, since
// members that decide differently split the group (RFC 9750 section 6.5).
type Authenticator interface {
	// Validate checks that c is valid and binds signatureKey, a copy.
	Validate(c Credential, signatureKey []byte, ev Event) error
	// Successor checks that next may replace prev in a member's leaf.
	Successor(prev, next Credential) error
	// ClientID returns the identity of the client c presents; two leaves
	// with equal ids are the same client (RFC 9420 section 12.2).
	ClientID(c Credential) ([]byte, error)
}

// TreeView reads a ratchet tree without changing it.
type TreeView struct{ t *tree.Tree }

// Leaf returns a copy of the leaf at index l, nil when it is blank or past
// the tree.
func (v TreeView) Leaf(l uint32) *LeafNode {
	if n := v.t.Leaf(l); n != nil {
		return n.Clone()
	}
	return nil
}

// Members returns the indices of the non-blank leaves in increasing order.
func (v TreeView) Members() []uint32 {
	var out []uint32
	for _, x := range v.t.NonBlank() {
		if x%2 == 0 {
			out = append(out, uint32(x/2))
		}
	}
	return out
}

// ProposalView is a proposal as the Policy sees it; every field is a copy.
type ProposalView struct {
	// Sender is the leaf index of the proposer.
	Sender uint32
	// SenderLeaf is the proposer's current leaf.
	SenderLeaf *LeafNode
	// Proposal is the proposal itself.
	Proposal *Proposal
	// ByReference is set for a proposal a Commit includes by reference.
	ByReference bool
	// Cached is the number of proposals already cached in the epoch, so a
	// Policy can bound the cache; it is zero inside a CommitView.
	Cached int
	// Tree is the tree of the epoch the proposal is sent in.
	Tree TreeView
	// FromSender is the number of proposals of the same sender already
	// cached; zero inside a CommitView.
	FromSender int
	// Extensions are the GroupContext extensions of the epoch.
	Extensions []Extension
}

// CommitView is a Commit as the Policy sees it, before it is applied; every
// field is a copy or a read-only view.
type CommitView struct {
	// Committer is the leaf index of the committer.
	Committer uint32
	// CommitterLeaf is the committer's current leaf.
	CommitterLeaf *LeafNode
	// Proposals are the committed proposals in order.
	Proposals []ProposalView
	// Path is the committer's new leaf, nil without a path.
	Path *LeafNode
	// Context is the GroupContext of the epoch the Commit is sent in.
	Context *GroupContext
	// Tree is the tree of that epoch.
	Tree TreeView
}

// JoinView is a group as the Policy sees it before a member joins it; every
// field is a copy or a read-only view.
type JoinView struct {
	// Context is the GroupContext of the group joined.
	Context *GroupContext
	// Tree is the group's tree.
	Tree TreeView
	// Signer is the leaf index of the member that signed the GroupInfo.
	Signer uint32
	// PSKs are the pre-shared keys of the Welcome.
	PSKs []*PSKID
	// InfoExtensions are the GroupInfo's extensions.
	InfoExtensions []Extension
}

// Policy holds the application's rules on top of RFC 9420 (section 12.2:
// "An application may extend the above procedure by additional rules").
// Like the Authenticator, it must decide the same way on every member.
type Policy interface {
	// CheckProposal decides whether a received proposal is cached.
	CheckProposal(v ProposalView) error
	// CheckCommit decides whether a Commit is acceptable.
	CheckCommit(v CommitView) error
	// CheckJoin decides whether a Welcome is accepted, including the
	// membership checks of a branch (RFC 9420 section 12.4.3.1).
	CheckJoin(v JoinView) error
}

// PSKStore holds the external and resumption pre-shared keys the
// application provides.
type PSKStore interface {
	// PSK returns a copy of the value of id, which the caller owns and
	// zeroes, or ErrNotFound.
	PSK(id *PSKID) ([]byte, error)
}

// KV is one key and value of a Batch.
type KV struct {
	Key, Value []byte
}

// Batch is a set of writes that a Store applies atomically: the deletes,
// then the puts. No key is in both.
type Batch struct {
	Put    []KV
	Delete [][]byte
}

func (b *Batch) zero() {
	for _, kv := range b.Put {
		clear(kv.Value)
	}
}

// Store persists the state of groups and KeyPackages. Every consumed secret is deleted in the
// same write that records the advance (RFC 9420 section 9.2).
//
// Apply must be atomic and durable: all of a batch or nothing. An error from Apply may still
// mean the batch was written (an acknowledgement lost), so a Group whose write failed refuses
// every later call, and the caller opens the group again to read what the Store holds. After a
// failed Create or Join, the caller opens the group id to learn whether it exists.
//
// A Store serves several groups and goroutines and must be safe for concurrent use (MemStore
// is). At most one Group may be open per group id, since two would write diverging secret
// trees, and Create, Join and Open of one group id, or Create and Join that use one
// KeyPackage, must not run concurrently on one Store.
type Store interface {
	// Get returns a copy of the value of key, which the caller owns, or
	// ErrNotFound.
	Get(key []byte) ([]byte, error)
	// Apply writes b atomically and durably and keeps none of its slices:
	// the library zeroes the values after Apply returns.
	Apply(b Batch) error
}

// DefaultMaxLeafLifetime is the default bound on not_after - not_before of a
// key_package leaf: 84 days and one hour.
const DefaultMaxLeafLifetime = 84*24*time.Hour + time.Hour

// DefaultKeyPackageLifetime is the default lifetime of a new KeyPackage,
// which starts one hour before its creation.
const DefaultKeyPackageLifetime = 84 * 24 * time.Hour

// DefaultMaxTreeBytes is the default bound on a ratchet tree a joiner
// accepts.
const DefaultMaxTreeBytes = 128 << 20

// Config holds the parameters every operation of a group uses. For the
// bounds, zero means the default and a negative value no bound.
type Config struct {
	// Authenticator validates credentials; it is required.
	Authenticator Authenticator
	// Policy adds the application's rules; it is required.
	Policy Policy
	// PSKs returns pre-shared keys; nil means none is available.
	PSKs PSKStore
	// MaxLeafLifetime bounds the lifetime of key_package leaves; zero means
	// DefaultMaxLeafLifetime and a negative value no bound.
	MaxLeafLifetime time.Duration
	// Now gives the time for the lifetime check of leaves this member sends
	// and for the previous-epoch window; nil means time.Now.
	Now func() time.Time
	// ResumptionPSKs is the number of past epochs whose resumption PSK is
	// kept besides the current one; zero keeps the current one only and a
	// negative value is refused.
	ResumptionPSKs int
	// OutOfOrderTolerance is the size of the window of generations a
	// receiver keeps per sender and ratchet, the newest one read included,
	// so OutOfOrderTolerance - 1 older generations stay readable (RFC 9420
	// section 15.3); zero means DefaultOutOfOrderTolerance, 1
	// reads messages in order only, and values above 65536 (1 << 16) are
	// refused.
	OutOfOrderTolerance uint32
	// MaxForwardDistance is how many generations one message may move a
	// sender's ratchet forward (RFC 9420 section 15.3); zero means
	// DefaultMaxForwardDistance, so the smallest bound is 1, and values above
	// 65536 (1 << 16) are refused.
	MaxForwardDistance uint32
	// PastEpochWindow is how long the previous epoch stays readable for late
	// application messages of members that stay, after a Commit is applied
	// (RFC 9420 section 12.4.2); zero means DefaultPastEpochWindow and a
	// negative value keeps no previous epoch. Now is its clock; the caller
	// calls Group.ExpirePastEpoch when the window ends.
	PastEpochWindow time.Duration
	// PrivateHandshakes sends proposals and Commits as PrivateMessage and
	// refuses those of other members sent as PublicMessage; otherwise they
	// are sent as PublicMessage and both are accepted.
	PrivateHandshakes bool
	// Envelope wraps and checks the authenticated data of every
	// PrivateMessage. Nil leaves it unchanged, as the RFC test vectors
	// need, and then a member can replay another member's signed content
	// under a later generation and use up that generation (RFC 9750 section
	// 8.6); applications set one.
	Envelope Envelope
}

// check refuses a Config without an Authenticator or a Policy, or with a
// value out of range.
func (c *Config) check() error {
	if c.Authenticator == nil || c.Policy == nil {
		return fmt.Errorf("%w: Config needs an Authenticator and a Policy", errs.ErrInvalidArgument)
	}
	if c.ResumptionPSKs < 0 {
		return fmt.Errorf("%w: negative ResumptionPSKs", errs.ErrInvalidArgument)
	}
	return c.keyOptions().Check()
}

func (c *Config) keyOptions() secrettree.Options {
	return secrettree.Options{MaxForwardDistance: c.MaxForwardDistance, OutOfOrderTolerance: c.OutOfOrderTolerance}
}

// Envelope binds the generation of a PrivateMessage into its signed
// authenticated data (RFC 9750 section 8.6: the signature does not cover
// the generation, so a member could re-encrypt another member's content
// under a new one).
type Envelope interface {
	// Wrap returns the authenticated data to send at generation gen for the
	// application's aad.
	Wrap(gen uint32, aad []byte) ([]byte, error)
	// Unwrap checks the authenticated data of a PrivateMessage received at
	// generation gen, before its key is consumed, and returns the
	// application's aad.
	Unwrap(gen uint32, authenticatedData []byte) ([]byte, error)
}

// JoinOptions are the parameters of Join.
type JoinOptions struct {
	Config
	// MaxTreeBytes bounds the encoded ratchet tree, from the Welcome or
	// given; zero means DefaultMaxTreeBytes and a negative value no bound.
	MaxTreeBytes int
	// Tree, when Join is given no tree and the Welcome carries none, returns
	// the encoded ratchet tree; export derives a secret of the new epoch
	// (RFC 9420 section 8.5), for a tree kept encrypted under it.
	Tree func(export func(label string, context []byte, length int) ([]byte, error)) ([]byte, error)
}

// CreateOptions are the parameters of Create.
type CreateOptions struct {
	Config
	// GroupID is the new group's id; nil means 32 random bytes (RFC 9420
	// section 11).
	GroupID []byte
	// KeyPackage is a KeyPackage of this client made by NewKeyPackage on the
	// same Store; its leaf becomes the creator's leaf and Create deletes its
	// private keys, as Join does, so no Join may use it at the same time.
	KeyPackage []byte
	// Extensions are the GroupContext extensions of epoch 0.
	Extensions []Extension
}

// CommitOptions say what a Commit carries besides the cached proposals it
// includes by reference.
type CommitOptions struct {
	// Add are the KeyPackages to add, each an encoded KeyPackage.
	Add [][]byte
	// Remove are the leaf indices to remove.
	Remove []uint32
	// PSKs are pre-shared keys to inject; a nil nonce means 32 random bytes.
	PSKs []*PSKID
	// Extensions are the new GroupContext extensions when SetExtensions is
	// set.
	Extensions []Extension
	// SetExtensions adds a GroupContextExtensions proposal with Extensions,
	// which may be empty.
	SetExtensions bool
	// References are the ProposalRefs of cached proposals to include.
	References [][]byte
	// NoPath omits the UpdatePath where RFC 9420 section 12.4 allows it; it
	// excludes Leaf and SignatureKey.
	NoPath bool
	// Leaf is a template for the committer's new leaf (credential,
	// capabilities, extensions, signature key); nil keeps the current one.
	Leaf *LeafNode
	// SignatureKey is the private key of Leaf.SignatureKey when it changes.
	SignatureKey ed25519.PrivateKey
	// RatchetTree puts the ratchet_tree extension in the GroupInfo.
	RatchetTree bool
	// AuthenticatedData is the Commit's authenticated_data.
	AuthenticatedData []byte
}
