package kolomls

import (
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// Credential is an MLS Credential (RFC 9420 section 5.3): Type, with Identity for
// a basic or Kolo credential and Certificates for an x509 chain.
type Credential = tree.Credential

// Capabilities are the versions, cipher suites, extensions, proposals and
// credential types a leaf supports (RFC 9420 section 7.2).
type Capabilities = tree.Capabilities

// LeafNode is a member's leaf in the ratchet tree (RFC 9420 section 7.2).
type LeafNode = tree.LeafNode

// Extension is an MLS Extension (RFC 9420 section 13.4): Type and Data.
type Extension = tls.Extension

// PSKID is a PreSharedKeyID (RFC 9420 section 8.4): ID for an external PSK; Usage,
// GroupID and Epoch for a resumption PSK.
type PSKID = schedule.PSKID

// GroupContext is the decoded GroupContext of an epoch (RFC 9420 section 8.1).
type GroupContext = schedule.GroupContext

// Proposal is a decoded proposal (RFC 9420 section 12.1); the field of its Type is set.
type Proposal = message.Proposal

const (
	// CredentialBasic is the type of a basic credential (RFC 9420 section 5.3).
	CredentialBasic = tree.CredentialBasic
	// CredentialX509 is the type of an x509 credential (RFC 9420 section 5.3).
	CredentialX509 = tree.CredentialX509
	// PSKExternal is the type of an external PSK (RFC 9420 section 8.4).
	PSKExternal = schedule.PSKExternal
	// PSKResumption is the type of a resumption PSK (RFC 9420 section 8.4).
	PSKResumption = schedule.PSKResumption
	// UsageApplication is the resumption usage for an application (RFC 9420 section 8.4).
	UsageApplication = schedule.UsageApplication
	// UsageBranch is the resumption usage for a branch (RFC 9420 section 8.4).
	UsageBranch = schedule.UsageBranch
	// DefaultOutOfOrderTolerance is the Config default for OutOfOrderTolerance.
	DefaultOutOfOrderTolerance = secrettree.DefaultOutOfOrderTolerance
	// DefaultMaxForwardDistance is the Config default for MaxForwardDistance.
	DefaultMaxForwardDistance = secrettree.DefaultMaxForwardDistance
)

var (
	// ErrMalformed reports input that is not the canonical encoding.
	ErrMalformed = errs.ErrMalformed
	// ErrTooLong reports a vector longer than a variable-size length can hold.
	ErrTooLong = errs.ErrTooLong
	// ErrInvalidArgument reports a key, size, index or count out of range.
	ErrInvalidArgument = errs.ErrInvalidArgument
	// ErrUnsupported reports a valid value this implementation does not support.
	ErrUnsupported = errs.ErrUnsupported
	// ErrDecrypt reports a failed decryption.
	ErrDecrypt = errs.ErrDecrypt
	// ErrInvalidTree reports a ratchet tree that breaks a rule of RFC 9420.
	ErrInvalidTree = errs.ErrInvalidTree
	// ErrInvalidCommit reports an UpdatePath or Commit that breaks a rule of RFC 9420.
	ErrInvalidCommit = errs.ErrInvalidCommit
	// ErrTooFarAhead reports a generation beyond the forward bound of a ratchet.
	ErrTooFarAhead = errs.ErrTooFarAhead
	// ErrTooOld reports a generation below the out-of-order window of a ratchet.
	ErrTooOld = errs.ErrTooOld
	// ErrReplay reports a generation whose key was already used.
	ErrReplay = errs.ErrReplay
	// ErrGenerationExhausted reports a ratchet that has used every generation.
	ErrGenerationExhausted = errs.ErrGenerationExhausted
	// ErrWrongGroup reports a message for another group.
	ErrWrongGroup = errs.ErrWrongGroup
	// ErrWrongEpoch reports a message for a past epoch.
	ErrWrongEpoch = errs.ErrWrongEpoch
	// ErrFutureEpoch reports a message for an epoch the group has not reached.
	ErrFutureEpoch = errs.ErrFutureEpoch
	// ErrSignature reports a signature that does not verify.
	ErrSignature = errs.ErrSignature
	// ErrMembershipTag reports a PublicMessage whose membership tag does not verify.
	ErrMembershipTag = errs.ErrMembershipTag
	// ErrConfirmationTag reports a confirmation tag that does not match.
	ErrConfirmationTag = errs.ErrConfirmationTag
	// ErrInvalidLeaf reports a LeafNode that breaks a rule of RFC 9420 section 7.3.
	ErrInvalidLeaf = errs.ErrInvalidLeaf
	// ErrInvalidKeyPackage reports a KeyPackage that breaks a rule of RFC 9420 section 10.1.
	ErrInvalidKeyPackage = errs.ErrInvalidKeyPackage
	// ErrInvalidProposal reports a proposal that breaks a rule of RFC 9420 section 12.1.
	ErrInvalidProposal = errs.ErrInvalidProposal
	// ErrInvalidWelcome reports a Welcome or GroupInfo that breaks a rule of RFC 9420 section 12.4.3.
	ErrInvalidWelcome = errs.ErrInvalidWelcome
	// ErrUnknownProposal reports a Commit that references a proposal this member does not hold.
	ErrUnknownProposal = errs.ErrUnknownProposal
	// ErrPSKNotFound reports a pre-shared key this member does not hold.
	ErrPSKNotFound = errs.ErrPSKNotFound
	// ErrKeyPackageNotFound reports a Welcome for none of this client's key packages.
	ErrKeyPackageNotFound = errs.ErrKeyPackageNotFound
	// ErrCredential wraps an error of the Authenticator.
	ErrCredential = errs.ErrCredential
	// ErrPolicy wraps an error of the Policy.
	ErrPolicy = errs.ErrPolicy
	// ErrPendingProposals reports application data sent while proposals are
	// cached: a Commit must come first (RFC 9420 section 12.4).
	ErrPendingProposals = errs.ErrPendingProposals
	// ErrPendingCommit reports a second pending Commit, or none where one is needed.
	ErrPendingCommit = errs.ErrPendingCommit
	// ErrRemoved reports a group this member was removed from.
	ErrRemoved = errs.ErrRemoved
	// ErrNotFound is what a Store returns for an absent key.
	ErrNotFound = errs.ErrNotFound
	// ErrStore wraps an error of the Store.
	ErrStore = errs.ErrStore
	// ErrGroupExists reports a group id this client already uses.
	ErrGroupExists = errs.ErrGroupExists
	// ErrUnknownSender reports a message from a leaf that is blank.
	ErrUnknownSender = errs.ErrUnknownSender
	// ErrClosed reports a Group used after Close.
	ErrClosed = errs.ErrClosed
)
