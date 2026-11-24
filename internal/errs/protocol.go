package errs

import "errors"

var (
	// ErrWrongGroup reports a message for another group.
	ErrWrongGroup = errors.New("kolomls: message for another group")
	// ErrWrongEpoch reports a message for a past epoch.
	ErrWrongEpoch = errors.New("kolomls: message for a past epoch")
	// ErrFutureEpoch reports a message for an epoch the group has not reached.
	ErrFutureEpoch = errors.New("kolomls: message for a future epoch")
	// ErrSignature reports a signature that does not verify.
	ErrSignature = errors.New("kolomls: invalid signature")
	// ErrMembershipTag reports a PublicMessage whose membership tag does not verify.
	ErrMembershipTag = errors.New("kolomls: invalid membership tag")
	// ErrConfirmationTag reports a confirmation tag that does not match.
	ErrConfirmationTag = errors.New("kolomls: invalid confirmation tag")
	// ErrInvalidLeaf reports a LeafNode that breaks a rule of RFC 9420 section 7.3.
	ErrInvalidLeaf = errors.New("kolomls: invalid leaf node")
	// ErrInvalidKeyPackage reports a KeyPackage that breaks a rule of RFC 9420 section 10.1.
	ErrInvalidKeyPackage = errors.New("kolomls: invalid key package")
	// ErrInvalidProposal reports a proposal that breaks a rule of RFC 9420 section 12.1.
	ErrInvalidProposal = errors.New("kolomls: invalid proposal")
	// ErrInvalidWelcome reports a Welcome or GroupInfo that breaks a rule of RFC 9420 section 12.4.3.
	ErrInvalidWelcome = errors.New("kolomls: invalid welcome")
	// ErrUnknownProposal reports a Commit that references a proposal this member does not hold.
	ErrUnknownProposal = errors.New("kolomls: unknown proposal reference")
	// ErrPSKNotFound reports a pre-shared key this member does not hold.
	ErrPSKNotFound = errors.New("kolomls: pre-shared key not found")
	// ErrKeyPackageNotFound reports a Welcome for none of this client's key packages.
	ErrKeyPackageNotFound = errors.New("kolomls: key package not found")
	// ErrCredential wraps an error of the Authenticator.
	ErrCredential = errors.New("kolomls: credential refused")
	// ErrPolicy wraps an error of the Policy.
	ErrPolicy = errors.New("kolomls: refused by policy")
	// ErrPendingProposals reports application data sent while proposals are
	// cached: a Commit must come first (RFC 9420 section 12.4).
	ErrPendingProposals = errors.New("kolomls: proposals pending")
	// ErrPendingCommit reports a second pending Commit, or none where one is needed.
	ErrPendingCommit = errors.New("kolomls: pending commit")
	// ErrRemoved reports a group this member was removed from.
	ErrRemoved = errors.New("kolomls: removed from the group")
	// ErrNotFound is what a Store returns for an absent key.
	ErrNotFound = errors.New("kolomls: not found")
	// ErrStore wraps an error of the Store.
	ErrStore = errors.New("kolomls: store failed")
	// ErrGroupExists reports a group id this client already uses.
	ErrGroupExists = errors.New("kolomls: group already exists")
	// ErrUnknownSender reports a message from a leaf that is blank.
	ErrUnknownSender = errors.New("kolomls: sender is not a member")
	// ErrClosed reports a Group used after Close.
	ErrClosed = errors.New("kolomls: group closed")
)
