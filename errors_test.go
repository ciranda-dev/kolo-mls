package kolomls

import (
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
)

// TestErrorsAreTheCoreSentinels: each exported error is the value the internal
// packages return, so errors.Is works across them.
func TestErrorsAreTheCoreSentinels(t *testing.T) {
	pairs := []struct {
		name     string
		pub, int error
	}{
		{"ErrMalformed", ErrMalformed, errs.ErrMalformed},
		{"ErrTooLong", ErrTooLong, errs.ErrTooLong},
		{"ErrInvalidArgument", ErrInvalidArgument, errs.ErrInvalidArgument},
		{"ErrUnsupported", ErrUnsupported, errs.ErrUnsupported},
		{"ErrDecrypt", ErrDecrypt, errs.ErrDecrypt},
		{"ErrInvalidTree", ErrInvalidTree, errs.ErrInvalidTree},
		{"ErrInvalidCommit", ErrInvalidCommit, errs.ErrInvalidCommit},
		{"ErrTooFarAhead", ErrTooFarAhead, errs.ErrTooFarAhead},
		{"ErrTooOld", ErrTooOld, errs.ErrTooOld},
		{"ErrReplay", ErrReplay, errs.ErrReplay},
		{"ErrGenerationExhausted", ErrGenerationExhausted, errs.ErrGenerationExhausted},
		{"ErrWrongGroup", ErrWrongGroup, errs.ErrWrongGroup},
		{"ErrWrongEpoch", ErrWrongEpoch, errs.ErrWrongEpoch},
		{"ErrFutureEpoch", ErrFutureEpoch, errs.ErrFutureEpoch},
		{"ErrSignature", ErrSignature, errs.ErrSignature},
		{"ErrMembershipTag", ErrMembershipTag, errs.ErrMembershipTag},
		{"ErrConfirmationTag", ErrConfirmationTag, errs.ErrConfirmationTag},
		{"ErrInvalidLeaf", ErrInvalidLeaf, errs.ErrInvalidLeaf},
		{"ErrInvalidKeyPackage", ErrInvalidKeyPackage, errs.ErrInvalidKeyPackage},
		{"ErrInvalidProposal", ErrInvalidProposal, errs.ErrInvalidProposal},
		{"ErrInvalidWelcome", ErrInvalidWelcome, errs.ErrInvalidWelcome},
		{"ErrUnknownProposal", ErrUnknownProposal, errs.ErrUnknownProposal},
		{"ErrPSKNotFound", ErrPSKNotFound, errs.ErrPSKNotFound},
		{"ErrKeyPackageNotFound", ErrKeyPackageNotFound, errs.ErrKeyPackageNotFound},
		{"ErrCredential", ErrCredential, errs.ErrCredential},
		{"ErrPolicy", ErrPolicy, errs.ErrPolicy},
		{"ErrPendingProposals", ErrPendingProposals, errs.ErrPendingProposals},
		{"ErrPendingCommit", ErrPendingCommit, errs.ErrPendingCommit},
		{"ErrRemoved", ErrRemoved, errs.ErrRemoved},
		{"ErrNotFound", ErrNotFound, errs.ErrNotFound},
		{"ErrStore", ErrStore, errs.ErrStore},
		{"ErrGroupExists", ErrGroupExists, errs.ErrGroupExists},
		{"ErrUnknownSender", ErrUnknownSender, errs.ErrUnknownSender},
		{"ErrClosed", ErrClosed, errs.ErrClosed},
	}
	if len(pairs) != 34 {
		t.Fatalf("%d pairs, want 34", len(pairs))
	}
	seen := map[error]string{}
	for _, p := range pairs {
		if p.pub == nil || !errors.Is(p.int, p.pub) {
			t.Errorf("%s is not the core sentinel", p.name)
		}
		if other, dup := seen[p.pub]; dup {
			t.Errorf("%s and %s are the same error", p.name, other)
		}
		seen[p.pub] = p.name
	}
}
