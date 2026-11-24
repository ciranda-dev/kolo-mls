package settle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
)

// SettledContext is the context of a settler's signature over a decided
// Commit.
const SettledContext = "kolo-mls/commit-settled/v0"

const settledTag = "kolo-mls/settled-commit/v0"

var (
	// ErrNotSettled reports a SettledCommit that does not settle the Commit
	// given in this member's epoch: malformed, for another group, epoch,
	// context or Commit, or with fewer than q valid settler signatures.
	ErrNotSettled = errors.New("kolomls: commit not settled")
	// ErrSettledMismatch reports a settled Commit that this member cannot
	// follow: it fails MLS processing or leads to another GroupContext than
	// the settlers signed. The member keeps its state.
	ErrSettledMismatch = errors.New("kolomls: settled commit does not match")
	// ErrEquivocation reports two settled Commits for one epoch.
	ErrEquivocation = errors.New("kolomls: two settled commits for one epoch")
)

// TBS is what each settler signs for the decided Commit of an epoch.
type TBS struct {
	// GroupID and Epoch name the epoch the Commit was sent in.
	GroupID []byte
	Epoch   uint64
	// Commit is the SHA-256 of the Commit's MLSMessage.
	Commit [32]byte
	// ContextBefore and ContextAfter are the SHA-256 of the encoded
	// GroupContext of the epoch and of the next one.
	ContextBefore, ContextAfter [32]byte
	// Braid is the group id of the admins' braid.
	Braid [32]byte
	// RefPosition is the settled position of the Commit's reference.
	RefPosition uint64
}

func (t *TBS) put(e *kolocodec.Encoder) {
	e.PutUvarint(0)
	e.PutBytes(t.GroupID)
	e.PutUvarint(t.Epoch)
	e.PutFixed(t.Commit[:])
	e.PutFixed(t.ContextBefore[:])
	e.PutFixed(t.ContextAfter[:])
	e.PutFixed(t.Braid[:])
	e.PutUvarint(t.RefPosition)
}

// Encode returns the bytes a settler signs.
func (t *TBS) Encode() []byte {
	var e kolocodec.Encoder
	t.put(&e)
	return e.Bytes()
}

func readTBS(d *kolocodec.Decoder) (*TBS, error) {
	v, err := d.Uvarint()
	if err != nil {
		return nil, err
	}
	if v != 0 {
		return nil, fmt.Errorf("version %d", v)
	}
	t := &TBS{}
	if t.GroupID, err = d.Bytes(suite.Nh); err != nil {
		return nil, err
	}
	if len(t.GroupID) != suite.Nh {
		return nil, fmt.Errorf("group id of %d bytes", len(t.GroupID))
	}
	if t.Epoch, err = d.Uvarint(); err != nil {
		return nil, err
	}
	for _, f := range []*[32]byte{&t.Commit, &t.ContextBefore, &t.ContextAfter, &t.Braid} {
		b, err := d.Fixed(32)
		if err != nil {
			return nil, err
		}
		*f = [32]byte(b)
	}
	t.RefPosition, err = d.Uvarint()
	return t, err
}

// DecodeTBS decodes the bytes a settler signs.
func DecodeTBS(b []byte) (*TBS, error) {
	d := kolocodec.NewDecoder(b)
	t, err := readTBS(d)
	if err == nil {
		err = d.Done()
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotSettled, err)
	}
	return t, nil
}

// Share is one settler's signature.
type Share struct {
	Signer    [32]byte
	Signature [64]byte
}

// Settled is a SettledCommit: the TBS and the settlers' signatures, signers
// in strictly increasing order.
type Settled struct {
	TBS    TBS
	Shares []Share
}

// Encode returns the SettledCommit that admins put on pins and gossip.
func (s *Settled) Encode() []byte {
	var e kolocodec.Encoder
	e.PutString(settledTag)
	s.TBS.put(&e)
	e.PutUvarint(uint64(len(s.Shares)))
	for _, sh := range s.Shares {
		e.PutFixed(sh.Signer[:])
		e.PutFixed(sh.Signature[:])
	}
	return e.Bytes()
}

// DecodeSettled decodes a SettledCommit with at most maxShares signatures,
// the settlers of the group; zero or less leaves only the size of b as the
// bound.
func DecodeSettled(b []byte, maxShares int) (*Settled, error) {
	s, err := decodeSettled(b, maxShares)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotSettled, err)
	}
	return s, nil
}

func decodeSettled(b []byte, maxShares int) (*Settled, error) {
	d := kolocodec.NewDecoder(b)
	tag, err := d.String(len(settledTag))
	if err != nil {
		return nil, err
	}
	if tag != settledTag {
		return nil, errors.New("not a SettledCommit")
	}
	t, err := readTBS(d)
	if err != nil {
		return nil, err
	}
	n, err := d.Uvarint()
	if err != nil {
		return nil, err
	}
	if n > uint64(d.Len()/96) || maxShares > 0 && n > uint64(maxShares) {
		return nil, fmt.Errorf("%d signatures", n)
	}
	s := &Settled{TBS: *t}
	for range n {
		k, err := d.Fixed(32)
		if err != nil {
			return nil, err
		}
		sig, err := d.Fixed(64)
		if err != nil {
			return nil, err
		}
		if len(s.Shares) > 0 && bytes.Compare(s.Shares[len(s.Shares)-1].Signer[:], k) >= 0 {
			return nil, errors.New("signers not strictly increasing")
		}
		s.Shares = append(s.Shares, Share{Signer: [32]byte(k), Signature: [64]byte(sig)})
	}
	return s, d.Done()
}

// Valid returns the number of distinct settlers of roles whose signature
// verifies and that member reports as the device of a current leaf;
// signatures of other keys and invalid ones do not count.
func (s *Settled) Valid(roles *Roles, member func(device [32]byte) bool) int {
	if s == nil || roles == nil || member == nil {
		return 0
	}
	tbs := s.TBS.Encode()
	counted := map[[32]byte]bool{}
	for _, sh := range s.Shares {
		if roles.Settler(sh.Signer[:]) && member(sh.Signer) && koloid.Verify(ed25519.PublicKey(sh.Signer[:]), SettledContext, tbs, sh.Signature[:]) {
			counted[sh.Signer] = true
		}
	}
	return len(counted)
}

// Check verifies that s settles commit in the epoch with the encoded
// GroupContext context and roles (docs/design.md, "The Kolo layer").
func (s *Settled) Check(context, commit []byte, gid []byte, epoch uint64, roles *Roles, member func(device [32]byte) bool) error {
	if s == nil || roles == nil || member == nil {
		return fmt.Errorf("%w: no SettledCommit, roles or member check", errs.ErrInvalidArgument)
	}
	if len(s.Shares) > len(roles.Settlers) {
		return fmt.Errorf("%w: more signatures than settlers", ErrNotSettled)
	}
	t := &s.TBS
	if !bytes.Equal(t.GroupID, gid) || t.Epoch != epoch || t.Braid != roles.Braid {
		return fmt.Errorf("%w: another group, epoch or braid", ErrNotSettled)
	}
	if t.ContextBefore != sha256.Sum256(context) || t.Commit != sha256.Sum256(commit) {
		return fmt.Errorf("%w: another GroupContext or Commit", ErrNotSettled)
	}
	if s.Valid(roles, member) < roles.Q() {
		return fmt.Errorf("%w: fewer than %d settler signatures", ErrNotSettled, roles.Q())
	}
	return nil
}
