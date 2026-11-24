package settle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	kolocodec "github.com/ciranda-dev/kolo-codec"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
)

var (
	// ErrMissing reports a value that Pins does not hold.
	ErrMissing = errors.New("kolomls: not on pins")
	// ErrPinTooLarge reports a value on pins past the bound asked for.
	ErrPinTooLarge = errors.New("kolomls: pinned data past the bound")
)

// Pins keeps what a Kolo group's devices fetch while they catch up: Commits
// by hash, SettledCommits by epoch and each epoch's archived messages for the
// life of the group, and encrypted trees by epoch while the latest or a
// Welcome that is not used yet names them (braid.Admin).
type Pins interface {
	// Put keeps value under key.
	Put(ctx context.Context, key string, value []byte) error
	// Get returns the value of key, an error wrapping ErrMissing when there
	// is none, or one wrapping ErrPinTooLarge, before more than max bytes
	// are read, when it is longer than max; max 0 or less is no bound.
	Get(ctx context.Context, key string, max int) ([]byte, error)
	// List returns the first max keys that start with prefix and sort after
	// the key after (all of them when after is empty), in increasing order;
	// max 0 or less is no bound. A caller reads on from the last key it got
	// until an empty list.
	List(ctx context.Context, prefix, after string, max int) ([]string, error)
	// Delete removes key; a key that is not there is not an error.
	Delete(ctx context.Context, key string) error
}

// ObjectKey is the key of a Commit MLSMessage with SHA-256 h.
func ObjectKey(h [32]byte) string {
	return "kolo-mls/object/" + hex.EncodeToString(h[:])
}

// SettledKey is the key of the SettledCommit of epoch of group gid.
func SettledKey(gid []byte, epoch uint64) string {
	return "kolo-mls/settled/" + hex.EncodeToString(gid) + "/" + strconv.FormatUint(epoch, 10)
}

// TreeKey is the key of the encrypted ratchet tree of epoch of group gid.
func TreeKey(gid []byte, epoch uint64) string {
	return "kolo-mls/tree/" + hex.EncodeToString(gid) + "/" + strconv.FormatUint(epoch, 10)
}

// ArchivePrefix is the prefix of the archived messages of epoch of group
// gid: the messages sent in it.
func ArchivePrefix(gid []byte, epoch uint64) string {
	return "kolo-mls/archive/" + hex.EncodeToString(gid) + "/" + strconv.FormatUint(epoch, 10) + "/"
}

// ArchiveKey is the key of an archived message of epoch of group gid.
func ArchiveKey(gid []byte, epoch uint64, msg []byte) string {
	h := sha256.Sum256(msg)
	return ArchivePrefix(gid, epoch) + hex.EncodeToString(h[:])
}

// GetObject returns the MLSMessage with SHA-256 h, at most max bytes, from
// pins, checking the hash.
func GetObject(ctx context.Context, p Pins, h [32]byte, max int) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: no Pins", errs.ErrInvalidArgument)
	}
	b, err := p.Get(ctx, ObjectKey(h), max)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(b) != h {
		return nil, fmt.Errorf("%w: object does not match its hash", ErrMissing)
	}
	return b, nil
}

// PutObject keeps an MLSMessage under its hash and returns the hash.
func PutObject(ctx context.Context, p Pins, msg []byte) ([32]byte, error) {
	if p == nil {
		return [32]byte{}, fmt.Errorf("%w: no Pins", errs.ErrInvalidArgument)
	}
	h := sha256.Sum256(msg)
	return h, p.Put(ctx, ObjectKey(h), msg)
}

// Labels of the exported key and nonce of the encrypted ratchet tree.
const (
	treeKeyLabel   = "kolo-mls/ratchet-tree/v0"
	treeNonceLabel = "kolo-mls/ratchet-tree-nonce/v0"
)

// ErrSealedTree reports an encrypted tree that does not open.
var ErrSealedTree = errors.New("kolomls: encrypted tree does not open")

// sealedOverhead is the sealer's device key and the AEAD tag.
const sealedOverhead = 32 + 16

// SealTree returns the ratchet tree of m's epoch encrypted with AES-128-GCM
// (docs/design.md, "The Kolo layer"): the key and nonce are exported from
// the epoch (RFC 9420 section 8.5) for this sealer's device key, which leads
// the result, and the group id and epoch are the additional data. Two
// sealers never share a key, so a sealer that seals another tree reuses
// only its own nonce.
func SealTree(m *Member) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: no Member", errs.ErrInvalidArgument)
	}
	t, err := m.g.RatchetTree()
	if err != nil {
		return nil, err
	}
	sealer, err := m.device()
	if err != nil {
		return nil, err
	}
	return Seal(m.g.Export, m.gid, m.g.Epoch(), sealer, t)
}

// Seal is SealTree for a tree of epoch of group gid, sealed by device
// sealer with the epoch's exporter.
func Seal(export func(label string, context []byte, length int) ([]byte, error), gid []byte, epoch uint64, sealer [32]byte, tree []byte) ([]byte, error) {
	key, nonce, err := treeKey(export, sealer)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	ct, err := suite.Seal(key, nonce, treeAAD(gid, epoch), tree)
	if err != nil {
		return nil, err
	}
	return append(sealer[:], ct...), nil
}

// OpenTree decrypts a tree sealed by SealTree for epoch of group gid with the
// exporter of that epoch.
func OpenTree(export func(label string, context []byte, length int) ([]byte, error), gid []byte, epoch uint64, sealed []byte) ([]byte, error) {
	if len(sealed) < sealedOverhead {
		return nil, fmt.Errorf("%w: %d bytes", ErrSealedTree, len(sealed))
	}
	key, nonce, err := treeKey(export, [32]byte(sealed[:32]))
	if err != nil {
		return nil, err
	}
	defer clear(key)
	t, err := suite.Open(key, nonce, treeAAD(gid, epoch), sealed[32:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSealedTree, err)
	}
	return t, nil
}

func treeAAD(gid []byte, epoch uint64) []byte {
	var e kolocodec.Encoder
	e.PutBytes(gid)
	e.PutUvarint(epoch)
	return e.Bytes()
}

func treeKey(export func(string, []byte, int) ([]byte, error), sealer [32]byte) (key, nonce []byte, err error) {
	if export == nil {
		return nil, nil, fmt.Errorf("%w: no exporter", errs.ErrInvalidArgument)
	}
	if key, err = export(treeKeyLabel, sealer[:], suite.Nk); err != nil {
		return nil, nil, err
	}
	if nonce, err = export(treeNonceLabel, sealer[:], suite.Nn); err != nil {
		clear(key)
		return nil, nil, err
	}
	return key, nonce, nil
}
