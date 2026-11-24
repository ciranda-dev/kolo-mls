// Package braid is the admin side of a Kolo group over the admins' braid:
// references, votes and signature shares, the decision of each epoch's
// Commit, tree serving and the successor group.
package braid

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	kolobraid "github.com/ciranda-dev/kolo-braid"
	"github.com/ciranda-dev/kolo-braid/devices"
	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"

	"github.com/ciranda-dev/kolo-mls/cred"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// Tags that start the braid data entries of kolo-mls.
const (
	refTag  = "kolo-mls/commit-ref/v0"
	voteTag = "kolo-mls/commit-vote/v0"
	sigTag  = "kolo-mls/commit-sig/v0"
)

var maxTag = max(len(refTag), len(voteTag), len(sigTag))

// ErrEntry reports a braid entry body of kolo-mls that does not decode.
var ErrEntry = errors.New("kolomls: invalid braid entry")

type kind uint8

const (
	kindRef kind = iota + 1
	kindVote
	kindSig
)

// Sig is a settled commit-sig entry: one settler's signature share.
type Sig struct {
	Position  uint64
	Writer    [32]byte
	TBS       settle.TBS
	Signature [64]byte
	// Cert is the SHA-256 of the writer's device certificate the entry
	// carries.
	Cert [32]byte
}

// entry is a decoded body; ref, vote or sig is set by kind, without the
// position and writer, which the braid gives.
type entry struct {
	kind    kind
	cert    []byte
	groupID []byte
	epoch   uint64
	ref     Ref
	vote    Vote
	sig     Sig
}

// Every body carries its writer's device certificate, so the braid's apply
// checks the writer against the revocations at the entry's own position.

// refBody is the body of an admin's reference to a Commit kept on pins.
func refBody(cert, gid []byte, epoch uint64, commit [32]byte) []byte {
	var e kolocodec.Encoder
	e.PutString(refTag)
	e.PutBytes(cert)
	e.PutBytes(gid)
	e.PutUvarint(epoch)
	e.PutFixed(commit[:])
	return e.Bytes()
}

// voteBody is the body of a settler's vote on a referenced Commit.
func voteBody(cert, gid []byte, epoch uint64, commit, contextBefore [32]byte, accept bool, reason Reason) []byte {
	var e kolocodec.Encoder
	e.PutString(voteTag)
	e.PutBytes(cert)
	e.PutBytes(gid)
	e.PutUvarint(epoch)
	e.PutFixed(commit[:])
	e.PutFixed(contextBefore[:])
	e.PutBool(accept)
	e.PutUvarint(uint64(reason))
	return e.Bytes()
}

// sigBody is the body of a settler's signature share over t.
func sigBody(cert []byte, t *settle.TBS, sig []byte) []byte {
	var e kolocodec.Encoder
	e.PutString(sigTag)
	e.PutBytes(cert)
	e.PutFixed(t.Encode())
	e.PutFixed(sig)
	return e.Bytes()
}

// decodeEntry decodes a body written by refBody, voteBody or sigBody; ok is
// false for a body of another tag, which is not an error.
func decodeEntry(body []byte) (e *entry, ok bool, err error) {
	d := kolocodec.NewDecoder(body)
	tag, err := d.String(maxTag)
	if err != nil {
		return nil, false, nil
	}
	e = &entry{}
	switch tag {
	case refTag:
		e.kind = kindRef
	case voteTag:
		e.kind = kindVote
	case sigTag:
		e.kind = kindSig
	default:
		return nil, false, nil
	}
	if err := e.read(d); err != nil {
		return nil, true, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	if err := d.Done(); err != nil {
		return nil, true, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	return e, true, nil
}

func (e *entry) read(d *kolocodec.Decoder) error {
	var err error
	if e.cert, err = d.Bytes(cred.MaxBody); err != nil {
		return err
	}
	if len(e.cert) == 0 {
		return errors.New("no device certificate")
	}
	h := sha256.Sum256(e.cert)
	e.ref.Cert, e.vote.Cert, e.sig.Cert = h, h, h
	if e.kind == kindSig {
		if d.Len() < 64 {
			return errors.New("short signature entry")
		}
		rest, err := d.Fixed(d.Len() - 64)
		if err != nil {
			return err
		}
		t, err := settle.DecodeTBS(rest)
		if err != nil {
			return errors.New("signed bytes do not decode")
		}
		sig, err := d.Fixed(64)
		if err != nil {
			return err
		}
		e.groupID, e.epoch = t.GroupID, t.Epoch
		e.sig.TBS, e.sig.Signature = *t, [64]byte(sig)
		return nil
	}
	if e.groupID, err = d.Bytes(suite.Nh); err != nil {
		return err
	}
	if len(e.groupID) != suite.Nh {
		return fmt.Errorf("group id of %d bytes", len(e.groupID))
	}
	if e.epoch, err = d.Uvarint(); err != nil {
		return err
	}
	commit, err := d.Fixed(32)
	if err != nil {
		return err
	}
	if e.kind == kindRef {
		e.ref.Commit = [32]byte(commit)
		return nil
	}
	ctx, err := d.Fixed(32)
	if err != nil {
		return err
	}
	accept, err := d.Bool()
	if err != nil {
		return err
	}
	reason, err := d.UvarintMax(255)
	if err != nil {
		return err
	}
	e.vote.Commit, e.vote.ContextBefore, e.vote.Accept, e.vote.Reason = [32]byte(commit), [32]byte(ctx), accept, Reason(reason)
	return nil
}

// Index keeps the kolo-mls entries of a braid in its view, by group, epoch
// and position, for the decision; it never touches MLS state, as a braid's
// apply function must not.
type Index struct {
	prefix []byte
	roster *devices.Store
}

// NewIndex returns an Index whose records live in the view under prefix; no
// other view key may start with it. Entries of a writer whose certificate
// roster revokes at the entry's position are rejected; a nil roster holds no
// revocation.
func NewIndex(prefix []byte, roster *devices.Store) *Index {
	return &Index{prefix: append([]byte(nil), prefix...), roster: roster}
}

func (x *Index) key(gid []byte, epoch, pos uint64) []byte {
	k := append(append([]byte(nil), x.prefix...), gid...)
	k = binary.BigEndian.AppendUint64(k, epoch)
	return binary.BigEndian.AppendUint64(k, pos)
}

// Apply records e when it is a kolo-mls entry and reports false for every
// other entry. A body with a kolo-mls tag that does not decode, or whose
// writer's certificate is not valid or revoked at e's position, is rejected
// on every peer.
func (x *Index) Apply(tx *kolobraid.Tx, e *kolobraid.Entry) (bool, error) {
	if e.Kind != kolobraid.KindData {
		return false, nil
	}
	d, ok, err := decodeEntry(e.Body)
	if !ok {
		return false, nil
	}
	if err != nil {
		return true, kolobraid.Reject(err.Error())
	}
	c, err := koloid.DecodeDeviceCert(d.cert)
	if err != nil || !bytes.Equal(c.Device(), e.Writer) {
		return true, kolobraid.Reject("the writer's device certificate")
	}
	var revs []*koloid.Revocation
	if x.roster != nil {
		if revs, err = x.roster.RevocationsOfTx(tx, c.Person(), c); err != nil {
			return true, err
		}
	}
	// Expiry stays out of apply, as in the devices roster.
	if c.Verify(&koloid.VerifyOptions{Person: c.Person(), Now: time.Unix(0, 0), Revocations: revs}) != nil {
		return true, kolobraid.Reject("the writer is revoked at this position")
	}
	return true, tx.Put(x.key(d.groupID, d.epoch, e.Position), append(append([]byte(nil), e.Writer...), e.Body...))
}

// Entries returns the kolo-mls entries of group gid and epoch in s, in the
// braid's order, or the storage error that cut the read short.
func (x *Index) Entries(s *kolobraid.Snapshot, gid []byte, epoch uint64) (refs []Ref, votes []Vote, sigs []Sig, err error) {
	if len(gid) != suite.Nh || epoch == ^uint64(0) {
		return nil, nil, nil, fmt.Errorf("%w: group id or epoch", errs.ErrInvalidArgument)
	}
	start := x.key(gid, epoch, 0)
	end := x.key(gid, epoch+1, 0)
	pairs, scanErr := s.ScanErr(start, end)
	for k, v := range pairs {
		if len(v) < 32 || len(k) != len(start) {
			return nil, nil, nil, fmt.Errorf("%w: index record", ErrEntry)
		}
		pos := binary.BigEndian.Uint64(k[len(k)-8:])
		writer := [32]byte(v[:32])
		e, _, err := decodeEntry(v[32:])
		if err != nil {
			return nil, nil, nil, err
		}
		switch e.kind {
		case kindRef:
			e.ref.Position, e.ref.Writer = pos, writer
			refs = append(refs, e.ref)
		case kindVote:
			e.vote.Position, e.vote.Writer = pos, writer
			votes = append(votes, e.vote)
		case kindSig:
			e.sig.Position, e.sig.Writer = pos, writer
			sigs = append(sigs, e.sig)
		}
	}
	if err := scanErr(); err != nil {
		return nil, nil, nil, err
	}
	return refs, votes, sigs, nil
}
