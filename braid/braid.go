package braid

import (
	"bytes"
	"context"
	"slices"

	kolobraid "github.com/ciranda-dev/kolo-braid"
	"github.com/ciranda-dev/kolo-braid/devices"
	koloid "github.com/ciranda-dev/kolo-id"
)

// BraidOrder is the Order of a kolo-braid braid whose apply function feeds
// an Index, with the devices roster in the same view.
type BraidOrder struct {
	b      *kolobraid.Braid
	idx    *Index
	roster *devices.Store
}

// NewBraidOrder returns the Order of b; b and idx are required, roster nil
// holds no revocation.
func NewBraidOrder(b *kolobraid.Braid, idx *Index, roster *devices.Store) *BraidOrder {
	return &BraidOrder{b: b, idx: idx, roster: roster}
}

// ID returns the braid's group id.
func (o *BraidOrder) ID() [32]byte { return [32]byte(o.b.GroupID()) }

// Append writes a data entry.
func (o *BraidOrder) Append(ctx context.Context, body []byte) error {
	_, err := o.b.Append(ctx, body)
	return err
}

// Entries reads the settled view.
func (o *BraidOrder) Entries(gid []byte, epoch uint64) ([]Ref, []Vote, []Sig, error) {
	s := o.b.Settled()
	defer s.Close()
	return o.idx.Entries(s, gid, epoch)
}

// Own reads the whole view, settled and tentative.
func (o *BraidOrder) Own(gid []byte, epoch uint64) ([]Vote, []Sig, error) {
	s := o.b.View()
	defer s.Close()
	_, votes, sigs, err := o.idx.Entries(s, gid, epoch)
	if err != nil {
		return nil, nil, err
	}
	me := [32]byte(o.b.PublicKey())
	var vs []Vote
	var ss []Sig
	for _, v := range votes {
		if v.Writer == me {
			vs = append(vs, v)
		}
	}
	for _, x := range sigs {
		if x.Writer == me {
			ss = append(ss, x)
		}
	}
	return vs, ss, nil
}

// Revocations reads what voids cert in the settled roster: the device's
// revocations and its issuer's.
func (o *BraidOrder) Revocations(cert *koloid.DeviceCert) ([]*koloid.Revocation, error) {
	if o.roster == nil {
		return nil, nil
	}
	s := o.b.Settled()
	defer s.Close()
	return o.roster.RevocationsOf(s, cert.Person(), cert)
}

// RevocationsAt reads what voids cert in the roster right after the settled
// entry at position. Each call replays the braid from its last such read
// to position (kolo-braid's SettledAt), so callers keep the answers.
func (o *BraidOrder) RevocationsAt(ctx context.Context, position uint64, cert *koloid.DeviceCert) ([]*koloid.Revocation, error) {
	if o.roster == nil {
		return nil, nil
	}
	s, err := o.b.SettledAt(ctx, position)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return o.roster.RevocationsOf(s, cert.Person(), cert)
}

// Roster reads the settled membership in one snapshot: the admins, and the
// seats and quorum of the settler config that settled it.
func (o *BraidOrder) Roster() (admins, settlers [][32]byte, q int, err error) {
	s := o.b.Settled()
	defer s.Close()
	for _, m := range s.Members() {
		if m.Roles&kolobraid.RoleAdmin != 0 {
			admins = append(admins, [32]byte(m.Key))
		}
	}
	st := s.Settlers()
	for _, m := range st.Seats {
		settlers = append(settlers, [32]byte(m.Key))
	}
	cmp := func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) }
	slices.SortFunc(admins, cmp)
	slices.SortFunc(settlers, cmp)
	return admins, settlers, st.Quorum, s.Err()
}
