// Package settle holds the Kolo rules every member device of a Kolo group
// needs: the roles extension, the commit Policy, the authenticated data
// envelope, the settled-commit signatures and the decision of each epoch's
// Commit over the settled order of the admins' braid.
package settle

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"

	kolocodec "github.com/ciranda-dev/kolo-codec"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/message"
)

// RolesExtension is the GroupContext extension type of the roles, from the
// private-use range of RFC 9420 section 17.3.
const RolesExtension uint16 = 0xF002

// Quorum is the rule that sets how many settlers must agree.
type Quorum uint8

// Quorum rules, as the braid's.
const (
	// Majority needs floor(s/2) + 1 of s settlers.
	Majority Quorum = 1
	// TwoThirds needs floor(2s/3) + 1 of s settlers.
	TwoThirds Quorum = 2
)

// ErrRoles reports a roles extension that does not decode or breaks a rule.
var ErrRoles = errors.New("kolomls: invalid roles extension")

// Roles names the group's braid, its admin devices and its settler devices.
type Roles struct {
	// Braid is the group id of the admins' braid.
	Braid [32]byte
	// Quorum is the settlers' quorum rule.
	Quorum Quorum
	// Admins and Settlers are device keys in strictly increasing order;
	// Settlers is a non-empty subset of Admins.
	Admins, Settlers [][32]byte
}

// Q returns how many settlers a settled Commit needs.
func (r *Roles) Q() int {
	s := len(r.Settlers)
	if r.Quorum == TwoThirds {
		return 2*s/3 + 1
	}
	return s/2 + 1
}

// RejectQuorum returns how many reject votes decide a reference: s - q + 1,
// so that one of the two outcomes is always reachable by s honest votes.
func (r *Roles) RejectQuorum() int {
	return len(r.Settlers) - r.Q() + 1
}

// Admin reports whether device is an admin.
func (r *Roles) Admin(device []byte) bool {
	return r != nil && contains(r.Admins, device)
}

// Settler reports whether device is a settler.
func (r *Roles) Settler(device []byte) bool {
	return r != nil && contains(r.Settlers, device)
}

func contains(keys [][32]byte, k []byte) bool {
	if len(k) != 32 {
		return false
	}
	_, ok := slices.BinarySearchFunc(keys, [32]byte(k), func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return ok
}

// Encode returns the extension data of r.
func (r *Roles) Encode() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(0)
	e.PutFixed(r.Braid[:])
	e.PutUvarint(uint64(r.Quorum))
	for _, l := range [][][32]byte{r.Admins, r.Settlers} {
		e.PutUvarint(uint64(len(l)))
		for _, k := range l {
			e.PutFixed(k[:])
		}
	}
	return e.Bytes()
}

// Extension returns r as a GroupContext extension.
func (r *Roles) Extension() kolomls.Extension {
	return kolomls.Extension{Type: RolesExtension, Data: r.Encode()}
}

// Limits cap what a roles extension may hold; zero or less is no cap, and
// then only the size of the extension bounds the counts.
type Limits struct {
	MaxAdmins, MaxSettlers int
}

// DecodeRoles decodes and checks the data of a roles extension.
func DecodeRoles(b []byte, l Limits) (*Roles, error) {
	d := kolocodec.NewDecoder(b)
	v, err := d.Uvarint()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRoles, err)
	}
	if v != 0 {
		return nil, fmt.Errorf("%w: version %d", ErrRoles, v)
	}
	r := &Roles{}
	braid, err := d.Fixed(32)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRoles, err)
	}
	r.Braid = [32]byte(braid)
	q, err := d.UvarintMax(uint64(TwoThirds))
	if err != nil || q == 0 {
		return nil, fmt.Errorf("%w: quorum rule", ErrRoles)
	}
	r.Quorum = Quorum(q)
	if r.Admins, err = readKeys(d, l.MaxAdmins); err != nil {
		return nil, err
	}
	if r.Settlers, err = readKeys(d, l.MaxSettlers); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRoles, err)
	}
	if len(r.Admins) == 0 || len(r.Settlers) == 0 {
		return nil, fmt.Errorf("%w: no admin or no settler", ErrRoles)
	}
	for _, k := range r.Settlers {
		if !r.Admin(k[:]) {
			return nil, fmt.Errorf("%w: a settler is not an admin", ErrRoles)
		}
	}
	return r, nil
}

// readKeys reads a count of at most max (none when max is zero or less) and
// that many keys in strictly increasing order.
func readKeys(d *kolocodec.Decoder, max int) ([][32]byte, error) {
	n, err := d.Uvarint()
	if err != nil {
		return nil, fmt.Errorf("%w: key count: %w", ErrRoles, err)
	}
	if n > uint64(d.Len()/32) || max > 0 && n > uint64(max) {
		return nil, fmt.Errorf("%w: key count %d", ErrRoles, n)
	}
	out := make([][32]byte, 0, n)
	for range n {
		k, err := d.Fixed(32)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRoles, err)
		}
		if len(out) > 0 && bytes.Compare(out[len(out)-1][:], k) >= 0 {
			return nil, fmt.Errorf("%w: keys not strictly increasing", ErrRoles)
		}
		out = append(out, [32]byte(k))
	}
	return out, nil
}

// NewRoles returns the roles of a braid with admins and settlers in any
// order, checked as DecodeRoles checks them.
func NewRoles(braid [32]byte, q Quorum, admins, settlers []ed25519.PublicKey, l Limits) (*Roles, error) {
	sorted := func(keys []ed25519.PublicKey) [][32]byte {
		var out [][32]byte
		for _, k := range keys {
			if len(k) == 32 {
				out = append(out, [32]byte(k))
			}
		}
		slices.SortFunc(out, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
		return slices.Compact(out)
	}
	r := &Roles{Braid: braid, Quorum: q, Admins: sorted(admins), Settlers: sorted(settlers)}
	if len(r.Admins) != len(admins) || len(r.Settlers) != len(settlers) {
		return nil, fmt.Errorf("%w: keys must be distinct and 32 bytes", ErrRoles)
	}
	return DecodeRoles(r.Encode(), l)
}

// RolesOf returns the roles extension of a GroupContext extension list.
func RolesOf(exts []kolomls.Extension, l Limits) (*Roles, error) {
	for _, e := range exts {
		if e.Type == RolesExtension {
			return DecodeRoles(e.Data, l)
		}
	}
	return nil, fmt.Errorf("%w: missing", ErrRoles)
}

// GroupExtensions returns the GroupContext extensions of a Kolo group:
// required_capabilities naming the Kolo credential and the roles extension
// (RFC 9420 section 11.1), and the roles.
func GroupExtensions(r *Roles) ([]kolomls.Extension, error) {
	rc := &message.RequiredCapabilities{Extensions: []uint16{RolesExtension}, Credentials: []uint16{cred.Type}}
	b, err := rc.Marshal()
	if err != nil {
		return nil, err
	}
	return []kolomls.Extension{{Type: message.ExtRequiredCapabilities, Data: b}, r.Extension()}, nil
}

// Capabilities returns the capabilities every Kolo leaf lists besides the
// version and the cipher suite.
func Capabilities() kolomls.Capabilities {
	return kolomls.Capabilities{Extensions: []uint16{RolesExtension}, Credentials: []uint16{cred.Type}}
}

// checkGroupExtensions checks a Kolo group's GroupContext extensions: the
// required capabilities, valid roles, no external senders.
func checkGroupExtensions(exts []kolomls.Extension, l Limits) (*Roles, error) {
	var rcOK bool
	for _, e := range exts {
		switch e.Type {
		case message.ExtExternalSenders:
			return nil, fmt.Errorf("%w: external senders", ErrRule)
		case message.ExtRequiredCapabilities:
			rc, err := message.UnmarshalRequiredCapabilities(e.Data)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrRule, err)
			}
			rcOK = slices.Contains(rc.Extensions, RolesExtension) && slices.Contains(rc.Credentials, cred.Type)
		}
	}
	if !rcOK {
		return nil, fmt.Errorf("%w: required capabilities must name the Kolo credential and the roles extension", ErrRule)
	}
	return RolesOf(exts, l)
}
