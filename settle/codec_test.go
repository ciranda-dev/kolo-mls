package settle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"

	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/kolotest"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

func key(b byte) [32]byte { return [32]byte{b} }

func keyb(b byte) []byte { k := key(b); return k[:] }

func keys(bs ...byte) [][32]byte {
	var out [][32]byte
	for _, b := range bs {
		out = append(out, key(b))
	}
	return out
}

// TestQuorum: q and the reject quorum for the seat counts of the braid's
// table (1, 2, 3, 4, 5 and 7 seats).
func TestQuorum(t *testing.T) {
	for _, c := range []struct{ s, majority, twoThirds int }{{1, 1, 1}, {2, 2, 2}, {3, 2, 3}, {4, 3, 3}, {5, 3, 4}, {7, 4, 5}} {
		var settlers [][32]byte
		for i := range c.s {
			settlers = append(settlers, key(byte(i+1)))
		}
		m := &Roles{Quorum: Majority, Settlers: settlers}
		tt := &Roles{Quorum: TwoThirds, Settlers: settlers}
		if m.Q() != c.majority || tt.Q() != c.twoThirds || m.RejectQuorum() != c.s-c.majority+1 || tt.RejectQuorum() != c.s-c.twoThirds+1 {
			t.Fatalf("%d seats: q %d and %d", c.s, m.Q(), tt.Q())
		}
	}
}

func rolesBytes(version, quorum uint64, admins, settlers [][32]byte, extra ...byte) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutFixed(make([]byte, 32))
	e.PutUvarint(quorum)
	for _, l := range [][][32]byte{admins, settlers} {
		e.PutUvarint(uint64(len(l)))
		for _, k := range l {
			e.PutFixed(k[:])
		}
	}
	return append(e.Bytes(), extra...)
}

func TestRolesCodec(t *testing.T) {
	r := &Roles{Braid: key(9), Quorum: TwoThirds, Admins: keys(1, 2, 3), Settlers: keys(1, 3)}
	got, err := DecodeRoles(r.Encode(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Encode(), r.Encode()) || !got.Admin(keyb(2)) {
		t.Fatal("round trip differs")
	}
	if !got.Settler(keyb(3)) || got.Settler(keyb(2)) || got.Admin([]byte{1}) {
		t.Fatal("membership checks")
	}
	for name, b := range map[string][]byte{
		"version 1":           rolesBytes(1, 1, keys(1), keys(1)),
		"quorum 0":            rolesBytes(0, 0, keys(1), keys(1)),
		"quorum 3":            rolesBytes(0, 3, keys(1), keys(1)),
		"no admin":            rolesBytes(0, 1, nil, nil),
		"no settler":          rolesBytes(0, 1, keys(1), nil),
		"settler not admin":   rolesBytes(0, 1, keys(1), keys(2)),
		"admins unsorted":     rolesBytes(0, 1, keys(2, 1), keys(1)),
		"admins repeated":     rolesBytes(0, 1, keys(1, 1), keys(1)),
		"settlers unsorted":   rolesBytes(0, 1, keys(1, 2), keys(2, 1)),
		"trailing byte":       rolesBytes(0, 1, keys(1), keys(1), 0),
		"short":               rolesBytes(0, 1, keys(1), keys(1))[:40],
		"empty":               nil,
		"too many admins":     rolesBytes(0, 1, keys(1, 2, 3), keys(1)),
		"too many settlers":   rolesBytes(0, 1, keys(1, 2), keys(1, 2)),
		"count past the data": append(rolesBytes(0, 1, keys(1), keys(1))[:68], 0x7f),
	} {
		if _, err := DecodeRoles(b, Limits{MaxAdmins: 2, MaxSettlers: 1}); !errors.Is(err, ErrRoles) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := DecodeRoles(rolesBytes(0, 1, keys(1, 2), keys(1)), Limits{MaxAdmins: 2, MaxSettlers: 1}); err != nil {
		t.Fatalf("at the bounds: %v", err)
	}
	if _, err := NewRoles(key(1), Majority, []ed25519.PublicKey{keyb(1), keyb(1)}, []ed25519.PublicKey{keyb(1)}, Limits{}); !errors.Is(err, ErrRoles) {
		t.Fatalf("NewRoles with a repeated key: %v", err)
	}
	if _, err := NewRoles(key(1), Majority, []ed25519.PublicKey{{1}}, []ed25519.PublicKey{{1}}, Limits{}); !errors.Is(err, ErrRoles) {
		t.Fatalf("NewRoles with a short key: %v", err)
	}
	if _, err := RolesOf(nil, Limits{}); !errors.Is(err, ErrRoles) {
		t.Fatalf("no roles: %v", err)
	}
}

func TestGroupExtensions(t *testing.T) {
	r := &Roles{Braid: key(9), Quorum: Majority, Admins: keys(1), Settlers: keys(1)}
	exts, err := GroupExtensions(r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := checkGroupExtensions(exts, Limits{}); err != nil || !bytes.Equal(got.Encode(), r.Encode()) {
		t.Fatalf("Kolo extensions: %v", err)
	}
	rc := func(c message.RequiredCapabilities) tls.Extension {
		b, _ := c.Marshal()
		return tls.Extension{Type: message.ExtRequiredCapabilities, Data: b}
	}
	for name, l := range map[string][]tls.Extension{
		"no required capabilities": {r.Extension()},
		"no credential type":       {rc(message.RequiredCapabilities{Extensions: []uint16{RolesExtension}}), r.Extension()},
		"no roles extension type":  {rc(message.RequiredCapabilities{Credentials: []uint16{cred.Type}}), r.Extension()},
		"malformed":                {{Type: message.ExtRequiredCapabilities, Data: []byte{1}}, r.Extension()},
		"external senders":         append(slices.Clone(exts), tls.Extension{Type: message.ExtExternalSenders}),
	} {
		if _, err := checkGroupExtensions(l, Limits{}); !errors.Is(err, ErrRule) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := checkGroupExtensions(exts[:1], Limits{}); !errors.Is(err, ErrRoles) {
		t.Fatalf("no roles: %v", err)
	}
	caps := Capabilities()
	if len(caps.Extensions) != 1 || caps.Extensions[0] != RolesExtension || caps.Credentials[0] != cred.Type {
		t.Fatal("capabilities")
	}
}

func TestEnvelope(t *testing.T) {
	var e Envelope
	ad, err := e.Wrap(7, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e.Unwrap(7, ad); err != nil || string(got) != "aad" {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if _, err := e.Unwrap(8, ad); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("other generation: %v", err)
	}
	var v1 kolocodec.Encoder
	v1.PutUvarint(1)
	v1.PutUvarint(7)
	v1.PutBytes(nil)
	for name, b := range map[string][]byte{"version 1": v1.Bytes(), "trailing": append(ad, 0), "empty": nil, "short": ad[:2], "no generation": {0}} {
		if _, err := e.Unwrap(7, b); !errors.Is(err, ErrEnvelope) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func signer(t *testing.T) (*koloid.Identity, [32]byte) {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id, [32]byte(id.PublicKey())
}

func testTBS() *TBS {
	return &TBS{GroupID: bytes.Repeat([]byte{1}, 32), Epoch: 5, Commit: key(2), ContextBefore: key(3), ContextAfter: key(4), Braid: key(5), RefPosition: 77}
}

func TestSettledCodec(t *testing.T) {
	tbs := testTBS()
	got, err := DecodeTBS(tbs.Encode())
	if err != nil || !bytes.Equal(got.Encode(), tbs.Encode()) {
		t.Fatalf("TBS round trip: %v", err)
	}
	var ids []*koloid.Identity
	var pubs [][32]byte
	for range 3 {
		id, pub := signer(t)
		ids, pubs = append(ids, id), append(pubs, pub)
	}
	r, err := NewRoles(tbs.Braid, Majority, []ed25519.PublicKey{pubs[0][:], pubs[1][:], pubs[2][:]}, []ed25519.PublicKey{pubs[0][:], pubs[1][:], pubs[2][:]}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var shares []Share
	for i, id := range ids {
		sig, err := sign(id, tbs)
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, Share{Signer: pubs[i], Signature: [64]byte(sig)})
	}
	outsider, out := signer(t)
	osig, _ := sign(outsider, tbs)
	bad := shares[2]
	bad.Signature[0] ^= 1
	s := assemble(tbs, append([]Share{bad, {Signer: out, Signature: [64]byte(osig)}, shares[0]}, shares[0], shares[1]), r)
	if len(s.Shares) != 2 {
		t.Fatalf("Assemble kept %d shares", len(s.Shares))
	}
	enc := s.Encode()
	d, err := DecodeSettled(enc, 0)
	if err != nil || !bytes.Equal(d.Encode(), enc) {
		t.Fatalf("round trip: %v", err)
	}
	all := func([32]byte) bool { return true }
	if d.Valid(r, all) != 2 || d.Valid(r, func(k [32]byte) bool { return k != pubs[0] }) != 1 {
		t.Fatal("valid count")
	}
	// Valid ignores a correct signature of a key outside the settlers and a
	// settler's signature that does not verify.
	mixed := &Settled{TBS: *tbs, Shares: []Share{{Signer: out, Signature: [64]byte(osig)}, bad, shares[0]}}
	if mixed.Valid(r, all) != 1 {
		t.Fatalf("valid count with an outsider and a bad share: %d", mixed.Valid(r, all))
	}
	// Unsorted, repeated or too many signers, another tag, trailing bytes.
	swapped := &Settled{TBS: *tbs, Shares: []Share{s.Shares[1], s.Shares[0]}}
	repeated := &Settled{TBS: *tbs, Shares: []Share{s.Shares[0], s.Shares[0]}}
	if bytes.Compare(s.Shares[0].Signer[:], s.Shares[1].Signer[:]) > 0 {
		t.Fatal("Assemble did not sort")
	}
	other := bytes.Replace(enc, []byte("settled-commit/v0"), []byte("settled-commit/v1"), 1)
	for name, b := range map[string][]byte{
		"unsorted": swapped.Encode(), "repeated": repeated.Encode(), "trailing": append(enc, 0), "tag": other, "empty": nil,
		"short group id": (&Settled{TBS: TBS{GroupID: []byte{1}}}).Encode(),
	} {
		if _, err := DecodeSettled(b, 0); !errors.Is(err, ErrNotSettled) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := DecodeSettled(enc, 1); !errors.Is(err, ErrNotSettled) {
		t.Fatalf("more shares than the bound: %v", err)
	}
	if _, err := DecodeTBS(append(tbs.Encode(), 0)); !errors.Is(err, ErrNotSettled) {
		t.Fatalf("TBS trailing byte: %v", err)
	}
	v1 := tbs.Encode()
	v1[0] = 1
	if _, err := DecodeTBS(v1); !errors.Is(err, ErrNotSettled) {
		t.Fatalf("TBS version 1: %v", err)
	}
}

// TestNoRoleCeilings: with no Limits set, a group of 1,100 admins and 70
// settlers is accepted and settles with every settler's signature.
func TestNoRoleCeilings(t *testing.T) {
	tbs := testTBS()
	var ids []*koloid.Identity
	var admins, settlers []ed25519.PublicKey
	for range 70 {
		id, pub := signer(t)
		ids, settlers = append(ids, id), append(settlers, pub[:])
	}
	admins = append(admins, settlers...)
	for i := range 1030 {
		admins = append(admins, []byte{byte(i), byte(i >> 8), 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	}
	r, err := NewRoles(tbs.Braid, Majority, admins, settlers, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Admins) != 1100 || len(r.Settlers) != 70 || r.Q() != 36 {
		t.Fatalf("%d admins, %d settlers, q %d", len(r.Admins), len(r.Settlers), r.Q())
	}
	exts, err := GroupExtensions(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkGroupExtensions(exts, Limits{}); err != nil {
		t.Fatal(err)
	}
	var shares []Share
	for _, id := range ids {
		sig, err := sign(id, tbs)
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, Share{Signer: [32]byte(id.PublicKey()), Signature: [64]byte(sig)})
	}
	enc := assemble(tbs, shares, r).Encode()
	for _, max := range []int{0, 70} {
		s, err := DecodeSettled(enc, max)
		if err != nil || len(s.Shares) != 70 {
			t.Fatalf("DecodeSettled(%d): %v", max, err)
		}
		all := func([32]byte) bool { return true }
		if s.Valid(r, all) != 70 {
			t.Fatalf("DecodeSettled(%d): valid count", max)
		}
	}
	if _, err := DecodeSettled(enc, 69); !errors.Is(err, ErrNotSettled) {
		t.Fatalf("more shares than settlers: %v", err)
	}
	if _, err := DecodeRoles(r.Encode(), Limits{MaxAdmins: 1099}); !errors.Is(err, ErrRoles) {
		t.Fatalf("an application's cap: %v", err)
	}
}

// TestSettledCheck: each field a member compares before it processes a
// Commit.
func TestSettledCheck(t *testing.T) {
	context, commit := []byte("context"), []byte("commit")
	tbs := testTBS()
	tbs.ContextBefore, tbs.Commit = sha256.Sum256(context), sha256.Sum256(commit)
	var ids []*koloid.Identity
	var pubs []ed25519.PublicKey
	for range 4 {
		id, _ := signer(t)
		ids, pubs = append(ids, id), append(pubs, id.PublicKey())
	}
	r, err := NewRoles(tbs.Braid, Majority, pubs, pubs, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var shares []Share
	for _, id := range ids[:3] {
		sig, _ := sign(id, tbs)
		shares = append(shares, Share{Signer: [32]byte(id.PublicKey()), Signature: [64]byte(sig)})
	}
	s := assemble(tbs, shares, r)
	all := func([32]byte) bool { return true }
	if err := s.Check(context, commit, tbs.GroupID, tbs.Epoch, r, all); err != nil {
		t.Fatal(err)
	}
	two := assemble(tbs, shares[:2], r)
	otherBraid := *r
	otherBraid.Braid = key(6)
	many := &Settled{TBS: *tbs, Shares: append(append([]Share{}, s.Shares...), Share{Signer: key(0xff)}, Share{Signer: key(0xfe)})}
	for name, err := range map[string]error{
		"context":       s.Check([]byte("other"), commit, tbs.GroupID, tbs.Epoch, r, all),
		"commit":        s.Check(context, []byte("other"), tbs.GroupID, tbs.Epoch, r, all),
		"group":         s.Check(context, commit, make([]byte, 32), tbs.Epoch, r, all),
		"epoch":         s.Check(context, commit, tbs.GroupID, tbs.Epoch+1, r, all),
		"braid":         s.Check(context, commit, tbs.GroupID, tbs.Epoch, &otherBraid, all),
		"two of four":   two.Check(context, commit, tbs.GroupID, tbs.Epoch, r, all),
		"not leaves":    s.Check(context, commit, tbs.GroupID, tbs.Epoch, r, func([32]byte) bool { return false }),
		"too many sigs": many.Check(context, commit, tbs.GroupID, tbs.Epoch, r, all),
	} {
		if !errors.Is(err, ErrNotSettled) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// sign and assemble are the settler's side, in package braid, repeated for
// these tests.
func sign(id *koloid.Identity, t *TBS) ([]byte, error) {
	return id.Sign(SettledContext, t.Encode())
}

func assemble(t *TBS, shares []Share, roles *Roles) *Settled {
	tbs := t.Encode()
	byKey := map[[32]byte]Share{}
	for _, sh := range shares {
		if _, ok := byKey[sh.Signer]; !ok && roles.Settler(sh.Signer[:]) && koloid.Verify(ed25519.PublicKey(sh.Signer[:]), SettledContext, tbs, sh.Signature[:]) {
			byKey[sh.Signer] = sh
		}
	}
	s := &Settled{TBS: *t}
	for _, k := range roles.Settlers {
		if sh, ok := byKey[k]; ok {
			s.Shares = append(s.Shares, sh)
		}
	}
	return s
}

// TestCapabilitiesAgree: the test helpers' leaf capabilities are these.
func TestCapabilitiesAgree(t *testing.T) {
	if fmt.Sprint(Capabilities()) != fmt.Sprint(kolotest.Capabilities()) {
		t.Fatal("kolotest capabilities differ")
	}
}

// TestSignedBytes pins the bytes settlers sign and the SettledCommit
// encoding, built here field by field from the format.
func TestSignedBytes(t *testing.T) {
	key32 := func(b byte) string { return fmt.Sprintf("%02x", b) + strings.Repeat("00", 31) }
	wantTBS := "00" + "20" + strings.Repeat("01", 32) + "05" + key32(2) + key32(3) + key32(4) + key32(5) + "4d"
	if got := hex.EncodeToString(testTBS().Encode()); got != wantTBS {
		t.Fatalf("TBS\n got %s\nwant %s", got, wantTBS)
	}
	s := &Settled{TBS: *testTBS(), Shares: []Share{{Signer: key(9), Signature: [64]byte(bytes.Repeat([]byte{7}, 64))}}}
	want := "1a" + hex.EncodeToString([]byte(settledTag)) + wantTBS + "01" + key32(9) + strings.Repeat("07", 64)
	if got := hex.EncodeToString(s.Encode()); got != want {
		t.Fatalf("SettledCommit\n got %s\nwant %s", got, want)
	}
	if len(settledTag) != 0x1a {
		t.Fatal("tag length")
	}
	if n := len(s.Encode()) + 95*96; n > maxSettledBytes(96) {
		t.Fatalf("a SettledCommit of 96 shares takes %d bytes", n)
	}
}

// TestSettledNil: a check without roles or a member test is refused.
func TestSettledNil(t *testing.T) {
	s := &Settled{TBS: *testTBS()}
	if err := s.Check(nil, nil, s.TBS.GroupID, s.TBS.Epoch, nil, func([32]byte) bool { return true }); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("no roles: %v", err)
	}
	if err := s.Check(nil, nil, s.TBS.GroupID, s.TBS.Epoch, &Roles{}, nil); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("no member check: %v", err)
	}
	if (*Settled)(nil).Valid(&Roles{}, nil) != 0 {
		t.Fatal("a nil SettledCommit counts")
	}
}
