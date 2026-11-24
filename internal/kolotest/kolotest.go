// Package kolotest builds kolo-id persons and devices with Kolo credentials
// for the tests of the Kolo layer.
package kolotest

import (
	"crypto/ed25519"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// rolesExtension is the roles extension type, repeated here because the
// tests of package settle import this package, so it cannot import settle.
const rolesExtension uint16 = 0xF002

// Device is one device of a person: its kolo-id identity and certificate.
type Device struct {
	Person *koloid.Identity
	ID     *koloid.Identity
	Cert   *koloid.DeviceCert
}

// Person returns a new person key.
func Person(t testing.TB) *koloid.Identity {
	t.Helper()
	p, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// NewDevice returns a device of person certified by the person key, an
// approver when approver is set.
func NewDevice(t testing.TB, person *koloid.Identity, approver bool) *Device {
	t.Helper()
	return certify(t, person, nil, approver, time.Time{})
}

// Approved returns an ordinary device certified by the approver device a.
func Approved(t testing.TB, a *Device) *Device {
	t.Helper()
	return certifyBy(t, a)
}

// Expiring returns a device of person whose certificate expires at exp.
func Expiring(t testing.TB, person *koloid.Identity, exp time.Time) *Device {
	t.Helper()
	return certify(t, person, nil, false, exp)
}

func certify(t testing.TB, person *koloid.Identity, parent *koloid.DeviceCert, approver bool, exp time.Time) *Device {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Time{}
	if !exp.IsZero() {
		issued = exp.Add(-time.Hour)
	}
	o, err := person.OfferDeviceCert(id.PublicKey(), &koloid.IssueOptions{Parent: parent, Serial: 1, Approver: approver, IssuedAt: issued, ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	c, err := id.AcceptDeviceCert(o, person.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return &Device{Person: person, ID: id, Cert: c}
}

func certifyBy(t testing.TB, a *Device) *Device {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	o, err := a.ID.OfferDeviceCert(id.PublicKey(), &koloid.IssueOptions{Parent: a.Cert, Serial: 1})
	if err != nil {
		t.Fatal(err)
	}
	c, err := id.AcceptDeviceCert(o, a.Person.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return &Device{Person: a.Person, ID: id, Cert: c}
}

// Key returns the device key as an array.
func (d *Device) Key() [32]byte { return [32]byte(d.ID.PublicKey()) }

// Credential returns a Kolo credential of d for a new MLS signature key.
func (d *Device) Credential(t testing.TB) (tree.Credential, ed25519.PrivateKey) {
	t.Helper()
	_, sig, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cred.New(d.ID, d.Cert, sig.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return c, sig
}

// Capabilities are those of a Kolo leaf, as settle.Capabilities gives
// them (TestCapabilitiesAgree).
func Capabilities() tree.Capabilities {
	return tree.Capabilities{Extensions: []uint16{rolesExtension}, Credentials: []uint16{cred.Type}}
}

// KeyPackage makes a KeyPackage of d whose private keys go in st.
func (d *Device) KeyPackage(t testing.TB, st kolomls.Store) []byte {
	t.Helper()
	c, sig := d.Credential(t)
	kp, err := kolomls.NewKeyPackage(st, kolomls.KeyPackageOptions{Credential: c, SignatureKey: sig, Capabilities: Capabilities()})
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// CreateOptions returns the options of a group that d creates on st with cfg
// and the GroupContext extensions exts, from a new KeyPackage of d made on st.
func (d *Device) CreateOptions(t testing.TB, st kolomls.Store, cfg kolomls.Config, exts []tls.Extension) kolomls.CreateOptions {
	t.Helper()
	return kolomls.CreateOptions{Config: cfg, KeyPackage: d.KeyPackage(t, st), Extensions: exts}
}
