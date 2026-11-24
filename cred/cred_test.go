package cred_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/kolotest"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// TestSizes measures the credential, leaf and KeyPackage sizes of a device
// certified by the person key and by an approver.
func TestSizes(t *testing.T) {
	person := kolotest.Person(t)
	approver := kolotest.NewDevice(t, person, true)
	for _, c := range []struct {
		name    string
		d       *kolotest.Device
		maxCert int
	}{
		{"person-issued", kolotest.NewDevice(t, person, false), 256},
		{"approver-issued", kolotest.Approved(t, approver), 514},
	} {
		cr, _ := c.d.Credential(t)
		n := len(c.d.Cert.Encode())
		lenBytes := 1
		if n >= 128 {
			lenBytes = 2
		}
		if n > c.maxCert || len(cr.Identity) != 1+lenBytes+n+64 || len(cr.Identity) > cred.MaxBody {
			t.Fatalf("%s: certificate %d, body %d", c.name, n, len(cr.Identity))
		}
		kp := c.d.KeyPackage(t, kolomls.NewMemStore())
		m, err := message.UnmarshalMLSMessage(kp)
		if err != nil {
			t.Fatal(err)
		}
		var w tls.Writer
		m.KeyPackage.LeafNode.Write(&w)
		leaf, _ := w.Bytes()
		t.Logf("%s: certificate %d bytes, credential body %d bytes, leaf node %d bytes, KeyPackage MLSMessage %d bytes", c.name, n, len(cr.Identity), len(leaf), len(kp))
	}
}

func TestEncodeDecode(t *testing.T) {
	d := kolotest.Approved(t, kolotest.NewDevice(t, kolotest.Person(t), true))
	c, sig := d.Credential(t)
	got, err := cred.Decode(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Device(), d.ID.PublicKey()) || !bytes.Equal(got.Person(), d.Person.PublicKey()) {
		t.Fatal("wrong device or person")
	}
	if again := got.Encode(); again.Type != cred.Type || !bytes.Equal(again.Identity, c.Identity) {
		t.Fatal("re-encoding differs")
	}
	if !koloid.Verify(d.ID.PublicKey(), cred.LeafKeyContext, cred.Binding(sig.Public().(ed25519.PublicKey), d.Cert), got.Signature) {
		t.Fatal("binding signature")
	}
	if _, err := cred.New(d.ID, kolotest.NewDevice(t, d.Person, false).Cert, sig.Public().(ed25519.PublicKey)); !errors.Is(err, cred.ErrCredential) {
		t.Fatalf("certificate of another device: %v", err)
	}
	if _, err := cred.New(d.ID, d.Cert, []byte{1}); !errors.Is(err, cred.ErrCredential) {
		t.Fatalf("short signature key: %v", err)
	}
}

// body encodes a credential body from its parts.
func body(version uint64, cert, sig []byte, extra ...byte) tree.Credential {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutBytes(cert)
	e.PutFixed(sig)
	return tree.Credential{Type: cred.Type, Identity: append(e.Bytes(), extra...)}
}

func TestDecodeRefuses(t *testing.T) {
	d := kolotest.NewDevice(t, kolotest.Person(t), false)
	good, _ := d.Credential(t)
	parsed, err := cred.Decode(good)
	if err != nil {
		t.Fatal(err)
	}
	cert, sig := d.Cert.Encode(), parsed.Signature
	for name, c := range map[string]tree.Credential{
		"basic type":       {Type: tree.CredentialBasic, Identity: good.Identity},
		"too long":         {Type: cred.Type, Identity: make([]byte, cred.MaxBody+1)},
		"empty":            {Type: cred.Type},
		"version 1":        body(1, cert, sig),
		"trailing byte":    body(0, cert, sig, 0),
		"short signature":  body(0, cert, sig[:63]),
		"bad certificate":  body(0, append([]byte{9}, cert[1:]...), sig),
		"long certificate": body(0, make([]byte, 515), sig),
	} {
		if _, err := cred.Decode(c); !errors.Is(err, cred.ErrCredential) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestValidate runs each step of the Authentication Service check (RFC
// 9420 section 5.3.1) and its refusals.
func TestValidate(t *testing.T) {
	person := kolotest.Person(t)
	d := kolotest.NewDevice(t, person, false)
	c, sig := d.Credential(t)
	pub := sig.Public().(ed25519.PublicKey)
	a := &cred.Authenticator{Now: time.Now}
	for _, ev := range []kolomls.Event{kolomls.EventKeyPackage, kolomls.EventJoin, kolomls.EventAdd, kolomls.EventUpdate, kolomls.EventCommitPath} {
		if err := a.Validate(c, pub, ev); err != nil {
			t.Fatalf("event %d: %v", ev, err)
		}
	}
	other, _ := d.Credential(t)
	cases := map[string]struct {
		c   tree.Credential
		key []byte
	}{
		"other signature key":     {c, other.Identity[:0]},
		"short signature key":     {c, pub[:31]},
		"small-order key":         {c, make([]byte, 32)},
		"identity point key":      {c, append([]byte{1}, make([]byte, 31)...)},
		"binding for another key": {other, pub},
		"basic credential":        {tree.Credential{Type: tree.CredentialBasic, Identity: []byte("x")}, pub},
	}
	for name, k := range cases {
		if err := a.Validate(k.c, k.key, kolomls.EventAdd); !errors.Is(err, cred.ErrCredential) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A small-order MLS signature key, bound by the device itself.
	for _, weak := range [][]byte{make([]byte, 32), append([]byte{1}, make([]byte, 31)...)} {
		bound, err := cred.New(d.ID, d.Cert, weak)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Validate(bound, weak, kolomls.EventAdd); !errors.Is(err, cred.ErrCredential) || errors.Is(err, koloid.ErrCertSignature) {
			t.Fatalf("small-order key bound by the device: %v", err)
		}
	}
	// A signature key of 31 bytes, bound by the device itself.
	short := pub[:31]
	ssig, err := d.ID.Sign(cred.LeafKeyContext, cred.Binding(short, d.Cert))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate((&cred.Credential{Cert: d.Cert, Signature: ssig}).Encode(), short, kolomls.EventAdd); !errors.Is(err, cred.ErrCredential) || errors.Is(err, koloid.ErrCertSignature) {
		t.Fatalf("31-byte key bound by the device: %v", err)
	}
	// The certificate hash is in the binding: a signature cannot move to a
	// renewed certificate of the same device key.
	renewed := renew(t, person, d)
	parsed, _ := cred.Decode(c)
	moved := (&cred.Credential{Cert: renewed, Signature: parsed.Signature}).Encode()
	if err := a.Validate(moved, pub, kolomls.EventAdd); !errors.Is(err, koloid.ErrCertSignature) {
		t.Fatalf("binding moved to another certificate: %v", err)
	}
}

func renew(t *testing.T, person *koloid.Identity, d *kolotest.Device) *koloid.DeviceCert {
	t.Helper()
	o, err := person.OfferDeviceCert(d.ID.PublicKey(), &koloid.IssueOptions{Serial: 2})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.ID.AcceptDeviceCert(o, person.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestExpiry: only the member that adds a KeyPackage checks expiry; every
// receiver accepts an expired certificate (RFC 9420 section 5.3.2).
func TestExpiry(t *testing.T) {
	d := kolotest.Expiring(t, kolotest.Person(t), time.Now().Add(-time.Hour))
	c, sig := d.Credential(t)
	if err := (&cred.Authenticator{}).Validate(c, sig.Public().(ed25519.PublicKey), kolomls.EventKeyPackage); !errors.Is(err, cred.ErrCredential) {
		t.Fatalf("no clock: %v", err)
	}
	a := &cred.Authenticator{Now: time.Now}
	if err := a.Validate(c, sig.Public().(ed25519.PublicKey), kolomls.EventKeyPackage); !errors.Is(err, koloid.ErrCertExpired) {
		t.Fatalf("expired at EventKeyPackage: %v", err)
	}
	for _, ev := range []kolomls.Event{kolomls.EventJoin, kolomls.EventAdd, kolomls.EventUpdate, kolomls.EventCommitPath} {
		if err := a.Validate(c, sig.Public().(ed25519.PublicKey), ev); err != nil {
			t.Fatalf("event %d refused an expired certificate: %v", ev, err)
		}
	}
	earlier := time.Now().Add(-90 * time.Minute)
	if err := (&cred.Authenticator{Now: func() time.Time { return earlier }}).Validate(c, sig.Public().(ed25519.PublicKey), kolomls.EventKeyPackage); err != nil {
		t.Fatalf("valid at Now: %v", err)
	}
}

// TestRevocations: revocations are checked when this member adds a
// KeyPackage, and Revoked reports them for any event.
func TestRevocations(t *testing.T) {
	person := kolotest.Person(t)
	d := kolotest.NewDevice(t, person, false)
	c, sig := d.Credential(t)
	r, err := person.RevokeDevice(&koloid.RevokeOptions{Person: person.PublicKey(), Device: d.ID.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	asked := 0
	a := &cred.Authenticator{Now: time.Now, Revocations: func(p, dev ed25519.PublicKey) []*koloid.Revocation {
		asked++
		if !bytes.Equal(p, person.PublicKey()) || !bytes.Equal(dev, d.ID.PublicKey()) {
			t.Fatal("asked for another device")
		}
		return []*koloid.Revocation{r}
	}}
	if err := a.Validate(c, sig.Public().(ed25519.PublicKey), kolomls.EventKeyPackage); !errors.Is(err, koloid.ErrCertRevoked) {
		t.Fatalf("revoked at EventKeyPackage: %v", err)
	}
	if err := a.Validate(c, sig.Public().(ed25519.PublicKey), kolomls.EventAdd); err != nil || asked != 1 {
		t.Fatalf("receivers do not check revocations: %v, asked %d", err, asked)
	}
	if err := cred.Revoked(c, []*koloid.Revocation{r}); !errors.Is(err, koloid.ErrCertRevoked) {
		t.Fatalf("Revoked: %v", err)
	}
	if err := cred.Revoked(c, nil); err != nil {
		t.Fatalf("not revoked: %v", err)
	}
	if err := cred.Revoked(tree.Credential{Type: tree.CredentialBasic}, nil); !errors.Is(err, cred.ErrCredential) {
		t.Fatalf("Revoked of a basic credential: %v", err)
	}
}

func TestExpect(t *testing.T) {
	d := kolotest.NewDevice(t, kolotest.Person(t), false)
	c, sig := d.Credential(t)
	refused := errors.New("not a contact")
	var got kolomls.Event
	a := &cred.Authenticator{Expect: func(p, dev ed25519.PublicKey, ev kolomls.Event) error {
		got = ev
		if !bytes.Equal(p, d.Person.PublicKey()) || !bytes.Equal(dev, d.ID.PublicKey()) {
			t.Fatal("Expect got another person or device")
		}
		return refused
	}}
	if err := a.Validate(c, sig.Public().(ed25519.PublicKey), kolomls.EventUpdate); !errors.Is(err, refused) || !errors.Is(err, cred.ErrCredential) || got != kolomls.EventUpdate {
		t.Fatalf("Expect refusal: %v", err)
	}
}

func TestSuccessor(t *testing.T) {
	person := kolotest.Person(t)
	d := kolotest.NewDevice(t, person, false)
	a := &cred.Authenticator{}
	c1, _ := d.Credential(t)
	c2, _ := d.Credential(t)
	if err := a.Successor(c1, c2); err != nil {
		t.Fatalf("same device, new signature key: %v", err)
	}
	renewed := mustCred(t, d.ID, renew(t, person, d))
	if err := a.Successor(c1, renewed); err != nil {
		t.Fatalf("renewed certificate: %v", err)
	}
	// The same device key certified by another person.
	other := kolotest.Person(t)
	o, err := other.OfferDeviceCert(d.ID.PublicKey(), &koloid.IssueOptions{Serial: 1})
	if err != nil {
		t.Fatal(err)
	}
	oc, err := d.ID.AcceptDeviceCert(o, other.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Successor(c1, mustCred(t, d.ID, oc)); !errors.Is(err, cred.ErrCredential) {
		t.Fatalf("same device, another person: %v", err)
	}
	sibling, _ := kolotest.NewDevice(t, person, false).Credential(t)
	stranger, _ := kolotest.NewDevice(t, kolotest.Person(t), false).Credential(t)
	for name, next := range map[string]tree.Credential{"another device": sibling, "another person": stranger, "basic": {Type: tree.CredentialBasic}} {
		if err := a.Successor(c1, next); !errors.Is(err, cred.ErrCredential) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := a.Successor(tree.Credential{Type: tree.CredentialBasic}, c1); !errors.Is(err, cred.ErrCredential) {
		t.Fatalf("basic predecessor: %v", err)
	}
}

func mustCred(t *testing.T, id *koloid.Identity, c *koloid.DeviceCert) tree.Credential {
	t.Helper()
	_, sig, _ := ed25519.GenerateKey(nil)
	cr, err := cred.New(id, c, sig.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return cr
}

// TestClientID: the client id is the device key, from the cache once the
// credential was seen; the cache is emptied when full.
func TestClientID(t *testing.T) {
	a := &cred.Authenticator{MaxCached: 2}
	var devs []*kolotest.Device
	var creds []tree.Credential
	for range 3 {
		d := kolotest.NewDevice(t, kolotest.Person(t), false)
		c, _ := d.Credential(t)
		devs, creds = append(devs, d), append(creds, c)
	}
	for round := range 2 {
		for i, c := range creds {
			id, err := a.ClientID(c)
			if err != nil || !bytes.Equal(id, devs[i].ID.PublicKey()) {
				t.Fatalf("round %d, credential %d: %v", round, i, err)
			}
			id[0] ^= 1
		}
	}
	// A basic credential with the bytes of a cached Kolo one is not a hit.
	if _, err := a.ClientID(tree.Credential{Type: tree.CredentialBasic, Identity: creds[2].Identity}); !errors.Is(err, cred.ErrCredential) {
		t.Fatalf("basic credential: %v", err)
	}
	if _, err := a.ClientID(tree.Credential{Type: cred.Type, Identity: []byte{0}}); !errors.Is(err, cred.ErrCredential) {
		t.Fatalf("malformed credential: %v", err)
	}
}

// TestCacheBound measures the smallest Kolo leaf in a ratchet tree and
// checks that DefaultMaxCached covers every leaf of the largest tree a
// joiner accepts by default.
func TestCacheBound(t *testing.T) {
	d := kolotest.NewDevice(t, kolotest.Person(t), false)
	kp := d.KeyPackage(t, kolomls.NewMemStore())
	m, err := message.UnmarshalMLSMessage(kp)
	if err != nil {
		t.Fatal(err)
	}
	m.KeyPackage.LeafNode.Capabilities = tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}, Credentials: []uint16{cred.Type}, Extensions: []uint16{0xF002}}
	var w tls.Writer
	tree.Node{Leaf: m.KeyPackage.LeafNode}.Write(&w)
	leaf, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	// A tree of n leaves holds n leaf nodes and n - 1 parents of at least
	// one byte each.
	most := kolomls.DefaultMaxTreeBytes / (len(leaf) + 1)
	t.Logf("smallest Kolo leaf node %d bytes: at most %d leaves in %d tree bytes", len(leaf), most, kolomls.DefaultMaxTreeBytes)
	if cred.DefaultMaxCached < most {
		t.Fatalf("DefaultMaxCached %d below %d", cred.DefaultMaxCached, most)
	}
}

func TestConcurrentCache(t *testing.T) {
	a := &cred.Authenticator{}
	d := kolotest.NewDevice(t, kolotest.Person(t), false)
	c, sig := d.Credential(t)
	done := make(chan error, 8)
	for range 8 {
		go func() {
			if err := a.Validate(c, sig.Public().(ed25519.PublicKey), kolomls.EventAdd); err != nil {
				done <- err
				return
			}
			_, err := a.ClientID(c)
			done <- err
		}()
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	d := kolotest.Approved(f, kolotest.NewDevice(f, kolotest.Person(f), true))
	c, _ := d.Credential(f)
	f.Add(c.Identity)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, b []byte) {
		cr, err := cred.Decode(tree.Credential{Type: cred.Type, Identity: b})
		if err != nil {
			return
		}
		if again := cr.Encode(); !bytes.Equal(again.Identity, b) {
			t.Fatal("decode then encode differs")
		}
	})
}

// TestBinding pins the bytes the device signs: version 0, the cipher suite,
// the MLS signature key and the SHA-256 of the certificate.
func TestBinding(t *testing.T) {
	d := kolotest.NewDevice(t, kolotest.Person(t), false)
	key := bytes.Repeat([]byte{7}, 32)
	h := sha256.Sum256(d.Cert.Encode())
	want := append(append([]byte{0, 1}, key...), h[:]...)
	if got := cred.Binding(key, d.Cert); !bytes.Equal(got, want) {
		t.Fatalf("binding %x", got)
	}
}

func TestNilCredential(t *testing.T) {
	var c *cred.Credential
	if c.Device() != nil || c.Person() != nil || c.Encode().Type != cred.Type || len((&cred.Credential{}).Encode().Identity) != 0 {
		t.Fatal("nil credential")
	}
}
