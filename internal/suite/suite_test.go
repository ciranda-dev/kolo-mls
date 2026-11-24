package suite

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type cryptoBasics struct {
	CipherSuite uint16 `json:"cipher_suite"`
	RefHash     struct {
		Label string      `json:"label"`
		Value testvec.Hex `json:"value"`
		Out   testvec.Hex `json:"out"`
	} `json:"ref_hash"`
	ExpandWithLabel struct {
		Secret  testvec.Hex `json:"secret"`
		Label   string      `json:"label"`
		Context testvec.Hex `json:"context"`
		Length  int         `json:"length"`
		Out     testvec.Hex `json:"out"`
	} `json:"expand_with_label"`
	DeriveSecret struct {
		Secret testvec.Hex `json:"secret"`
		Label  string      `json:"label"`
		Out    testvec.Hex `json:"out"`
	} `json:"derive_secret"`
	DeriveTreeSecret struct {
		Secret     testvec.Hex `json:"secret"`
		Label      string      `json:"label"`
		Generation uint32      `json:"generation"`
		Length     int         `json:"length"`
		Out        testvec.Hex `json:"out"`
	} `json:"derive_tree_secret"`
	SignWithLabel struct {
		Priv      testvec.Hex `json:"priv"`
		Pub       testvec.Hex `json:"pub"`
		Content   testvec.Hex `json:"content"`
		Label     string      `json:"label"`
		Signature testvec.Hex `json:"signature"`
	} `json:"sign_with_label"`
	EncryptWithLabel struct {
		Priv       testvec.Hex `json:"priv"`
		Pub        testvec.Hex `json:"pub"`
		Label      string      `json:"label"`
		Context    testvec.Hex `json:"context"`
		Plaintext  testvec.Hex `json:"plaintext"`
		KEMOutput  testvec.Hex `json:"kem_output"`
		Ciphertext testvec.Hex `json:"ciphertext"`
	} `json:"encrypt_with_label"`
}

func TestCryptoBasicsVectors(t *testing.T) {
	var v []cryptoBasics
	testvec.Load(t, "crypto-basics.json", &v)
	checked, skipped := 0, 0
	for _, e := range v {
		if e.CipherSuite != ID {
			skipped++
			continue
		}
		checked++

		r := e.RefHash
		if got, err := RefHash(r.Label, r.Value); err != nil || !bytes.Equal(got, r.Out) {
			t.Errorf("RefHash = %x, %v; want %x", got, err, r.Out)
		}

		x := e.ExpandWithLabel
		if got, err := ExpandWithLabel(x.Secret, x.Label, x.Context, x.Length); err != nil || !bytes.Equal(got, x.Out) {
			t.Errorf("ExpandWithLabel = %x, %v; want %x", got, err, x.Out)
		}

		d := e.DeriveSecret
		if got, err := DeriveSecret(d.Secret, d.Label); err != nil || !bytes.Equal(got, d.Out) {
			t.Errorf("DeriveSecret = %x, %v; want %x", got, err, d.Out)
		}

		dt := e.DeriveTreeSecret
		if got, err := DeriveTreeSecret(dt.Secret, dt.Label, dt.Generation, dt.Length); err != nil || !bytes.Equal(got, dt.Out) {
			t.Errorf("DeriveTreeSecret = %x, %v; want %x", got, err, dt.Out)
		}

		s := e.SignWithLabel
		if !VerifyWithLabel(s.Pub, s.Label, s.Content, s.Signature) {
			t.Error("VerifyWithLabel rejects the vector signature")
		}
		priv := ed25519.NewKeyFromSeed(s.Priv)
		sig, err := SignWithLabel(priv, s.Label, s.Content)
		if err != nil || !VerifyWithLabel(s.Pub, s.Label, s.Content, sig) {
			t.Errorf("SignWithLabel then VerifyWithLabel failed: %v", err)
		}
		// Ed25519 is deterministic, so the vector signature is reproduced.
		if !bytes.Equal(sig, s.Signature) {
			t.Errorf("SignWithLabel = %x, want %x", sig, s.Signature)
		}

		c := e.EncryptWithLabel
		if got, err := DecryptWithLabel(c.Priv, c.Label, c.Context, c.KEMOutput, c.Ciphertext); err != nil || !bytes.Equal(got, c.Plaintext) {
			t.Errorf("DecryptWithLabel = %x, %v; want %x", got, err, c.Plaintext)
		}
		kem, ct, err := EncryptWithLabel(c.Pub, c.Label, c.Context, c.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := DecryptWithLabel(c.Priv, c.Label, c.Context, kem, ct); err != nil || !bytes.Equal(got, c.Plaintext) {
			t.Errorf("EncryptWithLabel round trip = %x, %v", got, err)
		}
	}
	if checked != 1 || skipped != 6 {
		t.Fatalf("crypto-basics.json: %d suite 1 entries checked, %d other suites skipped; want 1 and 6", checked, skipped)
	}
	t.Logf("crypto-basics.json: %d suite 1 entries checked, 0 suite 1 skipped, %d other-suite entries skipped", checked, skipped)
}

func TestHash(t *testing.T) {
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := hex.EncodeToString(Hash([]byte("abc"))); got != want {
		t.Fatalf("Hash(abc) = %s", got)
	}
}

func TestRefHashEncoding(t *testing.T) {
	got, err := RefHash("L", []byte{0xaa})
	want := sha256.Sum256([]byte{1, 'L', 1, 0xaa})
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("RefHash = %x, %v; want %x", got, err, want)
	}
}

// RFC 5869 appendix A.1, so that a swap of salt and IKM is caught.
func TestExtractExpandRFC5869(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := unhex(t, "000102030405060708090a0b0c")
	prk, err := Extract(salt, ikm)
	if err != nil || hex.EncodeToString(prk) != "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5" {
		t.Fatalf("Extract = %x, %v", prk, err)
	}
	okm, err := Expand(prk, unhex(t, "f0f1f2f3f4f5f6f7f8f9"), 42)
	if err != nil || hex.EncodeToString(okm) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" {
		t.Fatalf("Expand = %x, %v", okm, err)
	}
}

func TestExpandLimits(t *testing.T) {
	prk := make([]byte, Nh)
	if b, err := Expand(prk, nil, 255*Nh); err != nil || len(b) != 255*Nh {
		t.Fatalf("Expand(8160) = %d bytes, %v", len(b), err)
	}
	for _, n := range []int{-1, 255*Nh + 1} {
		if _, err := Expand(prk, nil, n); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Expand(%d) error = %v", n, err)
		}
	}
	for _, n := range []int{-1, 0x10000, 255*Nh + 1} {
		if _, err := ExpandWithLabel(prk, "x", nil, n); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("ExpandWithLabel(%d) error = %v", n, err)
		}
	}
	if b, err := ExpandWithLabel(prk, "x", nil, 0); err != nil || len(b) != 0 {
		t.Fatalf("ExpandWithLabel(0) = %x, %v", b, err)
	}
}

// ExpandWithLabel must equal HKDF-Expand over the KDFLabel bytes of RFC 9420
// section 8, built here by hand.
func TestExpandWithLabelEncoding(t *testing.T) {
	prk := bytes.Repeat([]byte{7}, Nh)
	info := append([]byte{0, 16, 9}, "MLS 1.0 x"...)
	info = append(info, 2, 0xc0, 0xff)
	want, _ := Expand(prk, info, 16)
	got, err := ExpandWithLabel(prk, "x", []byte{0xc0, 0xff}, 16)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("ExpandWithLabel = %x, %v; want %x", got, err, want)
	}
	treeWant, _ := ExpandWithLabel(prk, "y", []byte{0, 0, 1, 2}, 12)
	treeGot, err := DeriveTreeSecret(prk, "y", 0x0102, 12)
	if err != nil || !bytes.Equal(treeGot, treeWant) {
		t.Fatalf("DeriveTreeSecret = %x, %v; want %x", treeGot, err, treeWant)
	}
	dsWant, _ := ExpandWithLabel(prk, "z", nil, Nh)
	if ds, err := DeriveSecret(prk, "z"); err != nil || !bytes.Equal(ds, dsWant) {
		t.Fatalf("DeriveSecret = %x, %v", ds, err)
	}
}

func TestSignVerifyRejects(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignWithLabel(priv, "L", []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyWithLabel(pub, "L", []byte("c"), sig) {
		t.Fatal("valid signature rejected")
	}
	plain := ed25519.Sign(priv, []byte("c"))
	for name, ok := range map[string]bool{
		"other label":       VerifyWithLabel(pub, "M", []byte("c"), sig),
		"other content":     VerifyWithLabel(pub, "L", []byte("d"), sig),
		"unlabeled sig":     VerifyWithLabel(pub, "L", []byte("c"), plain),
		"short pub":         VerifyWithLabel(pub[:31], "L", []byte("c"), sig),
		"long pub":          VerifyWithLabel(append(append([]byte{}, pub...), 0), "L", []byte("c"), sig),
		"empty pub":         VerifyWithLabel(nil, "L", []byte("c"), sig),
		"short signature":   VerifyWithLabel(pub, "L", []byte("c"), sig[:63]),
		"long signature":    VerifyWithLabel(pub, "L", []byte("c"), append(append([]byte{}, sig...), 0)),
		"flipped signature": VerifyWithLabel(pub, "L", []byte("c"), flip(sig)),
	} {
		if ok {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, n := range []int{0, 32, 63, 65} {
		if _, err := SignWithLabel(make([]byte, n), "L", nil); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("SignWithLabel with %d-byte key: error = %v", n, err)
		}
	}
}

func flip(b []byte) []byte {
	c := append([]byte{}, b...)
	c[0] ^= 1
	return c
}

func TestEncryptDecryptRejects(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kem, ct, err := EncryptWithLabel(pub, "L", []byte("ctx"), []byte("pt"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := DecryptWithLabel(priv, "L", []byte("ctx"), kem, ct); err != nil || string(pt) != "pt" {
		t.Fatalf("round trip = %q, %v", pt, err)
	}
	for name, err := range map[string]error{
		"other label":      second(DecryptWithLabel(priv, "M", []byte("ctx"), kem, ct)),
		"other context":    second(DecryptWithLabel(priv, "L", []byte("cty"), kem, ct)),
		"flipped ct":       second(DecryptWithLabel(priv, "L", []byte("ctx"), kem, flip(ct))),
		"flipped kem":      second(DecryptWithLabel(priv, "L", []byte("ctx"), flip(kem), ct)),
		"short kem":        second(DecryptWithLabel(priv, "L", []byte("ctx"), kem[:31], ct)),
		"low order kem":    second(DecryptWithLabel(priv, "L", []byte("ctx"), make([]byte, 32), ct)),
		"truncated ct":     second(DecryptWithLabel(priv, "L", []byte("ctx"), kem, ct[:15])),
		"other recipient":  second(DecryptWithLabel(other, "L", []byte("ctx"), kem, ct)),
		"empty ciphertext": second(DecryptWithLabel(priv, "L", []byte("ctx"), kem, nil)),
	} {
		if !errors.Is(err, errs.ErrDecrypt) {
			t.Errorf("%s: error = %v, want ErrDecrypt", name, err)
		}
	}
	if _, err := DecryptWithLabel(priv[:31], "L", nil, kem, ct); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Errorf("short private key: error = %v", err)
	}
	for name, p := range map[string][]byte{"short": pub[:31], "empty": nil, "low order": make([]byte, 32)} {
		if _, _, err := EncryptWithLabel(p, "L", nil, nil); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("%s public key: error = %v", name, err)
		}
	}
}

func second(_ []byte, err error) error { return err }

func TestCheckPublicKey(t *testing.T) {
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPublicKey(pub); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 32)
	one[0] = 1
	// Low-order points of Curve25519: u = 0, 1, and two points of order 8.
	for name, k := range map[string][]byte{
		"empty": nil, "short": pub[:31], "long": append(slices.Clone(pub), 0),
		"zero": make([]byte, 32), "one": one,
		"order 8 a": unhex(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
		"order 8 b": unhex(t, "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
	} {
		if err := CheckPublicKey(k); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

// RFC 9180 appendix A.1.1, DHKEM(X25519, HKDF-SHA256): ikmE derives skEm, pkEm.
func TestDeriveKeyPairRFC9180(t *testing.T) {
	priv, pub, err := DeriveKeyPair(unhex(t, "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(pub) != "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431" {
		t.Fatalf("pkEm = %x", pub)
	}
	// SerializePrivateKey clamps (RFC 9180 section 7.1.2), so compare the key
	// pair through a round trip rather than the raw skEm bytes.
	kem, ct, err := EncryptWithLabel(pub, "L", nil, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := DecryptWithLabel(priv, "L", nil, kem, ct); err != nil || string(pt) != "m" {
		t.Fatalf("derived key pair does not decrypt: %v", err)
	}
	sk := unhex(t, "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
	if pt, err := DecryptWithLabel(sk, "L", nil, kem, ct); err != nil || string(pt) != "m" {
		t.Fatalf("skEm does not decrypt for pkEm: %v", err)
	}
}

// RFC 4231 test case 2.
func TestMAC(t *testing.T) {
	key, data := []byte("Jefe"), []byte("what do ya want for nothing?")
	tag := MAC(key, data)
	if hex.EncodeToString(tag) != "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" {
		t.Fatalf("MAC = %x", tag)
	}
	if !VerifyMAC(key, data, tag) {
		t.Fatal("VerifyMAC rejects a valid tag")
	}
	for name, tg := range map[string][]byte{"flipped": flip(tag), "short": tag[:31], "empty": nil} {
		if VerifyMAC(key, data, tg) {
			t.Errorf("%s tag accepted", name)
		}
	}
	if VerifyMAC([]byte("jefe"), data, tag) {
		t.Error("tag accepted under another key")
	}
	if !hmac.Equal(tag, MAC(key, data)) {
		t.Error("MAC is not deterministic")
	}
}

// The GCM specification's AES-128 test cases 1 and 2.
func TestAEAD(t *testing.T) {
	key, nonce := make([]byte, Nk), make([]byte, Nn)
	ct, err := Seal(key, nonce, nil, nil)
	if err != nil || hex.EncodeToString(ct) != "58e2fccefa7e3061367f1d57a4e7455a" {
		t.Fatalf("case 1: %x, %v", ct, err)
	}
	ct, err = Seal(key, nonce, nil, make([]byte, 16))
	if err != nil || hex.EncodeToString(ct) != "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf" {
		t.Fatalf("case 2: %x, %v", ct, err)
	}
	if pt, err := Open(key, nonce, nil, ct); err != nil || !bytes.Equal(pt, make([]byte, 16)) {
		t.Fatalf("Open = %x, %v", pt, err)
	}
	if _, err := Open(key, nonce, nil, flip(ct)); !errors.Is(err, errs.ErrDecrypt) {
		t.Errorf("flipped ciphertext: error = %v", err)
	}
	if _, err := Open(key, nonce, []byte("aad"), ct); !errors.Is(err, errs.ErrDecrypt) {
		t.Errorf("other aad: error = %v", err)
	}
	for _, c := range [][2]int{{15, Nn}, {17, Nn}, {32, Nn}, {Nk, 11}, {Nk, 13}} {
		if _, err := Seal(make([]byte, c[0]), make([]byte, c[1]), nil, nil); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Seal key %d nonce %d: error = %v", c[0], c[1], err)
		}
		if _, err := Open(make([]byte, c[0]), make([]byte, c[1]), nil, ct); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Open key %d nonce %d: error = %v", c[0], c[1], err)
		}
	}
}
