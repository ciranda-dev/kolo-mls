// Package testvec loads the official MLS test vectors for the tests. The
// files are not in the repository: scripts/fetch-vectors.sh downloads them.
package testvec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Commit is the pinned commit of the vector repository.
const Commit = "2034fe72e0c805a683ba76165660c834f2a8142a"

// SHA256 maps each vector file to its pinned SHA-256; scripts/fetch-vectors.sh
// pins the same list.
var SHA256 = map[string]string{
	"crypto-basics.json":                  "17cfcf89af9f51d0f2aa7af77f6f9ec99376a039214b6d42a6f11646b83e8c29",
	"deserialization.json":                "1e394706e79f77df71454e5970f2aa736d4ab8b6c7e3219dd5609992388a953e",
	"key-schedule.json":                   "05aa9a68bd2538ace72d8c53375984cc728ef62220ebf314df675708546d97a7",
	"message-protection.json":             "f7c1ae62ce63c3003e526d539c99f2b1444f65ee0a487d3a5667d46867526c45",
	"messages.json":                       "b194abe1561995223482dbad51c180146920dc2f637e74d01e07a388308791fb",
	"passive-client-handling-commit.json": "b24949fdf857bf79d511f57504a8bdc7ce3247eb199684745e439c11b1a1da21",
	"passive-client-random.json":          "0095d863e9d316872e237fc708debcd20ba2687ee905a3e831f97dd3e578d3c1",
	"passive-client-welcome.json":         "92ebb04b67b1aca4290965ae363650921842ceebe275bd79a2733414078d849c",
	"psk_secret.json":                     "2b534969dba0b65a04b7d790496af5c0ccdb472b3fc4ca25c8c82df3e8523784",
	"secret-tree.json":                    "08f92e6272452e2c832e32d38e16cf0c4aa28967e47d3842c60bc354c6b67a94",
	"transcript-hashes.json":              "58046b58fbd98519b4e60953a105f550e4b427e2b140ea67dedcb751260eecb8",
	"tree-math.json":                      "27f04891f56106593b74b674445f01b845e173953770c084deb2f8cf5592e2fc",
	"tree-operations.json":                "9a25f8720714d1256ba2dad8d83a660ba0bae0d33ed15c682b9d74a5d67aad0a",
	"tree-validation.json":                "b66a432d93b520623f0640835ed43b9dfc95e116b8be081d81581d7c11e67a37",
	"treekem.json":                        "d8bbdf78394797f21db7476fd286af6830ebcb18d2e3b2c839fecd4eb11056f8",
	"welcome.json":                        "06be9d5c99817ef2545e4b15b8e73fd9b604685a8e55b59ca168eda98e236502",
}

// Dir returns the vector directory: $KOLO_MLS_VECTORS, or testdata/vectors
// at the module root.
func Dir(t testing.TB) string {
	t.Helper()
	if d := os.Getenv("KOLO_MLS_VECTORS"); d != "" {
		return d
	}
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return filepath.Join(d, "testdata", "vectors")
		}
		up := filepath.Dir(d)
		if up == d {
			t.Fatal("testvec: go.mod not found above the test directory")
		}
		d = up
	}
}

// Present reports whether vector file name is in the vector directory; fuzz
// targets use it to add vector seeds without skipping when they are absent.
func Present(t testing.TB, name string) bool {
	_, err := os.Stat(filepath.Join(Dir(t), name))
	return err == nil
}

// Load decodes vector file name into v after checking its pinned SHA-256.
// A missing file fails the test when KOLO_MLS_REQUIRE_VECTORS=1 and skips it
// otherwise.
func Load(t testing.TB, name string, v any) {
	t.Helper()
	want, ok := SHA256[name]
	if !ok {
		t.Fatalf("testvec: %s is not a pinned vector file", name)
	}
	p := filepath.Join(Dir(t), name)
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		msg := "testvec: " + p + " not found; run scripts/fetch-vectors.sh"
		if os.Getenv("KOLO_MLS_REQUIRE_VECTORS") == "1" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("testvec: %s has SHA-256 %s, want %s", p, got, want)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("testvec: %s: %v", name, err)
	}
}

// Hex is a byte string encoded as hex in JSON.
type Hex []byte

// UnmarshalJSON decodes a hex string; null gives nil.
func (h *Hex) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*h = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = v
	return nil
}
