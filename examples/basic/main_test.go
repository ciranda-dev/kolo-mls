package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	kolomls "github.com/ciranda-dev/kolo-mls"
)

func TestRuns(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out); err != nil {
		t.Fatal(err)
	}
	want := "bob read \"hello, bob\" in epoch 1\nmembers: 2\nsame epoch authenticator: true\n"
	if out.String() != want {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
}

// TestREADMEHoldsThisProgram: the quick start in the README is this file, byte for byte.
func TestREADMEHoldsThisProgram(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "```go\n"+string(src)+"```\n") {
		t.Fatal("README.md does not contain examples/basic/main.go as its Go block")
	}
}

// TestEnvelopeSet: the program binds the generation of every PrivateMessage
// into its authenticated data (RFC 9750 section 8.6).
func TestEnvelopeSet(t *testing.T) {
	e := config(directory{}).Envelope
	if e == nil {
		t.Fatal("nil Envelope")
	}
	ad, err := e.Wrap(3, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Unwrap(4, ad); err == nil {
		t.Fatal("authenticated data of generation 3 read at generation 4")
	}
	if aad, err := e.Unwrap(3, ad); err != nil || string(aad) != "aad" {
		t.Fatalf("Unwrap: %q %v", aad, err)
	}
}

// TestNameRegisteredOnce: the directory binds a name to one signature key,
// so a second registration of the name is refused.
func TestNameRegisteredOnce(t *testing.T) {
	d := directory{}
	if _, err := keyPackage(kolomls.NewMemStore(), d, "alice"); err != nil {
		t.Fatal(err)
	}
	key := d["alice"]
	if _, err := keyPackage(kolomls.NewMemStore(), d, "alice"); err == nil || !bytes.Equal(d["alice"], key) {
		t.Fatalf("second registration of alice: %v", err)
	}
}
