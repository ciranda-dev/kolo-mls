package testvec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The fetch script and this package must pin the same commit and hashes.
func TestScriptPinsSameFiles(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "fetch-vectors.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "COMMIT="+Commit+"\n") {
		t.Fatalf("fetch-vectors.sh does not pin commit %s", Commit)
	}
	got := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^([0-9a-f]{64}) (\S+)$`).FindAllStringSubmatch(s, -1) {
		got[m[2]] = m[1]
	}
	if len(got) != len(SHA256) || len(got) != 16 {
		t.Fatalf("fetch-vectors.sh pins %d files, testvec %d; want 16", len(got), len(SHA256))
	}
	for name, sum := range SHA256 {
		if got[name] != sum {
			t.Errorf("%s: script pins %q, testvec %q", name, got[name], sum)
		}
	}
}

type fakeTB struct {
	testing.TB
	fatal, skip string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatal(args ...any) {
	f.fatal = fmt.Sprint(args...)
	runtime.Goexit()
}

func (f *fakeTB) Fatalf(format string, args ...any) {
	f.fatal = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (f *fakeTB) Skip(args ...any) {
	f.skip = fmt.Sprint(args...)
	runtime.Goexit()
}

func load(t *testing.T, name string) *fakeTB {
	f := &fakeTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var v any
		Load(f, name, &v)
	}()
	<-done
	return f
}

func TestLoadMissingOrWrong(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KOLO_MLS_VECTORS", dir)

	t.Setenv("KOLO_MLS_REQUIRE_VECTORS", "")
	if f := load(t, "tree-math.json"); f.skip == "" || f.fatal != "" {
		t.Errorf("missing file, not required: skip %q fatal %q; want a skip", f.skip, f.fatal)
	}

	t.Setenv("KOLO_MLS_REQUIRE_VECTORS", "1")
	if f := load(t, "tree-math.json"); f.fatal == "" || f.skip != "" {
		t.Errorf("missing file, required: skip %q fatal %q; want a failure", f.skip, f.fatal)
	}

	if err := os.WriteFile(filepath.Join(dir, "tree-math.json"), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f := load(t, "tree-math.json"); !strings.Contains(f.fatal, "SHA-256") {
		t.Errorf("wrong content: fatal %q; want a SHA-256 failure", f.fatal)
	}

	if f := load(t, "other.json"); !strings.Contains(f.fatal, "not a pinned") {
		t.Errorf("unknown file: fatal %q", f.fatal)
	}
}

func TestHex(t *testing.T) {
	var v struct{ A, B Hex }
	if err := json.Unmarshal([]byte(`{"A":"00ff","B":null}`), &v); err != nil || string(v.A) != "\x00\xff" || v.B != nil {
		t.Fatalf("got %x %x, %v", v.A, v.B, err)
	}
	if err := json.Unmarshal([]byte(`{"A":"0g"}`), &v); err == nil {
		t.Fatal("bad hex accepted")
	}
	if err := json.Unmarshal([]byte(`{"A":1}`), &v); err == nil {
		t.Fatal("number accepted")
	}
}
