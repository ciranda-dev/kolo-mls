package tree

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

func vectorTrees(f *testing.F) [][]byte {
	var out [][]byte
	if testvec.Present(f, "tree-validation.json") {
		var v []struct {
			Tree testvec.Hex `json:"tree"`
		}
		testvec.Load(f, "tree-validation.json", &v)
		for _, e := range v {
			out = append(out, e.Tree)
		}
	}
	return out
}

// FuzzRatchetTree checks that any accepted ratchet_tree re-encodes to itself
// and that validating and walking it never panics.
func FuzzRatchetTree(f *testing.F) {
	s := simGroup(f, 5)
	b, _ := s.tr.Marshal()
	f.Add(b)
	for _, t := range vectorTrees(f) {
		f.Add(t)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		tr, err := UnmarshalTree(in)
		if err != nil {
			if !errors.Is(err, errs.ErrMalformed) && !errors.Is(err, errs.ErrInvalidTree) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		out, err := tr.Marshal()
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("decode-encode differs: %v", err)
		}
		if err := tr.Verify([]byte("group")); err != nil && !errors.Is(err, errs.ErrInvalidTree) {
			t.Fatalf("Verify error %v is not ErrInvalidTree", err)
		}
		for x := range tr.Width() {
			tr.Resolution(x, nil)
		}
		for l := range tr.Leaves() {
			if tr.Leaf(uint32(l)) != nil {
				if _, _, err := tr.FilteredDirectPath(uint32(l)); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

// FuzzLeafNode checks that any accepted LeafNode re-encodes to itself.
func FuzzLeafNode(f *testing.F) {
	leaf, _, _ := testLeaf(f, SourceCommit, []byte("g"), 1, 8)
	leaf.ParentHash = []byte{1, 2}
	f.Add(encodeLeaf(f, leaf))
	kp, _, _ := testLeaf(f, SourceKeyPackage, nil, 0, 8)
	kp.Credential = Credential{Type: CredentialX509, Certificates: chain(f, []byte{1})}
	f.Add(encodeLeaf(f, kp))
	f.Fuzz(func(t *testing.T, in []byte) {
		n, err := decodeLeaf(in)
		if err != nil {
			if !errors.Is(err, errs.ErrMalformed) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if out := encodeLeaf(t, n); !bytes.Equal(out, in) {
			t.Fatal("decode-encode differs")
		}
		n.VerifySignature([]byte("g"), 1)
	})
}

// FuzzUpdatePath checks that any accepted UpdatePath re-encodes to itself and
// that merging and decrypting it into a fixed group never panics.
func FuzzUpdatePath(f *testing.F) {
	s := simGroup(f, 5)
	p, err := s.tr.Clone().CreatePath(1, nil, s.sigs[1], s.gid, nil, s.context)
	if err != nil {
		f.Fatal(err)
	}
	var w tls.Writer
	p.UpdatePath.Write(&w)
	seed, _ := w.Bytes()
	f.Add(seed)
	gc, _ := s.context(nil)
	f.Fuzz(func(t *testing.T, in []byte) {
		var u *UpdatePath
		err := tls.Decode(in, func(r *tls.Reader) (err error) {
			u, err = ReadUpdatePath(r)
			return err
		})
		if err != nil {
			if !errors.Is(err, errs.ErrMalformed) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		var w tls.Writer
		u.Write(&w)
		if out, err := w.Bytes(); err != nil || !bytes.Equal(out, in) {
			t.Fatalf("decode-encode differs: %v", err)
		}
		tr := s.tr.Clone()
		if err := tr.Merge(1, u); err != nil {
			return
		}
		tr.DecryptPath(1, u, nil, gc, s.privs[0])
	})
}

// FuzzNode checks that any accepted optional<Node> re-encodes to itself.
func FuzzNode(f *testing.F) {
	s := simGroup(f, 3)
	for _, x := range s.tr.NonBlank() {
		var w tls.Writer
		s.tr.Node(x).Write(&w)
		b, _ := w.Bytes()
		f.Add(b, x)
	}
	f.Fuzz(func(t *testing.T, in []byte, x uint64) {
		var n Node
		err := tls.Decode(in, func(r *tls.Reader) (err error) {
			n, err = ReadNode(r, x)
			return err
		})
		if err != nil {
			if !errors.Is(err, errs.ErrMalformed) && !errors.Is(err, errs.ErrInvalidTree) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		var w tls.Writer
		n.Write(&w)
		if out, err := w.Bytes(); err != nil || !bytes.Equal(out, in) {
			t.Fatalf("decode-encode differs: %v", err)
		}
	})
}
