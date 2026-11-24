package tree

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// blankTree encodes a ratchet_tree of n - 1 blank nodes ending in leaf.
func blankTree(t *testing.T, n int, leaf *LeafNode) []byte {
	t.Helper()
	var w tls.Writer
	w.Vector(func(w *tls.Writer) {
		for range n - 1 {
			w.U8(0)
		}
		w.U8(1)
		w.U8(nodeLeaf)
		leaf.Write(w)
	})
	b, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBlankNodesAreNotStored(t *testing.T) {
	leaf, _, _ := testLeaf(t, SourceKeyPackage, nil, 0, 32)
	const n = 1<<16 + 1
	tr, err := UnmarshalTree(blankTree(t, n, leaf))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Width() != 1<<17-1 || len(tr.nodes) != 1 {
		t.Fatalf("width %d with %d stored nodes, want %d with 1", tr.Width(), len(tr.nodes), 1<<17-1)
	}
	if _, err := tr.TreeHash(); err != nil {
		t.Fatal(err)
	}
	// One entry per ancestor of the leaf and one per blank sibling subtree.
	if len(tr.cache) > 2*17 {
		t.Fatalf("%d cached hashes for one leaf in a tree of depth 16", len(tr.cache))
	}
	b, err := tr.Marshal()
	if err != nil || len(b) != len(blankTree(t, n, leaf)) {
		t.Fatalf("re-encoding: %d bytes, %v", len(b), err)
	}
}

// Leaves added into a blank region must leave the cache equal to a fresh
// computation after every step.
func TestCacheAcrossBlankRegions(t *testing.T) {
	leaf, _, _ := testLeaf(t, SourceKeyPackage, nil, 0, 32)
	tr, err := UnmarshalTree(blankTree(t, 255, leaf))
	if err != nil {
		t.Fatal(err)
	}
	var last uint32
	for i := range 40 {
		if _, err := tr.TreeHash(); err != nil {
			t.Fatal(err)
		}
		l, _, _ := testLeaf(t, SourceKeyPackage, nil, 0, 32)
		if i%3 == 2 {
			err = tr.RemoveLeaf(last)
		} else {
			last, err = tr.AddLeaf(l)
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := tr.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := UnmarshalTree(b)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := fresh.TreeHashes()
		got, _ := tr.TreeHashes()
		if len(got) != len(want) {
			t.Fatalf("step %d: %d hashes, want %d", i, len(got), len(want))
		}
		for x := range want {
			if !bytes.Equal(got[x], want[x]) {
				t.Fatalf("step %d: cached hash of node %d differs", i, x)
			}
		}
	}
}

func TestTreeFieldSizes(t *testing.T) {
	leaf, _, _ := testLeaf(t, SourceKeyPackage, nil, 0, 32)
	ok := blankTree(t, 1, leaf)
	if _, err := UnmarshalTree(ok); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(n *LeafNode){
		"short encryption key": func(n *LeafNode) { n.EncryptionKey = n.EncryptionKey[:31] },
		"long signature key":   func(n *LeafNode) { n.SignatureKey = append(n.SignatureKey, 0) },
		"short signature":      func(n *LeafNode) { n.Signature = n.Signature[:63] },
		"parent hash of 31":    func(n *LeafNode) { n.Source, n.ParentHash = SourceCommit, make([]byte, 31) },
	} {
		c := leaf.Clone()
		change(c)
		if _, err := UnmarshalTree(blankTree(t, 1, c)); !errors.Is(err, errs.ErrInvalidTree) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	c := leaf.Clone()
	c.Source, c.ParentHash = SourceCommit, make([]byte, 32)
	if _, err := UnmarshalTree(blankTree(t, 1, c)); err != nil {
		t.Errorf("commit leaf with a 32-byte parent hash: %v", err)
	}
	for name, p := range map[string]ParentNode{
		"short parent key":       {EncryptionKey: make([]byte, 31)},
		"parent hash of 33":      {EncryptionKey: make([]byte, 32), ParentHash: make([]byte, 33)},
		"parent key of 33 bytes": {EncryptionKey: make([]byte, 33)},
	} {
		var w tls.Writer
		w.Vector(func(w *tls.Writer) {
			w.U8(0)
			w.U8(1)
			w.U8(nodeParent)
			p.write(w)
		})
		b, _ := w.Bytes()
		if _, err := UnmarshalTree(b); !errors.Is(err, errs.ErrInvalidTree) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	var w tls.Writer
	w.Vector(func(w *tls.Writer) {
		w.U8(0)
		w.U8(1)
		w.U8(nodeParent)
		(&ParentNode{EncryptionKey: make([]byte, 32), ParentHash: make([]byte, 32)}).write(w)
	})
	b, _ := w.Bytes()
	if _, err := UnmarshalTree(b); err != nil {
		t.Errorf("parent with suite sizes: %v", err)
	}
}

func TestX509Chain(t *testing.T) {
	leaf, _, _ := testLeaf(t, SourceKeyPackage, nil, 0, 32)
	leaf.Credential = Credential{Type: CredentialX509, Certificates: chain(t, []byte{1}, nil, make([]byte, 300))}
	got, err := decodeLeaf(encodeLeaf(t, leaf))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := got.Credential.CertificateList()
	if err != nil || len(certs) != 3 || len(certs[2]) != 300 {
		t.Fatalf("chain = %d certificates, %v", len(certs), err)
	}
	// A chain whose last certificate is truncated or not minimal is malformed.
	for _, chain := range [][]byte{{2, 1}, {0x40, 0x01, 0}, {0xc0}} {
		leaf.Credential.Certificates = chain
		if _, err := decodeLeaf(encodeLeaf(t, leaf)); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("chain %x: error = %v", chain, err)
		}
	}
}

func TestFromNodes(t *testing.T) {
	s := simGroup(t, 5)
	nodes := map[uint64]Node{}
	for _, x := range s.tr.NonBlank() {
		var w tls.Writer
		s.tr.Node(x).Write(&w)
		b, _ := w.Bytes()
		var n Node
		err := tls.Decode(b, func(r *tls.Reader) (err error) {
			n, err = ReadNode(r, x)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		nodes[x] = n
	}
	got, err := FromNodes(s.tr.Width(), nodes)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := s.tr.TreeHash()
	if h, _ := got.TreeHash(); !bytes.Equal(h, want) {
		t.Fatal("tree from its nodes has another tree hash")
	}
	leaf := Node{Leaf: s.tr.Leaf(0)}
	parent := s.tr.Node(s.tr.NonBlank()[1])
	for name, c := range map[string]struct {
		width uint64
		nodes map[uint64]Node
	}{
		"width 0":            {0, nil},
		"width 6":            {6, nil},
		"node outside":       {3, map[uint64]Node{4: leaf}},
		"leaf at odd index":  {3, map[uint64]Node{1: leaf}},
		"parent at a leaf":   {3, map[uint64]Node{0: parent}},
		"blank node":         {3, map[uint64]Node{0: {}}},
		"leaf and parent":    {3, map[uint64]Node{0: {Leaf: leaf.Leaf, Parent: parent.Parent}}},
		"width above 2^33-1": {1<<34 - 1, nil},
	} {
		if _, err := FromNodes(c.width, c.nodes); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

// chain encodes an x509 chain for a test.
func chain(t testing.TB, certs ...[]byte) []byte {
	t.Helper()
	b, err := Chain(certs...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TreeHashes returns the tree hash of every node; tests compare it with the
// vectors and with a fresh decode.
func (t *Tree) TreeHashes() ([][]byte, error) {
	if _, err := t.hash(t.root(), nil); err != nil {
		return nil, err
	}
	out := make([][]byte, t.width)
	for x := range out {
		h, err := t.hash(uint64(x), nil)
		if err != nil {
			return nil, err
		}
		out[x] = bytes.Clone(h)
	}
	return out, nil
}
