package tree

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

func encodeLeaf(t testing.TB, n *LeafNode) []byte {
	t.Helper()
	var w tls.Writer
	n.Write(&w)
	b, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeLeaf(b []byte) (*LeafNode, error) {
	var n *LeafNode
	err := tls.Decode(b, func(r *tls.Reader) (err error) {
		n, err = ReadLeafNode(r)
		return err
	})
	return n, err
}

func TestLeafNodeCodec(t *testing.T) {
	leaf, _, _ := testLeaf(t, SourceKeyPackage, nil, 0, 4)
	leaf.Credential = Credential{Type: CredentialX509, Certificates: chain(t, []byte{1, 2}, nil)}
	leaf.Extensions = []tls.Extension{{Type: 0xf002, Data: []byte{9}}}
	b := encodeLeaf(t, leaf)
	got, err := decodeLeaf(b)
	certs, cerr := got.Credential.CertificateList()
	if err != nil || cerr != nil || len(certs) != 2 || !bytes.Equal(certs[0], []byte{1, 2}) || len(certs[1]) != 0 || got.NotAfter != leaf.NotAfter {
		t.Fatalf("x509 leaf round trip: %+v, %v, %v", got, err, cerr)
	}
	if again := encodeLeaf(t, got); !bytes.Equal(again, b) {
		t.Fatal("re-encoding differs")
	}

	// The credential type sits right after the two 33-byte keys.
	for _, typ := range []uint16{0, 3, 0xfafa} {
		bad := slices.Clone(b)
		bad[66], bad[67] = byte(typ>>8), byte(typ)
		if _, err := decodeLeaf(bad); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("credential type %#x: error = %v", typ, err)
		}
	}
	// Read on their own, so that a misaligned parse of the rest cannot hide a
	// missing check.
	for _, typ := range []uint16{0, 3, 0xfafa} {
		if _, err := readCredential(tls.NewReader([]byte{byte(typ >> 8), byte(typ)})); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("readCredential type %#x alone: error = %v", typ, err)
		}
	}
	for _, src := range []uint8{0, 4, 255} {
		n, _, _ := testLeaf(t, SourceUpdate, nil, 0, 4)
		enc := encodeLeaf(t, n)
		// leaf_node_source comes before the empty extensions (1 byte) and the
		// signature (2-byte length, 64 bytes).
		i := len(enc) - 64 - 2 - 1 - 1
		if enc[i] != SourceUpdate {
			t.Fatalf("source byte not found at %d", i)
		}
		enc[i] = src
		if _, err := decodeLeaf(enc); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("leaf_node_source %d: error = %v", src, err)
		}
	}
	for n := range len(b) {
		if _, err := decodeLeaf(b[:n]); !errors.Is(err, errs.ErrMalformed) {
			t.Fatalf("prefix of %d bytes: error = %v", n, err)
		}
	}
}

func TestLeafNodeSignatureBinding(t *testing.T) {
	kp, _, _ := testLeaf(t, SourceKeyPackage, nil, 0, 4)
	if !kp.VerifySignature([]byte("any"), 7) {
		t.Error("key_package leaf must not bind a group or leaf index")
	}
	for _, src := range []uint8{SourceUpdate, SourceCommit} {
		n, _, _ := testLeaf(t, src, []byte("g"), 3, 4)
		if !n.VerifySignature([]byte("g"), 3) {
			t.Fatalf("source %d: valid signature rejected", src)
		}
		if n.VerifySignature([]byte("h"), 3) || n.VerifySignature([]byte("g"), 4) {
			t.Errorf("source %d: signature not bound to group and leaf", src)
		}
		n.Signature[0] ^= 1
		if n.VerifySignature([]byte("g"), 3) {
			t.Errorf("source %d: flipped signature accepted", src)
		}
	}
}

func TestParentNodeUnmergedOrder(t *testing.T) {
	for in, ok := range map[string]bool{
		"0101" + "00" + "08" + "00000001" + "00000002": true,
		"0101" + "00" + "08" + "00000002" + "00000002": false,
		"0101" + "00" + "08" + "00000003" + "00000001": false,
		"0101" + "00" + "00":                           true,
	} {
		b, _ := hex.DecodeString(in)
		_, err := readParentNode(tls.NewReader(b))
		if (err == nil) != ok || (!ok && !errors.Is(err, errs.ErrMalformed)) {
			t.Errorf("readParentNode(%s) error = %v, want ok %v", in, err, ok)
		}
	}
}

func TestReadTreeChecks(t *testing.T) {
	s := newSim(t)
	s.pending = map[uint32]bool{}
	s.add()
	s.add()
	s.commit(1)
	b, err := s.tr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got := mustTree(t, b); got.Width() != 7 {
		t.Fatalf("3 leaves: width %d, want 7", got.Width())
	}

	leafEnc := encodeLeaf(t, s.tr.Leaf(0))
	entry := func(typ uint8, body []byte) []byte { return append([]byte{1, typ}, body...) }
	vec := func(entries ...[]byte) []byte {
		var w tls.Writer
		w.Vector(func(w *tls.Writer) {
			for _, e := range entries {
				w.Fixed(e)
			}
		})
		out, _ := w.Bytes()
		return out
	}
	parent := append(append([]byte{32}, make([]byte, 32)...), 0, 0)
	for name, in := range map[string][]byte{
		"empty":            vec(),
		"blank last":       vec(entry(1, leafEnc), []byte{0}),
		"only blank":       vec([]byte{0}),
		"parent at leaf":   vec(entry(2, parent)),
		"leaf at parent":   vec(entry(1, leafEnc), entry(1, leafEnc), entry(1, leafEnc)),
		"node type 0":      vec(entry(0, leafEnc)),
		"node type 3":      vec(entry(3, leafEnc)),
		"presence octet 2": vec([]byte{2, 1}),
	} {
		if _, err := UnmarshalTree(in); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	for n, width := range map[int]uint64{1: 1, 3: 3, 4: 7, 5: 7, 7: 7} {
		entries := [][]byte{entry(1, leafEnc)}
		for i := 1; i < n; i++ {
			if i%2 == 1 {
				entries = append(entries, entry(2, parent))
			} else {
				entries = append(entries, entry(1, leafEnc))
			}
		}
		tr, err := UnmarshalTree(vec(entries...))
		if err != nil || tr.Width() != width {
			t.Errorf("%d entries: width %d, %v; want %d", n, tr.Width(), err, width)
		}
	}
	if _, err := UnmarshalTree(append(b, 0)); !errors.Is(err, errs.ErrMalformed) {
		t.Errorf("trailing byte: error = %v", err)
	}
}

// fig is a tree whose non-blank nodes are given; leaves get distinct dummy
// keys and parents the given unmerged leaves.
func fig(width int, leaves []uint64, parents map[uint64][]uint32) *Tree {
	tr := &Tree{width: uint64(width)}
	for _, x := range leaves {
		tr.set(x, Node{Leaf: &LeafNode{EncryptionKey: []byte{byte(x)}}})
	}
	for x, u := range parents {
		tr.set(x, Node{Parent: &ParentNode{EncryptionKey: []byte{byte(x)}, UnmergedLeaves: u}})
	}
	return tr
}

// RFC 9420 Figures 10 and 11 with Table 2.
func TestResolutionAndFilteredPath(t *testing.T) {
	f10 := fig(15, []uint64{0, 2, 6, 8, 10, 14}, map[uint64][]uint32{3: {1}, 9: nil})
	for x, want := range map[uint64][]uint64{3: {3, 2}, 4: nil, 12: nil, 7: {3, 2, 9, 14}, 11: {9, 14}, 13: {14}} {
		if got := f10.Resolution(x, nil); !slices.Equal(got, want) {
			t.Errorf("Figure 10 resolution(%d) = %v, want %v", x, got, want)
		}
	}
	if got := f10.Resolution(7, map[uint32]bool{1: true, 7: true}); !slices.Equal(got, []uint64{3, 9}) {
		t.Errorf("resolution excluding leaves 1 and 7 = %v", got)
	}
	f10.nodes[3].Parent.UnmergedLeaves = []uint32{1, 40}
	if got := f10.Resolution(3, nil); !slices.Equal(got, []uint64{3, 2}) {
		t.Errorf("unmerged leaf outside the tree must be skipped: %v", got)
	}

	f11 := fig(15, []uint64{0, 2, 8, 10, 12}, map[uint64][]uint32{1: nil, 7: nil, 9: nil, 11: nil})
	for l, want := range map[uint32][]uint64{0: {1, 7}, 1: {1, 7}, 4: {9, 11, 7}, 5: {9, 11, 7}, 6: {11, 7}} {
		got, _, err := f11.FilteredDirectPath(l)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("Table 2 filtered direct path of leaf %d = %v, %v; want %v", l, got, err, want)
		}
	}
	if _, _, err := f11.FilteredDirectPath(8); err == nil {
		t.Error("leaf outside the tree accepted")
	}
}

func TestAddUpdateRemove(t *testing.T) {
	tr := fig(7, []uint64{0, 4}, map[uint64][]uint32{3: {2}, 5: nil})
	leaf := &LeafNode{EncryptionKey: []byte{99}}
	l, err := tr.AddLeaf(leaf)
	if err != nil || l != 1 || tr.Leaf(1) != leaf {
		t.Fatalf("AddLeaf = %d, %v; want the leftmost blank leaf 1", l, err)
	}
	if got := tr.Node(3).Parent.UnmergedLeaves; !slices.Equal(got, []uint32{1, 2}) {
		t.Errorf("unmerged of node 3 = %v, want [1 2]", got)
	}
	if tr.Node(1).Parent != nil {
		t.Error("blank node 1 must stay blank")
	}
	l, _ = tr.AddLeaf(leaf)
	if l != 3 || len(tr.Node(5).Parent.UnmergedLeaves) != 1 {
		t.Fatalf("second AddLeaf = %d, unmerged of 5 = %v", l, tr.Node(5).Parent.UnmergedLeaves)
	}
	l, _ = tr.AddLeaf(leaf)
	if l != 4 || tr.Width() != 15 || tr.Node(7).Parent != nil {
		t.Fatalf("AddLeaf on a full tree = %d, width %d", l, tr.Width())
	}

	if err := tr.UpdateLeaf(5, leaf); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Errorf("update of a blank leaf: %v", err)
	}
	if err := tr.UpdateLeaf(2, leaf); err != nil || tr.Node(5).Parent != nil || tr.Node(3).Parent != nil {
		t.Errorf("update must blank the direct path: %v", err)
	}
	if err := tr.RemoveLeaf(6); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Errorf("remove of a blank leaf: %v", err)
	}
	if err := tr.RemoveLeaf(4); err != nil || tr.Width() != 7 {
		t.Errorf("remove of the only right leaf must truncate: width %d, %v", tr.Width(), err)
	}
	if err := tr.RemoveLeaf(3); err != nil || tr.Width() != 7 {
		t.Errorf("remove keeps the width while leaf 2 lives: width %d, %v", tr.Width(), err)
	}
	if err := tr.RemoveLeaf(2); err != nil || tr.Width() != 3 {
		t.Errorf("width after removing leaves 2 to 4 = %d, %v; want 3", tr.Width(), err)
	}
	if tr.Leaf(9) != nil {
		t.Error("Leaf outside the tree must be nil")
	}
	if got := mergeSorted([]uint32{1, 5, 9}, []uint32{3, 4, 10}); !slices.Equal(got, []uint32{1, 3, 4, 5, 9, 10}) {
		t.Errorf("mergeSorted = %v", got)
	}
}

func simGroup(t testing.TB, n int) *sim {
	s := newSim(t)
	s.pending = map[uint32]bool{}
	for range n - 1 {
		s.add()
	}
	s.commit(0)
	for l := range uint32(n) {
		if l%2 == 1 {
			s.commit(l)
		}
	}
	return s
}

// wantErr fails unless err is kind and its text contains reason, so that a
// test cannot pass because a later check caught what the tested one missed.
func wantErr(t *testing.T, name string, err, kind error, reason string) {
	t.Helper()
	if !errors.Is(err, kind) || !strings.Contains(err.Error(), reason) {
		t.Errorf("%s: error = %v, want %v with %q", name, err, kind, reason)
	}
}

// resign replaces leaf l with a changed copy signed by sig.
func resign(t *testing.T, tr *Tree, gid []byte, l uint32, sig ed25519.PrivateKey, change func(*LeafNode)) {
	t.Helper()
	c := tr.Leaf(l).Clone()
	change(c)
	if err := c.Sign(sig, gid, l); err != nil {
		t.Fatal(err)
	}
	tr.set(2*uint64(l), Node{Leaf: c})
}

func setParent(tr *Tree, x uint64, change func(*ParentNode)) {
	p := *tr.nodes[x].Parent
	change(&p)
	tr.set(x, Node{Parent: &p})
}

func TestVerifyRejects(t *testing.T) {
	base := simGroup(t, 6)
	for name, c := range map[string]struct {
		change func(tr *Tree)
		reason string
	}{
		"leaf signature": {func(tr *Tree) {
			c := tr.Leaf(2).Clone()
			c.Signature = slices.Clone(c.Signature)
			c.Signature[0] ^= 1
			tr.set(4, Node{Leaf: c})
		}, "leaf 2 signature"},
		"duplicate signature key": {func(tr *Tree) {
			resign(t, tr, base.gid, 2, base.sigs[4], func(n *LeafNode) { n.SignatureKey = tr.Leaf(4).SignatureKey })
		}, "leaf 4 signature key not unique"},
		"duplicate leaf encryption key": {func(tr *Tree) {
			resign(t, tr, base.gid, 2, base.sigs[2], func(n *LeafNode) { n.EncryptionKey = tr.Leaf(4).EncryptionKey })
		}, "leaf 4 encryption key not unique"},
		"parent key equal to a leaf key": {func(tr *Tree) {
			setParent(tr, 9, func(p *ParentNode) { p.EncryptionKey = tr.Leaf(0).EncryptionKey })
		}, "node 9 encryption key not unique"},
		"parent hash": {func(tr *Tree) {
			setParent(tr, 3, func(p *ParentNode) { p.ParentHash = append(slices.Clone(p.ParentHash), 0) })
		}, "not parent-hash valid"},
		"parent key": {func(tr *Tree) {
			_, pub, _ := suite.GenerateKeyPair()
			setParent(tr, 9, func(p *ParentNode) { p.EncryptionKey = pub })
		}, "not parent-hash valid"},
		"unmerged blank leaf": {func(tr *Tree) {
			setParent(tr, 7, func(p *ParentNode) { p.UnmergedLeaves = []uint32{7} })
		}, "node 7 unmerged leaf 7"},
		"unmerged leaf outside the subtree": {func(tr *Tree) {
			setParent(tr, 1, func(p *ParentNode) { p.UnmergedLeaves = []uint32{2} })
		}, "node 1 unmerged leaf 2"},
		"unmerged leaf outside the tree": {func(tr *Tree) {
			setParent(tr, 7, func(p *ParentNode) { p.UnmergedLeaves = []uint32{20} })
		}, "node 7 unmerged leaf 20"},
	} {
		tr := base.tr.Clone()
		c.change(tr)
		wantErr(t, name, tr.Verify(base.gid), errs.ErrInvalidTree, c.reason)
	}
	wantErr(t, "other group id", base.tr.Verify([]byte("other group")), errs.ErrInvalidTree, "signature")
}

// unmergedTree is a group of 8 leaves where leaf 6 committed after leaf 5 was
// removed, leaf 0 committed, and leaf 5 was added again: leaf 5 is unmerged
// at node 11 and at the root, and the root's parent hash, from leaf 0,
// covers node 11 with leaf 5 left out.
func unmergedTree(t *testing.T) *sim {
	s := newSim(t)
	s.pending = map[uint32]bool{}
	for range 7 {
		s.add()
	}
	s.commit(0)
	s.remove(5)
	s.commit(6)
	s.commit(0)
	if l := s.add(); l != 5 {
		t.Fatalf("added leaf %d", l)
	}
	for _, x := range []uint64{7, 11} {
		if p := s.tr.nodes[x].Parent; p == nil || !slices.Equal(p.UnmergedLeaves, []uint32{5}) {
			t.Fatalf("node %d is not a parent with unmerged leaf 5", x)
		}
	}
	return s
}

// The original sibling hash drops the parent's unmerged leaves from the
// unmerged lists inside the sibling (RFC 9420 section 7.9).
func TestVerifyUnmergedInSibling(t *testing.T) {
	s := unmergedTree(t)
	if err := s.tr.Verify(s.gid); err != nil {
		t.Fatal(err)
	}
}

// An unmerged leaf must be listed at every non-blank node between it and the
// parent that lists it.
func TestVerifyUnmergedChain(t *testing.T) {
	s := unmergedTree(t)
	tr := s.tr.Clone()
	setParent(tr, 11, func(p *ParentNode) { p.UnmergedLeaves = nil })
	wantErr(t, "missing intermediate entry", tr.Verify(s.gid), errs.ErrInvalidTree, "node 11 misses unmerged leaf 5")
}

// The rest of a resolution must be exactly the parent's unmerged leaves: here
// leaf 1 sits under node 3 without being listed there, and only the
// resolution condition of RFC 9420 section 7.9.2 notices.
func TestVerifyResolutionCondition(t *testing.T) {
	s := newSim(t)
	s.pending = map[uint32]bool{}
	for range 3 {
		s.add()
	}
	s.commit(0)
	s.remove(1)
	s.commit(0)
	if l := s.add(); l != 1 {
		t.Fatalf("added leaf %d", l)
	}
	if err := s.tr.Verify(s.gid); err != nil {
		t.Fatal(err)
	}
	tr := s.tr.Clone()
	setParent(tr, 3, func(p *ParentNode) { p.UnmergedLeaves = nil })
	wantErr(t, "unlisted leaf", tr.Verify(s.gid), errs.ErrInvalidTree, "node 3 not parent-hash valid")
}

func TestInSubtree(t *testing.T) {
	for _, c := range []struct {
		x, c uint64
		want bool
	}{{7, 3, false}, {5, 3, true}, {0, 3, true}, {6, 3, true}, {8, 3, false}, {3, 3, true}, {4, 4, true}, {6, 4, false}, {11, 7, true}, {15, 7, false}} {
		if got := inSubtree(c.x, c.c); got != c.want {
			t.Errorf("inSubtree(%d, %d) = %v", c.x, c.c, got)
		}
	}
}

// Adds and Removes applied in one batch give the same tree as one by one.
func TestBatchEqualsSequence(t *testing.T) {
	s := simGroup(t, 9)
	one, batch := s.tr.Clone(), s.tr.Clone()
	for _, l := range []uint32{8, 6, 2} {
		if err := one.RemoveLeaf(l); err != nil {
			t.Fatal(err)
		}
	}
	if err := batch.RemoveLeaves([]uint32{8, 6, 2}); err != nil {
		t.Fatal(err)
	}
	// Fill the hash cache before the tree grows back over the truncated half.
	one.TreeHash()
	batch.TreeHash()
	var leaves []*LeafNode
	for range 4 {
		leaf, _, _ := testLeaf(t, SourceKeyPackage, nil, 0, 8)
		leaves = append(leaves, leaf)
	}
	var seq []uint32
	for _, leaf := range leaves {
		l, err := one.AddLeaf(leaf)
		if err != nil {
			t.Fatal(err)
		}
		seq = append(seq, l)
	}
	got, err := batch.AddLeaves(leaves)
	if err != nil || !slices.Equal(got, seq) || !slices.Equal(seq, []uint32{2, 6, 8, 9}) {
		t.Fatalf("AddLeaves = %v, %v; one by one %v", got, err, seq)
	}
	a, _ := one.Marshal()
	b, _ := batch.Marshal()
	if !bytes.Equal(a, b) {
		t.Fatal("batch and sequence differ")
	}
	fresh, _ := UnmarshalTree(b)
	want, _ := fresh.TreeHash()
	if got, _ := batch.TreeHash(); !bytes.Equal(got, want) {
		t.Fatal("cached tree hash after truncating and growing differs from a fresh decode")
	}
	if err := batch.RemoveLeaves([]uint32{3, 3}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Errorf("removing one leaf twice: %v", err)
	}
	all := s.tr.Clone()
	if err := all.RemoveLeaves([]uint32{1, 2, 3, 4, 5, 6, 7, 8}); err != nil || all.Width() != 1 {
		t.Errorf("removing all but leaf 0: width %d, %v", all.Width(), err)
	}
}

// A forged leaf that claims a parent hash for a parent which lists it as
// unmerged must not count as that parent's chain (RFC 9420 section 7.9.2).
func TestVerifyUnmergedChainEnd(t *testing.T) {
	// One sibling in the resolution: the leaf itself is the only node.
	s := newSim(t)
	s.pending = map[uint32]bool{}
	s.add()
	s.commit(0)
	tr := s.tr.Clone()
	setParent(tr, 1, func(p *ParentNode) { p.UnmergedLeaves = []uint32{1} })
	forge(t, tr, s, 1, 1, 0)
	wantErr(t, "unmerged leaf as the chain", tr.Verify(s.gid), errs.ErrInvalidTree, "node 1 not parent-hash valid")

	// Two nodes in the resolution: the forged leaf and a merged one.
	s = newSim(t)
	s.pending = map[uint32]bool{}
	s.add()
	s.add()
	s.commit(2)
	tr = s.tr.Clone()
	if tr.nodes[1].Parent != nil || tr.nodes[3].Parent == nil {
		t.Fatal("unexpected tree shape")
	}
	setParent(tr, 3, func(p *ParentNode) { p.UnmergedLeaves = []uint32{1} })
	forge(t, tr, s, 1, 3, 5)
	wantErr(t, "unmerged leaf beside a merged one", tr.Verify(s.gid), errs.ErrInvalidTree, "node 3 not parent-hash valid")
}

// forge makes leaf l a commit leaf whose parent hash is valid for parent x
// with sibling s, signed with the leaf's own key.
func forge(t *testing.T, tr *Tree, s *sim, l uint32, x, sibling uint64) {
	t.Helper()
	hashes, err := tr.TreeHashes()
	if err != nil {
		t.Fatal(err)
	}
	ph, err := parentHash(tr.nodes[x].Parent, hashes[sibling])
	if err != nil {
		t.Fatal(err)
	}
	resign(t, tr, s.gid, l, s.sigs[l], func(n *LeafNode) {
		n.Source, n.NotBefore, n.NotAfter, n.ParentHash = SourceCommit, 0, 0, ph
	})
}

// A Clone must not share the hash cache with its source.
func TestCloneIndependent(t *testing.T) {
	s := simGroup(t, 4)
	h, err := s.tr.TreeHash()
	if err != nil {
		t.Fatal(err)
	}
	c := s.tr.Clone()
	if err := c.RemoveLeaf(3); err != nil {
		t.Fatal(err)
	}
	if _, err := c.TreeHash(); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.tr.TreeHash(); !bytes.Equal(again, h) {
		t.Fatal("changing a Clone changed the tree hash of its source")
	}
}

func TestMergeRejects(t *testing.T) {
	s := simGroup(t, 5)
	lowOrder := make([]byte, 32)
	for name, c := range map[string]struct {
		change func(u *UpdatePath) uint32
		reason string
	}{
		"node count": {func(u *UpdatePath) uint32 { u.Nodes = u.Nodes[1:]; return 1 }, "UpdatePath has 2 nodes"},
		"source": {func(u *UpdatePath) uint32 {
			u.Leaf.Source = SourceUpdate
			return 1
		}, "leaf_node_source 2"},
		"parent hash": {func(u *UpdatePath) uint32 {
			u.Leaf.ParentHash = append(slices.Clone(u.Leaf.ParentHash), 1)
			return 1
		}, "leaf parent_hash"},
		"node key changed": {func(u *UpdatePath) uint32 {
			_, pub, _ := suite.GenerateKeyPair()
			u.Nodes[len(u.Nodes)-1].EncryptionKey = pub
			return 1
		}, "leaf parent_hash"},
		"blank sender": {func(u *UpdatePath) uint32 { return 7 }, "sender leaf 7 is blank"},
		"leaf key kept": {func(u *UpdatePath) uint32 {
			u.Leaf.EncryptionKey = s.tr.Leaf(1).EncryptionKey
			return 1
		}, "keeps the committer's encryption key"},
		"leaf key of another leaf": {func(u *UpdatePath) uint32 {
			u.Leaf.EncryptionKey = s.tr.Leaf(3).EncryptionKey
			return 1
		}, "encryption key 0 already in the tree"},
		"node key of another node": {func(u *UpdatePath) uint32 {
			u.Nodes[0].EncryptionKey = s.tr.Leaf(0).EncryptionKey
			return 1
		}, "encryption key 1 already in the tree"},
		"node key repeated in the path": {func(u *UpdatePath) uint32 {
			u.Nodes[1].EncryptionKey = u.Nodes[0].EncryptionKey
			return 1
		}, "encryption key 2 already in the tree"},
		"own old path key": {func(u *UpdatePath) uint32 {
			// Allowed by the key rules, since node 3 is replaced; the parent
			// hash then fails.
			u.Nodes[1].EncryptionKey = s.tr.Node(3).Parent.EncryptionKey
			return 1
		}, "leaf parent_hash"},
		"low order node key": {func(u *UpdatePath) uint32 {
			u.Nodes[1].EncryptionKey = lowOrder
			return 1
		}, "encryption key 2: kolomls: invalid argument: HPKE public key of low order"},
		"short leaf key": {func(u *UpdatePath) uint32 {
			u.Leaf.EncryptionKey = u.Leaf.EncryptionKey[:31]
			return 1
		}, "encryption key 0: kolomls: invalid argument: HPKE public key size"},
	} {
		tr := s.tr.Clone()
		p, err := tr.CreatePath(1, nil, s.sigs[1], s.gid, nil, s.context)
		if err != nil {
			t.Fatal(err)
		}
		u := *p.UpdatePath
		u.Leaf = u.Leaf.Clone()
		u.Nodes = slices.Clone(u.Nodes)
		sender := c.change(&u)
		wantErr(t, name, s.tr.Clone().Merge(sender, &u), errs.ErrInvalidCommit, c.reason)
	}
	// The merged tree keeps its own copy of the leaf.
	tr := s.tr.Clone()
	p, _ := tr.Clone().CreatePath(1, nil, s.sigs[1], s.gid, nil, s.context)
	if err := tr.Merge(1, p.UpdatePath); err != nil {
		t.Fatal(err)
	}
	tr.TreeHash() // the second call reads the cache
	h, _ := tr.TreeHash()
	p.UpdatePath.Leaf.Signature[0] ^= 1
	h[0] ^= 1
	if again, _ := tr.TreeHash(); bytes.Equal(again, h) || tr.Leaf(1).Signature[0] == p.UpdatePath.Leaf.Signature[0] {
		t.Error("the tree shares the UpdatePath leaf or its hash with the caller")
	}
}

// A new leaf can carry a new signature key: CreatePath copies the template.
func TestCreatePathTemplate(t *testing.T) {
	s := simGroup(t, 3)
	pub, sig, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := s.tr.Leaf(1).Clone()
	tmpl.SignatureKey = pub
	tr := s.tr.Clone()
	p, err := tr.CreatePath(1, tmpl, sig, s.gid, nil, s.context)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tr.Leaf(1).SignatureKey, pub) || !p.UpdatePath.Leaf.VerifySignature(s.gid, 1) {
		t.Error("new signature key not used")
	}
	if err := tr.Verify(s.gid); err != nil {
		t.Error(err)
	}
}

func TestVerifyRejectsBadKeys(t *testing.T) {
	s := simGroup(t, 4)
	tr := s.tr.Clone()
	setParent(tr, 3, func(p *ParentNode) { p.EncryptionKey = make([]byte, 32) })
	wantErr(t, "low order parent key", tr.Verify(s.gid), errs.ErrInvalidTree, "node 3 encryption key")
	tr = s.tr.Clone()
	resign(t, tr, s.gid, 2, s.sigs[2], func(n *LeafNode) { n.EncryptionKey = n.EncryptionKey[:31] })
	wantErr(t, "short leaf key", tr.Verify(s.gid), errs.ErrInvalidTree, "leaf 2 encryption key")
}

func TestPrivateCloneClearSetPathSecret(t *testing.T) {
	s := simGroup(t, 3)
	p := s.privs[0]
	c := p.Clone()
	for x, k := range c.Keys {
		k[0] ^= 1
		if p.Keys[x][0] == k[0] {
			t.Fatal("Clone shares key bytes")
		}
	}
	held := c.Keys[0]
	c.Clear()
	if len(c.Keys) != 0 || !bytes.Equal(held, make([]byte, len(held))) {
		t.Error("Clear left keys")
	}
	q := &Private{}
	for _, n := range []int{0, 31, 33} {
		if err := q.SetPathSecret(1, make([]byte, n)); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("%d-byte path secret: %v", n, err)
		}
	}
	if err := q.SetPathSecret(1, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	old := q.Keys[1]
	if err := q.SetPathSecret(1, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, make([]byte, len(old))) {
		t.Error("SetPathSecret did not clear the replaced key")
	}
}

func TestDecryptPathRejects(t *testing.T) {
	s := simGroup(t, 5)
	newPath := func() (*Tree, *Path, []byte) {
		tr := s.tr.Clone()
		p, err := tr.CreatePath(1, nil, s.sigs[1], s.gid, nil, s.context)
		if err != nil {
			t.Fatal(err)
		}
		th, _ := tr.TreeHash()
		gc, _ := s.context(th)
		return tr, p, gc
	}
	tr, p, gc := newPath()
	if _, _, _, err := tr.DecryptPath(1, p.UpdatePath, nil, gc, clonePrivate(s.privs[1])); !errors.Is(err, errs.ErrInvalidCommit) {
		t.Errorf("sender decrypting its own path: %v", err)
	}
	if _, _, _, err := tr.DecryptPath(1, p.UpdatePath, nil, gc, &Private{Leaf: 4, Keys: map[uint64][]byte{}}); !errors.Is(err, errs.ErrInvalidCommit) {
		t.Errorf("member with no key: %v", err)
	}
	if _, _, _, err := tr.DecryptPath(1, p.UpdatePath, nil, append(slices.Clone(gc), 0), clonePrivate(s.privs[4])); !errors.Is(err, errs.ErrDecrypt) {
		t.Errorf("other group context: %v", err)
	}
	extra := *p.UpdatePath
	extra.Nodes = slices.Clone(extra.Nodes)
	extra.Nodes[0].Secrets = append(slices.Clone(extra.Nodes[0].Secrets), extra.Nodes[0].Secrets[0])
	if _, _, _, err := tr.DecryptPath(1, &extra, nil, gc, clonePrivate(s.privs[0])); !errors.Is(err, errs.ErrInvalidCommit) {
		t.Errorf("ciphertext count: %v", err)
	}
	// A wrong count at a node the receiver does not decrypt at is refused too.
	top := *p.UpdatePath
	top.Nodes = slices.Clone(top.Nodes)
	last := len(top.Nodes) - 1
	top.Nodes[last].Secrets = append(slices.Clone(top.Nodes[last].Secrets), top.Nodes[last].Secrets[0])
	if _, _, _, err := tr.DecryptPath(1, &top, nil, gc, clonePrivate(s.privs[0])); !errors.Is(err, errs.ErrInvalidCommit) {
		t.Errorf("ciphertext count at another node: %v", err)
	}
	short := *p.UpdatePath
	short.Nodes = short.Nodes[:len(short.Nodes)-1]
	if _, _, _, err := tr.DecryptPath(1, &short, nil, gc, clonePrivate(s.privs[4])); !errors.Is(err, errs.ErrInvalidCommit) {
		t.Errorf("node count: %v", err)
	}

	// Leaf 0 decrypts at the lowest node, so a changed key above it must fail
	// the derivation check.
	bad := *p.UpdatePath
	bad.Nodes = slices.Clone(bad.Nodes)
	_, pub, _ := suite.GenerateKeyPair()
	bad.Nodes[len(bad.Nodes)-1].EncryptionKey = pub
	if _, _, _, err := tr.DecryptPath(1, &bad, nil, gc, clonePrivate(s.privs[0])); !errors.Is(err, errs.ErrInvalidCommit) {
		t.Errorf("derived key mismatch: %v", err)
	}

	// A path secret of the wrong length.
	wrong := *p.UpdatePath
	wrong.Nodes = slices.Clone(wrong.Nodes)
	kem, ct, err := suite.EncryptWithLabel(s.tr.Leaf(0).EncryptionKey, "UpdatePathNode", gc, make([]byte, 31))
	if err != nil {
		t.Fatal(err)
	}
	wrong.Nodes[0].Secrets = []HPKECiphertext{{KEMOutput: kem, Ciphertext: ct}}
	_, _, _, err = tr.DecryptPath(1, &wrong, nil, gc, clonePrivate(s.privs[0]))
	wantErr(t, "31-byte path secret", err, errs.ErrInvalidCommit, "path secret of 31 bytes")

	// DecryptPath never changes the state it is given.
	q := clonePrivate(s.privs[0])
	want := clonePrivate(q)
	tr.DecryptPath(1, &bad, nil, gc, q)
	_, _, next, err := tr.DecryptPath(1, p.UpdatePath, nil, gc, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Keys) != len(want.Keys) {
		t.Fatal("DecryptPath changed the state it was given")
	}
	for x, k := range want.Keys {
		if !bytes.Equal(q.Keys[x], k) {
			t.Fatalf("DecryptPath changed the key of node %d", x)
		}
	}
	if err := next.Check(tr); err != nil {
		t.Errorf("new state: %v", err)
	}
}

// Keys on the sender's direct path outside its filtered direct path are
// dropped too: here node 5, above leaf 2, whose copath leaf 3 is blank.
func TestDecryptPathDropsFilteredOutKeys(t *testing.T) {
	s := simGroup(t, 3)
	tr := s.tr.Clone()
	p, err := tr.CreatePath(2, nil, s.sigs[2], s.gid, nil, s.context)
	if err != nil {
		t.Fatal(err)
	}
	if path, _, _ := tr.FilteredDirectPath(2); slices.Contains(path, 5) {
		t.Fatal("node 5 should be filtered out")
	}
	th, _ := tr.TreeHash()
	gc, _ := s.context(th)
	q := clonePrivate(s.privs[0])
	q.Keys[5] = []byte{1}
	_, _, next, err := tr.DecryptPath(2, p.UpdatePath, nil, gc, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := next.Keys[5]; ok {
		t.Error("stale key of node 5 kept")
	}
}

func TestCreatePathExcludes(t *testing.T) {
	s := simGroup(t, 4)
	l := s.add()
	tr := s.tr.Clone()
	p, err := tr.CreatePath(0, nil, s.sigs[0], s.gid, map[uint32]bool{l: true}, s.context)
	if err != nil {
		t.Fatal(err)
	}
	_, copath, _ := tr.FilteredDirectPath(0)
	for i, c := range copath {
		want := len(tr.Resolution(c, map[uint32]bool{l: true}))
		if got := len(p.UpdatePath.Nodes[i].Secrets); got != want || (inSubtree(2*uint64(l), c) && got == len(tr.Resolution(c, nil))) {
			t.Errorf("node %d: %d ciphertexts, want %d without the new leaf", i, got, want)
		}
	}
	if _, err := s.tr.Clone().CreatePath(9, nil, s.sigs[0], s.gid, nil, s.context); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Errorf("blank leaf: %v", err)
	}
	if !p.UpdatePath.Leaf.VerifySignature(s.gid, 0) || p.UpdatePath.Leaf.Source != SourceCommit {
		t.Error("new leaf not signed as a commit leaf")
	}
}

func TestPrivateCheckAndPrune(t *testing.T) {
	s := simGroup(t, 4)
	p := clonePrivate(s.privs[0])
	if err := p.Check(s.tr); err != nil {
		t.Fatal(err)
	}
	other, _, _ := suite.GenerateKeyPair()
	for name, keys := range map[string]map[uint64][]byte{
		"outside":  {99: other},
		"blank":    {5: other},
		"mismatch": {0: other},
		"bad key":  {0: {1, 2}},
	} {
		q := &Private{Keys: keys}
		if err := q.Check(s.tr); err == nil {
			t.Errorf("%s: Check passed", name)
		}
	}
	tr := s.tr.Clone()
	if err := tr.RemoveLeaf(3); err != nil {
		t.Fatal(err)
	}
	p.Keys[99] = []byte{1}
	p.Prune(tr)
	if _, ok := p.Keys[99]; ok {
		t.Error("Prune kept a key outside the tree")
	}
	if _, ok := p.Keys[3]; ok {
		t.Error("Prune kept the key of a blanked node")
	}
	if err := p.Check(tr); err != nil {
		t.Errorf("after Prune: %v", err)
	}
}
