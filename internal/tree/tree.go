package tree

import (
	"crypto/ed25519"
	"fmt"
	"maps"
	"slices"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/treemath"
)

// ParentNode is an MLS ParentNode (RFC 9420 section 7.1).
type ParentNode struct {
	EncryptionKey  []byte
	ParentHash     []byte
	UnmergedLeaves []uint32
}

func (p *ParentNode) write(w *tls.Writer) {
	w.Opaque(p.EncryptionKey)
	w.Opaque(p.ParentHash)
	w.Vector(func(w *tls.Writer) {
		for _, l := range p.UnmergedLeaves {
			w.U32(l)
		}
	})
}

// unmerged_leaves must be sorted (RFC 9420 section 7.1); strictly, since a
// repeated leaf has no meaning and would break the canonical form.
func readParentNode(r *tls.Reader) (*ParentNode, error) {
	var p ParentNode
	var err error
	if p.EncryptionKey, err = r.Opaque(); err != nil {
		return nil, err
	}
	if p.ParentHash, err = r.Opaque(); err != nil {
		return nil, err
	}
	err = r.Vector(func(r *tls.Reader) error {
		l, err := r.U32()
		if err != nil {
			return err
		}
		if n := len(p.UnmergedLeaves); n > 0 && l <= p.UnmergedLeaves[n-1] {
			return fmt.Errorf("%w: unmerged_leaves not strictly increasing", errs.ErrMalformed)
		}
		p.UnmergedLeaves = append(p.UnmergedLeaves, l)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Node is one node of the tree: a leaf, a parent, or blank when both are nil.
type Node struct {
	Leaf   *LeafNode
	Parent *ParentNode
}

// Blank reports whether the node is blank.
func (n Node) Blank() bool {
	return n.Leaf == nil && n.Parent == nil
}

// NodeType values (RFC 9420 section 7.8).
const (
	nodeLeaf   uint8 = 1
	nodeParent uint8 = 2
)

// Tree is a ratchet tree in the array layout of RFC 9420 appendix C. It is
// not safe for concurrent use, reads included (they fill the hash cache).
type Tree struct {
	width uint64
	// nodes holds the non-blank nodes only, so blank nodes cost no memory: a
	// hostile ratchet_tree of blank nodes stays small (the ratchet tree bound of docs/limits.md).
	// Nodes are never changed in place.
	nodes map[uint64]Node
	// cache holds tree hashes, see hash.
	cache map[uint64]cachedHash
}

type cachedHash struct {
	h     [suite.Nh]byte
	blank bool
}

// set replaces node x and drops the cached hashes it changes.
func (t *Tree) set(x uint64, n Node) {
	if n.Blank() {
		delete(t.nodes, x)
	} else {
		if t.nodes == nil {
			t.nodes = map[uint64]Node{}
		}
		t.nodes[x] = n
	}
	for {
		delete(t.cache, x)
		p, err := treemath.Parent(x, t.Leaves())
		if err != nil {
			return
		}
		x = p
	}
}

// Width returns the number of nodes.
func (t *Tree) Width() uint64 {
	return t.width
}

// Leaves returns the number of leaves, blank ones included.
func (t *Tree) Leaves() uint64 {
	return (t.Width() + 1) / 2
}

// Node returns node x; the caller must not change it.
func (t *Tree) Node(x uint64) Node {
	return t.nodes[x]
}

// Leaf returns the LeafNode at leaf index l, nil if blank or outside the tree;
// the caller must not change it.
func (t *Tree) Leaf(l uint32) *LeafNode {
	if uint64(l) >= t.Leaves() {
		return nil
	}
	return t.nodes[2*uint64(l)].Leaf
}

// NonBlank returns the indices of the non-blank nodes in increasing order.
func (t *Tree) NonBlank() []uint64 {
	xs := slices.Collect(maps.Keys(t.nodes))
	slices.Sort(xs)
	return xs
}

// Clone returns a copy that can be changed without changing t.
func (t *Tree) Clone() *Tree {
	return &Tree{width: t.width, nodes: maps.Clone(t.nodes), cache: maps.Clone(t.cache)}
}

// Write appends the encoding of n as an optional<Node> (RFC 9420 section
// 12.4.3.3).
func (n Node) Write(w *tls.Writer) {
	w.Optional(!n.Blank())
	switch {
	case n.Leaf != nil:
		w.U8(nodeLeaf)
		n.Leaf.Write(w)
	case n.Parent != nil:
		w.U8(nodeParent)
		n.Parent.write(w)
	}
}

// ReadNode reads an optional<Node> for node index x and refuses a node type
// that does not match the index and field sizes of other suites.
func ReadNode(r *tls.Reader, x uint64) (Node, error) {
	var n Node
	present, err := r.Optional()
	if err != nil || !present {
		return n, err
	}
	typ, err := r.U8()
	if err != nil {
		return n, err
	}
	switch {
	case typ == nodeLeaf && x%2 == 0:
		n.Leaf, err = ReadLeafNode(r)
	case typ == nodeParent && x%2 == 1:
		n.Parent, err = readParentNode(r)
	default:
		err = fmt.Errorf("%w: node type %d at node %d", errs.ErrMalformed, typ, x)
	}
	if err != nil {
		return Node{}, err
	}
	if err := checkSizes(n, x); err != nil {
		return Node{}, err
	}
	return n, nil
}

// Write appends the ratchet_tree encoding (RFC 9420 section 12.4.3.3): the
// nodes up to the last non-blank one.
func (t *Tree) Write(w *tls.Writer) {
	end := t.last() + 1
	w.Vector(func(w *tls.Writer) {
		for x := range uint64(end) {
			t.nodes[x].Write(w)
		}
	})
}

// Marshal returns the ratchet_tree encoding of t.
func (t *Tree) Marshal() ([]byte, error) {
	var w tls.Writer
	t.Write(&w)
	return w.Bytes()
}

// ReadTree reads a ratchet_tree, refuses a blank last node, a node type that
// does not match its position and field sizes of other suites, and pads the
// tree with blank nodes to a full width (RFC 9420 section 12.4.3.3).
func ReadTree(r *tls.Reader) (*Tree, error) {
	t := Tree{nodes: map[uint64]Node{}}
	var count uint64
	err := r.Vector(func(r *tls.Reader) error {
		n, err := ReadNode(r, count)
		if !n.Blank() {
			t.nodes[count] = n
		}
		count++
		return err
	})
	if err != nil {
		return nil, err
	}
	if count == 0 || t.nodes[count-1].Blank() {
		return nil, fmt.Errorf("%w: ratchet_tree empty or ending with a blank node", errs.ErrMalformed)
	}
	// The padding to a full width is virtual (RFC 9420 section 12.4.3.3).
	t.width = 1
	for t.width < count {
		t.width = 2*t.width + 1
	}
	return &t, nil
}

// FromNodes returns a tree of width nodes from its non-blank nodes, as
// stored by the caller; width must be 2^(d+1) - 1 and hold every node.
func FromNodes(width uint64, nodes map[uint64]Node) (*Tree, error) {
	if width == 0 || width&(width+1) != 0 || width > treemath.NodeWidth(treemath.MaxLeaves) {
		return nil, fmt.Errorf("%w: tree width %d", errs.ErrInvalidArgument, width)
	}
	t := &Tree{width: width, nodes: make(map[uint64]Node, len(nodes))}
	for x, n := range nodes {
		if x >= width || n.Blank() || (n.Leaf != nil) != (x%2 == 0) || (n.Leaf != nil && n.Parent != nil) {
			return nil, fmt.Errorf("%w: node %d", errs.ErrInvalidArgument, x)
		}
		t.nodes[x] = n
	}
	return t, nil
}

// checkSizes refuses keys, signatures and parent hashes of other sizes than
// cipher suite 0x0001 uses while the tree is read, so the memory a tree costs
// stays within a small factor of its encoding (the ratchet tree bound of docs/limits.md).
func checkSizes(n Node, x uint64) error {
	var keyOK, hashOK bool
	if l := n.Leaf; l != nil {
		keyOK = len(l.EncryptionKey) == suite.Nh && len(l.SignatureKey) == ed25519.PublicKeySize && len(l.Signature) == ed25519.SignatureSize
		hashOK = len(l.ParentHash) == 0 || len(l.ParentHash) == suite.Nh
	} else {
		keyOK = len(n.Parent.EncryptionKey) == suite.Nh
		hashOK = len(n.Parent.ParentHash) == 0 || len(n.Parent.ParentHash) == suite.Nh
	}
	if !keyOK || !hashOK {
		return fmt.Errorf("%w: node %d has a key, signature or parent hash of the wrong size", errs.ErrInvalidTree, x)
	}
	return nil
}

// UnmarshalTree decodes a whole ratchet_tree with no trailing bytes.
func UnmarshalTree(b []byte) (*Tree, error) {
	var t *Tree
	err := tls.Decode(b, func(r *tls.Reader) (err error) {
		t, err = ReadTree(r)
		return err
	})
	return t, err
}

// New returns a one-leaf tree, as at group creation (RFC 9420 section 11).
func New(leaf *LeafNode) *Tree {
	return &Tree{width: 1, nodes: map[uint64]Node{0: {Leaf: leaf}}}
}

// last returns the index of the last non-blank node, or -1 for none.
func (t *Tree) last() int64 {
	last := int64(-1)
	for x := range t.nodes {
		last = max(last, int64(x))
	}
	return last
}

func (t *Tree) root() uint64 {
	return t.Leaves() - 1
}

// Resolution returns the resolution of node x as node indices (RFC 9420
// section 4.1.1), leaving out the leaves in excluded.
func (t *Tree) Resolution(x uint64, excluded map[uint32]bool) []uint64 {
	var out []uint64
	var walk func(x uint64)
	walk = func(x uint64) {
		n := t.nodes[x]
		switch {
		case n.Leaf != nil:
			if !excluded[uint32(x/2)] {
				out = append(out, x)
			}
		case n.Parent != nil:
			out = append(out, x)
			for _, l := range n.Parent.UnmergedLeaves {
				// An unchecked tree may list a leaf outside it.
				if !excluded[l] && 2*uint64(l) < t.Width() {
					out = append(out, 2*uint64(l))
				}
			}
		case x%2 == 1:
			// A subtree the hash cache knows to be blank has an empty
			// resolution, so blank regions are not walked node by node.
			if c, ok := t.cache[x]; ok && c.blank {
				return
			}
			l, err := treemath.Left(x, t.Leaves())
			if err != nil {
				return
			}
			r, err := treemath.Right(x, t.Leaves())
			if err != nil {
				return
			}
			walk(l)
			walk(r)
		}
	}
	walk(x)
	return out
}

// FilteredDirectPath returns the filtered direct path of leaf l and, for
// each of its nodes, the child on the copath of l (RFC 9420 section 4.1.2).
func (t *Tree) FilteredDirectPath(l uint32) (path, copath []uint64, err error) {
	x := 2 * uint64(l)
	d, err := treemath.DirectPath(x, t.Leaves())
	if err != nil {
		return nil, nil, err
	}
	c, err := treemath.Copath(x, t.Leaves())
	if err != nil {
		return nil, nil, err
	}
	for i := range d {
		if len(t.Resolution(c[i], nil)) > 0 {
			path = append(path, d[i])
			copath = append(copath, c[i])
		}
	}
	return path, copath, nil
}

func (t *Tree) blankDirectPath(l uint32) error {
	d, err := treemath.DirectPath(2*uint64(l), t.Leaves())
	if err != nil {
		return err
	}
	for _, x := range d {
		t.set(x, Node{})
	}
	return nil
}

// AddLeaf adds one leaf as AddLeaves does.
func (t *Tree) AddLeaf(leaf *LeafNode) (uint32, error) {
	ls, err := t.AddLeaves([]*LeafNode{leaf})
	if err != nil {
		return 0, err
	}
	return ls[0], nil
}

// AddLeaves applies the Adds of one Commit in order: each leaf goes to the
// leftmost blank leaf, extending the tree when there is none, and becomes
// unmerged on its direct path (RFC 9420 section 12.1.1). It costs one pass
// over the leaves, not one per Add.
func (t *Tree) AddLeaves(leaves []*LeafNode) ([]uint32, error) {
	out := make([]uint32, 0, len(leaves))
	l := uint64(0)
	for _, leaf := range leaves {
		for l < t.Leaves() && t.Leaf(uint32(l)) != nil {
			l++
		}
		if l == t.Leaves() {
			if t.Leaves() >= treemath.MaxLeaves {
				return nil, fmt.Errorf("%w: tree is full", errs.ErrInvalidArgument)
			}
			t.width = 2*t.width + 1
		}
		t.set(2*l, Node{Leaf: leaf})
		out = append(out, uint32(l))
	}
	// Adds neither set nor blank parents, so marking after placing them all
	// gives the same lists as marking after each one.
	added := map[uint64][]uint32{}
	for _, l := range out {
		d, err := treemath.DirectPath(2*uint64(l), t.Leaves())
		if err != nil {
			return nil, err
		}
		for _, x := range d {
			if t.nodes[x].Parent != nil {
				added[x] = append(added[x], l)
			}
		}
	}
	for x, ls := range added {
		c := *t.nodes[x].Parent
		c.UnmergedLeaves = mergeSorted(c.UnmergedLeaves, ls)
		t.set(x, Node{Parent: &c})
	}
	return out, nil
}

func mergeSorted(a, b []uint32) []uint32 {
	out := make([]uint32, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		if a[0] < b[0] {
			out, a = append(out, a[0]), a[1:]
		} else {
			out, b = append(out, b[0]), b[1:]
		}
	}
	out = append(out, a...)
	return append(out, b...)
}

// UpdateLeaf replaces leaf l and blanks its direct path (RFC 9420 section 12.1.2).
func (t *Tree) UpdateLeaf(l uint32, leaf *LeafNode) error {
	if t.Leaf(l) == nil {
		return fmt.Errorf("%w: leaf %d is blank", errs.ErrInvalidArgument, l)
	}
	if err := t.blankDirectPath(l); err != nil {
		return err
	}
	t.set(2*uint64(l), Node{Leaf: leaf})
	return nil
}

// RemoveLeaf removes one leaf as RemoveLeaves does.
func (t *Tree) RemoveLeaf(l uint32) error {
	return t.RemoveLeaves([]uint32{l})
}

// RemoveLeaves applies the Removes of one Commit: it blanks each leaf and its
// direct path, then truncates the tree once (RFC 9420 section 12.1.3);
// truncating once gives the same tree as after each Remove.
func (t *Tree) RemoveLeaves(leaves []uint32) error {
	for _, l := range leaves {
		if t.Leaf(l) == nil {
			return fmt.Errorf("%w: leaf %d is blank", errs.ErrInvalidArgument, l)
		}
		if err := t.blankDirectPath(l); err != nil {
			return err
		}
		t.set(2*uint64(l), Node{})
	}
	t.truncate()
	return nil
}

// truncate drops the right half while it is all blank (RFC 9420 section 7.7).
func (t *Tree) truncate() {
	last := t.last()
	for t.width > 1 {
		half := int64(t.width-1) / 2
		if last > half {
			break
		}
		t.width = uint64(half)
	}
	// Nodes past the new width are blank, so the node map holds none of them.
	for x := range t.cache {
		if x >= t.width {
			delete(t.cache, x)
		}
	}
}
