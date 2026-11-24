package tree

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/treemath"
)

// hash computes the tree hash of node x (RFC 9420 section 7.8) with the
// leaves in excluded, strictly increasing, blanked and dropped from unmerged
// lists.
func (t *Tree) hash(x uint64, excluded []uint32) ([]byte, error) {
	h, _, err := t.subtreeHash(x, excluded)
	return h, err
}

func excludes(x uint64, excluded []uint32) bool {
	half := uint64(1)<<treemath.Level(x) - 1
	lo := (x - half) / 2
	i, _ := slices.BinarySearch(excluded, uint32(min(lo, 1<<32-1)))
	return i < len(excluded) && uint64(excluded[i]) <= (x+half)/2
}

// subtreeHash returns the tree hash of node x and whether its subtree is all
// blank. It caches the hash of every subtree that holds a non-blank node and
// of the all-blank subtrees just below those, so blank nodes add no cache
// entries except at the edges of blank regions; a subtree with no excluded
// leaf uses the cache too.
func (t *Tree) subtreeHash(x uint64, excluded []uint32) ([]byte, bool, error) {
	if len(excluded) > 0 && !excludes(x, excluded) {
		excluded = nil
	}
	cache := len(excluded) == 0
	if c, ok := t.cache[x]; ok && cache {
		return c.h[:], c.blank, nil
	}
	var w tls.Writer
	n := t.nodes[x]
	blank := n.Blank()
	if x%2 == 0 {
		w.U8(nodeLeaf)
		w.U32(uint32(x / 2))
		leaf := n.Leaf
		if _, ok := slices.BinarySearch(excluded, uint32(x/2)); ok {
			leaf = nil
		}
		w.Optional(leaf != nil)
		if leaf != nil {
			leaf.Write(&w)
		}
		b, err := w.Bytes()
		if err != nil {
			return nil, false, err
		}
		// Leaf hashes are not cached: a parent recomputes at most two.
		return suite.Hash(b), blank, nil
	}
	l, err := treemath.Left(x, t.Leaves())
	if err != nil {
		return nil, false, err
	}
	r, err := treemath.Right(x, t.Leaves())
	if err != nil {
		return nil, false, err
	}
	lh, lb, err := t.subtreeHash(l, excluded)
	if err != nil {
		return nil, false, err
	}
	rh, rb, err := t.subtreeHash(r, excluded)
	if err != nil {
		return nil, false, err
	}
	w.U8(nodeParent)
	w.Optional(n.Parent != nil)
	if p := n.Parent; p != nil {
		if len(excluded) > 0 {
			c := *p
			c.UnmergedLeaves = slices.DeleteFunc(slices.Clone(p.UnmergedLeaves), func(l uint32) bool {
				_, ok := slices.BinarySearch(excluded, l)
				return ok
			})
			p = &c
		}
		p.write(&w)
	}
	w.Opaque(lh)
	w.Opaque(rh)
	b, err := w.Bytes()
	if err != nil {
		return nil, false, err
	}
	h := suite.Hash(b)
	blank = blank && lb && rb
	if cache && (!blank || x == t.root()) {
		if t.cache == nil {
			t.cache = map[uint64]cachedHash{}
		}
		t.cache[x] = cachedHash{h: [suite.Nh]byte(h), blank: blank}
		for _, c := range []struct {
			x     uint64
			h     []byte
			blank bool
		}{{l, lh, lb}, {r, rh, rb}} {
			if c.blank && c.x%2 == 1 {
				t.cache[c.x] = cachedHash{h: [suite.Nh]byte(c.h), blank: true}
			}
		}
	}
	return h, blank, nil
}

// TreeHash returns the tree hash of the root.
func (t *Tree) TreeHash() ([]byte, error) {
	h, err := t.hash(t.root(), nil)
	return bytes.Clone(h), err
}

// parentHash computes the parent hash of p with the given original sibling
// tree hash (RFC 9420 section 7.9).
func parentHash(p *ParentNode, siblingHash []byte) ([]byte, error) {
	var w tls.Writer
	w.Opaque(p.EncryptionKey)
	w.Opaque(p.ParentHash)
	w.Opaque(siblingHash)
	b, err := w.Bytes()
	if err != nil {
		return nil, err
	}
	return suite.Hash(b), nil
}

// originalSiblingHash is the tree hash of s with the unmerged leaves of p
// blanked and removed from every unmerged list (RFC 9420 section 7.9).
func (t *Tree) originalSiblingHash(p *ParentNode, s uint64) ([]byte, error) {
	if len(p.UnmergedLeaves) == 0 {
		return t.hash(s, nil)
	}
	// unmerged_leaves is strictly increasing (readParentNode, AddLeaves).
	return t.hash(s, p.UnmergedLeaves)
}

func nodeParentHash(n Node) []byte {
	switch {
	case n.Leaf != nil && n.Leaf.Source == SourceCommit:
		return n.Leaf.ParentHash
	case n.Parent != nil:
		return n.Parent.ParentHash
	}
	return nil
}

// parentHashValid reports whether exactly one descendant of parent x has a
// parent hash valid for x (RFC 9420 section 7.9.2), which chains it to a leaf.
func (t *Tree) parentHashValid(x uint64) (bool, error) {
	p := t.nodes[x].Parent
	l, err := treemath.Left(x, t.Leaves())
	if err != nil {
		return false, err
	}
	r, err := treemath.Right(x, t.Leaves())
	if err != nil {
		return false, err
	}
	matches := 0
	for _, side := range [][2]uint64{{l, r}, {r, l}} {
		c, s := side[0], side[1]
		ph, err := t.originalSiblingHash(p, s)
		if err != nil {
			return false, err
		}
		want, err := parentHash(p, ph)
		if err != nil {
			return false, err
		}
		// D must be in the resolution of c, and the rest of that resolution
		// must be exactly the unmerged leaves of p under c. Verify has checked
		// the unmerged lists, so the resolution has no repeated node. Counting
		// keeps this linear even when many nodes carry the wanted hash.
		res := t.Resolution(c, nil)
		under := map[uint64]bool{}
		for _, u := range p.UnmergedLeaves {
			if inSubtree(2*uint64(u), c) {
				under[2*uint64(u)] = true
			}
		}
		inUnder := 0
		for _, y := range res {
			if under[y] {
				inUnder++
			}
		}
		for _, d := range res {
			if !bytes.Equal(nodeParentHash(t.nodes[d]), want) {
				continue
			}
			rest := inUnder
			if under[d] {
				rest--
			}
			if rest == len(res)-1 && len(under) == len(res)-1 {
				matches++
			}
		}
	}
	return matches == 1, nil
}

func inSubtree(x, c uint64) bool {
	half := uint64(1)<<treemath.Level(c) - 1
	return c-half <= x && x <= c+half
}

// Verify runs the tree checks of RFC 9420 section 12.4.3.1 for groupID except
// credentials and capabilities, which are the caller's.
func (t *Tree) Verify(groupID []byte) error {
	encKeys := map[string]bool{}
	sigKeys := map[string]bool{}
	xs := t.NonBlank()
	for _, x := range xs {
		n := t.nodes[x]
		switch {
		case n.Leaf != nil:
			if !n.Leaf.VerifySignature(groupID, uint32(x/2)) {
				return fmt.Errorf("%w: leaf %d signature", errs.ErrInvalidTree, x/2)
			}
			if sigKeys[string(n.Leaf.SignatureKey)] {
				return fmt.Errorf("%w: leaf %d signature key not unique", errs.ErrInvalidTree, x/2)
			}
			sigKeys[string(n.Leaf.SignatureKey)] = true
			if err := suite.CheckPublicKey(n.Leaf.EncryptionKey); err != nil {
				return fmt.Errorf("%w: leaf %d encryption key: %w", errs.ErrInvalidTree, x/2, err)
			}
			if encKeys[string(n.Leaf.EncryptionKey)] {
				return fmt.Errorf("%w: leaf %d encryption key not unique", errs.ErrInvalidTree, x/2)
			}
			encKeys[string(n.Leaf.EncryptionKey)] = true
		case n.Parent != nil:
			if err := suite.CheckPublicKey(n.Parent.EncryptionKey); err != nil {
				return fmt.Errorf("%w: node %d encryption key: %w", errs.ErrInvalidTree, x, err)
			}
			if encKeys[string(n.Parent.EncryptionKey)] {
				return fmt.Errorf("%w: node %d encryption key not unique", errs.ErrInvalidTree, x)
			}
			encKeys[string(n.Parent.EncryptionKey)] = true
			if err := t.verifyUnmerged(x); err != nil {
				return err
			}
		}
	}
	// Parent hashes read resolutions, which need every unmerged list checked.
	for _, x := range xs {
		if t.nodes[x].Parent == nil {
			continue
		}
		ok, err := t.parentHashValid(x)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: node %d not parent-hash valid", errs.ErrInvalidTree, x)
		}
	}
	return nil
}

func (t *Tree) verifyUnmerged(x uint64) error {
	for _, u := range t.nodes[x].Parent.UnmergedLeaves {
		lx := 2 * uint64(u)
		if lx >= t.Width() || t.nodes[lx].Leaf == nil || !inSubtree(lx, x) {
			return fmt.Errorf("%w: node %d unmerged leaf %d", errs.ErrInvalidTree, x, u)
		}
		d, err := treemath.DirectPath(lx, t.Leaves())
		if err != nil {
			return err
		}
		for _, y := range d {
			if y == x {
				break
			}
			if p := t.nodes[y].Parent; p != nil {
				if _, ok := slices.BinarySearch(p.UnmergedLeaves, u); !ok {
					return fmt.Errorf("%w: node %d misses unmerged leaf %d", errs.ErrInvalidTree, y, u)
				}
			}
		}
	}
	return nil
}
