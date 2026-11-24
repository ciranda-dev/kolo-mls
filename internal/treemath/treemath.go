// Package treemath implements the array-based tree math of RFC 9420
// appendix C for the full binary trees MLS uses (section 4.1).
//
// Leaf i is node 2i. Node indices are uint64 because a tree of 2^32 leaves,
// the most a uint32 leaf index allows, has 2^33 - 1 nodes.
package treemath

import (
	"fmt"
	"math/bits"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
)

var errIndex = fmt.Errorf("%w: tree index", errs.ErrInvalidArgument)

// MaxLeaves is the largest leaf count: leaf indices are uint32 (RFC 9420 section 6).
const MaxLeaves = 1 << 32

// Level returns the level of node x; leaves are level 0.
func Level(x uint64) int {
	return bits.TrailingZeros64(^x)
}

// NodeWidth returns the number of nodes of a tree with n leaves.
func NodeWidth(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return 2*(n-1) + 1
}

func checkLeaves(n uint64) error {
	if n == 0 || n > MaxLeaves || n&(n-1) != 0 {
		return errIndex
	}
	return nil
}

func check(x, n uint64) error {
	if err := checkLeaves(n); err != nil {
		return err
	}
	if x >= NodeWidth(n) {
		return errIndex
	}
	return nil
}

// Root returns the root of a tree with n leaves; n must be a power of two.
func Root(n uint64) (uint64, error) {
	if err := checkLeaves(n); err != nil {
		return 0, err
	}
	return n - 1, nil
}

// Left returns the left child of the parent node x in a tree with n leaves.
func Left(x, n uint64) (uint64, error) {
	if err := check(x, n); err != nil {
		return 0, err
	}
	k := Level(x)
	if k == 0 {
		return 0, errIndex
	}
	return x ^ 1<<(k-1), nil
}

// Right returns the right child of the parent node x in a tree with n leaves.
func Right(x, n uint64) (uint64, error) {
	if err := check(x, n); err != nil {
		return 0, err
	}
	k := Level(x)
	if k == 0 {
		return 0, errIndex
	}
	return x ^ 3<<(k-1), nil
}

// Parent returns the parent of node x in a tree with n leaves.
func Parent(x, n uint64) (uint64, error) {
	if err := check(x, n); err != nil {
		return 0, err
	}
	if x == n-1 {
		return 0, errIndex
	}
	k := Level(x)
	b := (x >> (k + 1)) & 1
	return (x | 1<<k) ^ b<<(k+1), nil
}

// Sibling returns the other child of the parent of node x.
func Sibling(x, n uint64) (uint64, error) {
	p, err := Parent(x, n)
	if err != nil {
		return 0, err
	}
	if x < p {
		return Right(p, n)
	}
	return Left(p, n)
}

// DirectPath returns the ancestors of node x from its parent to the root.
func DirectPath(x, n uint64) ([]uint64, error) {
	if err := check(x, n); err != nil {
		return nil, err
	}
	var d []uint64
	for x != n-1 {
		p, err := Parent(x, n)
		if err != nil {
			return nil, err
		}
		d = append(d, p)
		x = p
	}
	return d, nil
}

// Copath returns the siblings of node x and of its ancestors below the root,
// from x up.
func Copath(x, n uint64) ([]uint64, error) {
	d, err := DirectPath(x, n)
	if err != nil {
		return nil, err
	}
	c := make([]uint64, len(d))
	for i, y := range d {
		s, err := Sibling(x, n)
		if err != nil {
			return nil, err
		}
		c[i], x = s, y
	}
	return c, nil
}

// CommonAncestor returns the lowest node that is x or an ancestor of x and
// also y or an ancestor of y; both must be nodes of one tree.
func CommonAncestor(x, y uint64) uint64 {
	lx, ly := Level(x)+1, Level(y)+1
	if lx <= ly && x>>ly == y>>ly {
		return y
	}
	if ly <= lx && x>>lx == y>>lx {
		return x
	}
	k := 0
	for x != y {
		x, y = x>>1, y>>1
		k++
	}
	return x<<k + 1<<(k-1) - 1
}
