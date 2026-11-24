package treemath

import (
	"errors"
	"slices"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
)

func TestTreeMathVectors(t *testing.T) {
	var v []struct {
		NLeaves uint64    `json:"n_leaves"`
		NNodes  uint64    `json:"n_nodes"`
		Root    uint64    `json:"root"`
		Left    []*uint64 `json:"left"`
		Right   []*uint64 `json:"right"`
		Parent  []*uint64 `json:"parent"`
		Sibling []*uint64 `json:"sibling"`
	}
	testvec.Load(t, "tree-math.json", &v)
	if len(v) != 10 {
		t.Fatalf("tree-math.json has %d entries, want 10", len(v))
	}
	nodes := 0
	for _, e := range v {
		n := e.NLeaves
		if got := NodeWidth(n); got != e.NNodes {
			t.Errorf("NodeWidth(%d) = %d, want %d", n, got, e.NNodes)
		}
		if got, err := Root(n); err != nil || got != e.Root {
			t.Errorf("Root(%d) = %d, %v, want %d", n, got, err, e.Root)
		}
		for name, c := range map[string]struct {
			want []*uint64
			f    func(x uint64) (uint64, error)
		}{
			"left":    {e.Left, func(x uint64) (uint64, error) { return Left(x, n) }},
			"right":   {e.Right, func(x uint64) (uint64, error) { return Right(x, n) }},
			"parent":  {e.Parent, func(x uint64) (uint64, error) { return Parent(x, n) }},
			"sibling": {e.Sibling, func(x uint64) (uint64, error) { return Sibling(x, n) }},
		} {
			if uint64(len(c.want)) != e.NNodes {
				t.Fatalf("n=%d %s has %d values", n, name, len(c.want))
			}
			for x, w := range c.want {
				got, err := c.f(uint64(x))
				switch {
				case w == nil && !errors.Is(err, errs.ErrInvalidArgument):
					t.Errorf("n=%d %s(%d) = %d, %v; want an error", n, name, x, got, err)
				case w != nil && (err != nil || got != *w):
					t.Errorf("n=%d %s(%d) = %d, %v; want %d", n, name, x, got, err, *w)
				}
			}
		}
		nodes += int(e.NNodes)
	}
	t.Logf("tree-math.json: %d entries (%d nodes) checked, 0 skipped", len(v), nodes)
}

func TestLevel(t *testing.T) {
	for x, want := range map[uint64]int{0: 0, 1: 1, 2: 0, 3: 2, 5: 1, 7: 3, 11: 2, 15: 4, 1<<32 - 1: 32} {
		if got := Level(x); got != want {
			t.Errorf("Level(%d) = %d, want %d", x, got, want)
		}
	}
	if NodeWidth(0) != 0 || NodeWidth(1) != 1 || NodeWidth(MaxLeaves) != 1<<33-1 {
		t.Error("NodeWidth")
	}
}

func TestLeafCounts(t *testing.T) {
	if r, err := Root(MaxLeaves); err != nil || r != MaxLeaves-1 {
		t.Fatalf("Root(2^32) = %d, %v", r, err)
	}
	for _, n := range []uint64{0, 3, 5, 6, 12, MaxLeaves + 1, MaxLeaves * 2, 1 << 63} {
		if _, err := Root(n); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Root(%d) error = %v", n, err)
		}
		if _, err := Parent(0, n); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Parent(0, %d) error = %v", n, err)
		}
	}
}

func TestOutOfRange(t *testing.T) {
	for _, c := range []struct{ x, n uint64 }{{7, 4}, {15, 8}, {3, 2}, {1, 1}, {1 << 33, MaxLeaves}} {
		if _, err := Parent(c.x, c.n); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Parent(%d, %d) error = %v", c.x, c.n, err)
		}
		if _, err := Left(c.x, c.n); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Left(%d, %d) error = %v", c.x, c.n, err)
		}
		if _, err := Right(c.x, c.n); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Right(%d, %d) error = %v", c.x, c.n, err)
		}
		if _, err := DirectPath(c.x, c.n); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("DirectPath(%d, %d) error = %v", c.x, c.n, err)
		}
		if _, err := Copath(c.x, c.n); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Copath(%d, %d) error = %v", c.x, c.n, err)
		}
	}
}

func TestPaths(t *testing.T) {
	for _, c := range []struct {
		x, n           uint64
		direct, copath []uint64
	}{
		{0, 8, []uint64{1, 3, 7}, []uint64{2, 5, 11}},
		{14, 8, []uint64{13, 11, 7}, []uint64{12, 9, 3}},
		{6, 8, []uint64{5, 3, 7}, []uint64{4, 1, 11}},
		{5, 8, []uint64{3, 7}, []uint64{1, 11}},
		{7, 8, nil, nil},
		{0, 1, nil, nil},
		{2, 2, []uint64{1}, []uint64{0}},
	} {
		d, err := DirectPath(c.x, c.n)
		if err != nil || !slices.Equal(d, c.direct) {
			t.Errorf("DirectPath(%d, %d) = %v, %v; want %v", c.x, c.n, d, err, c.direct)
		}
		cp, err := Copath(c.x, c.n)
		if err != nil || !slices.Equal(cp, c.copath) {
			t.Errorf("Copath(%d, %d) = %v, %v; want %v", c.x, c.n, cp, err, c.copath)
		}
	}
	last := uint64(2 * (MaxLeaves - 1)) // leaf 2^32 - 1
	d, err := DirectPath(last, MaxLeaves)
	if err != nil || len(d) != 32 || d[0] != last-1 || d[31] != MaxLeaves-1 {
		t.Fatalf("DirectPath of the last leaf of 2^32: len %d, %v", len(d), err)
	}
}

func commonAncestorSemantic(x, y, n uint64) uint64 {
	dx, _ := DirectPath(x, n)
	dy, _ := DirectPath(y, n)
	best := uint64(0)
	bestLevel := 99
	for _, a := range append([]uint64{x}, dx...) {
		if (a == y || slices.Contains(dy, a)) && Level(a) < bestLevel {
			best, bestLevel = a, Level(a)
		}
	}
	return best
}

func TestCommonAncestor(t *testing.T) {
	for _, c := range [][3]uint64{{0, 2, 1}, {0, 14, 7}, {4, 6, 5}, {1, 5, 3}, {3, 3, 3}, {0, 0, 0}, {8, 13, 11}, {2, 9, 7}} {
		if got := CommonAncestor(c[0], c[1]); got != c[2] {
			t.Errorf("CommonAncestor(%d, %d) = %d, want %d", c[0], c[1], got, c[2])
		}
	}
	for n := uint64(1); n <= 64; n *= 2 {
		w := NodeWidth(n)
		for x := uint64(0); x < w; x++ {
			for y := uint64(0); y < w; y++ {
				if got, want := CommonAncestor(x, y), commonAncestorSemantic(x, y, n); got != want {
					t.Fatalf("n=%d CommonAncestor(%d, %d) = %d, want %d", n, x, y, got, want)
				}
			}
		}
	}
}
