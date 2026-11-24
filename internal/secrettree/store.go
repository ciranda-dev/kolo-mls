package secrettree

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/treemath"
)

// Record is one stored part of a Tree: the secret of a kept node, or the two
// ratchets of a leaf in use with their held keys. A nil Value deletes it.
type Record struct {
	// Leaf is set for a leaf record; Index is then a leaf index, else a
	// node index.
	Leaf  bool
	Index uint64
	Value []byte
}

// Records returns every record of t, nodes then leaves, each in increasing
// order; the values belong to the caller.
func (t *Tree) Records() ([]Record, error) {
	out := make([]Record, 0, len(t.nodes)+len(t.leaves))
	for _, x := range slices.Sorted(maps.Keys(t.nodes)) {
		out = append(out, Record{Index: x, Value: slices.Clone(t.nodes[x][:])})
	}
	for _, l := range slices.Sorted(maps.Keys(t.leaves)) {
		v, err := t.leaves[l].marshal()
		if err != nil {
			zeroRecords(out)
			return nil, err
		}
		out = append(out, Record{Leaf: true, Index: uint64(l), Value: v})
	}
	return out, nil
}

// Changes returns the records that committing lk writes and deletes, and
// refuses a lookup that Commit would refuse; the values belong to the caller.
func (t *Tree) Changes(lk *Lookup) ([]Record, error) {
	if err := t.valid(lk); err != nil {
		return nil, err
	}
	var out []Record
	if lk.derived {
		out = append(out, Record{Index: lk.gone})
		for _, x := range slices.Sorted(maps.Keys(lk.nodes)) {
			out = append(out, Record{Index: x, Value: slices.Clone(lk.nodes[x][:])})
		}
	}
	v, err := lk.lf.marshal()
	if err != nil {
		zeroRecords(out)
		return nil, err
	}
	return append(out, Record{Leaf: true, Index: uint64(lk.leaf), Value: v}), nil
}

func zeroRecords(rs []Record) {
	for _, r := range rs {
		clear(r.Value)
	}
}

// marshal encodes both ratchets: secret, next generation and held keys.
func (lf *leaf) marshal() ([]byte, error) {
	var w tls.Writer
	for _, r := range lf.r {
		w.Fixed(r.secret[:])
		w.U32(r.next)
		w.Vector(func(w *tls.Writer) {
			for _, h := range r.held {
				w.U32(h.gen)
				w.Fixed(h.key[:])
				w.Fixed(h.nonce[:])
			}
		})
	}
	return w.Bytes()
}

// unmarshalLeaf decodes a leaf record; held keys must be ascending and below
// the next generation, as the ratchets keep them.
func unmarshalLeaf(b []byte) (*leaf, error) {
	lf := &leaf{}
	err := tls.Decode(b, func(rd *tls.Reader) error {
		for i := range lf.r {
			r := &lf.r[i]
			s, err := rd.Fixed(suite.Nh)
			if err != nil {
				return err
			}
			copy(r.secret[:], s)
			clear(s)
			if r.next, err = rd.U32(); err != nil {
				return err
			}
			err = rd.Vector(func(rd *tls.Reader) error {
				var h held
				var err error
				if h.gen, err = rd.U32(); err != nil {
					return err
				}
				if h.gen >= r.next || (len(r.held) > 0 && h.gen <= r.held[len(r.held)-1].gen) {
					return fmt.Errorf("%w: stored held generation %d", errs.ErrMalformed, h.gen)
				}
				k, err := rd.Fixed(suite.Nk)
				if err != nil {
					return err
				}
				n, err := rd.Fixed(suite.Nn)
				if err != nil {
					return err
				}
				copy(h.key[:], k)
				copy(h.nonce[:], n)
				clear(k)
				clear(n)
				r.held = append(r.held, h)
				clear(h.key[:])
				clear(h.nonce[:])
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		lf.clear()
		return nil, err
	}
	return lf, nil
}

// Load rebuilds the Tree of leafCount leaves from its records; get returns a
// copy of a record's value, which Load zeroes, or errs.ErrNotFound. It walks
// down from the root through consumed nodes only, so it reads the records
// that exist and the nodes above them. Held keys outside the window of opts
// are deleted, and the leaf records that changed are returned for the
// caller to write.
func Load(leafCount uint32, opts Options, get func(leaf bool, index uint64) ([]byte, error)) (*Tree, []Record, error) {
	t, root, err := empty(leafCount, opts)
	if err != nil {
		return nil, nil, err
	}
	stack := []uint64{root}
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if err := t.loadNode(x, get, &stack); err != nil {
			t.Clear()
			return nil, nil, err
		}
	}
	var pruned []Record
	for _, l := range slices.Sorted(maps.Keys(t.leaves)) {
		lf := t.leaves[l]
		n := len(lf.r[0].held) + len(lf.r[1].held)
		for i := range lf.r {
			lf.r[i].prune(t.opts.OutOfOrderTolerance)
		}
		if len(lf.r[0].held)+len(lf.r[1].held) == n {
			continue
		}
		v, err := lf.marshal()
		if err != nil {
			zeroRecords(pruned)
			t.Clear()
			return nil, nil, err
		}
		pruned = append(pruned, Record{Leaf: true, Index: uint64(l), Value: v})
	}
	return t, pruned, nil
}

// loadNode reads node x: its kept secret, the ratchets of its leaf, or, for
// a consumed parent, its children, which it pushes on stack.
func (t *Tree) loadNode(x uint64, get func(bool, uint64) ([]byte, error), stack *[]uint64) error {
	v, err := get(false, x)
	switch {
	case err == nil:
		defer clear(v)
		if len(v) != suite.Nh {
			return fmt.Errorf("%w: stored node secret of %d bytes", errs.ErrMalformed, len(v))
		}
		s := new([suite.Nh]byte)
		copy(s[:], v)
		t.nodes[x] = s
		return nil
	case !errors.Is(err, errs.ErrNotFound):
		return err
	}
	if x%2 == 0 {
		v, err := get(true, x/2)
		if errors.Is(err, errs.ErrNotFound) {
			return fmt.Errorf("%w: no stored secret for leaf %d", errs.ErrMalformed, x/2)
		}
		if err != nil {
			return err
		}
		defer clear(v)
		lf, err := unmarshalLeaf(v)
		if err != nil {
			return err
		}
		t.leaves[uint32(x/2)] = lf
		return nil
	}
	left, err := treemath.Left(x, t.n)
	if err != nil {
		return err
	}
	right, err := treemath.Right(x, t.n)
	if err != nil {
		return err
	}
	*stack = append(*stack, right, left)
	return nil
}
