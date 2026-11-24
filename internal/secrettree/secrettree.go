package secrettree

import (
	"cmp"
	"fmt"
	"maps"
	"math"
	"slices"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/treemath"
)

// Kind selects one of the two ratchets of a leaf (RFC 9420 section 9).
type Kind int

const (
	// Handshake is the ratchet of Proposal and Commit messages.
	Handshake Kind = iota
	// Application is the ratchet of application messages.
	Application
)

var kindLabels = [2]string{"handshake", "application"}

// Defaults of Options, the values of a published MLS implementation.
const (
	DefaultOutOfOrderTolerance uint32 = 5
	DefaultMaxForwardDistance  uint32 = 1000
)

// MaxBound is the largest value of either Options field: one message that
// moves a ratchet 2^16 generations and keeps every key costs about 0.15 s
// of CPU, the per-message budget.
const MaxBound uint32 = 1 << 16

// Options bounds what a receiver accepts (RFC 9420 section 15.3); a zero
// field takes its default, and a field above MaxBound is refused.
type Options struct {
	// MaxForwardDistance is the most generations a received generation may
	// lie past the ratchet head.
	MaxForwardDistance uint32
	// OutOfOrderTolerance is the size of the window of generations kept
	// below the ratchet head, the newest generation read included, so
	// OutOfOrderTolerance - 1 older generations stay readable.
	OutOfOrderTolerance uint32
}

// Check refuses a field above MaxBound.
func (o Options) Check() error {
	if o.MaxForwardDistance > MaxBound || o.OutOfOrderTolerance > MaxBound {
		return fmt.Errorf("%w: ratchet bound above %d", errs.ErrInvalidArgument, MaxBound)
	}
	return nil
}

type held struct {
	gen   uint32
	key   [suite.Nk]byte
	nonce [suite.Nn]byte
}

type ratchet struct {
	secret [suite.Nh]byte
	// next is the generation of secret; math.MaxUint32 once exhausted, since
	// a sender has at most 2^32 - 1 generations (the uint32 generation of
	// RFC 9420 section 6.3.2).
	next uint32
	// held keeps the unused keys of generations below next, ascending.
	held []held
}

type leaf struct{ r [2]ratchet }

// Tree is the secret tree of one epoch; it is not safe for concurrent use.
type Tree struct {
	n      uint64
	opts   Options
	nodes  map[uint64]*[suite.Nh]byte
	leaves map[uint32]*leaf
	// ver counts the changes, so a Lookup of an older state is refused.
	ver uint64
}

// New returns the secret tree of a ratchet tree with leafCount leaves, a
// power of two, rooted at encryptionSecret, which New copies.
func New(encryptionSecret []byte, leafCount uint32, opts Options) (*Tree, error) {
	if len(encryptionSecret) != suite.Nh {
		return nil, fmt.Errorf("%w: encryption secret size", errs.ErrInvalidArgument)
	}
	t, root, err := empty(leafCount, opts)
	if err != nil {
		return nil, err
	}
	s := new([suite.Nh]byte)
	copy(s[:], encryptionSecret)
	t.nodes[root] = s
	return t, nil
}

// empty returns a Tree of leafCount leaves with no secret, and its root.
func empty(leafCount uint32, opts Options) (*Tree, uint64, error) {
	if err := opts.Check(); err != nil {
		return nil, 0, err
	}
	if opts.MaxForwardDistance == 0 {
		opts.MaxForwardDistance = DefaultMaxForwardDistance
	}
	if opts.OutOfOrderTolerance == 0 {
		opts.OutOfOrderTolerance = DefaultOutOfOrderTolerance
	}
	n := uint64(leafCount)
	// Root refuses a leaf count of zero or not a power of two.
	root, err := treemath.Root(n)
	if err != nil {
		return nil, 0, err
	}
	return &Tree{n: n, opts: opts, nodes: map[uint64]*[suite.Nh]byte{}, leaves: map[uint32]*leaf{}}, root, nil
}

// Lookup is the key and nonce of one generation with the ratchet change
// that using them makes; the Tree changes only when the Lookup is
// committed, so a message that fails authentication consumes nothing.
type Lookup struct {
	t     *Tree
	ver   uint64
	leaf  uint32
	kind  Kind
	gen   uint32
	key   [suite.Nk]byte
	nonce [suite.Nn]byte
	// lf is the leaf after the change; nil once committed or discarded.
	lf *leaf
	// derived is set when this is the first use of the leaf: node gone is
	// consumed and nodes are the siblings kept on its path.
	derived bool
	gone    uint64
	nodes   map[uint64]*[suite.Nh]byte
}

// Leaf returns the leaf index of the ratchet.
func (lk *Lookup) Leaf() uint32 { return lk.leaf }

// Kind returns the ratchet kind.
func (lk *Lookup) Kind() Kind { return lk.kind }

// Generation returns the generation of the key.
func (lk *Lookup) Generation() uint32 { return lk.gen }

// Key returns a copy of the AEAD key.
func (lk *Lookup) Key() []byte { return slices.Clone(lk.key[:]) }

// Nonce returns a copy of the AEAD nonce.
func (lk *Lookup) Nonce() []byte { return slices.Clone(lk.nonce[:]) }

// Discard zeroes the key, the nonce and an uncommitted change.
func (lk *Lookup) Discard() {
	if lk == nil {
		return
	}
	clear(lk.key[:])
	clear(lk.nonce[:])
	if lk.lf != nil {
		lk.lf.clear()
		lk.lf = nil
	}
	for _, s := range lk.nodes {
		clear(s[:])
	}
	lk.nodes = nil
}

// PeekNext returns the next generation of the sender ratchet of leaf l
// without changing the Tree; Commit makes it used.
func (t *Tree) PeekNext(l uint32, k Kind) (*Lookup, error) {
	lk, err := t.lookup(l, k)
	if err != nil {
		return nil, err
	}
	if err := lk.send(t.opts.OutOfOrderTolerance); err != nil {
		lk.Discard()
		return nil, err
	}
	return lk, nil
}

// Peek returns the key and nonce of generation gen of the ratchet of leaf l
// for a receiver without changing the Tree. Committed, the key is deleted,
// skipped keys inside the out-of-order window are kept and every consumed
// ratchet secret is deleted (RFC 9420 sections 9.2 and 15.3).
func (t *Tree) Peek(l uint32, k Kind, gen uint32) (*Lookup, error) {
	lk, err := t.lookup(l, k)
	if err != nil {
		return nil, err
	}
	if err := lk.receive(gen, t.opts); err != nil {
		lk.Discard()
		return nil, err
	}
	return lk, nil
}

// Commit applies the change of lk, which must come from the last state of
// t, and deletes every value it consumed.
func (t *Tree) Commit(lk *Lookup) error {
	if err := t.valid(lk); err != nil {
		return err
	}
	if lk.derived {
		s := t.nodes[lk.gone]
		clear(s[:])
		delete(t.nodes, lk.gone)
		maps.Copy(t.nodes, lk.nodes)
	}
	if old := t.leaves[lk.leaf]; old != nil {
		old.clear()
	}
	t.leaves[lk.leaf] = lk.lf
	lk.lf, lk.nodes = nil, nil
	t.ver++
	return nil
}

// valid refuses a lookup of another tree, one used or discarded, and one
// made before a later change, which it discards.
func (t *Tree) valid(lk *Lookup) error {
	if lk == nil || lk.t != t || lk.lf == nil {
		return fmt.Errorf("%w: lookup already used or of another tree", errs.ErrInvalidArgument)
	}
	if lk.ver != t.ver {
		lk.Discard()
		return fmt.Errorf("%w: lookup made before a later change", errs.ErrInvalidArgument)
	}
	return nil
}

// lookup returns a Lookup holding a copy of leaf l's state, derived from the
// lowest kept ancestor on first use, which the caller then changes.
func (t *Tree) lookup(l uint32, k Kind) (*Lookup, error) {
	if k != Handshake && k != Application {
		return nil, fmt.Errorf("%w: ratchet kind %d", errs.ErrInvalidArgument, k)
	}
	if uint64(l) >= t.n {
		return nil, fmt.Errorf("%w: leaf %d of %d", errs.ErrInvalidArgument, l, t.n)
	}
	lk := &Lookup{t: t, ver: t.ver, leaf: l, kind: k}
	if lf := t.leaves[l]; lf != nil {
		lk.lf = lf.clone()
		return lk, nil
	}
	if err := t.derive(lk); err != nil {
		lk.Discard()
		return nil, err
	}
	return lk, nil
}

func (lk *Lookup) send(tol uint32) error {
	r := &lk.lf.r[lk.kind]
	gen := r.next
	if gen == math.MaxUint32 {
		return errs.ErrGenerationExhausted
	}
	var next [suite.Nh]byte
	key, nonce, err := step(&r.secret, &next, gen, true)
	if err != nil {
		return err
	}
	lk.set(gen, key, nonce)
	r.secret = next
	clear(next[:])
	r.next = gen + 1
	r.prune(tol)
	return nil
}

func (lk *Lookup) receive(gen uint32, opts Options) error {
	r := &lk.lf.r[lk.kind]
	tol := opts.OutOfOrderTolerance
	if gen < r.next {
		if r.next-gen > tol {
			return fmt.Errorf("%w: generation %d, head %d", errs.ErrTooOld, gen, r.next)
		}
		i, ok := slices.BinarySearchFunc(r.held, gen, func(h held, g uint32) int { return cmp.Compare(h.gen, g) })
		if !ok {
			return fmt.Errorf("%w: generation %d", errs.ErrReplay, gen)
		}
		lk.gen, lk.key, lk.nonce = gen, r.held[i].key, r.held[i].nonce
		r.remove(i)
		return nil
	}
	if gen-r.next > opts.MaxForwardDistance {
		return fmt.Errorf("%w: generation %d, head %d", errs.ErrTooFarAhead, gen, r.next)
	}
	if gen == math.MaxUint32 {
		return errs.ErrGenerationExhausted
	}
	// Keys of generations below low leave the window once gen is consumed.
	low := uint32(0)
	if gen >= tol {
		low = gen + 1 - tol
	}
	var cur, next [suite.Nh]byte
	defer clear(cur[:])
	defer clear(next[:])
	cur = r.secret
	fresh := make([]held, 0, min(gen-r.next, tol))
	defer clear(fresh)
	for g := r.next; g < gen; g++ {
		keep := g >= low
		k, n, err := step(&cur, &next, g, keep)
		if err != nil {
			return err
		}
		if keep {
			fresh = append(fresh, held{gen: g})
			copy(fresh[len(fresh)-1].key[:], k)
			copy(fresh[len(fresh)-1].nonce[:], n)
			clear(k)
			clear(n)
		}
		cur = next
	}
	key, nonce, err := step(&cur, &next, gen, true)
	if err != nil {
		return err
	}
	lk.set(gen, key, nonce)
	r.secret = next
	r.next = gen + 1
	r.prune(tol)
	r.add(fresh)
	return nil
}

// set records the generation, key and nonce of lk and zeroes key and nonce.
func (lk *Lookup) set(gen uint32, key, nonce []byte) {
	lk.gen = gen
	copy(lk.key[:], key)
	copy(lk.nonce[:], nonce)
	clear(key)
	clear(nonce)
}

// Clear zeroes and drops every secret of the tree; later calls fail.
func (t *Tree) Clear() {
	for _, s := range t.nodes {
		clear(s[:])
	}
	clear(t.nodes)
	for _, lf := range t.leaves {
		lf.clear()
	}
	clear(t.leaves)
	t.ver++
}

// step derives the key and nonce (when keys is set) of generation g from
// cur and writes ratchet secret g + 1 into next; the last generation has no
// successor, so next is zero then.
func step(cur, next *[suite.Nh]byte, g uint32, keys bool) (key, nonce []byte, err error) {
	if keys {
		if key, err = suite.DeriveTreeSecret(cur[:], "key", g, suite.Nk); err != nil {
			return nil, nil, err
		}
		if nonce, err = suite.DeriveTreeSecret(cur[:], "nonce", g, suite.Nn); err != nil {
			clear(key)
			return nil, nil, err
		}
	}
	clear(next[:])
	if g+1 == math.MaxUint32 {
		return key, nonce, nil
	}
	s, err := suite.DeriveTreeSecret(cur[:], "secret", g, suite.Nh)
	if err != nil {
		clear(key)
		clear(nonce)
		return nil, nil, err
	}
	copy(next[:], s)
	clear(s)
	return key, nonce, nil
}

// prune drops the held keys that fell out of the window below r.next.
func (r *ratchet) prune(tol uint32) {
	if r.next <= tol {
		return
	}
	low := r.next - tol
	i := 0
	for i < len(r.held) && r.held[i].gen < low {
		i++
	}
	n := copy(r.held, r.held[i:])
	clear(r.held[n:])
	r.held = r.held[:n]
}

// remove deletes held key i, leaving no copy in the backing array.
func (r *ratchet) remove(i int) {
	n := copy(r.held[i:], r.held[i+1:]) + i
	clear(r.held[n:])
	r.held = r.held[:n]
}

// add appends fresh keys, zeroing the old backing array when it moves.
func (r *ratchet) add(fresh []held) {
	if len(fresh) == 0 {
		return
	}
	if len(r.held)+len(fresh) > cap(r.held) {
		h := make([]held, len(r.held), len(r.held)+len(fresh))
		copy(h, r.held)
		clear(r.held[:cap(r.held)])
		r.held = h
	}
	r.held = append(r.held, fresh...)
}

func (lf *leaf) clear() {
	for i := range lf.r {
		r := &lf.r[i]
		clear(r.secret[:])
		clear(r.held[:cap(r.held)])
		r.held = nil
	}
}

func (lf *leaf) clone() *leaf {
	c := *lf
	for i := range c.r {
		c.r[i].held = slices.Clone(lf.r[i].held)
	}
	return &c
}

// derive fills lk with the first state of its leaf, derived from the lowest
// kept ancestor down (RFC 9420 section 9): each parent derives both children
// and is consumed, its unused child kept, and the leaf secret is consumed
// once both ratchets start (section 9.2). The Tree is not changed.
func (t *Tree) derive(lk *Lookup) error {
	target := 2 * uint64(lk.leaf)
	x := target
	for t.nodes[x] == nil {
		// Every leaf has one kept node on its path until Clear empties the tree.
		p, err := treemath.Parent(x, t.n)
		if err != nil {
			return fmt.Errorf("%w: secret tree cleared", errs.ErrInvalidArgument)
		}
		x = p
	}
	lk.derived, lk.gone, lk.nodes = true, x, map[uint64]*[suite.Nh]byte{}
	var cur [suite.Nh]byte
	defer clear(cur[:])
	cur = *t.nodes[x]
	for x != target {
		left, err := treemath.Left(x, t.n)
		if err != nil {
			return err
		}
		right, err := treemath.Right(x, t.n)
		if err != nil {
			return err
		}
		ls, err := derive(&cur, "tree", "left")
		if err != nil {
			return err
		}
		rs, err := derive(&cur, "tree", "right")
		if err != nil {
			clear(ls[:])
			return err
		}
		if target < x {
			lk.nodes[right] = rs
			cur, x = *ls, left
			clear(ls[:])
		} else {
			lk.nodes[left] = ls
			cur, x = *rs, right
			clear(rs[:])
		}
	}
	lk.lf = &leaf{}
	for i, label := range kindLabels {
		r, err := derive(&cur, label, "")
		if err != nil {
			return err
		}
		lk.lf.r[i].secret = *r
		clear(r[:])
	}
	return nil
}

func derive(s *[suite.Nh]byte, label, context string) (*[suite.Nh]byte, error) {
	b, err := suite.ExpandWithLabel(s[:], label, []byte(context), suite.Nh)
	if err != nil {
		return nil, err
	}
	out := new([suite.Nh]byte)
	copy(out[:], b)
	clear(b)
	return out, nil
}
