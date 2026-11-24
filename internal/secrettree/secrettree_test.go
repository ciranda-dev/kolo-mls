package secrettree

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
	"github.com/ciranda-dev/kolo-mls/internal/treemath"
)

// oracle derives keys straight from the RFC 9420 section 9 formulas, with no
// laziness and no deletion, for comparison.
type oracle struct {
	root   []byte
	n      uint64
	chains map[[2]uint64][][]byte
}

func newOracle(root []byte, n uint32) *oracle {
	return &oracle{root: root, n: uint64(n), chains: map[[2]uint64][][]byte{}}
}

func mustExpand(tb testing.TB, s []byte, label, context string) []byte {
	b, err := suite.ExpandWithLabel(s, label, []byte(context), suite.Nh)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func (o *oracle) key(tb testing.TB, l uint32, k Kind, gen uint32) (key, nonce []byte) {
	id := [2]uint64{uint64(l), uint64(k)}
	c := o.chains[id]
	if c == nil {
		x, _ := treemath.Root(o.n)
		s := o.root
		target := 2 * uint64(l)
		for x != target {
			if target < x {
				s = mustExpand(tb, s, "tree", "left")
				x, _ = treemath.Left(x, o.n)
			} else {
				s = mustExpand(tb, s, "tree", "right")
				x, _ = treemath.Right(x, o.n)
			}
		}
		c = [][]byte{mustExpand(tb, s, []string{"handshake", "application"}[k], "")}
	}
	for g := uint32(len(c)); g <= gen; g++ {
		s, err := suite.DeriveTreeSecret(c[g-1], "secret", g-1, suite.Nh)
		if err != nil {
			tb.Fatal(err)
		}
		c = append(c, s)
	}
	o.chains[id] = c
	key, _ = suite.DeriveTreeSecret(c[gen], "key", gen, suite.Nk)
	nonce, _ = suite.DeriveTreeSecret(c[gen], "nonce", gen, suite.Nn)
	return key, nonce
}

func secret(b byte) []byte { return bytes.Repeat([]byte{b}, suite.Nh) }

func mustNew(tb testing.TB, n uint32, o Options) *Tree {
	tb.Helper()
	tr, err := New(secret(7), n, o)
	if err != nil {
		tb.Fatal(err)
	}
	return tr
}

// snapshot renders the whole state, including the stale part of each held
// array, so a test can check that a refused call changed nothing.
func snapshot(t *Tree) string {
	var b strings.Builder
	xs := make([]uint64, 0, len(t.nodes))
	for x := range t.nodes {
		xs = append(xs, x)
	}
	slices.Sort(xs)
	for _, x := range xs {
		fmt.Fprintf(&b, "n%d:%x;", x, t.nodes[x][:])
	}
	ls := make([]uint32, 0, len(t.leaves))
	for l := range t.leaves {
		ls = append(ls, l)
	}
	slices.Sort(ls)
	for _, l := range ls {
		for k, r := range t.leaves[l].r {
			fmt.Fprintf(&b, "l%d/%d:%x:%d:%d:", l, k, r.secret[:], r.next, len(r.held))
			for _, h := range r.held[:cap(r.held)] {
				fmt.Fprintf(&b, "%d.%x.%x,", h.gen, h.key[:], h.nonce[:])
			}
			b.WriteString(";")
		}
	}
	return b.String()
}

func zero(b []byte) bool { return !slices.ContainsFunc(b, func(c byte) bool { return c != 0 }) }

// staleFree reports whether no held array keeps key bytes past its length.
func staleFree(t *Tree) bool {
	for _, lf := range t.leaves {
		for _, r := range lf.r {
			for _, h := range r.held[len(r.held):cap(r.held)] {
				if h != (held{}) {
					return false
				}
			}
		}
	}
	return true
}

// windowed reports whether every held key lies inside its ratchet's window,
// ascending and below the head, so no key outlives the tolerance.
func windowed(t *Tree) bool {
	for _, lf := range t.leaves {
		for _, r := range lf.r {
			for i, h := range r.held {
				if h.gen >= r.next || r.next-h.gen > t.opts.OutOfOrderTolerance || (i > 0 && r.held[i-1].gen >= h.gen) {
					return false
				}
			}
		}
	}
	return true
}

func TestSecretTreeVectors(t *testing.T) {
	var v []struct {
		CipherSuite      uint16      `json:"cipher_suite"`
		EncryptionSecret testvec.Hex `json:"encryption_secret"`
		Leaves           [][]struct {
			Generation       uint32      `json:"generation"`
			HandshakeKey     testvec.Hex `json:"handshake_key"`
			HandshakeNonce   testvec.Hex `json:"handshake_nonce"`
			ApplicationKey   testvec.Hex `json:"application_key"`
			ApplicationNonce testvec.Hex `json:"application_nonce"`
		} `json:"leaves"`
	}
	testvec.Load(t, "secret-tree.json", &v)
	entries, skipped, gens := 0, 0, 0
	for _, e := range v {
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		entries++
		n := uint32(len(e.Leaves))
		recv, err := New(e.EncryptionSecret, n, Options{})
		if err != nil {
			t.Fatal(err)
		}
		send, err := New(e.EncryptionSecret, n, Options{})
		if err != nil {
			t.Fatal(err)
		}
		for l, list := range e.Leaves {
			for _, g := range list {
				gens++
				want := [2][2][]byte{{g.HandshakeKey, g.HandshakeNonce}, {g.ApplicationKey, g.ApplicationNonce}}
				for k := range Kind(2) {
					key, nonce, err := recv.Key(uint32(l), k, g.Generation)
					if err != nil || !bytes.Equal(key, want[k][0]) || !bytes.Equal(nonce, want[k][1]) {
						t.Fatalf("entry %d leaf %d gen %d kind %d: receiver key differs (%v)", entries, l, g.Generation, k, err)
					}
					for steps := 0; ; steps++ {
						if steps > int(g.Generation) {
							t.Fatalf("entry %d leaf %d kind %d: sender never reached generation %d", entries, l, k, g.Generation)
						}
						gen, key, nonce, err := send.Next(uint32(l), k)
						if err != nil {
							t.Fatal(err)
						}
						if gen == g.Generation {
							if !bytes.Equal(key, want[k][0]) || !bytes.Equal(nonce, want[k][1]) {
								t.Fatalf("entry %d leaf %d gen %d kind %d: sender key differs", entries, l, gen, k)
							}
							break
						}
					}
				}
			}
		}
	}
	// 21 entries: 3 for suite 1 (1, 8 and 32 leaves, generations 0 and 15).
	if entries != 3 || skipped != 18 || gens != 82 {
		t.Fatalf("checked %d suite 1 entries and %d leaf generations, skipped %d; want 3, 82 and 18", entries, gens, skipped)
	}
}

// TestSecretTreeVectorsStored runs secret-tree.json with every step
// written to records and the tree loaded back from them before the next
// one, for the receiver and for the sender.
func TestSecretTreeVectorsStored(t *testing.T) {
	var v []struct {
		CipherSuite      uint16      `json:"cipher_suite"`
		EncryptionSecret testvec.Hex `json:"encryption_secret"`
		Leaves           [][]struct {
			Generation       uint32      `json:"generation"`
			HandshakeKey     testvec.Hex `json:"handshake_key"`
			HandshakeNonce   testvec.Hex `json:"handshake_nonce"`
			ApplicationKey   testvec.Hex `json:"application_key"`
			ApplicationNonce testvec.Hex `json:"application_nonce"`
		} `json:"leaves"`
	}
	testvec.Load(t, "secret-tree.json", &v)
	entries, skipped, gens, loads := 0, 0, 0, 0
	for _, e := range v {
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		entries++
		n := uint32(len(e.Leaves))
		stores := [2]recordMap{{}, {}}
		for i := range stores {
			tr, err := New(e.EncryptionSecret, n, Options{})
			if err != nil {
				t.Fatal(err)
			}
			stores[i].write(t, must(t)(tr.Records()))
		}
		load := func(st recordMap) *Tree {
			loads++
			tr, _, err := Load(n, Options{}, st.get)
			if err != nil {
				t.Fatal(err)
			}
			return tr
		}
		for l, list := range e.Leaves {
			for _, g := range list {
				gens++
				want := [2][2][]byte{{g.HandshakeKey, g.HandshakeNonce}, {g.ApplicationKey, g.ApplicationNonce}}
				for k := range Kind(2) {
					recv := load(stores[0])
					lk, err := recv.Peek(uint32(l), k, g.Generation)
					if err != nil || !bytes.Equal(lk.Key(), want[k][0]) || !bytes.Equal(lk.Nonce(), want[k][1]) {
						t.Fatalf("entry %d leaf %d gen %d kind %d: receiver key differs (%v)", entries, l, g.Generation, k, err)
					}
					stores[0].write(t, must(t)(recv.Changes(lk)))
					for steps := 0; ; steps++ {
						if steps > int(g.Generation) {
							t.Fatalf("entry %d leaf %d kind %d: sender never reached generation %d", entries, l, k, g.Generation)
						}
						send := load(stores[1])
						lk, err := send.PeekNext(uint32(l), k)
						if err != nil {
							t.Fatal(err)
						}
						stores[1].write(t, must(t)(send.Changes(lk)))
						if lk.Generation() == g.Generation {
							if !bytes.Equal(lk.Key(), want[k][0]) || !bytes.Equal(lk.Nonce(), want[k][1]) {
								t.Fatalf("entry %d leaf %d gen %d kind %d: sender key differs", entries, l, g.Generation, k)
							}
							break
						}
					}
				}
			}
		}
		if _, err := load(stores[0]).Peek(0, Handshake, 15); !errors.Is(err, errs.ErrReplay) {
			t.Fatalf("stored receiver serves generation 15 again: %v", err)
		}
	}
	if entries != 3 || skipped != 18 || gens != 82 {
		t.Fatalf("checked %d suite 1 entries and %d leaf generations, skipped %d; want 3, 82 and 18", entries, gens, skipped)
	}
	t.Logf("%d entries, %d leaf generations, %d loads", entries, gens, loads)
}

// TestFigure27 replays the RFC 9420 section 9.2 example: a member receives
// generation 1 from D in a four-member group, with generation 0 missing.
func TestFigure27(t *testing.T) {
	tr := mustNew(t, 4, Options{})
	o := newOracle(secret(7), 4)
	key, nonce, err := tr.Key(3, Application, 1)
	if err != nil {
		t.Fatal(err)
	}
	wk, wn := o.key(t, 3, Application, 1)
	if !bytes.Equal(key, wk) || !bytes.Equal(nonce, wn) {
		t.Fatal("K1 or N1 differs")
	}
	// G (3), F (5) and D (6) are consumed; E (1) and C (4) are kept.
	if len(tr.nodes) != 2 || tr.nodes[1] == nil || tr.nodes[4] == nil {
		t.Fatalf("kept nodes %v, want E (1) and C (4)", slices.Sorted(func(yield func(uint64) bool) {
			for x := range tr.nodes {
				if !yield(x) {
					return
				}
			}
		}))
	}
	d := tr.leaves[3]
	if d == nil || len(tr.leaves) != 1 {
		t.Fatal("only D's ratchets should exist")
	}
	// AR2 kept, K0 and N0 kept, HR0 kept.
	ar := d.r[Application]
	if ar.next != 2 || len(ar.held) != 1 || ar.held[0].gen != 0 {
		t.Fatalf("application ratchet next %d held %d", ar.next, len(ar.held))
	}
	if d.r[Handshake].next != 0 || zero(d.r[Handshake].secret[:]) {
		t.Fatal("HR0 not kept")
	}
	key0, nonce0 := o.key(t, 3, Application, 0)
	if !bytes.Equal(ar.held[0].key[:], key0) || !bytes.Equal(ar.held[0].nonce[:], nonce0) {
		t.Fatal("K0 or N0 differs")
	}
	if key, nonce, err := tr.Key(3, Application, 0); err != nil || !bytes.Equal(key, key0) || !bytes.Equal(nonce, nonce0) {
		t.Fatalf("generation 0 after 1: %v", err)
	}
	for l := range uint32(3) {
		if _, _, err := tr.Key(l, Handshake, 0); err != nil {
			t.Fatal(err)
		}
	}
	if len(tr.nodes) != 0 || len(tr.leaves) != 4 {
		t.Fatalf("after every leaf: %d nodes, %d leaves", len(tr.nodes), len(tr.leaves))
	}
}

func TestNewRefuses(t *testing.T) {
	cases := []struct {
		s []byte
		n uint32
	}{
		{nil, 1}, {secret(1)[:31], 1}, {append(secret(1), 0), 1},
		{secret(1), 0}, {secret(1), 3}, {secret(1), 6}, {secret(1), math.MaxUint32}, {secret(1), 1<<31 + 1},
	}
	for _, c := range cases {
		if _, err := New(c.s, c.n, Options{}); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("New(%d bytes, %d): %v", len(c.s), c.n, err)
		}
	}
	for _, n := range []uint32{1, 2, 1 << 20, 1 << 31} {
		tr, err := New(secret(1), n, Options{})
		if err != nil {
			t.Fatalf("New(%d): %v", n, err)
		}
		if _, _, err := tr.Key(n-1, Application, 0); err != nil {
			t.Fatalf("last leaf of %d: %v", n, err)
		}
	}
}

func TestNewCopiesSecret(t *testing.T) {
	s := secret(7)
	tr, err := New(s, 2, Options{})
	if err != nil {
		t.Fatal(err)
	}
	clear(s)
	o := newOracle(secret(7), 2)
	key, _, err := tr.Key(1, Handshake, 0)
	if wk, _ := o.key(t, 1, Handshake, 0); err != nil || !bytes.Equal(key, wk) {
		t.Fatal("tree depends on the caller's slice")
	}
}

func TestDefaults(t *testing.T) {
	tr := mustNew(t, 1, Options{})
	if tr.opts.MaxForwardDistance != 1000 || tr.opts.OutOfOrderTolerance != 5 {
		t.Fatalf("defaults %+v", tr.opts)
	}
	tr = mustNew(t, 1, Options{MaxForwardDistance: 7, OutOfOrderTolerance: 2})
	if tr.opts.MaxForwardDistance != 7 || tr.opts.OutOfOrderTolerance != 2 {
		t.Fatalf("options %+v", tr.opts)
	}
}

func TestBadArguments(t *testing.T) {
	tr := mustNew(t, 4, Options{})
	before := snapshot(tr)
	for _, k := range []Kind{-1, 2, 100} {
		if _, _, err := tr.Key(0, k, 0); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Key kind %d: %v", k, err)
		}
		if _, _, _, err := tr.Next(0, k); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Next kind %d: %v", k, err)
		}
	}
	for _, l := range []uint32{4, 5, math.MaxUint32} {
		if _, _, err := tr.Key(l, Application, 0); !errors.Is(err, errs.ErrInvalidArgument) || !strings.Contains(err.Error(), "leaf") {
			t.Errorf("Key leaf %d: %v", l, err)
		}
		if _, _, _, err := tr.Next(l, Handshake); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("Next leaf %d: %v", l, err)
		}
	}
	if snapshot(tr) != before {
		t.Fatal("a refused call changed the tree")
	}
}

func TestForwardBound(t *testing.T) {
	for _, d := range []uint32{1, 3, 1000} {
		opts := Options{MaxForwardDistance: d}
		tr := mustNew(t, 2, opts)
		if _, _, err := tr.Key(0, Application, d+1); !errors.Is(err, errs.ErrTooFarAhead) {
			t.Fatalf("d %d: generation d + 1 from head 0: %v", d, err)
		}
		if _, _, err := tr.Key(0, Application, math.MaxUint32); !errors.Is(err, errs.ErrTooFarAhead) {
			t.Fatalf("d %d: hostile generation: %v", d, err)
		}
		if _, _, err := tr.Key(0, Application, d); err != nil {
			t.Fatalf("d %d: generation d from head 0: %v", d, err)
		}
		before := snapshot(tr)
		if _, _, err := tr.Key(0, Application, 2*d+2); !errors.Is(err, errs.ErrTooFarAhead) {
			t.Fatalf("d %d: head d + 1, generation 2d + 2: %v", d, err)
		}
		if snapshot(tr) != before {
			t.Fatal("a refused generation changed the tree")
		}
		o := newOracle(secret(7), 2)
		key, nonce, err := tr.Key(0, Application, 2*d+1)
		wk, wn := o.key(t, 0, Application, 2*d+1)
		if err != nil || !bytes.Equal(key, wk) || !bytes.Equal(nonce, wn) {
			t.Fatalf("d %d: head d + 1, generation 2d + 1: %v", d, err)
		}
	}
}

func TestOutOfOrderWindow(t *testing.T) {
	for _, tol := range []uint32{1, 2, 5, 9} {
		tr := mustNew(t, 2, Options{OutOfOrderTolerance: tol})
		o := newOracle(secret(7), 2)
		const g = 20
		if _, _, err := tr.Key(1, Handshake, g); err != nil {
			t.Fatal(err)
		}
		// Head is g + 1: generations g + 1 - tol to g - 1 are kept.
		r := tr.leaves[1].r[Handshake]
		if r.next != g+1 || len(r.held) != int(tol-1) {
			t.Fatalf("tol %d: next %d, %d held", tol, r.next, len(r.held))
		}
		before := snapshot(tr)
		if _, _, err := tr.Key(1, Handshake, g-tol); !errors.Is(err, errs.ErrTooOld) {
			t.Fatalf("tol %d: generation below the window: %v", tol, err)
		}
		if _, _, err := tr.Key(1, Handshake, 0); !errors.Is(err, errs.ErrTooOld) {
			t.Fatalf("tol %d: generation 0: %v", tol, err)
		}
		if _, _, err := tr.Key(1, Handshake, g); !errors.Is(err, errs.ErrReplay) {
			t.Fatalf("tol %d: replay of the head: %v", tol, err)
		}
		if snapshot(tr) != before {
			t.Fatal("a refused generation changed the tree")
		}
		for x := g + 1 - tol; x < g; x++ {
			key, nonce, err := tr.Key(1, Handshake, x)
			wk, wn := o.key(t, 1, Handshake, x)
			if err != nil || !bytes.Equal(key, wk) || !bytes.Equal(nonce, wn) {
				t.Fatalf("tol %d: kept generation %d: %v", tol, x, err)
			}
			if _, _, err := tr.Key(1, Handshake, x); !errors.Is(err, errs.ErrReplay) {
				t.Fatalf("tol %d: second use of %d: %v", tol, x, err)
			}
			if !staleFree(tr) {
				t.Fatal("a used key stays in the held array")
			}
		}
		if len(tr.leaves[1].r[Handshake].held) != 0 {
			t.Fatal("held keys left after using all")
		}
	}
}

// TestWindowSlides moves the head in small steps and checks that kept keys
// leave the window exactly at the tolerance.
func TestWindowSlides(t *testing.T) {
	tr := mustNew(t, 1, Options{OutOfOrderTolerance: 3})
	if _, _, err := tr.Key(0, Application, 1); err != nil {
		t.Fatal(err)
	}
	// Head 2, generation 0 kept (2 - 0 <= 3).
	if _, _, err := tr.Key(0, Application, 3); err != nil {
		t.Fatal(err)
	}
	// Head 4: generation 0 is out (4 - 0 > 3), 2 kept.
	if _, _, err := tr.Key(0, Application, 0); !errors.Is(err, errs.ErrTooOld) {
		t.Fatalf("generation 0 at head 4: %v", err)
	}
	r := tr.leaves[0].r[Application]
	if len(r.held) != 1 || r.held[0].gen != 2 || !staleFree(tr) {
		t.Fatalf("held %v", r.held)
	}
	if _, _, err := tr.Key(0, Application, 4); err != nil {
		t.Fatal(err)
	}
	// Head 5: 2 still in (5 - 2 = 3).
	if _, _, err := tr.Key(0, Application, 2); err != nil {
		t.Fatalf("generation 2 at head 5: %v", err)
	}
	if _, _, err := tr.Key(0, Application, 6); err != nil {
		t.Fatal(err)
	}
	// Head 7: 5 kept; Next moves the head to 8 and 9 and prunes it at 9.
	if _, _, _, err := tr.Next(0, Application); err != nil {
		t.Fatal(err)
	}
	if len(tr.leaves[0].r[Application].held) != 1 {
		t.Fatal("generation 5 dropped at head 8")
	}
	if _, _, _, err := tr.Next(0, Application); err != nil {
		t.Fatal(err)
	}
	if r := tr.leaves[0].r[Application]; len(r.held) != 0 || !staleFree(tr) {
		t.Fatalf("generation 5 kept at head 9: %v", r.held)
	}
}

func TestSentGenerationsAreUsed(t *testing.T) {
	tr := mustNew(t, 2, Options{})
	for range 3 {
		if _, _, _, err := tr.Next(1, Application); err != nil {
			t.Fatal(err)
		}
	}
	for g := range uint32(3) {
		if _, _, err := tr.Key(1, Application, g); !errors.Is(err, errs.ErrReplay) {
			t.Fatalf("own generation %d: %v", g, err)
		}
	}
	gen, _, _, err := tr.Next(1, Handshake)
	if err != nil || gen != 0 {
		t.Fatalf("handshake ratchet is separate: %d %v", gen, err)
	}
}

// setHead puts a ratchet at generation next with a chosen secret, to test the
// end of the generation space without 2^32 derivations.
func setHead(t *testing.T, tr *Tree, l uint32, k Kind, next uint32, s []byte) {
	t.Helper()
	if _, _, err := tr.Key(l, k, 0); err != nil {
		t.Fatal(err)
	}
	r := &tr.leaves[l].r[k]
	copy(r.secret[:], s)
	r.next = next
	r.held = nil
}

func TestGenerationExhausted(t *testing.T) {
	s := secret(9)
	last := uint32(math.MaxUint32 - 1)
	wk, _ := suite.DeriveTreeSecret(s, "key", last, suite.Nk)
	wn, _ := suite.DeriveTreeSecret(s, "nonce", last, suite.Nn)

	tr := mustNew(t, 1, Options{})
	setHead(t, tr, 0, Application, last, s)
	gen, key, nonce, err := tr.Next(0, Application)
	if err != nil || gen != last || !bytes.Equal(key, wk) || !bytes.Equal(nonce, wn) {
		t.Fatalf("last generation: %d %v", gen, err)
	}
	r := tr.leaves[0].r[Application]
	if r.next != math.MaxUint32 || !zero(r.secret[:]) {
		t.Fatal("ratchet secret kept after the last generation")
	}
	before := snapshot(tr)
	if _, _, _, err := tr.Next(0, Application); !errors.Is(err, errs.ErrGenerationExhausted) {
		t.Fatalf("after the last generation: %v", err)
	}
	if _, _, err := tr.Key(0, Application, math.MaxUint32); !errors.Is(err, errs.ErrGenerationExhausted) {
		t.Fatalf("generation 2^32 - 1 on an exhausted ratchet: %v", err)
	}
	if snapshot(tr) != before {
		t.Fatal("a refused call changed the tree")
	}

	tr = mustNew(t, 1, Options{MaxForwardDistance: 10})
	setHead(t, tr, 0, Handshake, last-3, s)
	if _, _, err := tr.Key(0, Handshake, math.MaxUint32); !errors.Is(err, errs.ErrGenerationExhausted) {
		t.Fatalf("receiver, generation 2^32 - 1: %v", err)
	}
	key, nonce, err = tr.Key(0, Handshake, last)
	if err != nil {
		t.Fatal(err)
	}
	wk, wn = refKeyFrom(t, s, last-3, last)
	if !bytes.Equal(key, wk) || !bytes.Equal(nonce, wn) {
		t.Fatal("receiver key at the last generation differs")
	}
	if r := tr.leaves[0].r[Handshake]; r.next != math.MaxUint32 || !zero(r.secret[:]) || len(r.held) != 3 {
		t.Fatalf("receiver after the last generation: next %d held %d", r.next, len(r.held))
	}
	if _, _, err := tr.Key(0, Handshake, last-1); err != nil {
		t.Fatalf("kept key below an exhausted head: %v", err)
	}
}

func refKeyFrom(t *testing.T, s []byte, from, gen uint32) (key, nonce []byte) {
	for g := from; g < gen; g++ {
		var err error
		if s, err = suite.DeriveTreeSecret(s, "secret", g, suite.Nh); err != nil {
			t.Fatal(err)
		}
	}
	key, _ = suite.DeriveTreeSecret(s, "key", gen, suite.Nk)
	nonce, _ = suite.DeriveTreeSecret(s, "nonce", gen, suite.Nn)
	return key, nonce
}

// TestDeletion checks the deletion schedule of RFC 9420 section 9.2 through
// the API and the state: no consumed key comes back, no parent stays after
// its children, and no ratchet secret is kept for a consumed generation.
func TestDeletion(t *testing.T) {
	tr := mustNew(t, 8, Options{})
	o := newOracle(secret(7), 8)
	root := tr.nodes[7]
	if _, _, err := tr.Key(5, Application, 3); err != nil {
		t.Fatal(err)
	}
	if !zero(root[:]) {
		t.Fatal("deleted root secret not zeroed")
	}
	n8, n13 := tr.nodes[8], tr.nodes[13]
	if _, _, err := tr.Key(4, Handshake, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tr.Key(7, Handshake, 0); err != nil {
		t.Fatal(err)
	}
	if !zero(n8[:]) || !zero(n13[:]) {
		t.Fatal("deleted leaf or parent secret not zeroed")
	}
	if tr.nodes[8] != nil || tr.nodes[13] != nil || tr.nodes[12] == nil {
		t.Fatal("nodes 8 and 13 must be gone and 12 kept")
	}
	for _, x := range []uint64{7, 11, 9, 10} {
		if tr.nodes[x] != nil {
			t.Fatalf("node %d kept after its children", x)
		}
	}
	if len(tr.nodes) != 2 || tr.nodes[3] == nil {
		t.Fatal("unused subtrees 3 and 12 must stay")
	}
	r := tr.leaves[5].r[Application]
	o.key(t, 5, Application, 4)
	ar4 := o.chains[[2]uint64{5, uint64(Application)}]
	if !bytes.Equal(r.secret[:], ar4[4]) {
		t.Fatal("ratchet secret is not the one of generation 4")
	}
	if _, _, err := tr.Key(5, Application, 3); !errors.Is(err, errs.ErrReplay) {
		t.Fatalf("used generation 3 again: %v", err)
	}
	for g := range uint32(3) {
		if _, _, err := tr.Key(5, Application, g); err != nil {
			t.Fatal(err)
		}
		if _, _, err := tr.Key(5, Application, g); !errors.Is(err, errs.ErrReplay) {
			t.Fatalf("used generation %d again: %v", g, err)
		}
	}
	// No state anywhere holds a used key or an old ratchet secret.
	used := map[string]bool{}
	for g := range uint32(4) {
		k, n := o.key(t, 5, Application, g)
		used[string(k)], used[string(n)] = true, true
		used[string(ar4[g])] = true
	}
	st := snapshot(tr)
	for u := range used {
		if strings.Contains(st, fmt.Sprintf("%x", u)) {
			t.Fatal("a consumed value is still in the tree")
		}
	}
	if !staleFree(tr) {
		t.Fatal("stale held keys")
	}
}

// TestHeldArrayGrowth checks that moving the held keys to a larger array
// zeroes the old one.
func TestHeldArrayGrowth(t *testing.T) {
	tr := mustNew(t, 1, Options{OutOfOrderTolerance: 10})
	if _, _, err := tr.Key(0, Application, 2); err != nil {
		t.Fatal(err)
	}
	old := tr.leaves[0].r[Application].held
	old = old[:cap(old)]
	if len(old) == 0 {
		t.Fatal("no held keys")
	}
	if _, _, err := tr.Key(0, Application, 8); err != nil {
		t.Fatal(err)
	}
	if &tr.leaves[0].r[Application].held[0] == &old[0] {
		t.Fatal("held array did not move")
	}
	for _, h := range old {
		if h != (held{}) {
			t.Fatal("old held array not zeroed")
		}
	}
}

func TestClear(t *testing.T) {
	tr := mustNew(t, 8, Options{})
	if _, _, err := tr.Key(2, Application, 4); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := tr.Next(6, Handshake); err != nil {
		t.Fatal(err)
	}
	var nodes []*[suite.Nh]byte
	for _, s := range tr.nodes {
		nodes = append(nodes, s)
	}
	leaves := []*leaf{tr.leaves[2], tr.leaves[6]}
	heldArr := tr.leaves[2].r[Application].held
	heldArr = heldArr[:cap(heldArr)]
	if len(nodes) == 0 || len(heldArr) == 0 {
		t.Fatal("nothing to clear")
	}
	tr.Clear()
	for _, s := range nodes {
		if !zero(s[:]) {
			t.Fatal("node secret not zeroed")
		}
	}
	for _, lf := range leaves {
		for _, r := range lf.r {
			if !zero(r.secret[:]) || r.held != nil {
				t.Fatal("ratchet not zeroed")
			}
		}
	}
	for _, h := range heldArr {
		if h != (held{}) {
			t.Fatal("held key not zeroed")
		}
	}
	if len(tr.nodes) != 0 || len(tr.leaves) != 0 {
		t.Fatal("maps not emptied")
	}
	if _, _, err := tr.Key(0, Application, 0); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("Key after Clear: %v", err)
	}
	if _, _, _, err := tr.Next(1, Application); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("Next after Clear: %v", err)
	}
	tr.Clear()
}

func TestErrorsHoldNoSecret(t *testing.T) {
	s := secret(0xab)
	tr, _ := New(s, 2, Options{MaxForwardDistance: 2, OutOfOrderTolerance: 1})
	_, _, err1 := tr.Key(0, Application, 9)
	_, _, _ = tr.Key(0, Application, 1)
	_, _, err2 := tr.Key(0, Application, 1)
	_, _, err3 := tr.Key(0, Application, 0)
	for _, err := range []error{err1, err2, err3} {
		if err == nil || !strings.HasPrefix(err.Error(), "kolomls: ") || strings.Contains(err.Error(), "abab") {
			t.Fatalf("error %v", err)
		}
	}
}
