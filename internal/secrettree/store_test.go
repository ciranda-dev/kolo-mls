package secrettree

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
)

// recordMap is a Store of records keyed by kind and index.
type recordMap map[[2]uint64][]byte

func recKey(leaf bool, x uint64) [2]uint64 { return [2]uint64{uint64(btoi(leaf)), x} }

func (m recordMap) write(tb testing.TB, rs []Record) {
	tb.Helper()
	for _, r := range rs {
		if r.Value == nil {
			if _, ok := m[recKey(r.Leaf, r.Index)]; !ok {
				tb.Fatalf("deletes absent record %v", r)
			}
			delete(m, recKey(r.Leaf, r.Index))
			continue
		}
		m[recKey(r.Leaf, r.Index)] = r.Value
	}
}

// must returns rs, failing tb on err.
func must(tb testing.TB) func(rs []Record, err error) []Record {
	return func(rs []Record, err error) []Record {
		tb.Helper()
		if err != nil {
			tb.Fatal(err)
		}
		return rs
	}
}

func (m recordMap) get(leaf bool, x uint64) ([]byte, error) {
	v, ok := m[recKey(leaf, x)]
	if !ok {
		return nil, errs.ErrNotFound
	}
	return bytes.Clone(v), nil
}

// matches fails unless m holds exactly the records of t.
func (m recordMap) matches(tb testing.TB, t *Tree) {
	tb.Helper()
	rs, err := t.Records()
	if err != nil {
		tb.Fatal(err)
	}
	if len(rs) != len(m) {
		tb.Fatalf("%d records stored, tree has %d", len(m), len(rs))
	}
	for _, r := range rs {
		if !bytes.Equal(m[recKey(r.Leaf, r.Index)], r.Value) {
			tb.Fatalf("record %v differs", r.Index)
		}
	}
}

// TestPeekChangesNothing peeks every kind of lookup and discards it: the
// tree's state and records stay as they were.
func TestPeekChangesNothing(t *testing.T) {
	tr := mustNew(t, 8, Options{})
	if _, _, err := tr.Key(2, Application, 3); err != nil {
		t.Fatal(err)
	}
	before := snapshot(tr)
	for _, c := range []struct {
		l   uint32
		k   Kind
		gen uint32
	}{{2, Application, 1}, {2, Application, 4}, {2, Application, 9}, {2, Handshake, 0}, {5, Application, 2}, {0, Handshake, 7}} {
		lk, err := tr.Peek(c.l, c.k, c.gen)
		if err != nil {
			t.Fatal(err)
		}
		lk.Discard()
		if snapshot(tr) != before {
			t.Fatalf("Peek(%d, %d, %d) changed the tree", c.l, c.k, c.gen)
		}
	}
	lk, err := tr.PeekNext(6, Handshake)
	if err != nil {
		t.Fatal(err)
	}
	lk.Discard()
	if snapshot(tr) != before {
		t.Fatal("PeekNext changed the tree")
	}
	for _, f := range []func() error{
		func() error { _, err := tr.Peek(2, Application, 3); return err },
		func() error { _, err := tr.Peek(2, Application, 2000); return err },
		func() error { _, err := tr.Peek(9, Application, 0); return err },
	} {
		if f() == nil || snapshot(tr) != before {
			t.Fatal("a refused Peek changed the tree")
		}
	}
}

// TestUncommittedKeyStaysUsable: a key looked up for a message that is then
// refused is still there for the real message, and the out-of-order keys
// below it too.
func TestUncommittedKeyStaysUsable(t *testing.T) {
	tr := mustNew(t, 4, Options{})
	o := newOracle(secret(7), 4)
	lk, err := tr.Peek(3, Application, 4)
	if err != nil {
		t.Fatal(err)
	}
	forged := lk.Key()
	lk.Discard()
	if !zero(lk.key[:]) || !zero(lk.nonce[:]) {
		t.Fatal("Discard left the key")
	}
	key, nonce, err := tr.Key(3, Application, 4)
	wk, wn := o.key(t, 3, Application, 4)
	if err != nil || !bytes.Equal(key, wk) || !bytes.Equal(nonce, wn) || !bytes.Equal(forged, wk) {
		t.Fatalf("key after a discarded lookup: %v", err)
	}
	for g := range uint32(4) {
		if _, _, err := tr.Key(3, Application, g); err != nil {
			t.Fatalf("generation %d after a discarded lookup: %v", g, err)
		}
	}
	if _, _, err := tr.Key(3, Application, 4); !errors.Is(err, errs.ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
}

func TestCommitRefusals(t *testing.T) {
	tr := mustNew(t, 4, Options{})
	other := mustNew(t, 4, Options{})
	a, err := tr.Peek(0, Application, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tr.Peek(1, Application, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := other.Peek(0, Application, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Commit(c); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("lookup of another tree: %v", err)
	}
	if err := tr.Commit(nil); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("nil lookup: %v", err)
	}
	if err := tr.Commit(a); err != nil {
		t.Fatal(err)
	}
	if err := tr.Commit(a); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("second commit: %v", err)
	}
	if _, err := tr.Changes(a); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("records of a used lookup: %v", err)
	}
	// b was made before a changed the tree; committing it would undo a's
	// derivation of the shared parent.
	before := snapshot(tr)
	if err := tr.Commit(b); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("stale lookup: %v", err)
	}
	if b.lf != nil || snapshot(tr) != before {
		t.Fatal("a refused commit changed the tree or kept the lookup")
	}
	// A discarded lookup cannot be committed either.
	e, _ := tr.Peek(2, Application, 0)
	e.Discard()
	before = snapshot(tr)
	if err := tr.Commit(e); !errors.Is(err, errs.ErrInvalidArgument) || snapshot(tr) != before {
		t.Fatalf("commit of a discarded lookup: %v", err)
	}
	d, _ := tr.Peek(1, Application, 0)
	tr.Clear()
	if err := tr.Commit(d); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("commit after Clear: %v", err)
	}
	if _, err := tr.PeekNext(0, Application); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("PeekNext after Clear: %v", err)
	}
	var nilLookup *Lookup
	nilLookup.Discard()
}

// TestDiscardZeroes: Discard zeroes the changed state a lookup holds and
// the nodes its first use would keep.
func TestDiscardZeroes(t *testing.T) {
	tr := mustNew(t, 4, Options{})
	lk, err := tr.Peek(1, Application, 3)
	if err != nil {
		t.Fatal(err)
	}
	lf, nodes := lk.lf, lk.nodes
	if len(nodes) == 0 || len(lf.r[Application].held) == 0 {
		t.Fatal("nothing to zero")
	}
	heldArr := lf.r[Application].held[:cap(lf.r[Application].held)]
	lk.Discard()
	for _, r := range lf.r {
		if !zero(r.secret[:]) {
			t.Fatal("ratchet secret kept")
		}
	}
	for _, h := range heldArr {
		if h != (held{}) {
			t.Fatal("held key kept")
		}
	}
	for _, s := range nodes {
		if !zero(s[:]) {
			t.Fatal("node secret kept")
		}
	}
}

// TestCommitDeletes checks that a commit zeroes what it replaces: the
// consumed node and the leaf's old state with its held keys.
func TestCommitDeletes(t *testing.T) {
	tr := mustNew(t, 2, Options{})
	root := tr.nodes[1]
	lk, err := tr.Peek(0, Application, 2)
	if err != nil {
		t.Fatal(err)
	}
	if zero(root[:]) {
		t.Fatal("Peek zeroed the root")
	}
	if err := tr.Commit(lk); err != nil {
		t.Fatal(err)
	}
	if !zero(root[:]) || tr.nodes[1] != nil || tr.nodes[2] == nil {
		t.Fatal("root kept after the first use of leaf 0, or leaf 1 not kept")
	}
	old := tr.leaves[0]
	heldArr := old.r[Application].held[:cap(old.r[Application].held)]
	if len(heldArr) == 0 {
		t.Fatal("no held keys")
	}
	if _, _, err := tr.Key(0, Application, 0); err != nil {
		t.Fatal(err)
	}
	if !zero(old.r[Application].secret[:]) || !zero(old.r[Handshake].secret[:]) {
		t.Fatal("replaced leaf state not zeroed")
	}
	for _, h := range heldArr {
		if h != (held{}) {
			t.Fatal("replaced held keys not zeroed")
		}
	}
}

// TestRecords checks the records of each change: the first use of a leaf
// deletes the consumed node and adds the siblings and the leaf; later uses
// rewrite only the leaf.
func TestRecords(t *testing.T) {
	tr := mustNew(t, 8, Options{})
	st := recordMap{}
	st.write(t, must(t)(tr.Records()))
	if len(st) != 1 || st[recKey(false, 7)] == nil {
		t.Fatal("a new tree is its root record")
	}
	lk, _ := tr.Peek(5, Application, 3)
	rs, err := tr.Changes(lk)
	if err != nil {
		t.Fatal(err)
	}
	want := "n7- n3 n8 n13 l5"
	if got := describe(rs); got != want {
		t.Fatalf("records of a first use: %s, want %s", got, want)
	}
	st.write(t, rs)
	if err := tr.Commit(lk); err != nil {
		t.Fatal(err)
	}
	st.matches(t, tr)
	lk, _ = tr.Peek(5, Application, 1)
	rs, _ = tr.Changes(lk)
	if got := describe(rs); got != "l5" {
		t.Fatalf("records of a later use: %s", got)
	}
	st.write(t, rs)
	tr.Commit(lk)
	st.matches(t, tr)
	loaded, _, err := Load(8, Options{}, st.get)
	if err != nil {
		t.Fatal(err)
	}
	st.matches(t, loaded)
	for _, g := range []uint32{0, 2, 4} {
		k1, n1, err1 := tr.Key(5, Application, g)
		k2, n2, err2 := loaded.Key(5, Application, g)
		if err1 != nil || err2 != nil || !bytes.Equal(k1, k2) || !bytes.Equal(n1, n2) {
			t.Fatalf("generation %d after Load: %v %v", g, err1, err2)
		}
	}
	if _, _, err := loaded.Key(5, Application, 1); !errors.Is(err, errs.ErrReplay) {
		t.Fatalf("used generation after Load: %v", err)
	}
}

func describe(rs []Record) string {
	var b bytes.Buffer
	for i, r := range rs {
		if i > 0 {
			b.WriteByte(' ')
		}
		kind := "n"
		if r.Leaf {
			kind = "l"
		}
		fmt.Fprintf(&b, "%s%d", kind, r.Index)
		if r.Value == nil {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func TestLoadRefuses(t *testing.T) {
	tr := mustNew(t, 4, Options{})
	if _, _, err := tr.Key(1, Application, 3); err != nil {
		t.Fatal(err)
	}
	good := recordMap{}
	good.write(t, must(t)(tr.Records()))
	leaf := good[recKey(true, 1)]
	// The leaf record: the handshake ratchet with no held keys (secret,
	// next, an empty vector), then the application one, whose three held
	// keys of 32 bytes follow a two-byte length.
	app := 32 + 4 + 1
	heldAt := app + 32 + 4 + 2
	edit := func(f func(b []byte) []byte) recordMap {
		m := recordMap{}
		for k, v := range good {
			m[k] = bytes.Clone(v)
		}
		m[recKey(true, 1)] = f(bytes.Clone(leaf))
		return m
	}
	boom := errors.New("disk")
	for name, c := range map[string]struct {
		m    recordMap
		get  func(bool, uint64) ([]byte, error)
		want error
	}{
		"missing leaf": {m: func() recordMap { m := edit(func(b []byte) []byte { return b }); delete(m, recKey(true, 1)); return m }(), want: errs.ErrMalformed},
		"short node": {m: func() recordMap {
			m := edit(func(b []byte) []byte { return b })
			m[recKey(false, 5)] = []byte{1}
			return m
		}(), want: errs.ErrMalformed},
		"trailing":     {m: edit(func(b []byte) []byte { return append(b, 0) }), want: errs.ErrMalformed},
		"truncated":    {m: edit(func(b []byte) []byte { return b[:len(b)-1] }), want: errs.ErrMalformed},
		"held at head": {m: edit(func(b []byte) []byte { b[heldAt+64+3] = 4; return b }), want: errs.ErrMalformed},
		"held order":   {m: edit(func(b []byte) []byte { b[heldAt+32+3] = 0; return b }), want: errs.ErrMalformed},
		"store error":  {get: func(bool, uint64) ([]byte, error) { return nil, boom }, want: boom},
		"node error": {get: func(leaf bool, x uint64) ([]byte, error) {
			if !leaf {
				return nil, boom
			}
			return good.get(leaf, x)
		}, want: boom},
		"leaf error": {get: func(leaf bool, x uint64) ([]byte, error) {
			if leaf {
				return nil, boom
			}
			return good.get(leaf, x)
		}, want: boom},
	} {
		get := c.get
		if get == nil {
			get = c.m.get
		}
		_, _, err := Load(4, Options{}, get)
		if !errors.Is(err, c.want) || name == "missing leaf" && !strings.Contains(err.Error(), "no stored secret for leaf 1") {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if _, _, err := Load(3, Options{}, good.get); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("leaf count 3: %v", err)
	}
	if _, _, err := Load(4, Options{}, good.get); err != nil {
		t.Fatal(err)
	}
}

// TestLoadReadsOnlyWhatExists counts the reads of Load: the consumed nodes
// above the records and the records, not the whole tree.
func TestLoadReadsOnlyWhatExists(t *testing.T) {
	tr := mustNew(t, 1<<20, Options{})
	if _, _, err := tr.Key(77, Application, 0); err != nil {
		t.Fatal(err)
	}
	st := recordMap{}
	st.write(t, must(t)(tr.Records()))
	reads := 0
	if _, _, err := Load(1<<20, Options{}, func(leaf bool, x uint64) ([]byte, error) { reads++; return st.get(leaf, x) }); err != nil {
		t.Fatal(err)
	}
	// 20 kept siblings, 20 consumed parents, the leaf node and its record.
	if reads != 42 {
		t.Fatalf("%d reads", reads)
	}
}

// FuzzSecretTreeStore loads a two-leaf tree whose leaf 1 record is the
// input: no panic, a typed error, and an accepted record encodes back to
// itself once held keys outside the window are pruned, and serves keys as
// the model of section 15.3 says.
func FuzzSecretTreeStore(f *testing.F) {
	tr := mustNew(f, 2, Options{})
	tr.Key(1, Application, 3)
	tr.Key(1, Handshake, 0)
	rs, _ := tr.Records()
	for _, r := range rs {
		if r.Leaf {
			f.Add(r.Value, uint32(1))
		}
	}
	f.Add(make([]byte, 2*(suite.Nh+4+1)), uint32(0xffffffff))
	f.Fuzz(func(t *testing.T, rec []byte, gen uint32) {
		st := recordMap{recKey(false, 0): secret(1), recKey(true, 1): rec}
		lt, rewrite, err := Load(2, Options{}, st.get)
		if err != nil {
			if !errors.Is(err, errs.ErrMalformed) {
				t.Fatalf("Load: %v", err)
			}
			return
		}
		// Held keys outside the window are pruned and their record returned.
		if len(rewrite) > 1 || len(rewrite) == 1 && (!rewrite[0].Leaf || rewrite[0].Index != 1) {
			t.Fatalf("records to rewrite: %v", rewrite)
		}
		st.write(t, rewrite)
		st.matches(t, lt)
		for k := range Kind(2) {
			lk, err := lt.Peek(1, k, gen)
			if err != nil {
				if !errors.Is(err, errs.ErrTooOld) && !errors.Is(err, errs.ErrTooFarAhead) && !errors.Is(err, errs.ErrReplay) && !errors.Is(err, errs.ErrGenerationExhausted) {
					t.Fatalf("Peek: %v", err)
				}
				continue
			}
			st.write(t, must(t)(lt.Changes(lk)))
			if err := lt.Commit(lk); err != nil {
				t.Fatal(err)
			}
			st.matches(t, lt)
			if _, err := lt.Peek(1, k, gen); !errors.Is(err, errs.ErrReplay) {
				t.Fatalf("generation %d used twice: %v", gen, err)
			}
		}
		if _, err := lt.PeekNext(1, Application); err != nil && !errors.Is(err, errs.ErrGenerationExhausted) {
			t.Fatalf("PeekNext: %v", err)
		}
	})
}

// TestChangesRefusals: Changes refuses what Commit refuses, so a caller
// never writes the records of a lookup that cannot be committed.
func TestChangesRefusals(t *testing.T) {
	tr, other := mustNew(t, 4, Options{}), mustNew(t, 4, Options{})
	a, _ := tr.Peek(0, Application, 0)
	b, _ := tr.Peek(1, Application, 0)
	c, _ := other.Peek(0, Application, 0)
	if _, err := tr.Changes(c); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("lookup of another tree: %v", err)
	}
	if err := tr.Commit(a); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Changes(b); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("stale lookup: %v", err)
	}
	if _, err := tr.Changes(a); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("used lookup: %v", err)
	}
}

// TestOptionsBound: a bound above MaxBound is refused, MaxBound itself is
// accepted.
func TestOptionsBound(t *testing.T) {
	for _, o := range []Options{{MaxForwardDistance: MaxBound + 1}, {OutOfOrderTolerance: MaxBound + 1}} {
		if _, err := New(secret(1), 2, o); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Fatalf("%+v: %v", o, err)
		}
		if _, _, err := Load(2, o, recordMap{}.get); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Fatalf("Load %+v: %v", o, err)
		}
	}
	if _, err := New(secret(1), 2, Options{MaxForwardDistance: MaxBound, OutOfOrderTolerance: MaxBound}); err != nil {
		t.Fatal(err)
	}
}

// TestLoadPrunes: a tree stored with a wider window and loaded with a
// smaller one drops the held keys outside it and returns their leaf records.
func TestLoadPrunes(t *testing.T) {
	tr := mustNew(t, 2, Options{OutOfOrderTolerance: 8})
	if _, _, err := tr.Key(1, Application, 6); err != nil {
		t.Fatal(err)
	}
	st := recordMap{}
	st.write(t, must(t)(tr.Records()))
	lt, rewrite, err := Load(2, Options{OutOfOrderTolerance: 3}, st.get)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(lt.leaves[1].r[Application].held); got != 2 || len(rewrite) != 1 || !rewrite[0].Leaf || rewrite[0].Index != 1 {
		t.Fatalf("%d held keys kept, %d records to rewrite", got, len(rewrite))
	}
	st.write(t, rewrite)
	st.matches(t, lt)
	if _, _, err := lt.Key(1, Application, 3); !errors.Is(err, errs.ErrTooOld) {
		t.Fatalf("pruned generation: %v", err)
	}
	if _, rewrite, _ := Load(2, Options{OutOfOrderTolerance: 3}, st.get); len(rewrite) != 0 {
		t.Fatal("a second Load rewrites again")
	}
}
