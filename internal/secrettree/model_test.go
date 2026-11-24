package secrettree

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
)

// model is the receiver rule of RFC 9420 section 15.3 as a plain set of used
// generations per ratchet, with no keys.
type model struct {
	n       uint64
	tol, d  uint32
	heads   map[[2]uint64]uint32
	used    map[[3]uint64]bool
	cleared bool
}

func newModel(n uint32, o Options) *model {
	if o.MaxForwardDistance == 0 {
		o.MaxForwardDistance = 1000
	}
	if o.OutOfOrderTolerance == 0 {
		o.OutOfOrderTolerance = 5
	}
	return &model{n: uint64(n), tol: o.OutOfOrderTolerance, d: o.MaxForwardDistance,
		heads: map[[2]uint64]uint32{}, used: map[[3]uint64]bool{}}
}

func (m *model) check(l uint32, k Kind) error {
	if m.cleared || uint64(l) >= m.n || (k != Handshake && k != Application) {
		return errs.ErrInvalidArgument
	}
	return nil
}

func (m *model) next(l uint32, k Kind) (uint32, error) {
	if err := m.check(l, k); err != nil {
		return 0, err
	}
	id := [2]uint64{uint64(l), uint64(k)}
	h := m.heads[id]
	if h == math.MaxUint32 {
		return 0, errs.ErrGenerationExhausted
	}
	m.used[[3]uint64{uint64(l), uint64(k), uint64(h)}] = true
	m.heads[id] = h + 1
	return h, nil
}

func (m *model) key(l uint32, k Kind, g uint32) error {
	if err := m.check(l, k); err != nil {
		return err
	}
	id := [2]uint64{uint64(l), uint64(k)}
	u := [3]uint64{uint64(l), uint64(k), uint64(g)}
	h := m.heads[id]
	switch {
	case g < h && h-g > m.tol:
		return errs.ErrTooOld
	case g < h && m.used[u]:
		return errs.ErrReplay
	case g < h:
	case g-h > m.d:
		return errs.ErrTooFarAhead
	case g == math.MaxUint32:
		return errs.ErrGenerationExhausted
	default:
		m.heads[id] = g + 1
	}
	m.used[u] = true
	return nil
}

// TestSenderReceiverAgree sends random bursts with Next on one tree and
// delivers them shuffled and with losses to another: every outcome matches
// the model and every key matches the sender's and the oracle's.
func TestSenderReceiverAgree(t *testing.T) {
	for seed := range uint64(1000) {
		rng := rand.New(rand.NewPCG(seed, 1))
		n := uint32(1) << rng.IntN(9)
		root := make([]byte, 32)
		for i := range root {
			root[i] = byte(rng.Uint32())
		}
		opts := Options{OutOfOrderTolerance: 1 + rng.Uint32N(8), MaxForwardDistance: 1 + rng.Uint32N(40)}
		send, err := New(root, n, opts)
		if err != nil {
			t.Fatal(err)
		}
		recv, err := New(root, n, opts)
		if err != nil {
			t.Fatal(err)
		}
		m := newModel(n, opts)
		o := newOracle(root, n)
		type msg struct {
			gen        uint32
			key, nonce []byte
		}
		for range 1 + rng.IntN(6) {
			l, k := rng.Uint32N(n), Kind(rng.IntN(2))
			var burst []msg
			for range 1 + rng.IntN(30) {
				gen, key, nonce, err := send.Next(l, k)
				if err != nil {
					t.Fatalf("seed %d: Next: %v", seed, err)
				}
				burst = append(burst, msg{gen, key, nonce})
			}
			if seed%4 != 0 {
				rng.Shuffle(len(burst), func(i, j int) { burst[i], burst[j] = burst[j], burst[i] })
			}
			for _, b := range burst {
				if rng.IntN(5) == 0 {
					continue
				}
				replay := rng.IntN(8) == 0
				for range 1 + btoi(replay) {
					want := m.key(l, k, b.gen)
					key, nonce, err := recv.Key(l, k, b.gen)
					if !sameOutcome(err, want) {
						t.Fatalf("seed %d leaf %d kind %d gen %d: got %v, model %v", seed, l, k, b.gen, err, want)
					}
					if err == nil && (!bytes.Equal(key, b.key) || !bytes.Equal(nonce, b.nonce)) {
						t.Fatalf("seed %d leaf %d kind %d gen %d: receiver and sender keys differ", seed, l, k, b.gen)
					}
				}
				if seed%16 == 0 {
					wk, wn := o.key(t, l, k, b.gen)
					if !bytes.Equal(b.key, wk) || !bytes.Equal(b.nonce, wn) {
						t.Fatalf("seed %d: sender key differs from the oracle", seed)
					}
				}
			}
			if !staleFree(recv) || !windowed(recv) {
				t.Fatalf("seed %d: stale or out-of-window held keys", seed)
			}
		}
	}
}

// TestInOrderAlwaysAgrees delivers every generation in order: nothing is
// ever refused, whatever the bounds.
func TestInOrderAlwaysAgrees(t *testing.T) {
	for seed := range uint64(1000) {
		rng := rand.New(rand.NewPCG(seed, 2))
		n := uint32(1) << rng.IntN(12)
		root := make([]byte, 32)
		root[0], root[1] = byte(seed), byte(seed>>8)
		opts := Options{OutOfOrderTolerance: 1 + rng.Uint32N(3), MaxForwardDistance: 1 + rng.Uint32N(3)}
		send, _ := New(root, n, opts)
		recv, _ := New(root, n, opts)
		l, k := rng.Uint32N(n), Kind(rng.IntN(2))
		for range 1 + rng.IntN(20) {
			gen, key, nonce, err := send.Next(l, k)
			if err != nil {
				t.Fatal(err)
			}
			rk, rn, err := recv.Key(l, k, gen)
			if err != nil || !bytes.Equal(key, rk) || !bytes.Equal(nonce, rn) {
				t.Fatalf("seed %d gen %d: %v", seed, gen, err)
			}
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func sameOutcome(got, want error) bool {
	if want == nil {
		return got == nil
	}
	return errors.Is(got, want)
}

// run applies ops encoded in b to a tree and the model, compares them, and
// returns a transcript of the outcomes. Every change goes through Peek or
// PeekNext and Commit and its records into a map, which must always equal
// the tree's records; some ops peek and discard first, and some reload the
// tree from the map.
func run(tb testing.TB, b []byte) []byte {
	if len(b) < 3 {
		return nil
	}
	n := uint32(1) << (b[0] % 7)
	opts := Options{OutOfOrderTolerance: uint32(b[1] % 9), MaxForwardDistance: uint32(b[2] % 50)}
	root := bytes.Repeat([]byte{b[0] ^ b[1]}, 32)
	tr, err := New(root, n, opts)
	if err != nil {
		tb.Fatal(err)
	}
	m := newModel(n, opts)
	o := newOracle(root, n)
	st := recordMap{}
	st.write(tb, must(tb)(tr.Records()))
	commit := func(lk *Lookup) {
		st.write(tb, must(tb)(tr.Changes(lk)))
		if err := tr.Commit(lk); err != nil {
			tb.Fatal(err)
		}
	}
	var out bytes.Buffer
	for ops := b[3:]; len(ops) >= 4; ops = ops[4:] {
		l := uint32(ops[1]) % (n + 2)
		k := Kind(ops[2]%3) - Kind(btoi(ops[2] == 255))
		g := uint32(ops[3]) % 64
		if ops[0]&0x40 != 0 {
			g = math.MaxUint32 - uint32(ops[3]%4)
		}
		switch ops[0] % 8 {
		case 0, 1, 2:
			wantGen, want := m.next(l, k)
			var gen uint32
			var key, nonce []byte
			lk, err := tr.PeekNext(l, k)
			if err == nil {
				gen, key, nonce = lk.Generation(), lk.Key(), lk.Nonce()
				commit(lk)
				lk.Discard()
			}
			if !sameOutcome(err, want) || (err == nil && gen != wantGen) {
				tb.Fatalf("Next(%d, %d) = %d %v, model %d %v", l, k, gen, err, wantGen, want)
			}
			if err == nil {
				wk, wn := o.key(tb, l, k, gen)
				if !bytes.Equal(key, wk) || !bytes.Equal(nonce, wn) {
					tb.Fatalf("Next(%d, %d) gen %d: key differs", l, k, gen)
				}
			}
			fmt.Fprintf(&out, "N%d %x %x %v;", gen, key, nonce, err)
		case 7:
			switch {
			case ops[3] == 0:
				tr.Clear()
				m.cleared = true
				out.WriteString("C;")
			case ops[3]%2 == 1 && !m.cleared:
				if tr, _, err = Load(n, opts, st.get); err != nil {
					tb.Fatalf("Load: %v", err)
				}
				out.WriteString("L;")
			}
		default:
			if ops[0]&0x80 != 0 {
				if lk, err := tr.Peek(l, k, g); err == nil {
					lk.Discard()
				}
			}
			want := m.key(l, k, g)
			var key, nonce []byte
			lk, err := tr.Peek(l, k, g)
			if err == nil {
				key, nonce = lk.Key(), lk.Nonce()
				if lk.Generation() != g || lk.Leaf() != l || lk.Kind() != k {
					tb.Fatal("lookup names another ratchet")
				}
				commit(lk)
				lk.Discard()
			}
			if !sameOutcome(err, want) {
				tb.Fatalf("Key(%d, %d, %d) = %v, model %v", l, k, g, err, want)
			}
			if err == nil {
				wk, wn := o.key(tb, l, k, g)
				if !bytes.Equal(key, wk) || !bytes.Equal(nonce, wn) {
					tb.Fatalf("Key(%d, %d, %d): key differs", l, k, g)
				}
			}
			fmt.Fprintf(&out, "K%x %x %v;", key, nonce, err)
		}
		if !staleFree(tr) || !windowed(tr) {
			tb.Fatal("stale or out-of-window held keys")
		}
		if !m.cleared {
			st.matches(tb, tr)
		}
	}
	return out.Bytes()
}

func TestRandomOps(t *testing.T) {
	for seed := range uint64(1000) {
		rng := rand.New(rand.NewPCG(seed, 3))
		b := make([]byte, 3+4*rng.IntN(60))
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		run(t, b)
	}
}
