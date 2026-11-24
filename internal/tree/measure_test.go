package tree

import (
	"crypto/ed25519"
	"math/bits"
	"math/rand/v2"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// measureIDLen is the size of a Kolo credential body.
const measureIDLen = 581

type measureGroup struct {
	t    *testing.T
	tr   *Tree
	gid  []byte
	sigs []ed25519.PrivateKey
}

func (g *measureGroup) context(th []byte) ([]byte, error) {
	gc := schedule.GroupContext{CipherSuite: suite.ID, GroupID: g.gid, Epoch: 1, TreeHash: th}
	return gc.Marshal()
}

func heap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// fresh builds the tree of a group whose creator added n - 1 members in one
// Commit with a path: every leaf set, only the creator's direct path set.
func fresh(t *testing.T, n int) *measureGroup {
	w := uint64(1) << bits.Len64(uint64(n-1))
	g := &measureGroup{t: t, gid: make([]byte, 32), tr: &Tree{width: 2*w - 1, nodes: map[uint64]Node{}}, sigs: make([]ed25519.PrivateKey, n)}
	excluded := map[uint32]bool{}
	for l := range n {
		leaf, sig, _ := testLeaf(t, SourceKeyPackage, nil, 0, measureIDLen)
		g.tr.nodes[2*uint64(l)] = Node{Leaf: leaf}
		g.sigs[l] = sig
		if l > 0 {
			excluded[uint32(l)] = true
		}
	}
	if _, err := g.tr.CreatePath(0, nil, g.sigs[0], g.gid, excluded, g.context); err != nil {
		t.Fatal(err)
	}
	return g
}

// populate gives every parent a key the way self-update Commits by one leaf
// of every pair would, top subtrees first, without encrypting path secrets:
// only the public tree is needed.
func (g *measureGroup) populate() {
	t := g.t
	pairs := g.tr.Leaves() / 2
	k := bits.Len64(pairs - 1)
	for i := range pairs {
		l := uint32(2 * (bits.Reverse64(i) >> (64 - k)))
		if pairs == 1 {
			l = 0
		}
		if g.tr.Leaf(l) == nil {
			continue
		}
		path, copath, err := g.tr.FilteredDirectPath(l)
		if err != nil {
			t.Fatal(err)
		}
		keys := make([][]byte, len(path))
		for j := range keys {
			_, pub, err := suite.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			keys[j] = pub
		}
		ph, err := g.tr.setPath(l, path, copath, keys)
		if err != nil {
			t.Fatal(err)
		}
		leaf := g.tr.Leaf(l).Clone()
		_, leaf.EncryptionKey, _ = suite.GenerateKeyPair()
		leaf.Source, leaf.NotBefore, leaf.NotAfter, leaf.ParentHash = SourceCommit, 0, 0, ph
		if err := leaf.Sign(g.sigs[l], g.gid, l); err != nil {
			t.Fatal(err)
		}
		g.tr.set(2*uint64(l), Node{Leaf: leaf})
	}
}

// churn runs Commits that each remove one random member and add one new one.
func (g *measureGroup) churn(r *rand.Rand, commits int) {
	t := g.t
	for range commits {
		n := uint32(g.tr.Leaves())
		committer, victim := r.Uint32N(n), r.Uint32N(n)
		if committer == victim || g.tr.Leaf(committer) == nil || g.tr.Leaf(victim) == nil {
			continue
		}
		if err := g.tr.RemoveLeaf(victim); err != nil {
			t.Fatal(err)
		}
		leaf, sig, _ := testLeaf(t, SourceKeyPackage, nil, 0, measureIDLen)
		l, err := g.tr.AddLeaf(leaf)
		if err != nil {
			t.Fatal(err)
		}
		for uint32(len(g.sigs)) <= l {
			g.sigs = append(g.sigs, nil)
		}
		g.sigs[l] = sig
		if _, err := g.tr.CreatePath(committer, nil, g.sigs[committer], g.gid, map[uint32]bool{l: true}, g.context); err != nil {
			t.Fatal(err)
		}
	}
}

type measurement struct {
	treeBytes, heapBytes, commitBytes int
	join, commit, process             time.Duration
}

// measure times a joiner's decode and validation, one Commit with a path by
// member committer, and its processing by member receiver.
func (g *measureGroup) measure(committer, receiver uint32, base uint64) measurement {
	t := g.t
	var m measurement
	m.heapBytes = int(int64(heap()) - int64(base))
	enc, err := g.tr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	m.treeBytes = len(enc)

	start := time.Now()
	joined, err := UnmarshalTree(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := joined.Verify(g.gid); err != nil {
		t.Fatal(err)
	}
	if _, err := joined.TreeHash(); err != nil {
		t.Fatal(err)
	}
	m.join = time.Since(start)

	// The receiver's private state comes from its own Commit.
	before := g.tr.Clone()
	own, err := before.CreatePath(receiver, nil, g.sigs[receiver], g.gid, nil, g.context)
	if err != nil {
		t.Fatal(err)
	}
	sender := before.Clone()
	start = time.Now()
	p, err := sender.CreatePath(committer, nil, g.sigs[committer], g.gid, nil, g.context)
	if err != nil {
		t.Fatal(err)
	}
	m.commit = time.Since(start)
	var w tls.Writer
	p.UpdatePath.Write(&w)
	b, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	m.commitBytes = len(b)

	start = time.Now()
	recv := before.Clone()
	if err := recv.Merge(committer, p.UpdatePath); err != nil {
		t.Fatal(err)
	}
	th, err := recv.TreeHash()
	if err != nil {
		t.Fatal(err)
	}
	gc, _ := g.context(th)
	if _, _, _, err := recv.DecryptPath(committer, p.UpdatePath, nil, gc, own.Private); err != nil {
		t.Fatal(err)
	}
	m.process = time.Since(start)
	return m
}

// TestMeasure records tree size, memory and Commit and join cost for the
// leaf counts in KOLO_MLS_MEASURE (for example "64,1024,10000,100000").
func TestMeasure(t *testing.T) {
	spec := os.Getenv("KOLO_MLS_MEASURE")
	if spec == "" {
		t.Skip("set KOLO_MLS_MEASURE to a list of leaf counts to measure")
	}
	r := rand.New(rand.NewPCG(3, 4))
	for _, f := range strings.Split(spec, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 2 {
			t.Fatalf("bad leaf count %q", f)
		}
		base := heap()
		start := time.Now()
		g := fresh(t, n)
		built := time.Since(start)
		committer, receiver := uint32(n-1), uint32(n/2-1)
		m := g.measure(committer, receiver, base)
		report(t, n, "fresh", m, built)

		start = time.Now()
		g.populate()
		g.churn(r, 64)
		built = time.Since(start)
		for committer == receiver || g.tr.Leaf(committer) == nil || g.tr.Leaf(receiver) == nil {
			committer, receiver = r.Uint32N(uint32(g.tr.Leaves())), r.Uint32N(uint32(g.tr.Leaves()))
		}
		m = g.measure(committer, receiver, base)
		report(t, n, "churned", m, built)
		g = nil

		// Every parent set, then the second half of the leaves added without
		// a path: unmerged leaves on many parents, the costliest valid shape
		// for parent-hash validation (RFC 9420 section 7.9.2).
		u := fresh(t, n/2+1)
		u.populate()
		var leaves []*LeafNode
		for range n - n/2 - 1 {
			leaf, _, _ := testLeaf(t, SourceKeyPackage, nil, 0, measureIDLen)
			leaves = append(leaves, leaf)
		}
		if _, err := u.tr.AddLeaves(leaves); err != nil {
			t.Fatal(err)
		}
		enc, err := u.tr.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		start = time.Now()
		joined, err := UnmarshalTree(enc)
		if err != nil {
			t.Fatal(err)
		}
		if err := joined.Verify(u.gid); err != nil {
			t.Fatal(err)
		}
		t.Logf("leaves=%d state=unmerged tree_bytes=%d join=%v", n, len(enc), time.Since(start).Round(time.Microsecond))
	}
}

// hostileTree encodes a ratchet_tree of n nodes, node x written by node or
// blank when it returns false, then one leaf, so the last node is non-blank.
func hostileTree(t *testing.T, n int, node func(w *tls.Writer, x int) bool) []byte {
	leaf, _, _ := testLeaf(t, SourceKeyPackage, nil, 0, measureIDLen)
	var w tls.Writer
	w.Vector(func(w *tls.Writer) {
		for x := range n - 1 {
			if !node(w, x) {
				w.U8(0)
			}
		}
		w.U8(1)
		w.U8(nodeLeaf)
		leaf.Write(w)
	})
	in, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// smallLeaf writes the smallest leaf ReadTree accepts, with the given
// credential and extensions.
func smallLeaf(w *tls.Writer, cred func(w *tls.Writer), exts func(w *tls.Writer)) {
	w.U8(1)
	w.U8(nodeLeaf)
	w.Opaque(make([]byte, 32))
	w.Opaque(make([]byte, 32))
	cred(w)
	for range 5 {
		w.Opaque(nil)
	}
	w.U8(SourceUpdate)
	exts(w)
	w.Opaque(make([]byte, 64))
}

func basicEmpty(w *tls.Writer) { w.U16(CredentialBasic); w.Opaque(nil) }
func noExts(w *tls.Writer)     { w.Opaque(nil) }

// TestMeasureHostileTrees records the memory a joiner spends per input byte
// on hostile ratchet_tree shapes after decoding and hashing them: retained
// heap and all bytes allocated on the way.
func TestMeasureHostileTrees(t *testing.T) {
	if os.Getenv("KOLO_MLS_MEASURE") == "" {
		t.Skip("set KOLO_MLS_MEASURE to measure")
	}
	const n = 1<<20 - 1
	for _, c := range []struct {
		name string
		node func(w *tls.Writer, x int) bool
	}{
		{"all blank", func(*tls.Writer, int) bool { return false }},
		{"smallest leaves", func(w *tls.Writer, x int) bool {
			if x%2 == 1 {
				return false
			}
			smallLeaf(w, basicEmpty, noExts)
			return true
		}},
		{"smallest parents", func(w *tls.Writer, x int) bool {
			if x%2 == 0 {
				return false
			}
			w.U8(1)
			w.U8(nodeParent)
			w.Opaque(make([]byte, 32))
			w.Opaque(nil)
			w.Opaque(nil)
			return true
		}},
		{"leaves with 4096 empty extensions", func(w *tls.Writer, x int) bool {
			if x%2 == 1 || x > 2*256 {
				return false
			}
			smallLeaf(w, basicEmpty, func(w *tls.Writer) {
				w.Vector(func(w *tls.Writer) {
					for e := range 4096 {
						w.U16(uint16(e))
						w.Opaque(nil)
					}
				})
			})
			return true
		}},
		{"x509 leaves with 65536 empty certificates", func(w *tls.Writer, x int) bool {
			if x%2 == 1 || x > 2*16 {
				return false
			}
			smallLeaf(w, func(w *tls.Writer) {
				w.U16(CredentialX509)
				w.Vector(func(w *tls.Writer) {
					for range 65536 {
						w.Opaque(nil)
					}
				})
			}, noExts)
			return true
		}},
		{"parents with long unmerged lists", func(w *tls.Writer, x int) bool {
			if x%2 == 0 || x > 64 {
				return false
			}
			w.U8(1)
			w.U8(nodeParent)
			w.Opaque(make([]byte, 32))
			w.Opaque(nil)
			w.Vector(func(w *tls.Writer) {
				for u := range 1 << 16 {
					w.U32(uint32(u))
				}
			})
			return true
		}},
	} {
		in := hostileTree(t, n, c.node)
		var before runtime.MemStats
		base := heap()
		runtime.ReadMemStats(&before)
		start := time.Now()
		tr, err := UnmarshalTree(in)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tr.TreeHash(); err != nil {
			t.Fatal(err)
		}
		took := time.Since(start)
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		alloc := after.TotalAlloc - before.TotalAlloc
		used := int64(heap()) - int64(base)
		t.Logf("%s: input_bytes=%d stored_nodes=%d width=%d heap_bytes=%d heap_per_input_byte=%.1f allocated_bytes=%d allocated_per_input_byte=%.1f decode_and_hash=%v",
			c.name, len(in), len(tr.nodes), tr.Width(), used, float64(used)/float64(len(in)), alloc, float64(alloc)/float64(len(in)), took.Round(time.Millisecond))
		// docs/limits.md states about 7 bytes of memory per byte received.
		if float64(used)/float64(len(in)) > 8 {
			t.Errorf("%s: %.1f bytes of memory per input byte, above 8", c.name, float64(used)/float64(len(in)))
		}
		runtime.KeepAlive(tr)
	}
}

func report(t *testing.T, n int, state string, m measurement, built time.Duration) {
	t.Logf("leaves=%d state=%s tree_bytes=%d bytes_per_leaf=%d heap_bytes=%d heap_per_leaf=%d join=%v commit=%v commit_bytes=%d process=%v build=%v",
		n, state, m.treeBytes, m.treeBytes/n, m.heapBytes, m.heapBytes/n, m.join.Round(time.Microsecond), m.commit.Round(time.Microsecond), m.commitBytes, m.process.Round(time.Microsecond), built.Round(time.Millisecond))
}
