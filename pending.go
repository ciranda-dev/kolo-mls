package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"maps"
	"slices"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// PendingCommit is this member's Commit, stored apart from the group's state
// until ApplyPending or DiscardPending (RFC 9420 section 14).
type PendingCommit struct {
	commit  []byte
	welcome []byte
	next    *state
}

// Commit returns the Commit as an encoded MLSMessage.
func (pc *PendingCommit) Commit() []byte {
	return bytes.Clone(pc.commit)
}

// Welcome returns the Welcome for the added members as an encoded
// MLSMessage, nil when the Commit adds nobody.
func (pc *PendingCommit) Welcome() []byte {
	return bytes.Clone(pc.welcome)
}

// GroupContext returns the encoded GroupContext of the epoch the Commit starts.
func (pc *PendingCommit) GroupContext() []byte {
	return bytes.Clone(pc.next.ctxBytes)
}

// RatchetTree returns the encoded ratchet tree of the epoch the Commit starts,
// for a Welcome whose tree goes out of band (RFC 9420 section 12.4.3.3).
func (pc *PendingCommit) RatchetTree() ([]byte, error) {
	return pc.next.tree.Marshal()
}

// PendingLeaves returns copies of the leaves that the pending Commit adds
// or replaces, nil when there is no pending Commit.
func (g *Group) PendingLeaves() []*LeafNode {
	pc := g.pending
	if pc == nil {
		return nil
	}
	var out []*LeafNode
	for _, x := range pc.next.tree.NonBlank() {
		if x%2 != 0 {
			continue
		}
		// A stored pending Commit is decoded apart from the state, so leaves
		// are compared by their signatures.
		l := uint32(x / 2)
		n, old := pc.next.tree.Leaf(l), g.s.tree.Leaf(l)
		if old == nil || !bytes.Equal(n.Signature, old.Signature) {
			out = append(out, n.Clone())
		}
	}
	return out
}

// Pending returns the stored pending Commit, nil when there is none.
func (g *Group) Pending() *PendingCommit {
	return g.pending
}

// marshal encodes pc for the Store as changes to the current state base.
func (pc *PendingCommit) marshal(base *state) ([]byte, error) {
	n := pc.next
	var w tls.Writer
	w.U8(stateVersion)
	w.Opaque(pc.commit)
	w.Opaque(pc.welcome)
	n.ctx.Write(&w)
	w.Opaque(n.interim)
	w.U32(n.own())
	w.U64(n.tree.Width())
	w.Vector(func(w *tls.Writer) {
		for _, x := range changedNodes(base, n) {
			// Nodes past the new width are dropped when the record is read.
			if x < n.tree.Width() {
				w.U64(x)
				n.tree.Node(x).Write(w)
			}
		}
	})
	w.Vector(func(w *tls.Writer) {
		for _, x := range slices.Sorted(maps.Keys(n.priv.Keys)) {
			w.U64(x)
			w.Opaque(n.priv.Keys[x])
		}
	})
	seed := n.sig.Seed()
	w.Opaque(seed)
	clear(seed)
	writeSecrets(&w, n.secrets, true)
	writePast(&w, n.past)
	return w.Bytes()
}

func loadPending(base *state, b []byte) (*PendingCommit, error) {
	pc := &PendingCommit{}
	n := &state{priv: &tree.Private{Keys: map[uint64][]byte{}}}
	nodes := map[uint64]tree.Node{}
	for _, x := range base.tree.NonBlank() {
		nodes[x] = base.tree.Node(x)
	}
	var width uint64
	err := tls.Decode(b, func(r *tls.Reader) error {
		v, err := r.U8()
		if err != nil {
			return err
		}
		if v != stateVersion {
			return fmt.Errorf("%w: stored state version %d", errs.ErrUnsupported, v)
		}
		if pc.commit, err = r.Opaque(); err != nil {
			return err
		}
		if pc.welcome, err = r.Opaque(); err != nil {
			return err
		}
		if len(pc.welcome) == 0 {
			pc.welcome = nil
		}
		ctx, err := schedule.ReadGroupContext(r)
		if err != nil {
			return err
		}
		if err := n.setContext(ctx); err != nil {
			return err
		}
		if n.interim, err = r.Opaque(); err != nil {
			return err
		}
		if n.priv.Leaf, err = r.U32(); err != nil {
			return err
		}
		if width, err = r.U64(); err != nil {
			return err
		}
		err = r.Vector(func(r *tls.Reader) error {
			x, err := r.U64()
			if err != nil {
				return err
			}
			node, err := tree.ReadNode(r, x)
			if err != nil {
				return err
			}
			if node.Blank() {
				delete(nodes, x)
			} else {
				nodes[x] = node
			}
			return nil
		})
		if err != nil {
			return err
		}
		err = r.Vector(func(r *tls.Reader) error {
			x, err := r.U64()
			if err != nil {
				return err
			}
			n.priv.Keys[x], err = r.Opaque()
			return err
		})
		if err != nil {
			return err
		}
		seed, err := r.Opaque()
		if err != nil {
			return err
		}
		if len(seed) != ed25519.SeedSize {
			return fmt.Errorf("%w: stored signature key", errs.ErrMalformed)
		}
		n.sig = ed25519.NewKeyFromSeed(seed)
		clear(seed)
		if n.secrets, err = readSecrets(r, true); err != nil {
			return err
		}
		n.past, err = readPast(r)
		return err
	})
	if err != nil {
		n.clear()
		return nil, err
	}
	for x := range nodes {
		if x >= width {
			delete(nodes, x)
		}
	}
	if n.tree, err = tree.FromNodes(width, nodes); err != nil {
		n.clear()
		return nil, err
	}
	pc.next = n
	return pc, nil
}
