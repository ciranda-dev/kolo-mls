package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

type state struct {
	ctx      *GroupContext
	ctxBytes []byte
	tree     *tree.Tree
	priv     *tree.Private
	sig      ed25519.PrivateKey
	// secrets are those of the epoch that are kept (RFC 9420 section 9.2);
	// the confirmation key is cleared once used, and encryption_secret once
	// keys starts from it.
	secrets *schedule.Secrets
	// keys is the epoch's secret tree, nil until the epoch is current.
	keys    *secrettree.Tree
	interim []byte
	// past holds the resumption PSKs of past epochs, newest first.
	past []pastPSK
}

type pastPSK struct {
	epoch uint64
	psk   []byte
}

// nextPast returns the past resumption PSKs of the epoch after s, keeping keep.
func (s *state) nextPast(keep int) []pastPSK {
	if keep <= 0 {
		return nil
	}
	out := []pastPSK{{epoch: s.ctx.Epoch, psk: bytes.Clone(s.secrets.Resumption)}}
	for _, p := range s.past {
		if len(out) == keep {
			break
		}
		out = append(out, pastPSK{epoch: p.epoch, psk: bytes.Clone(p.psk)})
	}
	return out
}

// startKeys starts the secret tree of s from encryption_secret, which it
// deletes (RFC 9420 section 9.2); it does nothing once started.
func (s *state) startKeys(o secrettree.Options) error {
	if s.keys != nil {
		return nil
	}
	k, err := secrettree.New(s.secrets.Encryption, uint32(s.tree.Leaves()), o)
	if err != nil {
		return err
	}
	clear(s.secrets.Encryption)
	s.secrets.Encryption = nil
	s.keys = k
	return nil
}

func (s *state) own() uint32 {
	return s.priv.Leaf
}

func (s *state) setContext(ctx *GroupContext) error {
	b, err := ctx.Marshal()
	if err != nil {
		return err
	}
	s.ctx, s.ctxBytes = ctx, b
	return nil
}

func (s *state) clear() {
	if s == nil {
		return
	}
	if s.priv != nil {
		s.priv.Clear()
	}
	clear(s.sig)
	if s.secrets != nil {
		s.secrets.Clear()
	}
	if s.keys != nil {
		s.keys.Clear()
	}
	for _, p := range s.past {
		clear(p.psk)
	}
}

// Store keys, namespaced by the hex group id.
func groupKey(gid []byte, name string) []byte {
	return []byte("g/" + hex.EncodeToString(gid) + "/" + name)
}

func nodeKey(gid []byte, x uint64) []byte {
	return groupKey(gid, "node/"+strconv.FormatUint(x, 10))
}

func privKey(gid []byte, x uint64) []byte {
	return groupKey(gid, "priv/"+strconv.FormatUint(x, 10))
}

func epochKey(gid []byte, epoch uint64) []byte {
	return groupKey(gid, "epoch/"+strconv.FormatUint(epoch, 10))
}

func secretKey(gid []byte, epoch uint64, r secrettree.Record) []byte {
	kind := "/node/"
	if r.Leaf {
		kind = "/leaf/"
	}
	return groupKey(gid, "epoch/"+strconv.FormatUint(epoch, 10)+kind+strconv.FormatUint(r.Index, 10))
}

func writeKeys(b *Batch, gid []byte, epoch uint64, rs []secrettree.Record) {
	for _, r := range rs {
		if r.Value == nil {
			b.del(secretKey(gid, epoch, r))
		} else {
			b.put(secretKey(gid, epoch, r), r.Value)
		}
	}
}

// deleteKeys adds to b the deletion of every record of the secret tree k of
// epoch.
func deleteKeys(b *Batch, gid []byte, epoch uint64, k *secrettree.Tree) error {
	if k == nil {
		return nil
	}
	rs, err := k.Records()
	if err != nil {
		return err
	}
	for _, r := range rs {
		clear(r.Value)
		b.del(secretKey(gid, epoch, r))
	}
	return nil
}

func propKey(gid, ref []byte) []byte {
	return groupKey(gid, "prop/"+hex.EncodeToString(ref))
}

func keyPackageKey(ref []byte) []byte {
	return []byte("kp/" + hex.EncodeToString(ref))
}

const stateVersion uint8 = 0

// writeSecrets writes the kept secrets of an epoch; encryption_secret only
// for an epoch whose secret tree has not started (a pending Commit).
func writeSecrets(w *tls.Writer, s *schedule.Secrets, encryption bool) {
	for _, v := range secretList(s, encryption) {
		w.Opaque(*v)
	}
}

func secretList(s *schedule.Secrets, encryption bool) []*[]byte {
	l := []*[]byte{&s.SenderData, &s.Exporter, &s.Membership, &s.Resumption, &s.EpochAuthenticator, &s.Init}
	if encryption {
		l = append(l, &s.Encryption)
	}
	return l
}

func readSecrets(r *tls.Reader, encryption bool) (*schedule.Secrets, error) {
	var s schedule.Secrets
	for _, v := range secretList(&s, encryption) {
		b, err := r.Opaque()
		if err != nil {
			s.Clear()
			return nil, err
		}
		*v = b
		if len(b) != suite.Nh {
			s.Clear()
			return nil, fmt.Errorf("%w: stored secret of %d bytes", errs.ErrMalformed, len(b))
		}
	}
	return &s, nil
}

func writePast(w *tls.Writer, past []pastPSK) {
	w.Vector(func(w *tls.Writer) {
		for _, p := range past {
			w.U64(p.epoch)
			w.Opaque(p.psk)
		}
	})
}

func readPast(r *tls.Reader) ([]pastPSK, error) {
	var out []pastPSK
	err := r.Vector(func(r *tls.Reader) error {
		var p pastPSK
		var err error
		if p.epoch, err = r.U64(); err != nil {
			return err
		}
		p.psk, err = r.Opaque()
		out = append(out, p)
		return err
	})
	return out, err
}

func unmarshalEpoch(b []byte) (s *schedule.Secrets, past []pastPSK, err error) {
	err = tls.Decode(b, func(r *tls.Reader) (err error) {
		if s, err = readSecrets(r, false); err != nil {
			return err
		}
		past, err = readPast(r)
		return err
	})
	if err != nil {
		if s != nil {
			s.Clear()
		}
		for _, p := range past {
			clear(p.psk)
		}
		return nil, nil, err
	}
	return s, past, nil
}

// meta is the record that names everything else of a group in the Store.
type meta struct {
	ctx     *GroupContext
	interim []byte
	own     uint32
	width   uint64
	privs   []uint64
	props   [][]byte
}

func (m *meta) marshal() ([]byte, error) {
	var w tls.Writer
	w.U8(stateVersion)
	m.ctx.Write(&w)
	w.Opaque(m.interim)
	w.U32(m.own)
	w.U64(m.width)
	w.Vector(func(w *tls.Writer) {
		for _, x := range m.privs {
			w.U64(x)
		}
	})
	w.Vector(func(w *tls.Writer) {
		for _, r := range m.props {
			w.Opaque(r)
		}
	})
	return w.Bytes()
}

func unmarshalMeta(b []byte) (*meta, error) {
	var m meta
	err := tls.Decode(b, func(r *tls.Reader) error {
		v, err := r.U8()
		if err != nil {
			return err
		}
		if v != stateVersion {
			return fmt.Errorf("%w: stored state version %d", errs.ErrUnsupported, v)
		}
		if m.ctx, err = schedule.ReadGroupContext(r); err != nil {
			return err
		}
		if m.interim, err = r.Opaque(); err != nil {
			return err
		}
		if m.own, err = r.U32(); err != nil {
			return err
		}
		if m.width, err = r.U64(); err != nil {
			return err
		}
		err = r.Vector(func(r *tls.Reader) error {
			x, err := r.U64()
			m.privs = append(m.privs, x)
			return err
		})
		if err != nil {
			return err
		}
		return r.Vector(func(r *tls.Reader) error {
			ref, err := r.Opaque()
			m.props = append(m.props, ref)
			return err
		})
	})
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (b *Batch) put(key, value []byte) {
	b.Put = append(b.Put, KV{Key: key, Value: value})
}

func (b *Batch) del(key []byte) {
	b.Delete = append(b.Delete, key)
}

func marshalNode(n tree.Node) ([]byte, error) {
	var w tls.Writer
	n.Write(&w)
	return w.Bytes()
}

// writeState adds to b the writes that turn the stored state old (nil for
// none) into next, with the cached proposals props; replaced secrets are
// deleted in the same batch (RFC 9420 section 9.2), except the old secret
// tree, which the caller deletes or keeps for the previous-epoch window.
func writeState(b *Batch, old, next *state, props []*cached) error {
	gid := next.ctx.GroupID
	if err := writeMeta(b, next, props); err != nil {
		return err
	}

	var w tls.Writer
	writeSecrets(&w, next.secrets, false)
	writePast(&w, next.past)
	sb, err := w.Bytes()
	if err != nil {
		return err
	}
	b.put(epochKey(gid, next.ctx.Epoch), sb)
	if old != nil && old.ctx.Epoch != next.ctx.Epoch {
		b.del(epochKey(gid, old.ctx.Epoch))
	}
	if old == nil || old.ctx.Epoch != next.ctx.Epoch {
		rs, err := next.keys.Records()
		if err != nil {
			return err
		}
		writeKeys(b, gid, next.ctx.Epoch, rs)
	}
	if old == nil || !bytes.Equal(old.sig, next.sig) {
		b.put(groupKey(gid, "sig"), next.sig.Seed())
	}

	nb := next.tree.NonBlank()
	if old == nil || !slices.Equal(nb, old.tree.NonBlank()) {
		b.put(groupKey(gid, "index"), marshalIndex(nb))
	}
	for _, x := range changedNodes(old, next) {
		n := nodeAt(next.tree, x)
		if n.Blank() {
			b.del(nodeKey(gid, x))
			continue
		}
		nb, err := marshalNode(n)
		if err != nil {
			return err
		}
		b.put(nodeKey(gid, x), nb)
	}

	for x, k := range next.priv.Keys {
		if old != nil && bytes.Equal(old.priv.Keys[x], k) {
			continue
		}
		b.put(privKey(gid, x), bytes.Clone(k))
	}
	if old != nil {
		for x := range old.priv.Keys {
			if next.priv.Keys[x] == nil {
				b.del(privKey(gid, x))
			}
		}
	}
	return nil
}

// nodeAt returns node x of t, blank past its width.
func nodeAt(t *tree.Tree, x uint64) tree.Node {
	if x >= t.Width() {
		return tree.Node{}
	}
	return t.Node(x)
}

// changedNodes returns, in increasing order, the nodes that differ between
// the trees of old (nil for none) and next, a node of old past the width of
// next included. Nodes are never changed in place, so a changed node has a
// new pointer.
func changedNodes(old, next *state) []uint64 {
	xs := next.tree.NonBlank()
	if old != nil {
		xs = append(slices.Clone(xs), old.tree.NonBlank()...)
		slices.Sort(xs)
		xs = slices.Compact(xs)
	}
	out := xs[:0]
	for _, x := range xs {
		if old != nil {
			o, n := nodeAt(old.tree, x), nodeAt(next.tree, x)
			if o.Leaf == n.Leaf && o.Parent == n.Parent {
				continue
			}
		}
		out = append(out, x)
	}
	return out
}

func writeMeta(b *Batch, s *state, props []*cached) error {
	m := meta{ctx: s.ctx, interim: s.interim, own: s.own(), width: s.tree.Width(), privs: slices.Sorted(maps.Keys(s.priv.Keys))}
	for _, c := range props {
		m.props = append(m.props, c.ref)
	}
	mb, err := m.marshal()
	if err != nil {
		return err
	}
	b.put(groupKey(s.ctx.GroupID, "meta"), mb)
	return nil
}

// writeProps adds the writes of the proposal cache to b: props replaces
// old, and records in neither are untouched.
func writeProps(b *Batch, gid []byte, old, props []*cached) error {
	keep := map[string]bool{}
	for _, c := range props {
		keep[string(c.ref)] = true
	}
	for _, c := range old {
		if !keep[string(c.ref)] {
			b.del(propKey(gid, c.ref))
		}
	}
	had := map[string]bool{}
	for _, c := range old {
		had[string(c.ref)] = true
	}
	for _, c := range props {
		if had[string(c.ref)] {
			continue
		}
		v, err := c.marshal()
		if err != nil {
			return err
		}
		b.put(propKey(gid, c.ref), v)
	}
	return nil
}

// get reads the value of key, a copy the Store hands over, mapping a Store
// error to ErrStore.
func get(st Store, key []byte) ([]byte, error) {
	v, err := st.Get(key)
	if errors.Is(err, errs.ErrNotFound) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errs.ErrStore, err)
	}
	return v, nil
}

// getRecord reads a record that the group's meta record implies; a missing
// one means the stored state is incomplete.
func getRecord(st Store, key []byte) ([]byte, error) {
	v, err := get(st, key)
	if errors.Is(err, errs.ErrNotFound) {
		return nil, fmt.Errorf("%w: stored state incomplete", errs.ErrMalformed)
	}
	return v, err
}

// writeBatch applies b to st and then zeroes its values, which hold
// secrets.
func writeBatch(st Store, b Batch) error {
	err := st.Apply(b)
	b.zero()
	if err != nil {
		return fmt.Errorf("%w: %w", errs.ErrStore, err)
	}
	return nil
}

// loadState reads the state of group gid from st, with the secret tree
// records that pruning to the window of o changed, to be written back.
func loadState(st Store, gid []byte, o secrettree.Options) (s *state, m *meta, pruned []secrettree.Record, err error) {
	mb, err := get(st, groupKey(gid, "meta"))
	if err != nil {
		return nil, nil, nil, err
	}
	m, err = unmarshalMeta(mb)
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(m.ctx.GroupID, gid) {
		return nil, nil, nil, fmt.Errorf("%w: stored group id differs", errs.ErrMalformed)
	}
	s = &state{interim: m.interim}
	defer func() {
		if err != nil {
			s.clear()
		}
	}()
	if err := s.setContext(m.ctx); err != nil {
		return nil, nil, nil, err
	}
	sb, err := getRecord(st, epochKey(gid, m.ctx.Epoch))
	if err != nil {
		return nil, nil, nil, err
	}
	s.secrets, s.past, err = unmarshalEpoch(sb)
	clear(sb)
	if err != nil {
		return nil, nil, nil, err
	}
	seed, err := getRecord(st, groupKey(gid, "sig"))
	if err != nil {
		return nil, nil, nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, nil, nil, fmt.Errorf("%w: stored signature key", errs.ErrMalformed)
	}
	s.sig = ed25519.NewKeyFromSeed(seed)
	clear(seed)
	if s.tree, err = loadTree(st, gid, m.width); err != nil {
		return nil, nil, nil, err
	}
	s.priv = &tree.Private{Leaf: m.own, Keys: map[uint64][]byte{}}
	for _, x := range m.privs {
		k, err := getRecord(st, privKey(gid, x))
		if err != nil {
			return nil, nil, nil, err
		}
		s.priv.Keys[x] = k
	}
	s.keys, pruned, err = secrettree.Load(uint32(s.tree.Leaves()), o, func(leaf bool, x uint64) ([]byte, error) {
		return get(st, secretKey(gid, m.ctx.Epoch, secrettree.Record{Leaf: leaf, Index: x}))
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return s, m, pruned, nil
}

// marshalIndex encodes the non-blank node indices xs, increasing, as runs
// of consecutive indices: a dense tree is one run, and a hostile sparse one
// costs a record per non-blank node, not per blank one.
func marshalIndex(xs []uint64) []byte {
	var w tls.Writer
	w.Vector(func(w *tls.Writer) {
		for i := 0; i < len(xs); {
			j := i + 1
			for j < len(xs) && xs[j] == xs[j-1]+1 {
				j++
			}
			w.U64(xs[i])
			w.U64(uint64(j - i))
			i = j
		}
	})
	b, _ := w.Bytes()
	return b
}

func unmarshalIndex(b []byte, width uint64) ([]uint64, error) {
	var xs []uint64
	err := tls.Decode(b, func(r *tls.Reader) error {
		return r.Vector(func(r *tls.Reader) error {
			start, err := r.U64()
			if err != nil {
				return err
			}
			n, err := r.U64()
			if err != nil {
				return err
			}
			if n == 0 || start >= width || n > width-start || (len(xs) > 0 && start <= xs[len(xs)-1]) {
				return fmt.Errorf("%w: stored node index", errs.ErrMalformed)
			}
			for x := start; x < start+n; x++ {
				xs = append(xs, x)
			}
			return nil
		})
	})
	return xs, err
}

func loadTree(st Store, gid []byte, width uint64) (*tree.Tree, error) {
	if _, err := tree.FromNodes(width, nil); err != nil {
		return nil, err
	}
	ib, err := getRecord(st, groupKey(gid, "index"))
	if err != nil {
		return nil, err
	}
	xs, err := unmarshalIndex(ib, width)
	if err != nil {
		return nil, err
	}
	nodes := make(map[uint64]tree.Node, len(xs))
	for _, x := range xs {
		b, err := getRecord(st, nodeKey(gid, x))
		if err != nil {
			return nil, err
		}
		var n tree.Node
		err = tls.Decode(b, func(r *tls.Reader) (err error) {
			n, err = tree.ReadNode(r, x)
			return err
		})
		if err != nil {
			return nil, err
		}
		nodes[x] = n
	}
	return tree.FromNodes(width, nodes)
}

// deleteGroup adds to b the deletion of every record of the stored state s
// with its previous epoch, proposals and pending Commit.
func deleteGroup(b *Batch, s *state, prev *past, props []*cached) error {
	gid := s.ctx.GroupID
	if err := deleteKeys(b, gid, s.ctx.Epoch, s.keys); err != nil {
		return err
	}
	if err := writePastDelete(b, gid, prev, false); err != nil {
		return err
	}
	for _, name := range []string{"meta", "sig", "pending", "index"} {
		b.del(groupKey(gid, name))
	}
	b.del(epochKey(gid, s.ctx.Epoch))
	for _, x := range s.tree.NonBlank() {
		b.del(nodeKey(gid, x))
	}
	for x := range s.priv.Keys {
		b.del(privKey(gid, x))
	}
	for _, c := range props {
		b.del(propKey(gid, c.ref))
	}
	return nil
}
