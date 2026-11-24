package kolomls

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/framing"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// DefaultPastEpochWindow is how long the previous epoch stays readable for
// late application messages after a Commit is applied.
const DefaultPastEpochWindow = 10 * time.Second

// past is the previous epoch, kept for late application messages until end
// (RFC 9420 section 12.4.2: "A client might keep the secret tree for a short
// time to decrypt late messages in the previous epoch").
type past struct {
	epoch      uint64
	end        time.Time
	ctxBytes   []byte
	senderData []byte
	leaves     uint32
	// gone are the leaves of the old epoch whose client is not a member
	// after the Commit; sigs the old signature keys of leaves that changed.
	gone map[uint32]bool
	sigs map[uint32][]byte
	keys *secrettree.Tree
}

func (p *past) clear() {
	if p == nil {
		return
	}
	clear(p.senderData)
	if p.keys != nil {
		p.keys.Clear()
	}
}

// member reports whether old-epoch messages of leaf l are read: its client
// is still a member, at the same leaf.
func (p *past) member(cur *state) func(uint32) bool {
	return func(l uint32) bool {
		return l < p.leaves && !p.gone[l] && cur.tree.Leaf(l) != nil
	}
}

func (p *past) signatureKey(cur *state, l uint32) []byte {
	if k, ok := p.sigs[l]; ok {
		return k
	}
	return cur.tree.Leaf(l).SignatureKey
}

func (c *Config) pastWindow() time.Duration {
	if c.PastEpochWindow == 0 {
		return DefaultPastEpochWindow
	}
	return c.PastEpochWindow
}

// newPast describes the epoch of old for the window after next replaces it,
// nil when the window is off. The secret tree is attached once the change is
// written.
func (g *Group) newPast(old, next *state) (*past, error) {
	w := g.cfg.pastWindow()
	if w <= 0 || old.keys == nil {
		return nil, nil
	}
	p := &past{
		epoch:      old.ctx.Epoch,
		end:        g.cfg.now().Add(w),
		ctxBytes:   bytes.Clone(old.ctxBytes),
		senderData: bytes.Clone(old.secrets.SenderData),
		leaves:     uint32(old.tree.Leaves()),
		gone:       map[uint32]bool{},
		sigs:       map[uint32][]byte{},
	}
	for _, x := range old.tree.NonBlank() {
		if x%2 != 0 {
			continue
		}
		l := uint32(x / 2)
		o, n := old.tree.Leaf(l), next.tree.Leaf(l)
		// Leaves are never changed in place, so the same pointer is the
		// same leaf.
		if o == n {
			continue
		}
		if n == nil || !g.sameClient(o.Credential, n.Credential) {
			p.gone[l] = true
			continue
		}
		if !bytes.Equal(o.SignatureKey, n.SignatureKey) {
			p.sigs[l] = bytes.Clone(o.SignatureKey)
		}
	}
	// A leaf the Commit fills had no member in the old epoch.
	for _, x := range next.tree.NonBlank() {
		if l := uint32(x / 2); x%2 == 0 && l < p.leaves && old.tree.Leaf(l) == nil {
			p.gone[l] = true
		}
	}
	return p, nil
}

// sameClient reports whether two credentials name one client; an
// Authenticator error counts as different.
func (g *Group) sameClient(a, b Credential) bool {
	ia, err := g.cfg.Authenticator.ClientID(a)
	if err != nil {
		return false
	}
	ib, err := g.cfg.Authenticator.ClientID(b)
	return err == nil && bytes.Equal(ia, ib)
}

const pastVersion uint8 = 0

func (p *past) marshal() ([]byte, error) {
	var w tls.Writer
	w.U8(pastVersion)
	w.U64(p.epoch)
	w.U64(uint64(p.end.UnixNano()))
	w.Opaque(p.ctxBytes)
	w.Opaque(p.senderData)
	w.U32(p.leaves)
	w.Vector(func(w *tls.Writer) {
		for _, l := range slices.Sorted(maps.Keys(p.gone)) {
			w.U32(l)
		}
	})
	w.Vector(func(w *tls.Writer) {
		for _, l := range slices.Sorted(maps.Keys(p.sigs)) {
			w.U32(l)
			w.Opaque(p.sigs[l])
		}
	})
	return w.Bytes()
}

func unmarshalPast(b []byte) (*past, error) {
	p := &past{gone: map[uint32]bool{}, sigs: map[uint32][]byte{}}
	err := tls.Decode(b, func(r *tls.Reader) error {
		v, err := r.U8()
		if err != nil {
			return err
		}
		if v != pastVersion {
			return fmt.Errorf("%w: stored past epoch version %d", errs.ErrUnsupported, v)
		}
		if p.epoch, err = r.U64(); err != nil {
			return err
		}
		end, err := r.U64()
		if err != nil {
			return err
		}
		p.end = time.Unix(0, int64(end))
		if p.ctxBytes, err = r.Opaque(); err != nil {
			return err
		}
		if p.senderData, err = r.Opaque(); err != nil {
			return err
		}
		if len(p.senderData) != suite.Nh {
			return fmt.Errorf("%w: stored sender data secret", errs.ErrMalformed)
		}
		if p.leaves, err = r.U32(); err != nil {
			return err
		}
		err = r.Vector(func(r *tls.Reader) error {
			l, err := r.U32()
			if err != nil {
				return err
			}
			p.gone[l] = true
			return nil
		})
		if err != nil {
			return err
		}
		return r.Vector(func(r *tls.Reader) error {
			l, err := r.U32()
			if err != nil {
				return err
			}
			p.sigs[l], err = r.Opaque()
			return err
		})
	})
	if err != nil {
		p.clear()
		return nil, err
	}
	return p, nil
}

// writePastDelete adds to b the deletion of the previous epoch p (nil for
// none): its record unless keep, and its secret tree.
func writePastDelete(b *Batch, gid []byte, p *past, keep bool) error {
	if p == nil {
		return nil
	}
	if !keep {
		b.del(groupKey(gid, "prev"))
	}
	return deleteKeys(b, gid, p.epoch, p.keys)
}

// loadPast reads the stored previous epoch of the state s, nil when none is
// stored, with the records that pruning its secret tree changed.
func loadPast(st Store, s *state, o secrettree.Options) (*past, []secrettree.Record, error) {
	gid := s.ctx.GroupID
	b, err := get(st, groupKey(gid, "prev"))
	if errors.Is(err, errs.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	p, err := unmarshalPast(b)
	clear(b)
	if err != nil {
		return nil, nil, err
	}
	if p.epoch+1 != s.ctx.Epoch || p.leaves == 0 || p.leaves&(p.leaves-1) != 0 {
		p.clear()
		return nil, nil, fmt.Errorf("%w: stored past epoch", errs.ErrMalformed)
	}
	keys, pruned, err := secrettree.Load(p.leaves, o, func(leaf bool, x uint64) ([]byte, error) {
		return get(st, secretKey(gid, p.epoch, secrettree.Record{Leaf: leaf, Index: x}))
	})
	if err != nil {
		p.clear()
		return nil, nil, err
	}
	p.keys = keys
	return p, pruned, nil
}

// processPast reads a late application message of the previous epoch, from
// a sender that is still a member; it uses up the key like Process does.
// Once the window has ended the previous epoch is deleted.
func (g *Group) processPast(pm *message.PrivateMessage) (*Result, error) {
	p := g.prev
	if !g.cfg.now().Before(p.end) {
		if err := g.expire(); err != nil {
			return nil, err
		}
		return nil, errs.ErrWrongEpoch
	}
	ac, lk, err := framing.UnprotectPrivate(pm, p.senderData, p.keys, p.member(g.s))
	if err != nil {
		return nil, err
	}
	defer lk.Discard()
	sender := ac.Content.Sender.Index
	if err := framing.Verify(p.signatureKey(g.s, sender), ac, p.ctxBytes); err != nil {
		return nil, err
	}
	aad := ac.Content.AuthenticatedData
	if g.cfg.Envelope != nil {
		if aad, err = g.cfg.Envelope.Unwrap(lk.Generation(), aad); err != nil {
			return nil, fmt.Errorf("%w: authenticated data: %w", errs.ErrMalformed, err)
		}
	}
	rs, err := p.keys.Changes(lk)
	if err != nil {
		return nil, err
	}
	var b Batch
	writeKeys(&b, g.s.ctx.GroupID, p.epoch, rs)
	if err := g.write(b); err != nil {
		return nil, err
	}
	if err := p.keys.Commit(lk); err != nil {
		return nil, err
	}
	return &Result{Epoch: p.epoch, Sender: sender, Application: bytes.Clone(ac.Content.ApplicationData), AuthenticatedData: bytes.Clone(aad)}, nil
}

func (g *Group) expire() error {
	var b Batch
	if err := writePastDelete(&b, g.s.ctx.GroupID, g.prev, false); err != nil {
		return err
	}
	if err := g.write(b); err != nil {
		return err
	}
	g.prev.clear()
	g.prev = nil
	return nil
}

// ExpirePastEpoch deletes the previous epoch once its window has ended at
// Config.Now, and returns when the window of the one still kept ends, the
// zero time when none is kept. The library has no timers: the caller calls
// it again at that time.
func (g *Group) ExpirePastEpoch() (time.Time, error) {
	if err := g.live(); err != nil {
		return time.Time{}, err
	}
	if g.prev == nil {
		return time.Time{}, nil
	}
	if g.cfg.now().Before(g.prev.end) {
		return g.prev.end, nil
	}
	return time.Time{}, g.expire()
}
