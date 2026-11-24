package braid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	kolobraid "github.com/ciranda-dev/kolo-braid"
	koloid "github.com/ciranda-dev/kolo-id"
	kolostore "github.com/ciranda-dev/kolo-store"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/backendstore"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/kolotest"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// memPins is Pins in memory, safe for concurrent use.
type memPins struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newPins() *memPins { return &memPins{m: map[string][]byte{}} }

func (p *memPins) Put(_ context.Context, k string, v []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[k] = bytes.Clone(v)
	return nil
}

func (p *memPins) Get(_ context.Context, k string, max int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.m[k]
	if !ok {
		return nil, settle.ErrMissing
	}
	if max > 0 && len(v) > max {
		return nil, settle.ErrPinTooLarge
	}
	return bytes.Clone(v), nil
}

func (p *memPins) List(_ context.Context, prefix, after string, max int) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for k := range p.m {
		if strings.HasPrefix(k, prefix) && k > after {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	for i, k := range out {
		out[i] = strings.Clone(k)
	}
	return slices.Clone(out), nil
}

func (p *memPins) Delete(_ context.Context, k string) error {
	p.drop(k)
	return nil
}

func (p *memPins) clone() *memPins {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := newPins()
	for k, v := range p.m {
		c.m[k] = bytes.Clone(v)
	}
	return c
}

func (p *memPins) drop(k string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, k)
}

// memLog is an admins' order in memory: entries take positions in append
// order and settle when settle is called, like a braid whose settlers are
// all online.
type memLog struct {
	mu      sync.Mutex
	id      [32]byte
	entries []memEntry
	settled int
	// revs are the roster's revocations by device, each with the position
	// of the first entry it is in effect for.
	revs map[[32]byte][]posRev
	// admins, settlers and q are the braid's roster, as a test sets it.
	admins, settlers [][32]byte
	q                int
}

type posRev struct {
	pos int
	rev *koloid.Revocation
}

type memEntry struct {
	writer [32]byte
	body   []byte
	// rejected is set on an entry the braid's apply refused, as the Index
	// does for a writer revoked at that position.
	rejected bool
}

func newLog(id byte) *memLog {
	return &memLog{id: [32]byte{id, 0xb}, revs: map[[32]byte][]posRev{}}
}

func (l *memLog) settle() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.settled = len(l.entries)
}

// memOrder is one admin's Order on a memLog.
type memOrder struct {
	l  *memLog
	me [32]byte
}

func (o *memOrder) ID() [32]byte { return o.l.id }

func (o *memOrder) Append(_ context.Context, body []byte) error {
	d, ok, err := decodeEntry(body)
	if !ok || err != nil {
		return fmt.Errorf("not a kolo-mls entry: %v", err)
	}
	o.l.mu.Lock()
	defer o.l.mu.Unlock()
	// The Index's check at the entry's position.
	c, err := koloid.DecodeDeviceCert(d.cert)
	rejected := err != nil || [32]byte(c.Device()) != o.me
	if !rejected {
		revs := o.l.revocations(len(o.l.entries), c)
		rejected = c.Verify(&koloid.VerifyOptions{Person: c.Person(), Now: time.Unix(0, 0), Revocations: revs}) != nil
	}
	o.l.entries = append(o.l.entries, memEntry{writer: o.me, body: bytes.Clone(body), rejected: rejected})
	return nil
}

// revocations returns the revocations of cert's device and issuer in effect
// at position pos; the caller holds mu.
func (l *memLog) revocations(pos int, c *koloid.DeviceCert) []*koloid.Revocation {
	var out []*koloid.Revocation
	for _, k := range [][32]byte{[32]byte(c.Device()), [32]byte(c.Issuer())} {
		for _, r := range l.revs[k] {
			if r.pos <= pos {
				out = append(out, r.rev)
			}
		}
	}
	return out
}

func (o *memOrder) read(n int, gid []byte, epoch uint64) ([]Ref, []Vote, []Sig) {
	o.l.mu.Lock()
	defer o.l.mu.Unlock()
	var refs []Ref
	var votes []Vote
	var sigs []Sig
	for i, e := range o.l.entries[:n] {
		if e.rejected {
			continue
		}
		d, _, err := decodeEntry(e.body)
		if err != nil || !bytes.Equal(d.groupID, gid) || d.epoch != epoch {
			continue
		}
		pos := uint64(i)
		switch d.kind {
		case kindRef:
			d.ref.Position, d.ref.Writer = pos, e.writer
			refs = append(refs, d.ref)
		case kindVote:
			d.vote.Position, d.vote.Writer = pos, e.writer
			votes = append(votes, d.vote)
		case kindSig:
			d.sig.Position, d.sig.Writer = pos, e.writer
			sigs = append(sigs, d.sig)
		}
	}
	return refs, votes, sigs
}

func (o *memOrder) Entries(gid []byte, epoch uint64) ([]Ref, []Vote, []Sig, error) {
	o.l.mu.Lock()
	n := o.l.settled
	o.l.mu.Unlock()
	r, v, s := o.read(n, gid, epoch)
	return r, v, s, nil
}

func (o *memOrder) Own(gid []byte, epoch uint64) ([]Vote, []Sig, error) {
	o.l.mu.Lock()
	n := len(o.l.entries)
	o.l.mu.Unlock()
	_, votes, sigs := o.read(n, gid, epoch)
	var vs []Vote
	var ss []Sig
	for _, v := range votes {
		if v.Writer == o.me {
			vs = append(vs, v)
		}
	}
	for _, s := range sigs {
		if s.Writer == o.me {
			ss = append(ss, s)
		}
	}
	return vs, ss, nil
}

func (o *memOrder) Roster() ([][32]byte, [][32]byte, int, error) {
	o.l.mu.Lock()
	defer o.l.mu.Unlock()
	return slices.Clone(o.l.admins), slices.Clone(o.l.settlers), o.l.q, nil
}

func (o *memOrder) Revocations(c *koloid.DeviceCert) ([]*koloid.Revocation, error) {
	o.l.mu.Lock()
	defer o.l.mu.Unlock()
	return o.l.revocations(len(o.l.entries), c), nil
}

func (o *memOrder) RevocationsAt(_ context.Context, position uint64, c *koloid.DeviceCert) ([]*koloid.Revocation, error) {
	o.l.mu.Lock()
	defer o.l.mu.Unlock()
	if position >= uint64(o.l.settled) {
		return nil, kolobraid.ErrNotFound
	}
	return o.l.revocations(int(position), c), nil
}

// node is one device of a scenario: its identity, Store and Member, and its
// Admin when it is an admin.
type node struct {
	name    string
	dev     *kolotest.Device
	backend kolostore.Backend
	st      kolomls.Store
	auth    *cred.Authenticator
	m       *settle.Member
	admin   *Admin
	order   Order
	online  bool
	// revs are the revocations this device holds.
	revs []*koloid.Revocation
}

// world is a Kolo group of nodes with pins and gossip in memory.
type world struct {
	t     testing.TB
	ctx   context.Context
	pins  *memPins
	nodes []*node
	gid   []byte
	// sent holds every message of each epoch, for the removed-device checks.
	sent map[uint64][][]byte
	// applied holds the Commit hash each node applied per epoch.
	applied map[uint64]map[string][32]byte
	limits  settle.Limits
	now     time.Time
}

func newWorld(t testing.TB) *world {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &world{t: t, ctx: ctx, pins: newPins(), sent: map[uint64][][]byte{}, applied: map[uint64]map[string][32]byte{}, now: time.Now()}
}

func (w *world) clock() time.Time { return w.now }

// device makes a node for a device of person (a new person when nil).
func (w *world) device(name string, person *koloid.Identity) *node {
	if person == nil {
		person = kolotest.Person(w.t)
	}
	b := kolostore.NewMemory()
	n := &node{name: name, dev: kolotest.NewDevice(w.t, person, true), backend: b, st: backendstore.New(b, []byte("mls/")), online: true}
	n.auth = &cred.Authenticator{Now: w.clock}
	return n
}

func (w *world) config(n *node) kolomls.Config {
	return settle.NewConfig(n.auth, &settle.Policy{Limits: w.limits}, w.clock)
}

func (w *world) memberOptions(n *node) settle.MemberOptions {
	return settle.MemberOptions{Revocations: func(p, d ed25519.PublicKey) []*koloid.Revocation {
		var out []*koloid.Revocation
		for _, r := range n.revs {
			if bytes.Equal(r.Device(), d) {
				out = append(out, r)
			}
		}
		return out
	}}
}

// create makes founder the only admin and settler of a new group over order.
func (w *world) create(founder *node, order Order) {
	w.t.Helper()
	roles, err := settle.NewRoles(order.ID(), settle.Majority, []ed25519.PublicKey{founder.dev.ID.PublicKey()}, []ed25519.PublicKey{founder.dev.ID.PublicKey()}, w.limits)
	if err != nil {
		w.t.Fatal(err)
	}
	exts, err := settle.GroupExtensions(roles)
	if err != nil {
		w.t.Fatal(err)
	}
	co := founder.dev.CreateOptions(w.t, founder.st, w.config(founder), exts)
	m, err := settle.CreateMember(founder.st, co, w.memberOptions(founder))
	if err != nil {
		w.t.Fatal(err)
	}
	founder.m = m
	w.gid = m.GroupID()
	w.makeAdmin(founder, order)
	w.nodes = append(w.nodes, founder)
}

func (w *world) makeAdmin(n *node, order Order) {
	w.t.Helper()
	a, err := NewAdmin(n.dev.ID, order, n.m, Options{Pins: w.pins, Now: w.clock, ApproveRoles: approveAll})
	if err != nil {
		w.t.Fatal(err)
	}
	n.admin, n.order = a, order
}

// approveAll is an application that approves every roles change.
func approveAll(_, _ *settle.Roles) bool { return true }

func (w *world) admins() []*node {
	var out []*node
	for _, n := range w.nodes {
		if n.admin != nil && n.m != nil && !n.m.Removed() {
			out = append(out, n)
		}
	}
	return out
}

// live returns the online nodes that are still members.
func (w *world) live() []*node {
	var out []*node
	for _, n := range w.nodes {
		if n.online && n.m != nil && !n.m.Removed() {
			out = append(out, n)
		}
	}
	return out
}

// pump runs the admins and the order until every online live node reached
// epoch target, or fails after rounds rounds; settleOrder settles what was
// appended (or waits for the braid to settle) between rounds.
func (w *world) pump(target uint64, settleOrder func(), rounds int) []*Applied {
	w.t.Helper()
	var out []*Applied
	for range rounds {
		done := true
		for _, n := range w.live() {
			if n.m.Epoch() < target {
				done = false
			}
		}
		if done {
			return out
		}
		for _, n := range w.admins() {
			if !n.online || n.m.Removed() {
				continue
			}
			ap, err := n.admin.Step(w.ctx)
			if err != nil {
				w.t.Fatalf("%s Step: %v", n.name, err)
			}
			if ap != nil {
				out = append(out, ap)
				w.record(n, ap)
				w.gossip(n, ap)
			}
		}
		settleOrder()
	}
	w.t.Fatalf("epoch %d not reached in %d rounds", target, rounds)
	return nil
}

// record keeps the Commit hash node n applied in an epoch.
func (w *world) record(n *node, ap *Applied) {
	h := sha256.Sum256(ap.Commit)
	if w.applied[ap.Epoch] == nil {
		w.applied[ap.Epoch] = map[string][32]byte{}
		w.sent[ap.Epoch] = append(w.sent[ap.Epoch], ap.Commit)
	}
	w.applied[ap.Epoch][n.name] = h
}

// gossip delivers a settled Commit to every other online live node.
func (w *world) gossip(from *node, ap *Applied) {
	w.t.Helper()
	for _, n := range w.live() {
		if n == from || n.m.Epoch() != ap.Epoch {
			continue
		}
		if _, err := n.m.ApplySettled(ap.Settled, ap.Commit); err != nil {
			w.t.Fatalf("%s applying epoch %d: %v", n.name, ap.Epoch, err)
		}
		w.record(n, ap)
	}
}

// join adds the nodes by a Commit of admin and joins them with its Welcome.
func (w *world) join(admin *node, settleOrder func(), joiners ...*node) {
	w.t.Helper()
	var kps [][]byte
	for _, j := range joiners {
		kps = append(kps, j.dev.KeyPackage(w.t, j.st))
	}
	e := admin.m.Epoch()
	welcome, err := admin.admin.Commit(w.ctx, kolomls.CommitOptions{Add: kps})
	if err != nil {
		w.t.Fatal(err)
	}
	w.pump(e+1, settleOrder, 200)
	settled, err := w.pins.Get(w.ctx, settle.SettledKey(w.gid, e), 0)
	if err != nil || welcome == nil {
		w.t.Fatalf("no Welcome or SettledCommit: %v", err)
	}
	for _, j := range joiners {
		cfg := w.config(j)
		m, err := settle.JoinMember(j.st, welcome, settled, func(gid []byte, epoch uint64, max int) ([]byte, error) {
			return w.pins.Get(w.ctx, settle.TreeKey(gid, epoch), max)
		}, kolomls.JoinOptions{Config: cfg}, w.memberOptions(j))
		if err != nil {
			w.t.Fatalf("%s joining: %v", j.name, err)
		}
		j.m = m
		w.nodes = append(w.nodes, j)
	}
	if err := admin.admin.ReleaseWelcome(w.ctx, e); err != nil {
		w.t.Fatal(err)
	}
	w.check()
}

// check verifies that every online live node is in the same epoch with the
// same epoch authenticator and that each epoch has one applied Commit.
func (w *world) check() {
	w.t.Helper()
	var first *node
	var auth []byte
	for _, n := range w.live() {
		a, err := n.m.EpochAuthenticator()
		if err != nil {
			w.t.Fatal(err)
		}
		if first == nil {
			first, auth = n, a
			continue
		}
		if n.m.Epoch() != first.m.Epoch() || !bytes.Equal(a, auth) {
			w.t.Fatalf("%s at epoch %d differs from %s at epoch %d", n.name, n.m.Epoch(), first.name, first.m.Epoch())
		}
	}
	for e, by := range w.applied {
		var h [32]byte
		set := false
		for name, x := range by {
			if set && x != h {
				w.t.Fatalf("epoch %d: %s applied another Commit", e, name)
			}
			h, set = x, true
		}
	}
}

// send has n encrypt data and gossips it to every other online node, also
// archived on pins; it returns the message.
func (w *world) send(n *node, data string) []byte {
	msg, _ := w.sendCount(n, data)
	return msg
}

// sendCount is send that also returns how many nodes dropped the message as
// one of a revoked device.
func (w *world) sendCount(n *node, data string) ([]byte, int) {
	w.t.Helper()
	msg, err := n.m.Encrypt([]byte(data), nil)
	if err != nil {
		w.t.Fatalf("%s Encrypt: %v", n.name, err)
	}
	e := n.m.Epoch()
	w.sent[e] = append(w.sent[e], msg)
	if err := w.pins.Put(w.ctx, settle.ArchiveKey(w.gid, e, msg), msg); err != nil {
		w.t.Fatal(err)
	}
	dropped := 0
	for _, o := range w.live() {
		if o == n {
			continue
		}
		r, err := o.m.Receive(msg)
		if errors.Is(err, settle.ErrRevokedSender) {
			dropped++
			continue
		}
		if err != nil || string(r.Application) != data || r.Sender != n.m.OwnLeaf() {
			w.t.Fatalf("%s reading %s's message: %v", o.name, n.name, err)
		}
	}
	return msg, dropped
}

// proposeLeave has n send its own Remove, gossiped and archived, and
// returns it with its reference.
func (w *world) proposeLeave(n *node) ([]byte, []byte) {
	w.t.Helper()
	msg, err := n.m.Leave()
	if err != nil {
		w.t.Fatal(err)
	}
	return msg, w.spread(n, msg)
}

// spread archives a proposal of n and gives it to every other online node;
// it returns the proposal's reference.
func (w *world) spread(n *node, msg []byte) []byte {
	w.t.Helper()
	e := n.m.Epoch()
	w.sent[e] = append(w.sent[e], msg)
	if err := w.pins.Put(w.ctx, settle.ArchiveKey(w.gid, e, msg), msg); err != nil {
		w.t.Fatal(err)
	}
	var ref []byte
	for _, o := range w.live() {
		if o == n {
			continue
		}
		r, err := o.m.Receive(msg)
		if errors.Is(err, settle.ErrNotHeld) {
			continue
		}
		if err != nil {
			w.t.Fatalf("%s reading a proposal: %v", o.name, err)
		}
		ref = r.ProposalRef
	}
	return ref
}

// copyBackend returns a copy of n's backend, as a thief or a stolen disk
// image would hold it.
func copyBackend(t testing.TB, b kolostore.Backend) kolostore.Backend {
	t.Helper()
	c := kolostore.NewMemory()
	err := b.Scan(nil, nil, false, 0, func(k, v []byte) bool {
		if err := c.Put(k, v); err != nil {
			t.Fatal(err)
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// stolen is the state a removed device kept just before it applied its
// removal: the group opened from a copy of its Store.
type stolen struct {
	name  string
	g     *kolomls.Group
	epoch uint64
}

// steal opens a copy of n's group as it is now.
func (w *world) steal(n *node) *stolen {
	w.t.Helper()
	st := backendstore.New(copyBackend(w.t, n.backend), []byte("mls/"))
	cfg := w.config(n)
	cfg.PastEpochWindow = time.Hour
	g, err := kolomls.Open(st, w.gid, cfg)
	if err != nil {
		w.t.Fatal(err)
	}
	return &stolen{name: n.name, g: g, epoch: g.Epoch()}
}

// decryptsNothing checks that the stolen state reads none of the messages
// sent after its epoch: each is presented as a message of its own epoch,
// so its keys are tried, and none decrypts. It returns how many it tried.
func (w *world) decryptsNothing(s *stolen) int {
	w.t.Helper()
	tried := 0
	for e, msgs := range w.sent {
		if e <= s.epoch {
			continue
		}
		for _, msg := range msgs {
			m, err := message.UnmarshalMLSMessage(msg)
			if err != nil {
				w.t.Fatal(err)
			}
			m.Private.Epoch = s.epoch
			b, err := m.Marshal()
			if err != nil {
				w.t.Fatal(err)
			}
			if _, err := s.g.Process(b); !errors.Is(err, errs.ErrDecrypt) {
				w.t.Fatalf("stolen state of %s at epoch %d read a message of epoch %d: %v", s.name, s.epoch, e, err)
			}
			if _, err := s.g.Process(msg); err == nil {
				w.t.Fatalf("stolen state of %s read a message of epoch %d", s.name, e)
			}
			tried++
		}
	}
	return tried
}

func backendStore(b kolostore.Backend) kolomls.Store { return backendstore.New(b, []byte("mls/")) }

// mustGet, mustDecode and mustObject read what a test expects to be there.
func (w *world) mustGet(k string) []byte {
	w.t.Helper()
	v, err := w.pins.Get(w.ctx, k, 0)
	if err != nil {
		w.t.Fatalf("pins %s: %v", k, err)
	}
	return v
}

func (w *world) mustDecode(b []byte) *settle.Settled {
	w.t.Helper()
	s, err := settle.DecodeSettled(b, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *world) mustObject(h [32]byte) []byte {
	w.t.Helper()
	v, err := settle.GetObject(w.ctx, w.pins, h, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return v
}
