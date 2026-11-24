package kolomls

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

func TestScenario(t *testing.T) {
	w := newWorld(t, 5)
	w.commit(2, CommitOptions{})
	w.check()
	w.commit(1, CommitOptions{Remove: []uint32{3}})
	w.check()
	if len(w.members) != 4 {
		t.Fatalf("%d members after a Remove", len(w.members))
	}
	// An Update proposal by member 4, committed by member 0.
	ref := w.propose(4, func(g *Group) ([]byte, error) { return g.ProposeUpdate(nil) })
	w.reopen(4)
	w.commit(0, CommitOptions{References: [][]byte{ref}})
	w.check()
	// A Remove proposal, a partial Commit with an Add and no path, PSKs.
	ref = w.propose(1, func(g *Group) ([]byte, error) { return g.ProposeRemove(4) })
	w.commit(2, CommitOptions{References: [][]byte{ref}})
	w.check()
	for _, l := range w.leaves() {
		w.members[l].g.cfg.PSKs = pskMap{"ext": bytes.Repeat([]byte{9}, 32)}
	}
	w.cfg.PSKs = pskMap{"ext": bytes.Repeat([]byte{9}, 32)}
	c := newClient(t)
	w.commit(1, CommitOptions{NoPath: true, PSKs: []*schedule.PSKID{pskID("ext")}})
	w.check()
	pc := w.commit(0, CommitOptions{Add: [][]byte{c.keyPackage(t)}, PSKs: []*schedule.PSKID{pskID("ext")}})
	w.join(0, pc, []*client{c})
	resumption := &schedule.PSKID{Type: schedule.PSKResumption, Usage: schedule.UsageApplication, GroupID: w.members[0].g.GroupID(), Epoch: w.members[0].g.Epoch()}
	ref = w.propose(1, func(g *Group) ([]byte, error) { return g.ProposePSK(resumption) })
	w.commit(2, CommitOptions{References: [][]byte{ref}})
	w.check()
	ref = w.propose(0, func(g *Group) ([]byte, error) {
		return g.ProposeGroupContextExtensions([]tls.Extension{{Type: 1, Data: []byte{1}}})
	})
	w.commit(1, CommitOptions{References: [][]byte{ref}, RatchetTree: true})
	w.check()
	for _, l := range w.leaves() {
		w.reopen(l)
	}
	w.add(1, 3)
	w.commit(0, CommitOptions{})
	w.check()
}

func TestPendingCommit(t *testing.T) {
	w := newWorld(t, 3)
	a, b := w.members[0].g, w.members[1].g
	ctx, auth := a.GroupContext(), epochAuth(a)
	pa, err := a.Commit(CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unchanged(t, a, ctx, auth)
	if _, err := a.Commit(CommitOptions{}); !errors.Is(err, errs.ErrPendingCommit) {
		t.Fatalf("second pending Commit: %v", err)
	}
	// A crash before the Delivery Service decides: the pending Commit survives.
	w.reopen(0)
	a = w.members[0].g
	if a.Pending() == nil || !bytes.Equal(a.Pending().Commit(), pa.Commit()) {
		t.Fatal("pending Commit lost on reopen")
	}
	// Member 1's Commit wins: member 0 applies it, which drops its own.
	pb, err := b.Commit(CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	w.deliver(1, pb.Commit())
	if err := b.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	if a.Pending() != nil {
		t.Fatal("applying another Commit kept the pending one")
	}
	if _, err := a.st().Get(groupKey(a.GroupID(), "pending")); !errors.Is(err, errs.ErrNotFound) {
		t.Fatalf("stored pending Commit after another Commit: %v", err)
	}
	w.check()
	if err := a.ApplyPending(); !errors.Is(err, errs.ErrPendingCommit) {
		t.Fatalf("ApplyPending with none: %v", err)
	}
	if err := a.DiscardPending(); !errors.Is(err, errs.ErrPendingCommit) {
		t.Fatalf("DiscardPending with none: %v", err)
	}
	if _, err = a.Commit(CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.DiscardPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.st().Get(groupKey(a.GroupID(), "pending")); !errors.Is(err, errs.ErrNotFound) {
		t.Fatalf("pending Commit kept after DiscardPending: %v", err)
	}
	unchanged(t, a, w.members[1].g.GroupContext(), epochAuth(w.members[1].g))
}

func (g *Group) st() *MemStore {
	if c, ok := g.store.(*countStore); ok {
		return c.MemStore
	}
	return g.store.(*MemStore)
}

// TestMemStoreContract: a batch with a key in both its deletes and its puts
// is refused and changes nothing.
func TestMemStoreContract(t *testing.T) {
	st := NewMemStore()
	if err := st.Apply(Batch{Put: []KV{{Key: []byte("a"), Value: []byte{1}}}}); err != nil {
		t.Fatal(err)
	}
	err := st.Apply(Batch{Put: []KV{{Key: []byte("a"), Value: []byte{2}}}, Delete: [][]byte{[]byte("a")}})
	if !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("key in both: %v", err)
	}
	if v, _ := st.Get([]byte("a")); !bytes.Equal(v, []byte{1}) || len(st.m) != 1 {
		t.Fatal("a refused batch changed the store")
	}
}
