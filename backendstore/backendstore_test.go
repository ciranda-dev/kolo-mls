package backendstore_test

import (
	"testing"
	"time"

	kolostore "github.com/ciranda-dev/kolo-store"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/backendstore"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/kolotest"
)

// sharing is a Backend that hands out the slice it holds on Get, until the
// next batch.
type sharing struct {
	kolostore.Backend
	held map[string][]byte
}

func (s *sharing) Get(key []byte) ([]byte, error) {
	if v, ok := s.held[string(key)]; ok {
		return v, nil
	}
	v, err := s.Backend.Get(key)
	if err == nil {
		s.held[string(key)] = v
	}
	return v, err
}

func (s *sharing) NewBatch() kolostore.Batch {
	clear(s.held)
	return s.Backend.NewBatch()
}

type anyPolicy struct{}

func (anyPolicy) CheckProposal(kolomls.ProposalView) error { return nil }
func (anyPolicy) CheckCommit(kolomls.CommitView) error     { return nil }
func (anyPolicy) CheckJoin(kolomls.JoinView) error         { return nil }

// TestGetCopies: the library zeroes what Get returns, so Get returns a copy
// even from a Backend that hands out its own slice, and a group's records
// stay intact.
func TestGetCopies(t *testing.T) {
	st := backendstore.New(&sharing{Backend: kolostore.NewMemory(), held: map[string][]byte{}}, []byte("mls/"))
	if err := st.Apply(kolomls.Batch{Put: []kolomls.KV{{Key: []byte("k"), Value: []byte("value")}}}); err != nil {
		t.Fatal(err)
	}
	v, err := st.Get([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	clear(v)
	if v, err := st.Get([]byte("k")); err != nil || string(v) != "value" {
		t.Fatalf("value after the caller zeroed its copy: %q %v", v, err)
	}
	dev := kolotest.NewDevice(t, kolotest.Person(t), true)
	cfg := kolomls.Config{Authenticator: &cred.Authenticator{Now: time.Now}, Policy: anyPolicy{}}
	g, err := kolomls.Create(st, dev.CreateOptions(t, st, cfg, nil))
	if err != nil {
		t.Fatal(err)
	}
	gid := g.GroupID()
	if _, err := g.Commit(kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	g.Close()
	for i := range 2 {
		g, err := kolomls.Open(st, gid, cfg)
		if err != nil || g.Pending() == nil {
			t.Fatalf("open %d: %v", i+1, err)
		}
		g.Close()
	}
}
