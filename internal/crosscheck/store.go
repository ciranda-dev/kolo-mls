package crosscheck

import (
	"sync"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
)

// store is a kolomls.Store in memory that can be copied, so the driver can
// read the tree a pending Commit leads to without applying it.
type store struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newStore() *store { return &store{m: map[string][]byte{}} }

func (s *store) Get(key []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[string(key)]
	if !ok {
		return nil, errs.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (s *store) Apply(b kolomls.Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range b.Delete {
		delete(s.m, string(k))
	}
	for _, kv := range b.Put {
		s.m[string(kv.Key)] = append([]byte(nil), kv.Value...)
	}
	return nil
}
