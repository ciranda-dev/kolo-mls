package kolomls

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
)

// MemStore is a Store in memory, the reference for the Store contract and
// for tests; it copies every key and value, zeroes what it drops, and is
// safe for concurrent use.
type MemStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{m: map[string][]byte{}}
}

// Get returns a copy of the value of key, or ErrNotFound.
func (s *MemStore) Get(key []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[string(key)]
	if !ok {
		return nil, errs.ErrNotFound
	}
	return bytes.Clone(v), nil
}

// Apply applies the deletes, then the puts, of b; it refuses a batch with a
// key in both, which the Batch contract forbids.
func (s *MemStore) Apply(b Batch) error {
	del := make(map[string]bool, len(b.Delete))
	for _, k := range b.Delete {
		del[string(k)] = true
	}
	for _, kv := range b.Put {
		if del[string(kv.Key)] {
			return fmt.Errorf("%w: a key in a delete and a put of one batch", errs.ErrInvalidArgument)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range b.Delete {
		if v, ok := s.m[string(k)]; ok {
			clear(v)
			delete(s.m, string(k))
		}
	}
	for _, kv := range b.Put {
		if old, ok := s.m[string(kv.Key)]; ok {
			clear(old)
		}
		s.m[string(kv.Key)] = bytes.Clone(kv.Value)
	}
	return nil
}

// Clone returns a copy of s, as a disk image of it would hold.
func (s *MemStore) Clone() *MemStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := NewMemStore()
	for k, v := range s.m {
		c.m[k] = bytes.Clone(v)
	}
	return c
}
