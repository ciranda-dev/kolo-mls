// Package backendstore keeps the state of kolo-mls groups in a kolo-store
// Backend, such as its on-disk backend, under a key prefix: each group change is
// one atomic, durable Backend batch.
package backendstore

import (
	"bytes"
	"errors"
	"fmt"

	kolostore "github.com/ciranda-dev/kolo-store"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/internal/errs"
)

// Store is a kolomls.Store on a kolo-store Backend. Deletion on disk is best
// effort: the Backend removes a key in the batch, but backups, snapshots and
// freed blocks may keep its bytes.
type Store struct {
	b      kolostore.Backend
	prefix []byte
}

// New returns a Store whose keys live in b under prefix; no other user of b
// may write keys that start with it.
func New(b kolostore.Backend, prefix []byte) *Store {
	return &Store{b: b, prefix: append([]byte(nil), prefix...)}
}

func (s *Store) key(k []byte) []byte {
	return append(append(make([]byte, 0, len(s.prefix)+len(k)), s.prefix...), k...)
}

// Get returns a copy of the value of key, or kolomls.ErrNotFound.
func (s *Store) Get(key []byte) ([]byte, error) {
	v, err := s.b.Get(s.key(key))
	if errors.Is(err, kolostore.ErrNotFound) {
		return nil, errs.ErrNotFound
	}
	return bytes.Clone(v), err
}

// Apply writes the deletes and puts of b in one atomic, durable Backend
// batch, which keeps its own copies of the values.
func (s *Store) Apply(b kolomls.Batch) error {
	deleted := make(map[string]bool, len(b.Delete))
	for _, k := range b.Delete {
		deleted[string(k)] = true
	}
	for _, kv := range b.Put {
		if deleted[string(kv.Key)] {
			return fmt.Errorf("%w: a key both deleted and put in one batch", errs.ErrInvalidArgument)
		}
	}
	nb := s.b.NewBatch()
	for _, k := range b.Delete {
		nb.Delete(s.key(k))
	}
	for _, kv := range b.Put {
		nb.Put(s.key(kv.Key), kv.Value)
	}
	return nb.Commit()
}
