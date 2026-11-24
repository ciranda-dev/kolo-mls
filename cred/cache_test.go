package cred

import (
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// TestCacheEmptied: the cache never holds more than MaxCached ids.
func TestCacheEmptied(t *testing.T) {
	a := &Authenticator{MaxCached: 3}
	for i := range 10 {
		a.remember([]byte{byte(i)}, make([]byte, 32))
		if len(a.ids) > 3 {
			t.Fatalf("%d ids cached", len(a.ids))
		}
	}
	if _, err := a.ClientID(tree.Credential{Type: Type, Identity: []byte{9}}); err != nil {
		t.Fatalf("cached id: %v", err)
	}
}
