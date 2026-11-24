package tree

import (
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// TestShortHPKECiphertext: a kem_output under 32 bytes or a ciphertext under
// an AEAD tag is refused while decoding.
func TestShortHPKECiphertext(t *testing.T) {
	for _, c := range []struct {
		kem, ct int
		ok      bool
	}{{32, 16, true}, {31, 16, false}, {32, 15, false}} {
		var w tls.Writer
		w.Opaque(make([]byte, c.kem))
		w.Opaque(make([]byte, c.ct))
		b, _ := w.Bytes()
		err := tls.Decode(b, func(r *tls.Reader) error { _, err := ReadHPKECiphertext(r); return err })
		if (err == nil) != c.ok || !c.ok && !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("kem_output %d, ciphertext %d: %v", c.kem, c.ct, err)
		}
	}
}
