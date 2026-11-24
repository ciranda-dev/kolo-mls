package settle

import (
	"errors"
	"fmt"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

// ErrEnvelope reports authenticated data that is not a Kolo envelope of the
// message's generation.
var ErrEnvelope = errors.New("kolomls: invalid authenticated data envelope")

// maxAAD bounds the application's part of the envelope by what a
// PrivateMessage can carry (RFC 9420 section 2.1.2: 2^30 - 1).
const maxAAD = 1<<30 - 1

// Envelope binds the generation of every PrivateMessage into its signed
// authenticated data: uvarint version 0, uvarint generation, bytes(aad)
// (RFC 9750 section 8.6: a member cannot replay another member's content
// under a new generation).
type Envelope struct{}

// Wrap returns the authenticated data of generation gen for aad.
func (Envelope) Wrap(gen uint32, aad []byte) ([]byte, error) {
	var e kolocodec.Encoder
	e.PutUvarint(0)
	e.PutUvarint(uint64(gen))
	e.PutBytes(aad)
	return e.Bytes(), nil
}

// Unwrap checks that ad is the envelope of generation gen and returns the
// application's aad.
func (Envelope) Unwrap(gen uint32, ad []byte) ([]byte, error) {
	d := kolocodec.NewDecoder(ad)
	v, err := d.Uvarint()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvelope, err)
	}
	if v != 0 {
		return nil, fmt.Errorf("%w: version %d", ErrEnvelope, v)
	}
	g, err := d.Uvarint()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvelope, err)
	}
	if g != uint64(gen) {
		return nil, fmt.Errorf("%w: generation differs", ErrEnvelope)
	}
	aad, err := d.Bytes(maxAAD)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvelope, err)
	}
	if err := d.Done(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvelope, err)
	}
	return aad, nil
}
