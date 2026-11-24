// Package tls reads and writes the TLS presentation language of RFC 9420
// section 2.1 (RFC 9846 section 3) in its single canonical form.
package tls

import (
	"encoding/binary"
	"fmt"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
)

// MaxVarint is the largest value of a variable-size length (RFC 9420 section 2.1.2).
const MaxVarint = 1<<30 - 1

// Reader decodes from a byte slice. Decoded byte strings never alias the input.
type Reader struct {
	b []byte
}

// NewReader returns a Reader over b.
func NewReader(b []byte) *Reader {
	return &Reader{b: b}
}

// Decode runs f on b and fails if f leaves any byte unread.
func Decode(b []byte, f func(*Reader) error) error {
	r := NewReader(b)
	if err := f(r); err != nil {
		return err
	}
	if r.Len() != 0 {
		return fmt.Errorf("%w: trailing bytes", errs.ErrMalformed)
	}
	return nil
}

// Len returns the number of unread bytes.
func (r *Reader) Len() int {
	return len(r.b)
}

func (r *Reader) next(n int) ([]byte, error) {
	if n < 0 || n > len(r.b) {
		return nil, fmt.Errorf("%w: truncated", errs.ErrMalformed)
	}
	v := r.b[:n:n]
	r.b = r.b[n:]
	return v, nil
}

// U8 reads a uint8.
func (r *Reader) U8() (uint8, error) {
	b, err := r.next(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// U16 reads a big-endian uint16.
func (r *Reader) U16() (uint16, error) {
	b, err := r.next(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

// U32 reads a big-endian uint32.
func (r *Reader) U32() (uint32, error) {
	b, err := r.next(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// U64 reads a big-endian uint64.
func (r *Reader) U64() (uint64, error) {
	b, err := r.next(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// Varint reads a variable-size length and refuses prefix 11 and non-minimal
// encodings (RFC 9420 section 2.1.2).
func (r *Reader) Varint() (uint32, error) {
	b, err := r.next(1)
	if err != nil {
		return 0, err
	}
	prefix := b[0] >> 6
	if prefix == 3 {
		return 0, fmt.Errorf("%w: varint prefix 11", errs.ErrMalformed)
	}
	n := 1 << prefix
	v := uint32(b[0] & 0x3f)
	rest, err := r.next(n - 1)
	if err != nil {
		return 0, err
	}
	for _, c := range rest {
		v = v<<8 | uint32(c)
	}
	if prefix >= 1 && v < 1<<(8*(n/2)-2) {
		return 0, fmt.Errorf("%w: varint not minimal", errs.ErrMalformed)
	}
	return v, nil
}

// Skip reads past n bytes without copying them.
func (r *Reader) Skip(n int) error {
	_, err := r.next(n)
	return err
}

// Fixed reads exactly n bytes into a new slice.
func (r *Reader) Fixed(n int) ([]byte, error) {
	b, err := r.next(n)
	if err != nil {
		return nil, err
	}
	return append([]byte{}, b...), nil
}

// Opaque reads an opaque<V> byte string.
func (r *Reader) Opaque() ([]byte, error) {
	n, err := r.Varint()
	if err != nil {
		return nil, err
	}
	return r.Fixed(int(n))
}

// Optional reads the presence octet of an optional<T> (RFC 9420 section 2.1.1).
func (r *Reader) Optional() (bool, error) {
	v, err := r.U8()
	if err != nil {
		return false, err
	}
	switch v {
	case 0:
		return false, nil
	case 1:
		return true, nil
	}
	return false, fmt.Errorf("%w: presence octet not 0 or 1", errs.ErrMalformed)
}

// Vector reads a <V> vector, calling f once per element on a reader bounded
// to the vector, so an element cannot straddle the vector's end.
func (r *Reader) Vector(f func(*Reader) error) error {
	n, err := r.Varint()
	if err != nil {
		return err
	}
	b, err := r.next(int(n))
	if err != nil {
		return err
	}
	sub := NewReader(b)
	for sub.Len() > 0 {
		before := sub.Len()
		if err := f(sub); err != nil {
			return err
		}
		// Every MLS vector element takes at least one byte; this also stops a
		// broken element parser from looping forever.
		if sub.Len() == before {
			return fmt.Errorf("%w: empty vector element", errs.ErrMalformed)
		}
	}
	return nil
}

// Writer encodes into a growing byte slice and keeps the first error.
type Writer struct {
	b   []byte
	err error
}

// Bytes returns the encoding, or the first error met while writing.
func (w *Writer) Bytes() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	return w.b, nil
}

// U8 writes a uint8.
func (w *Writer) U8(v uint8) {
	w.b = append(w.b, v)
}

// U16 writes a big-endian uint16.
func (w *Writer) U16(v uint16) {
	w.b = binary.BigEndian.AppendUint16(w.b, v)
}

// U32 writes a big-endian uint32.
func (w *Writer) U32(v uint32) {
	w.b = binary.BigEndian.AppendUint32(w.b, v)
}

// U64 writes a big-endian uint64.
func (w *Writer) U64(v uint64) {
	w.b = binary.BigEndian.AppendUint64(w.b, v)
}

// Varint writes n as a minimal variable-size length; n above MaxVarint
// records errs.ErrTooLong.
func (w *Writer) Varint(n int) {
	switch {
	case n < 0 || n > MaxVarint:
		if w.err == nil {
			w.err = errs.ErrTooLong
		}
	case n < 1<<6:
		w.b = append(w.b, byte(n))
	case n < 1<<14:
		w.b = binary.BigEndian.AppendUint16(w.b, 0x4000|uint16(n))
	default:
		w.b = binary.BigEndian.AppendUint32(w.b, 0x80000000|uint32(n))
	}
}

// Fixed writes b with no length.
func (w *Writer) Fixed(b []byte) {
	w.b = append(w.b, b...)
}

// Opaque writes b as an opaque<V> byte string.
func (w *Writer) Opaque(b []byte) {
	w.Varint(len(b))
	w.Fixed(b)
}

// Optional writes the presence octet of an optional<T>.
func (w *Writer) Optional(present bool) {
	if present {
		w.U8(1)
	} else {
		w.U8(0)
	}
}

// Vector writes the elements that f writes as one <V> vector.
func (w *Writer) Vector(f func(*Writer)) {
	var sub Writer
	f(&sub)
	if sub.err != nil {
		if w.err == nil {
			w.err = sub.err
		}
		return
	}
	w.Opaque(sub.b)
}

// Extension is an MLS Extension (RFC 9420 section 13.4).
type Extension struct {
	Type uint16
	Data []byte
}

// ReadExtensions reads an Extension list<V> and refuses two extensions of one
// type (RFC 9420 section 13.4).
func ReadExtensions(r *Reader) ([]Extension, error) {
	var exts []Extension
	seen := map[uint16]bool{}
	err := r.Vector(func(r *Reader) error {
		t, err := r.U16()
		if err != nil {
			return err
		}
		if seen[t] {
			return fmt.Errorf("%w: duplicate extension type", errs.ErrMalformed)
		}
		seen[t] = true
		d, err := r.Opaque()
		if err != nil {
			return err
		}
		exts = append(exts, Extension{Type: t, Data: d})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return exts, nil
}

// WriteExtensions writes an Extension list<V>.
func WriteExtensions(w *Writer, exts []Extension) {
	w.Vector(func(w *Writer) {
		for _, e := range exts {
			w.U16(e.Type)
			w.Opaque(e.Data)
		}
	})
}
