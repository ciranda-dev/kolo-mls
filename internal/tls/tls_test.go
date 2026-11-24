package tls

import (
	"bytes"
	"encoding/hex"
	"errors"
	"runtime"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVarintDecode(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint32
		rest int
	}{
		{"00", 0, 0},
		{"25", 37, 0},
		{"3f", 63, 0},
		{"4040", 64, 0},
		{"7bbd", 15293, 0},
		{"7fff", 16383, 0},
		{"80004000", 16384, 0},
		{"9d7f3e7d", 494878333, 0},
		{"bfffffff", MaxVarint, 0},
		{"3fff", 63, 1},
	} {
		r := NewReader(unhex(t, c.in))
		got, err := r.Varint()
		if err != nil || got != c.want || r.Len() != c.rest {
			t.Errorf("Varint(%s) = %d, %v, rest %d; want %d, nil, rest %d", c.in, got, err, r.Len(), c.want, c.rest)
		}
	}
}

func TestVarintDecodeErrors(t *testing.T) {
	for _, in := range []string{
		"",         // empty
		"40",       // truncated 2-byte
		"800000",   // truncated 4-byte
		"c0",       // prefix 11
		"ffffffff", // prefix 11
		"c000000000000000",
		"c0000000ffffffff", // prefix 11 whose low 32 bits look minimal
		"4000",             // 0 in 2 bytes
		"403f",             // 63 in 2 bytes
		"80000000",         // 0 in 4 bytes
		"80003fff",         // 16383 in 4 bytes
	} {
		_, err := NewReader(unhex(t, in)).Varint()
		if !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("Varint(%q) error = %v, want ErrMalformed", in, err)
		}
	}
}

func TestVarintEncode(t *testing.T) {
	for _, c := range []struct {
		n    int
		want string
	}{
		{0, "00"}, {63, "3f"}, {64, "4040"}, {16383, "7fff"},
		{16384, "80004000"}, {MaxVarint, "bfffffff"},
	} {
		var w Writer
		w.Varint(c.n)
		got, err := w.Bytes()
		if err != nil || hex.EncodeToString(got) != c.want {
			t.Errorf("Varint(%d) = %x, %v; want %s", c.n, got, err, c.want)
		}
	}
	for _, n := range []int{-1, MaxVarint + 1} {
		var w Writer
		w.Varint(n)
		if _, err := w.Bytes(); !errors.Is(err, errs.ErrTooLong) {
			t.Errorf("Varint(%d) error = %v, want ErrTooLong", n, err)
		}
	}
}

func TestDeserializationVectors(t *testing.T) {
	var v []struct {
		Header testvec.Hex `json:"vlbytes_header"`
		Length uint32      `json:"length"`
	}
	testvec.Load(t, "deserialization.json", &v)
	if len(v) != 14 {
		t.Fatalf("deserialization.json has %d entries, want 14", len(v))
	}
	for _, e := range v {
		var got uint32
		err := Decode(e.Header, func(r *Reader) (err error) {
			got, err = r.Varint()
			return err
		})
		if err != nil || got != e.Length {
			t.Errorf("decode %x = %d, %v; want %d", e.Header, got, err, e.Length)
		}
		var w Writer
		w.Varint(int(e.Length))
		if b, err := w.Bytes(); err != nil || !bytes.Equal(b, e.Header) {
			t.Errorf("encode %d = %x, %v; want %x", e.Length, b, err, e.Header)
		}
	}
	t.Logf("deserialization.json: %d entries checked, 0 skipped", len(v))
}

func TestIntegers(t *testing.T) {
	r := NewReader(unhex(t, "01"+"0203"+"04050607"+"08090a0b0c0d0e0f"))
	a, _ := r.U8()
	b, _ := r.U16()
	c, _ := r.U32()
	d, err := r.U64()
	if err != nil || a != 1 || b != 0x0203 || c != 0x04050607 || d != 0x08090a0b0c0d0e0f || r.Len() != 0 {
		t.Fatalf("got %x %x %x %x %v", a, b, c, d, err)
	}
	var w Writer
	w.U8(a)
	w.U16(b)
	w.U32(c)
	w.U64(d)
	if got, _ := w.Bytes(); hex.EncodeToString(got) != "0102030405060708090a0b0c0d0e0f" {
		t.Fatalf("encode = %x", got)
	}
	for n, f := range map[int]func(*Reader) error{
		1: func(r *Reader) error { _, err := r.U8(); return err },
		2: func(r *Reader) error { _, err := r.U16(); return err },
		4: func(r *Reader) error { _, err := r.U32(); return err },
		8: func(r *Reader) error { _, err := r.U64(); return err },
	} {
		if err := f(NewReader(make([]byte, n-1))); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("%d-byte integer from %d bytes: error = %v", n, n-1, err)
		}
	}
}

func TestOptional(t *testing.T) {
	for in, want := range map[string]bool{"00": false, "01": true} {
		got, err := NewReader(unhex(t, in)).Optional()
		if err != nil || got != want {
			t.Errorf("Optional(%s) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "02", "ff"} {
		if _, err := NewReader(unhex(t, in)).Optional(); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("Optional(%q) error = %v, want ErrMalformed", in, err)
		}
	}
	var w Writer
	w.Optional(false)
	w.Optional(true)
	if got, _ := w.Bytes(); hex.EncodeToString(got) != "0001" {
		t.Fatalf("encode = %x", got)
	}
}

func TestOpaque(t *testing.T) {
	in := unhex(t, "03616263")
	got, err := NewReader(in).Opaque()
	if err != nil || string(got) != "abc" {
		t.Fatalf("Opaque = %q, %v", got, err)
	}
	in[1] = 'x'
	if string(got) != "abc" {
		t.Fatal("decoded bytes alias the input")
	}
	empty, err := NewReader([]byte{0}).Opaque()
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty Opaque = %x, %v", empty, err)
	}
	for _, s := range []string{"05abcd", "4040", "c0"} {
		if _, err := NewReader(unhex(t, s)).Opaque(); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("Opaque(%s) error = %v, want ErrMalformed", s, err)
		}
	}
	if _, err := NewReader(nil).Fixed(-1); !errors.Is(err, errs.ErrMalformed) {
		t.Errorf("Fixed(-1) error = %v", err)
	}
}

func TestSkip(t *testing.T) {
	r := NewReader([]byte{1, 2, 3})
	if err := r.Skip(2); err != nil || r.Len() != 1 {
		t.Fatalf("Skip(2) = %v, %d left", err, r.Len())
	}
	if v, _ := r.U8(); v != 3 {
		t.Fatalf("after Skip read %d", v)
	}
	for _, n := range []int{1, -1} {
		if err := NewReader(nil).Skip(n); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("Skip(%d) on no input: %v", n, err)
		}
	}
}

// A length header of 2^30 - 1 with three bytes behind it must fail without
// allocating the claimed length.
func TestOpaqueHugeLengthNoAlloc(t *testing.T) {
	in := unhex(t, "bfffffff616263")
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := NewReader(in).Opaque()
	runtime.ReadMemStats(&after)
	if !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
	if d := after.TotalAlloc - before.TotalAlloc; d > 1<<20 {
		t.Fatalf("allocated %d bytes for a 7-byte input", d)
	}
}

func readU16s(r *Reader) ([]uint16, error) {
	var out []uint16
	err := r.Vector(func(r *Reader) error {
		v, err := r.U16()
		out = append(out, v)
		return err
	})
	return out, err
}

func TestVector(t *testing.T) {
	r := NewReader(unhex(t, "0400010002ff"))
	got, err := readU16s(r)
	if err != nil || len(got) != 2 || got[0] != 1 || got[1] != 2 || r.Len() != 1 {
		t.Fatalf("Vector = %v, %v, rest %d", got, err, r.Len())
	}
	if got, err := readU16s(NewReader([]byte{0})); err != nil || len(got) != 0 {
		t.Fatalf("empty Vector = %v, %v", got, err)
	}
	// An element that straddles the end of the vector fails even though the
	// outer input has the missing byte.
	if _, err := readU16s(NewReader(unhex(t, "03000100020000"))); !errors.Is(err, errs.ErrMalformed) {
		t.Errorf("straddling element: error = %v", err)
	}
	if _, err := readU16s(NewReader(unhex(t, "05000100"))); !errors.Is(err, errs.ErrMalformed) {
		t.Errorf("truncated vector: error = %v", err)
	}
	if _, err := readU16s(NewReader(unhex(t, "c0"))); !errors.Is(err, errs.ErrMalformed) {
		t.Errorf("bad length: error = %v", err)
	}
	err = NewReader(unhex(t, "0100")).Vector(func(*Reader) error { return nil })
	if !errors.Is(err, errs.ErrMalformed) {
		t.Errorf("element that reads nothing: error = %v", err)
	}
	sentinel := errors.New("element")
	err = NewReader(unhex(t, "0100")).Vector(func(*Reader) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Errorf("element error not returned: %v", err)
	}
}

func TestWriterVector(t *testing.T) {
	var w Writer
	w.Vector(func(w *Writer) {
		w.U16(1)
		w.U16(2)
	})
	w.Vector(func(*Writer) {})
	if got, err := w.Bytes(); err != nil || hex.EncodeToString(got) != "040001000200" {
		t.Fatalf("Vector = %x, %v", got, err)
	}
	var big Writer
	big.Vector(func(w *Writer) { w.Fixed(make([]byte, 64)) })
	if got, _ := big.Bytes(); hex.EncodeToString(got[:2]) != "4040" || len(got) != 66 {
		t.Fatalf("64-byte Vector header = %x", got[:2])
	}
	var inner Writer
	inner.U8(1)
	inner.Vector(func(w *Writer) { w.Varint(-1) })
	if _, err := inner.Bytes(); !errors.Is(err, errs.ErrTooLong) {
		t.Fatalf("inner error = %v, want ErrTooLong", err)
	}
	var outer Writer
	outer.Varint(MaxVarint + 1)
	outer.Vector(func(w *Writer) { w.Varint(-1) })
	if _, err := outer.Bytes(); !errors.Is(err, errs.ErrTooLong) {
		t.Fatalf("outer error = %v, want ErrTooLong", err)
	}
}

func TestDecodeTrailing(t *testing.T) {
	f := func(r *Reader) error { _, err := r.U8(); return err }
	if err := Decode([]byte{1}, f); err != nil {
		t.Fatal(err)
	}
	if err := Decode([]byte{1, 2}, f); !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("trailing byte: error = %v", err)
	}
	if err := Decode(nil, f); !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("short input: error = %v", err)
	}
}

func TestExtensions(t *testing.T) {
	in := unhex(t, "07"+"0001"+"0161"+"f002"+"00")
	exts, err := ReadExtensions(NewReader(in))
	if err != nil || len(exts) != 2 || exts[0].Type != 1 || string(exts[0].Data) != "a" || exts[1].Type != 0xf002 || len(exts[1].Data) != 0 {
		t.Fatalf("ReadExtensions = %+v, %v", exts, err)
	}
	var w Writer
	WriteExtensions(&w, exts)
	if got, _ := w.Bytes(); !bytes.Equal(got, in) {
		t.Fatalf("WriteExtensions = %x, want %x", got, in)
	}
	if _, err := ReadExtensions(NewReader(unhex(t, "08"+"0001"+"0161"+"0001"+"0162"))); !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("duplicate type: error = %v", err)
	}
	for _, s := range []string{"0300010161", "0200", "0100"} {
		if _, err := ReadExtensions(NewReader(unhex(t, s))); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("ReadExtensions(%s) error = %v", s, err)
		}
	}
}

// sink exercises every Reader and Writer operation in one structure.
type sink struct {
	a       uint8
	b       uint16
	c       uint32
	d       uint64
	e       []byte
	hasF    bool
	f       []byte
	g       [][]byte
	h       []Extension
	i       []byte
	varints []uint32
}

func readSink(r *Reader) (*sink, error) {
	var s sink
	var err error
	if s.a, err = r.U8(); err != nil {
		return nil, err
	}
	if s.b, err = r.U16(); err != nil {
		return nil, err
	}
	if s.c, err = r.U32(); err != nil {
		return nil, err
	}
	if s.d, err = r.U64(); err != nil {
		return nil, err
	}
	if s.e, err = r.Opaque(); err != nil {
		return nil, err
	}
	if s.hasF, err = r.Optional(); err != nil {
		return nil, err
	}
	if s.hasF {
		if s.f, err = r.Opaque(); err != nil {
			return nil, err
		}
	}
	err = r.Vector(func(r *Reader) error {
		v, err := r.Opaque()
		s.g = append(s.g, v)
		return err
	})
	if err != nil {
		return nil, err
	}
	if s.h, err = ReadExtensions(r); err != nil {
		return nil, err
	}
	if s.i, err = r.Fixed(4); err != nil {
		return nil, err
	}
	err = r.Vector(func(r *Reader) error {
		v, err := r.Varint()
		s.varints = append(s.varints, v)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *sink) write(w *Writer) {
	w.U8(s.a)
	w.U16(s.b)
	w.U32(s.c)
	w.U64(s.d)
	w.Opaque(s.e)
	w.Optional(s.hasF)
	if s.hasF {
		w.Opaque(s.f)
	}
	w.Vector(func(w *Writer) {
		for _, v := range s.g {
			w.Opaque(v)
		}
	})
	WriteExtensions(w, s.h)
	w.Fixed(s.i)
	w.Vector(func(w *Writer) {
		for _, v := range s.varints {
			w.Varint(int(v))
		}
	})
}

var sinkSeeds = []string{
	"01" + "0002" + "00000003" + "0000000000000004" + "0161" + "01" + "0162" + "040163" + "0164" + "06" + "0001" + "00" + "0002" + "00" + "61626364" + "03" + "00" + "4040",
	"00" + "0000" + "00000000" + "0000000000000000" + "00" + "00" + "00" + "00" + "00000000" + "00",
}

func TestSinkRoundTrip(t *testing.T) {
	for _, s := range sinkSeeds {
		in := unhex(t, s)
		var got *sink
		err := Decode(in, func(r *Reader) (err error) {
			got, err = readSink(r)
			return err
		})
		if err != nil {
			t.Fatalf("decode %s: %v", s, err)
		}
		var w Writer
		got.write(&w)
		if out, err := w.Bytes(); err != nil || !bytes.Equal(out, in) {
			t.Fatalf("re-encode = %x, %v; want %s", out, err, s)
		}
	}
}

// FuzzVarint checks that every accepted varint re-encodes to the bytes read,
// and that every encodable value decodes back to itself.
func FuzzVarint(f *testing.F) {
	for _, s := range []string{"00", "3f", "4040", "7fff", "80004000", "bfffffff", "c0", "4000", "80003fff"} {
		f.Add(unhex(f, s), uint32(0))
	}
	f.Add([]byte{}, uint32(MaxVarint))
	f.Fuzz(func(t *testing.T, in []byte, n uint32) {
		r := NewReader(in)
		if v, err := r.Varint(); err == nil {
			var w Writer
			w.Varint(int(v))
			out, err := w.Bytes()
			if err != nil || !bytes.Equal(out, in[:len(in)-r.Len()]) {
				t.Fatalf("decode %x = %d, re-encode = %x, %v", in, v, out, err)
			}
		}
		n &= MaxVarint
		var w Writer
		w.Varint(int(n))
		enc, err := w.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		r = NewReader(enc)
		if v, err := r.Varint(); err != nil || v != n || r.Len() != 0 {
			t.Fatalf("encode %d = %x, decode = %d, %v", n, enc, v, err)
		}
	})
}

// FuzzReader checks that any input the reader accepts re-encodes to itself.
func FuzzReader(f *testing.F) {
	for _, s := range sinkSeeds {
		f.Add(unhex(f, s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var s *sink
		err := Decode(in, func(r *Reader) (err error) {
			s, err = readSink(r)
			return err
		})
		if err != nil {
			if !errors.Is(err, errs.ErrMalformed) {
				t.Fatalf("error %v is not ErrMalformed", err)
			}
			return
		}
		var w Writer
		s.write(&w)
		out, err := w.Bytes()
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("decode-encode %x = %x, %v", in, out, err)
		}
	})
}
