package secrettree

import (
	"math/bits"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func heapBytes() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestMeasure prints the heap of a receiver's secret tree for the member
// counts in KOLO_MLS_MEASURE (for example "1024,100000"): after New, after
// one message from every member, and in the worst case where both ratchets
// of every member hold the most out-of-order keys the default window keeps.
func TestMeasure(t *testing.T) {
	spec := os.Getenv("KOLO_MLS_MEASURE")
	if spec == "" {
		t.Skip("set KOLO_MLS_MEASURE to a list of member counts to measure")
	}
	for _, f := range strings.Split(spec, ",") {
		m, err := strconv.Atoi(f)
		if err != nil || m < 1 || int64(m) > 1<<31 {
			t.Fatalf("bad member count %q", f)
		}
		n := uint32(1) << bits.Len32(uint32(m-1))
		base := heapBytes()
		tr := mustNew(t, n, Options{})
		h0 := heapBytes() - base
		start := time.Now()
		for l := range uint32(m) {
			if _, _, err := tr.Key(l, Application, 0); err != nil {
				t.Fatal(err)
			}
		}
		first := time.Since(start)
		h1 := heapBytes() - base
		tol := DefaultOutOfOrderTolerance
		start = time.Now()
		for l := range uint32(m) {
			if _, _, err := tr.Key(l, Application, tol); err != nil {
				t.Fatal(err)
			}
			if _, _, err := tr.Key(l, Handshake, tol-1); err != nil {
				t.Fatal(err)
			}
		}
		worst := time.Since(start)
		h2 := heapBytes() - base
		r := tr.leaves[0].r
		if len(r[Application].held) != int(tol-1) || len(r[Handshake].held) != int(tol-1) {
			t.Fatalf("held %d and %d keys", len(r[Application].held), len(r[Handshake].held))
		}
		t.Logf("members %d leaves %d, %d nodes kept: New %d B; one message each %d B (%d B/member, %v); worst %d B (%d B/member, %d held keys each, %v)",
			m, n, len(tr.nodes), h0, h1, h1/uint64(m), first, h2, h2/uint64(m), 2*(tol-1), worst)
		runtime.KeepAlive(tr)
	}
}
