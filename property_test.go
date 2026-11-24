package kolomls

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
)

// TestRandomHistories runs random group histories of up to 30 members (Adds, Removes,
// Updates, members reopened from their Store, PrivateMessage handshakes on odd seeds). After
// every step the members hold the same state and read each other's messages in random order.
// KOLO_MLS_LONG=1 runs 1,000 histories, 50 otherwise.
func TestRandomHistories(t *testing.T) {
	seeds := 50
	if os.Getenv("KOLO_MLS_LONG") == "1" && !raceEnabled {
		seeds = 1000
	}
	largest, steps, private, apps, reads, replays := 0, 0, 0, 0, 0, 0
	for seed := range seeds {
		r := rand.New(rand.NewPCG(uint64(seed), 9420))
		cfg := testConfig()
		if seed%2 == 1 {
			cfg.PrivateHandshakes = true
			private++
		}
		w := newWorldWith(t, 1+r.IntN(4), cfg)
		for range 10 {
			largest = max(largest, len(w.members))
			steps++
			ls := w.leaves()
			pick := func() uint32 { return ls[r.IntN(len(ls))] }
			committer := pick()
			switch op := r.IntN(7); {
			case (op == 0 || op == 6) && len(ls) < 30:
				w.add(committer, 1+r.IntN(min(8, 30-len(ls))))
			case op == 1 && len(ls) > 1:
				victim := pick()
				for victim == committer {
					victim = pick()
				}
				w.commit(committer, CommitOptions{Remove: []uint32{victim}})
			case op == 2 && len(ls) > 1:
				proposer := pick()
				for proposer == committer {
					proposer = pick()
				}
				ref := w.propose(proposer, func(g *Group) ([]byte, error) { return g.ProposeUpdate(nil) })
				w.commit(committer, CommitOptions{References: [][]byte{ref}})
			case op == 3 && len(ls) > 2:
				proposer, victim := pick(), pick()
				for proposer == committer || victim == committer {
					proposer, victim = pick(), pick()
				}
				ref := w.propose(proposer, func(g *Group) ([]byte, error) { return g.ProposeRemove(victim) })
				w.commit(committer, CommitOptions{References: [][]byte{ref}})
			case op == 4:
				w.reopen(pick())
				continue
			default:
				w.commit(committer, CommitOptions{})
			}
			w.check()
			n, rd, rp := w.chatter(r)
			apps, reads, replays = apps+n, reads+rd, replays+rp
		}
	}
	if private != seeds/2 || (seeds == 1000 && largest != 30) {
		t.Fatalf("largest group %d members, %d private seeds of %d", largest, private, seeds)
	}
	if apps < steps || reads == 0 || replays == 0 {
		t.Fatalf("%d application messages, %d reads, %d replays in %d steps", apps, reads, replays, steps)
	}
	t.Logf("%d seeds (%d private), %d steps, largest group %d members; %d application messages, %d reads, %d replays refused",
		seeds, private, steps, largest, apps, reads, replays)
}

// chatter has a random member send one to four application messages that every other member
// reads in a random order, then gives each member one message again, which it must refuse as a
// replay with its Store unchanged. It returns the counts.
func (w *world) chatter(r *rand.Rand) (sent, read, replayed int) {
	w.t.Helper()
	ls := w.leaves()
	sender := ls[r.IntN(len(ls))]
	var msgs, data [][]byte
	for i := range 1 + r.IntN(4) {
		d := fmt.Appendf(nil, "%d from %d", i, sender)
		msgs, data = append(msgs, w.encrypt(sender, d, d[:1])), append(data, d)
	}
	for _, l := range ls {
		if l == sender {
			continue
		}
		for _, i := range r.Perm(len(msgs)) {
			w.receive(l, sender, msgs[i], data[i], data[i][:1])
			read++
		}
		g := w.members[l].g
		before := snapshotStore(g.st())
		if _, err := g.Process(msgs[r.IntN(len(msgs))]); !errors.Is(err, errs.ErrReplay) || !sameStore(before, snapshotStore(g.st())) {
			w.t.Fatalf("member %d: replay: %v", l, err)
		}
		replayed++
	}
	if read != len(msgs)*(len(ls)-1) || replayed != len(ls)-1 {
		w.t.Fatalf("%d reads and %d replays for %d messages and %d members", read, replayed, len(msgs), len(ls))
	}
	return len(msgs), read, replayed
}
