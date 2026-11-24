package braid

import (
	"bytes"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/kolotest"
	"github.com/ciranda-dev/kolo-mls/settle"
)

func key(b byte) [32]byte { return [32]byte{b} }

func keys(bs ...byte) [][32]byte {
	var out [][32]byte
	for _, b := range bs {
		out = append(out, key(b))
	}
	return out
}

func TestDecide(t *testing.T) {
	r := &settle.Roles{Quorum: settle.Majority, Admins: keys(1, 2, 3, 4, 9), Settlers: keys(1, 2, 3, 4)}
	ctx := key(0xcc)
	ref := func(pos uint64, w byte, c byte) Ref { return Ref{Position: pos, Writer: key(w), Commit: key(c)} }
	vote := func(pos uint64, w byte, c byte, accept bool) Vote {
		return Vote{Position: pos, Writer: key(w), Commit: key(c), ContextBefore: ctx, Accept: accept}
	}
	cases := []struct {
		name      string
		refs      []Ref
		votes     []Vote
		decided   byte
		candidate byte
	}{
		{"nothing", nil, nil, 0, 0},
		{"no votes", []Ref{ref(1, 1, 0xa)}, nil, 0, 0xa},
		{"q accepts", []Ref{ref(1, 1, 0xa)}, []Vote{vote(2, 1, 0xa, true), vote(3, 2, 0xa, true), vote(4, 3, 0xa, true)}, 0xa, 0},
		{"q - 1 accepts", []Ref{ref(1, 1, 0xa)}, []Vote{vote(2, 1, 0xa, true), vote(3, 2, 0xa, true)}, 0, 0xa},
		{"r rejects then the next", []Ref{ref(1, 1, 0xa), ref(2, 2, 0xb)}, []Vote{vote(3, 1, 0xa, false), vote(4, 2, 0xa, false), vote(5, 1, 0xb, true), vote(6, 2, 0xb, true), vote(7, 3, 0xb, true)}, 0xb, 0},
		{"undecided blocks a later accepted", []Ref{ref(1, 1, 0xa), ref(2, 2, 0xb)}, []Vote{vote(3, 1, 0xb, true), vote(4, 2, 0xb, true), vote(5, 3, 0xb, true)}, 0, 0xa},
		{"vote before its reference", []Ref{ref(5, 1, 0xa)}, []Vote{vote(2, 1, 0xa, true), vote(3, 2, 0xa, true), vote(6, 3, 0xa, true)}, 0, 0xa},
		{"vote of a non-settler", []Ref{ref(1, 1, 0xa)}, []Vote{vote(2, 9, 0xa, true), vote(3, 2, 0xa, true), vote(4, 3, 0xa, true)}, 0, 0xa},
		{"vote on another context", []Ref{ref(1, 1, 0xa)}, []Vote{{Position: 2, Writer: key(1), Commit: key(0xa), Accept: true}, vote(3, 2, 0xa, true), vote(4, 3, 0xa, true)}, 0, 0xa},
		{"one vote per settler", []Ref{ref(1, 1, 0xa)}, []Vote{vote(2, 1, 0xa, true), vote(3, 1, 0xa, true), vote(4, 2, 0xa, true)}, 0, 0xa},
		{"first vote counts", []Ref{ref(1, 1, 0xa)}, []Vote{vote(2, 1, 0xa, false), vote(3, 1, 0xa, true), vote(4, 2, 0xa, true), vote(5, 3, 0xa, true)}, 0, 0xa},
		{"reference of a non-admin", []Ref{ref(1, 7, 0xa), ref(2, 1, 0xb)}, []Vote{vote(3, 1, 0xa, true), vote(4, 2, 0xa, true), vote(5, 3, 0xa, true)}, 0, 0xb},
		{"a Commit referenced twice counts once", []Ref{ref(1, 1, 0xa), ref(2, 2, 0xa), ref(3, 2, 0xb)}, []Vote{vote(4, 1, 0xa, false), vote(5, 2, 0xa, false)}, 0, 0xb},
		{"an admin's reference before its last one was rejected does not count", []Ref{ref(1, 1, 0xa), ref(2, 1, 0xb)}, []Vote{vote(3, 1, 0xa, false), vote(4, 2, 0xa, false), vote(5, 1, 0xb, true), vote(6, 2, 0xb, true), vote(7, 3, 0xb, true)}, 0, 0},
		{"an admin's reference after the rejection counts", []Ref{ref(1, 1, 0xa), ref(5, 1, 0xb)}, []Vote{vote(3, 1, 0xa, false), vote(4, 2, 0xa, false), vote(6, 1, 0xb, true), vote(7, 2, 0xb, true), vote(8, 3, 0xb, true)}, 0xb, 0},
		{"another admin's reference between counts", []Ref{ref(1, 1, 0xa), ref(2, 1, 0xb), ref(3, 2, 0xc)}, []Vote{vote(4, 1, 0xa, false), vote(5, 2, 0xa, false), vote(6, 1, 0xc, true), vote(7, 2, 0xc, true), vote(8, 3, 0xc, true)}, 0xc, 0},
		{"a rejected Commit referenced again stays rejected", []Ref{ref(1, 1, 0xa), ref(2, 1, 0xb), ref(9, 2, 0xa)}, []Vote{vote(3, 1, 0xa, false), vote(4, 2, 0xa, false), vote(5, 1, 0xb, false), vote(6, 2, 0xb, false), vote(10, 3, 0xa, true), vote(11, 4, 0xa, true), vote(12, 1, 0xa, true)}, 0, 0},
	}
	for _, c := range cases {
		d := Decide(c.refs, c.votes, r, ctx)
		var dec, cand byte
		if d.Decided != nil {
			dec = d.Decided.Commit[0]
		}
		if d.Candidate != nil {
			cand = d.Candidate.Commit[0]
		}
		if dec != c.decided || cand != c.candidate {
			t.Errorf("%s: decided %x, candidate %x", c.name, dec, cand)
		}
	}
	d := Decide([]Ref{ref(1, 1, 0xa), ref(2, 2, 0xb)}, []Vote{vote(3, 1, 0xa, false), vote(4, 2, 0xa, false), vote(5, 1, 0xb, false), vote(6, 3, 0xb, false)}, r, ctx)
	if len(d.Rejected) != 2 || d.Rejected[0] != key(0xa) || d.Rejected[1] != key(0xb) || d.Candidate != nil || d.Decided != nil {
		t.Fatalf("rejected %v", d.Rejected)
	}
	d = Decide([]Ref{ref(1, 1, 0xa)}, []Vote{vote(2, 2, 0xa, true), vote(3, 2, 0xa, false), vote(4, 9, 0xa, true), vote(5, 9, 0xa, false)}, r, ctx)
	if len(d.Equivocators) != 1 || d.Equivocators[0] != key(2) || !d.Voted[key(2)] {
		t.Fatalf("equivocators %v", d.Equivocators)
	}
}

// TestSignValid: a share made by Sign counts in Settled.Valid for its TBS
// only.
func TestSignValid(t *testing.T) {
	id := kolotest.Person(t)
	k := [32]byte(id.PublicKey())
	roles := &settle.Roles{Settlers: [][32]byte{k}, Admins: [][32]byte{k}}
	tbs := &settle.TBS{GroupID: bytes.Repeat([]byte{1}, 32), Epoch: 3, Commit: [32]byte{2}, RefPosition: 9}
	sig, err := Sign(id, tbs)
	if err != nil {
		t.Fatal(err)
	}
	s := &settle.Settled{TBS: *tbs, Shares: []settle.Share{{Signer: k, Signature: [64]byte(sig)}}}
	all := func([32]byte) bool { return true }
	if s.Valid(roles, all) != 1 {
		t.Fatal("a share of Sign is not valid")
	}
	s.TBS.RefPosition++
	if s.Valid(roles, all) != 0 {
		t.Fatal("a share is valid for another TBS")
	}
	if _, err := Sign(nil, tbs); err == nil {
		t.Fatal("Sign without an identity")
	}
	if d := Decide(nil, nil, nil, [32]byte{}); d.Decided != nil || d.Candidate != nil {
		t.Fatal("a decision without roles")
	}
}
