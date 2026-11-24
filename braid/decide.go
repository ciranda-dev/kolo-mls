package braid

import (
	"crypto/ed25519"
	"fmt"

	koloid "github.com/ciranda-dev/kolo-id"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// Reason says why a settler votes against a Commit.
type Reason uint8

// Vote reasons; an accept vote has none.
const (
	ReasonNone        Reason = 0
	ReasonInvalid     Reason = 1
	ReasonUnavailable Reason = 2
)

// Ref is a settled commit-ref entry of one epoch: an admin's reference to a
// Commit kept on pins.
type Ref struct {
	// Position is the entry's settled position in the braid.
	Position uint64
	// Writer is the admin device that wrote it.
	Writer [32]byte
	// Commit is the SHA-256 of the Commit's MLSMessage.
	Commit [32]byte
	// Cert is the SHA-256 of the writer's device certificate the entry
	// carries.
	Cert [32]byte
}

// Vote is a settled commit-vote entry of one epoch.
type Vote struct {
	Position      uint64
	Writer        [32]byte
	Commit        [32]byte
	ContextBefore [32]byte
	Accept        bool
	Reason        Reason
	Cert          [32]byte
}

// Decision is the state of an epoch's decision over its settled entries.
type Decision struct {
	// Decided is the epoch's Commit, nil while none is decided.
	Decided *Ref
	// Candidate is the first reference not yet decided, nil when there is
	// none or once one is decided.
	Candidate *Ref
	// Voted holds the settlers whose vote on the candidate counted.
	Voted map[[32]byte]bool
	// Rejected are the Commits rejected before the candidate or decision.
	Rejected [][32]byte
	// Equivocators are the settlers that cast both an accept and a reject
	// vote on one Commit, in key order.
	Equivocators [][32]byte
}

// Decide computes an epoch's decision from its settled references and votes
// in settled order; the rules are in docs/design.md, "The Kolo layer".
func Decide(refs []Ref, votes []Vote, roles *settle.Roles, contextBefore [32]byte) Decision {
	if roles == nil {
		return Decision{}
	}
	byCommit := map[[32]byte][]Vote{}
	for _, v := range votes {
		byCommit[v.Commit] = append(byCommit[v.Commit], v)
	}
	d := decide(refs, byCommit, roles, contextBefore)
	d.Equivocators = equivocators(votes, roles)
	return d
}

func equivocators(votes []Vote, roles *settle.Roles) [][32]byte {
	type key struct{ w, c [32]byte }
	first := map[key]bool{}
	bad := map[[32]byte]bool{}
	for _, v := range votes {
		if !roles.Settler(v.Writer[:]) {
			continue
		}
		k := key{v.Writer, v.Commit}
		if a, ok := first[k]; ok && a != v.Accept {
			bad[v.Writer] = true
		} else if !ok {
			first[k] = v.Accept
		}
	}
	var out [][32]byte
	for _, k := range roles.Settlers {
		if bad[k] {
			out = append(out, k)
		}
	}
	return out
}

func decide(refs []Ref, byCommit map[[32]byte][]Vote, roles *settle.Roles, contextBefore [32]byte) Decision {
	q, r := roles.Q(), roles.RejectQuorum()
	seen := map[[32]byte]bool{}
	// An admin's reference counts only when it is ordered after the vote
	// that rejected its previous one, so one admin holds at most one
	// candidate at a time and costs the epoch one fetch timeout per round.
	free := map[[32]byte]uint64{}
	var rejected [][32]byte
	for i := range refs {
		ref := &refs[i]
		if p, busy := free[ref.Writer]; !roles.Admin(ref.Writer[:]) || seen[ref.Commit] || (busy && ref.Position <= p) {
			continue
		}
		seen[ref.Commit] = true
		accept, reject := 0, 0
		var at uint64
		voted := map[[32]byte]bool{}
		for _, v := range byCommit[ref.Commit] {
			if v.Position <= ref.Position || voted[v.Writer] || !roles.Settler(v.Writer[:]) || v.ContextBefore != contextBefore {
				continue
			}
			voted[v.Writer] = true
			if v.Accept {
				accept++
			} else if reject++; reject == r {
				at = v.Position
			}
		}
		switch {
		case accept >= q:
			return Decision{Decided: ref, Voted: voted, Rejected: rejected}
		case reject >= r:
			rejected = append(rejected, ref.Commit)
			free[ref.Writer] = at
		default:
			return Decision{Candidate: ref, Voted: voted, Rejected: rejected}
		}
	}
	return Decision{Rejected: rejected}
}

// Sign returns a settler's signature over t with its device identity.
func Sign(id *koloid.Identity, t *settle.TBS) ([]byte, error) {
	if id == nil || t == nil {
		return nil, fmt.Errorf("%w: no identity or TBS", errs.ErrInvalidArgument)
	}
	return id.Sign(settle.SettledContext, t.Encode())
}

// Assemble returns the SettledCommit of t from shares, keeping one valid
// share per settler of roles, in signer order.
func Assemble(t *settle.TBS, shares []settle.Share, roles *settle.Roles) *settle.Settled {
	if t == nil || roles == nil {
		return &settle.Settled{}
	}
	tbs := t.Encode()
	byKey := map[[32]byte]settle.Share{}
	for _, sh := range shares {
		if _, ok := byKey[sh.Signer]; ok || !roles.Settler(sh.Signer[:]) {
			continue
		}
		if koloid.Verify(ed25519.PublicKey(sh.Signer[:]), settle.SettledContext, tbs, sh.Signature[:]) {
			byKey[sh.Signer] = sh
		}
	}
	s := &settle.Settled{TBS: *t}
	for _, k := range roles.Settlers {
		if sh, ok := byKey[k]; ok {
			s.Shares = append(s.Shares, sh)
		}
	}
	return s
}
