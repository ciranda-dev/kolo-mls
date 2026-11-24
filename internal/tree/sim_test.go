package tree

import (
	"bytes"
	"crypto/ed25519"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/treemath"
)

// sim drives a whole group in memory: every member's private state follows
// each Commit, so the tests can check the tree invariant of RFC 9420
// section 4.2 after every step.
type sim struct {
	t       testing.TB
	tr      *Tree
	gid     []byte
	epoch   uint64
	sigs    map[uint32]ed25519.PrivateKey
	privs   map[uint32]*Private
	pending map[uint32]bool
}

// testLeaf returns a signed LeafNode with a basic credential of idLen bytes.
func testLeaf(t testing.TB, source uint8, gid []byte, leaf uint32, idLen int) (*LeafNode, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, sig, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	encPriv, encPub, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, idLen)
	copy(id, pub)
	n := &LeafNode{
		EncryptionKey: encPub,
		SignatureKey:  pub,
		Credential:    Credential{Type: CredentialBasic, Identity: id},
		Capabilities:  Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}, Credentials: []uint16{1}},
		Source:        source,
		NotAfter:      1<<64 - 1,
	}
	if source != SourceKeyPackage {
		n.NotAfter = 0
	}
	if err := n.Sign(sig, gid, leaf); err != nil {
		t.Fatal(err)
	}
	return n, sig, encPriv
}

func newSim(t testing.TB) *sim {
	s := &sim{t: t, gid: []byte("group"), sigs: map[uint32]ed25519.PrivateKey{}, privs: map[uint32]*Private{}}
	leaf, sig, enc := testLeaf(t, SourceKeyPackage, nil, 0, 32)
	s.tr = New(leaf)
	s.sigs[0] = sig
	s.privs[0] = &Private{Leaf: 0, Keys: map[uint64][]byte{0: enc}}
	return s
}

func (s *sim) context(th []byte) ([]byte, error) {
	g := schedule.GroupContext{CipherSuite: suite.ID, GroupID: s.gid, Epoch: s.epoch + 1, TreeHash: th}
	return g.Marshal()
}

func (s *sim) add() uint32 {
	leaf, sig, enc := testLeaf(s.t, SourceKeyPackage, nil, 0, 32)
	l, err := s.tr.AddLeaf(leaf)
	if err != nil {
		s.t.Fatal(err)
	}
	s.sigs[l] = sig
	s.privs[l] = &Private{Leaf: l, Keys: map[uint64][]byte{2 * uint64(l): enc}}
	s.pending[l] = true
	return l
}

func (s *sim) update(l uint32) {
	leaf, sig, enc := testLeaf(s.t, SourceUpdate, s.gid, l, 32)
	if err := s.tr.UpdateLeaf(l, leaf); err != nil {
		s.t.Fatal(err)
	}
	s.sigs[l] = sig
	s.privs[l].Keys[2*uint64(l)] = enc
}

func (s *sim) remove(l uint32) {
	if err := s.tr.RemoveLeaf(l); err != nil {
		s.t.Fatal(err)
	}
	delete(s.sigs, l)
	delete(s.privs, l)
}

// commit makes committer send a Commit with a path; new members get the path
// secret of their common ancestor with the committer, as a Welcome gives it.
func (s *sim) commit(committer uint32) {
	t := s.t
	for _, p := range s.privs {
		p.Prune(s.tr)
	}
	path, err := s.tr.CreatePath(committer, nil, s.sigs[committer], s.gid, s.pending, s.context)
	if err != nil {
		t.Fatalf("CreatePath by %d: %v", committer, err)
	}
	th, err := s.tr.TreeHash()
	if err != nil {
		t.Fatal(err)
	}
	gc, err := s.context(th)
	if err != nil {
		t.Fatal(err)
	}
	_, copath, err := s.tr.FilteredDirectPath(committer)
	if err != nil {
		t.Fatal(err)
	}
	for l, p := range s.privs {
		switch {
		case l == committer:
			s.privs[l] = path.Private
		case s.pending[l]:
			k := slices.IndexFunc(copath, func(c uint64) bool { return inSubtree(2*uint64(l), c) })
			ps := path.PathSecrets[k]
			for _, x := range path.FilteredPath[k:] {
				if err := p.SetPathSecret(x, ps); err != nil {
					t.Fatal(err)
				}
				if ps, err = suite.DeriveSecret(ps, "path"); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(ps, path.CommitSecret) {
				t.Fatalf("new member %d derives another commit secret", l)
			}
		default:
			_, cs, next, err := s.tr.DecryptPath(committer, path.UpdatePath, s.pending, gc, p)
			if err != nil {
				t.Fatalf("member %d processing the path of %d: %v", l, committer, err)
			}
			p.Clear()
			s.privs[l] = next
			if !bytes.Equal(cs, path.CommitSecret) {
				t.Fatalf("member %d derives another commit secret", l)
			}
		}
	}
	s.pending = map[uint32]bool{}
	s.epoch++
	s.check()
}

// check verifies the tree as a joiner would, and the tree invariant: a member
// holds the key of exactly its leaf and the non-blank nodes of its direct
// path where it is not unmerged.
func (s *sim) check() {
	t := s.t
	if err := s.tr.Verify(s.gid); err != nil {
		t.Fatalf("epoch %d: %v", s.epoch, err)
	}
	// The cached tree hashes must equal those of a fresh decode.
	b, err := s.tr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := UnmarshalTree(b)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := fresh.TreeHashes()
	got, _ := s.tr.TreeHashes()
	if !slices.EqualFunc(got, want, bytes.Equal) {
		t.Fatalf("epoch %d: cached tree hashes differ from a fresh decode", s.epoch)
	}
	for l, p := range s.privs {
		if err := p.Check(s.tr); err != nil {
			t.Fatalf("epoch %d member %d: %v", s.epoch, l, err)
		}
		d, err := treemath.DirectPath(2*uint64(l), s.tr.Leaves())
		if err != nil {
			t.Fatal(err)
		}
		for x := range p.Keys {
			if x != 2*uint64(l) && !slices.Contains(d, x) {
				t.Fatalf("epoch %d: member %d holds the key of node %d outside its direct path", s.epoch, l, x)
			}
		}
		if p.Keys[2*uint64(l)] == nil {
			t.Fatalf("epoch %d: member %d lost its leaf key", s.epoch, l)
		}
		for _, x := range d {
			parent := s.tr.Node(x).Parent
			if parent == nil {
				continue
			}
			want := !slices.Contains(parent.UnmergedLeaves, l)
			if has := p.Keys[x] != nil; has != want {
				t.Fatalf("epoch %d: member %d key of node %d: has %v, want %v", s.epoch, l, x, has, want)
			}
		}
	}
}

func (s *sim) members() []uint32 {
	var out []uint32
	for l := range s.privs {
		out = append(out, l)
	}
	slices.Sort(out)
	return out
}

// TestTreeInvariant runs random Commits with Updates, Removes and Adds and
// checks the tree and every member's keys after each one.
func TestTreeInvariant(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	s := newSim(t)
	s.pending = map[uint32]bool{}
	for range 4 {
		s.add()
	}
	s.commit(0)
	maxMembers := 0
	for range 60 {
		m := s.members()
		committer := m[r.IntN(len(m))]
		for _, l := range m {
			if l == committer {
				continue
			}
			switch r.IntN(12) {
			case 0:
				s.update(l)
			case 1:
				if len(s.privs) > 2 {
					s.remove(l)
				}
			}
		}
		for range r.IntN(4) {
			s.add()
		}
		s.commit(committer)
		maxMembers = max(maxMembers, len(s.privs))
	}
	t.Logf("60 commits, up to %d members; final group of %d members in a tree of %d leaves", maxMembers, len(s.privs), s.tr.Leaves())
}
