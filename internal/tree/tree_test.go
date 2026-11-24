package tree

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

func mustTree(t testing.TB, b []byte) *Tree {
	t.Helper()
	tr, err := UnmarshalTree(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := tr.Marshal()
	if err != nil || !bytes.Equal(out, b) {
		t.Fatalf("ratchet_tree does not re-encode to itself: %v", err)
	}
	return tr
}

// applyProposal applies an Add, Update or Remove Proposal to tr. It reads the
// KeyPackage of an Add only far enough to take its LeafNode; package kolomls brings
// the real Proposal and KeyPackage decoders.
func applyProposal(tr *Tree, b []byte, sender uint32) error {
	r := tls.NewReader(b)
	typ, err := r.U16()
	if err != nil {
		return err
	}
	switch typ {
	case 1:
		if _, err := r.U16(); err != nil {
			return err
		}
		if _, err := r.U16(); err != nil {
			return err
		}
		if _, err := r.Opaque(); err != nil {
			return err
		}
		leaf, err := ReadLeafNode(r)
		if err != nil {
			return err
		}
		if _, err := tls.ReadExtensions(r); err != nil {
			return err
		}
		if _, err := r.Opaque(); err != nil {
			return err
		}
		_, err = tr.AddLeaf(leaf)
		if err != nil {
			return err
		}
	case 2:
		leaf, err := ReadLeafNode(r)
		if err != nil {
			return err
		}
		if err := tr.UpdateLeaf(sender, leaf); err != nil {
			return err
		}
	case 3:
		removed, err := r.U32()
		if err != nil {
			return err
		}
		if err := tr.RemoveLeaf(removed); err != nil {
			return err
		}
	default:
		return fmt.Errorf("proposal type %d", typ)
	}
	if r.Len() != 0 {
		return errors.New("trailing bytes after the proposal")
	}
	return nil
}

func TestTreeOperationsVectors(t *testing.T) {
	var v []struct {
		CipherSuite    uint16      `json:"cipher_suite"`
		TreeBefore     testvec.Hex `json:"tree_before"`
		Proposal       testvec.Hex `json:"proposal"`
		ProposalSender uint32      `json:"proposal_sender"`
		TreeHashBefore testvec.Hex `json:"tree_hash_before"`
		TreeAfter      testvec.Hex `json:"tree_after"`
		TreeHashAfter  testvec.Hex `json:"tree_hash_after"`
	}
	testvec.Load(t, "tree-operations.json", &v)
	checked := 0
	for i, e := range v {
		if e.CipherSuite != suite.ID {
			t.Fatalf("entry %d has cipher suite %d", i, e.CipherSuite)
		}
		checked++
		tr := mustTree(t, e.TreeBefore)
		if h, err := tr.TreeHash(); err != nil || !bytes.Equal(h, e.TreeHashBefore) {
			t.Errorf("entry %d: tree hash before = %x, %v", i, h, err)
		}
		if err := applyProposal(tr, e.Proposal, e.ProposalSender); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if b, err := tr.Marshal(); err != nil || !bytes.Equal(b, e.TreeAfter) {
			t.Errorf("entry %d: tree after differs: %v", i, err)
		}
		if h, err := tr.TreeHash(); err != nil || !bytes.Equal(h, e.TreeHashAfter) {
			t.Errorf("entry %d: tree hash after = %x, %v", i, h, err)
		}
	}
	if checked != 5 {
		t.Fatalf("tree-operations.json: %d suite 1 entries, want 5", checked)
	}
	t.Logf("tree-operations.json: %d suite 1 entries checked, 0 skipped", checked)
}

func TestTreeValidationVectors(t *testing.T) {
	var v []struct {
		CipherSuite uint16        `json:"cipher_suite"`
		Tree        testvec.Hex   `json:"tree"`
		GroupID     testvec.Hex   `json:"group_id"`
		Resolutions [][]uint64    `json:"resolutions"`
		TreeHashes  []testvec.Hex `json:"tree_hashes"`
	}
	testvec.Load(t, "tree-validation.json", &v)
	checked, skipped := 0, 0
	for i, e := range v {
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		checked++
		tr := mustTree(t, e.Tree)
		if uint64(len(e.Resolutions)) != tr.Width() || uint64(len(e.TreeHashes)) != tr.Width() {
			t.Fatalf("entry %d: %d resolutions, %d hashes for %d nodes", i, len(e.Resolutions), len(e.TreeHashes), tr.Width())
		}
		for x, want := range e.Resolutions {
			if got := tr.Resolution(uint64(x), nil); !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
				t.Errorf("entry %d: resolution(%d) = %v, want %v", i, x, got, want)
			}
		}
		hashes, err := tr.TreeHashes()
		if err != nil {
			t.Fatal(err)
		}
		for x, want := range e.TreeHashes {
			if !bytes.Equal(hashes[x], want) {
				t.Errorf("entry %d: tree hash of node %d = %x, want %x", i, x, hashes[x], want)
			}
		}
		if err := tr.Verify(e.GroupID); err != nil {
			t.Errorf("entry %d: Verify: %v", i, err)
		}
	}
	if checked != 14 || skipped != 84 {
		t.Fatalf("tree-validation.json: %d suite 1 entries, %d skipped; want 14 and 84", checked, skipped)
	}
	t.Logf("tree-validation.json: %d suite 1 entries checked, 0 suite 1 skipped, %d other-suite entries skipped", checked, skipped)
}

type treeKEMVector struct {
	CipherSuite             uint16      `json:"cipher_suite"`
	GroupID                 testvec.Hex `json:"group_id"`
	Epoch                   uint64      `json:"epoch"`
	ConfirmedTranscriptHash testvec.Hex `json:"confirmed_transcript_hash"`
	RatchetTree             testvec.Hex `json:"ratchet_tree"`
	LeavesPrivate           []struct {
		Index          uint32      `json:"index"`
		EncryptionPriv testvec.Hex `json:"encryption_priv"`
		SignaturePriv  testvec.Hex `json:"signature_priv"`
		PathSecrets    []struct {
			Node       uint64      `json:"node"`
			PathSecret testvec.Hex `json:"path_secret"`
		} `json:"path_secrets"`
	} `json:"leaves_private"`
	UpdatePaths []struct {
		Sender        uint32        `json:"sender"`
		UpdatePath    testvec.Hex   `json:"update_path"`
		PathSecrets   []testvec.Hex `json:"path_secrets"`
		CommitSecret  testvec.Hex   `json:"commit_secret"`
		TreeHashAfter testvec.Hex   `json:"tree_hash_after"`
	} `json:"update_paths"`
}

// clonePrivate copies the keys too: DecryptPath zeroes the keys it replaces.
func clonePrivate(p *Private) *Private {
	c := &Private{Leaf: p.Leaf, Keys: map[uint64][]byte{}}
	for x, k := range p.Keys {
		c.Keys[x] = bytes.Clone(k)
	}
	return c
}

func TestTreeKEMVectors(t *testing.T) {
	var v []treeKEMVector
	testvec.Load(t, "treekem.json", &v)
	checked, skipped, paths, decrypts := 0, 0, 0, 0
	for i, e := range v {
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		checked++
		tr := mustTree(t, e.RatchetTree)
		privs := map[uint32]*Private{}
		sigs := map[uint32]ed25519.PrivateKey{}
		for _, lp := range e.LeavesPrivate {
			p := &Private{Leaf: lp.Index, Keys: map[uint64][]byte{2 * uint64(lp.Index): lp.EncryptionPriv}}
			for _, ps := range lp.PathSecrets {
				if err := p.SetPathSecret(ps.Node, ps.PathSecret); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.Check(tr); err != nil {
				t.Fatalf("entry %d leaf %d: private state: %v", i, lp.Index, err)
			}
			privs[lp.Index] = p
			sigs[lp.Index] = ed25519.NewKeyFromSeed(lp.SignaturePriv)
		}
		context := func(th []byte) ([]byte, error) {
			g := schedule.GroupContext{CipherSuite: e.CipherSuite, GroupID: e.GroupID, Epoch: e.Epoch, TreeHash: th, ConfirmedTranscriptHash: e.ConfirmedTranscriptHash}
			return g.Marshal()
		}
		for k, up := range e.UpdatePaths {
			paths++
			var u *UpdatePath
			err := tls.Decode(up.UpdatePath, func(r *tls.Reader) (err error) {
				u, err = ReadUpdatePath(r)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			var w tls.Writer
			u.Write(&w)
			if b, _ := w.Bytes(); !bytes.Equal(b, up.UpdatePath) {
				t.Fatalf("entry %d path %d: UpdatePath does not re-encode", i, k)
			}
			merged := tr.Clone()
			if err := merged.Merge(up.Sender, u); err != nil {
				t.Fatalf("entry %d path %d: Merge: %v", i, k, err)
			}
			if !u.Leaf.VerifySignature(e.GroupID, up.Sender) {
				t.Errorf("entry %d path %d: leaf signature", i, k)
			}
			th, err := merged.TreeHash()
			if err != nil || !bytes.Equal(th, up.TreeHashAfter) {
				t.Errorf("entry %d path %d: tree hash after = %x, %v", i, k, th, err)
			}
			gc, _ := context(th)
			for j, p := range privs {
				if j == up.Sender || tr.Leaf(j) == nil {
					continue
				}
				decrypts++
				ps, cs, _, err := merged.DecryptPath(up.Sender, u, nil, gc, p)
				if err != nil {
					t.Fatalf("entry %d path %d leaf %d: %v", i, k, j, err)
				}
				if !bytes.Equal(ps, up.PathSecrets[j]) || !bytes.Equal(cs, up.CommitSecret) {
					t.Errorf("entry %d path %d leaf %d: path secret %x commit secret %x", i, k, j, ps, cs)
				}
			}

			created := tr.Clone()
			np, err := created.CreatePath(up.Sender, nil, sigs[up.Sender], e.GroupID, nil, context)
			if err != nil {
				t.Fatalf("entry %d path %d: CreatePath: %v", i, k, err)
			}
			if err := created.Verify(e.GroupID); err != nil {
				t.Errorf("entry %d path %d: tree after CreatePath: %v", i, k, err)
			}
			if err := np.Private.Check(created); err != nil {
				t.Errorf("entry %d path %d: committer state: %v", i, k, err)
			}
			nth, _ := created.TreeHash()
			ngc, _ := context(nth)
			for j, p := range privs {
				if j == up.Sender || tr.Leaf(j) == nil {
					continue
				}
				_, cs, q, err := created.DecryptPath(up.Sender, np.UpdatePath, nil, ngc, p)
				if err != nil || !bytes.Equal(cs, np.CommitSecret) {
					t.Fatalf("entry %d path %d leaf %d: new path: %x, %v", i, k, j, cs, err)
				}
				q.Prune(created)
				if err := q.Check(created); err != nil {
					t.Errorf("entry %d path %d leaf %d: state after new path: %v", i, k, j, err)
				}
			}
		}
	}
	if checked != 11 || skipped != 66 {
		t.Fatalf("treekem.json: %d suite 1 entries, %d skipped; want 11 and 66", checked, skipped)
	}
	t.Logf("treekem.json: %d suite 1 entries (%d update paths, %d decryptions) checked, 0 suite 1 skipped, %d other-suite entries skipped", checked, paths, decrypts, skipped)
}
