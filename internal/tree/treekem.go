package tree

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/treemath"
)

// HPKECiphertext is an MLS HPKECiphertext (RFC 9420 section 7.6).
type HPKECiphertext struct {
	KEMOutput  []byte
	Ciphertext []byte
}

// Smallest sizes in every registered cipher suite (RFC 9420 section 17.1):
// public keys and kem_output 32 bytes (X25519), AEAD tags 16. Decoders refuse
// shorter values so that tiny elements cannot inflate memory.
const (
	minKey        = 32
	minCiphertext = 16
)

func readMin(r *tls.Reader, n int) ([]byte, error) {
	b, err := r.Opaque()
	if err == nil && len(b) < n {
		err = fmt.Errorf("%w: %d bytes, below the %d of every cipher suite", errs.ErrMalformed, len(b), n)
	}
	return b, err
}

// ReadHPKECiphertext reads an HPKECiphertext.
func ReadHPKECiphertext(r *tls.Reader) (HPKECiphertext, error) {
	var c HPKECiphertext
	var err error
	if c.KEMOutput, err = readMin(r, minKey); err != nil {
		return c, err
	}
	c.Ciphertext, err = readMin(r, minCiphertext)
	return c, err
}

// UpdatePathNode is an MLS UpdatePathNode (RFC 9420 section 7.6).
type UpdatePathNode struct {
	EncryptionKey []byte
	Secrets       []HPKECiphertext
}

// UpdatePath is an MLS UpdatePath (RFC 9420 section 7.6).
type UpdatePath struct {
	Leaf  *LeafNode
	Nodes []UpdatePathNode
}

// Write appends the encoding of u to w.
func (u *UpdatePath) Write(w *tls.Writer) {
	u.Leaf.Write(w)
	w.Vector(func(w *tls.Writer) {
		for _, n := range u.Nodes {
			w.Opaque(n.EncryptionKey)
			w.Vector(func(w *tls.Writer) {
				for _, c := range n.Secrets {
					w.Opaque(c.KEMOutput)
					w.Opaque(c.Ciphertext)
				}
			})
		}
	})
}

// ReadUpdatePath reads an UpdatePath.
func ReadUpdatePath(r *tls.Reader) (*UpdatePath, error) {
	var u UpdatePath
	var err error
	if u.Leaf, err = ReadLeafNode(r); err != nil {
		return nil, err
	}
	err = r.Vector(func(r *tls.Reader) error {
		var n UpdatePathNode
		var err error
		if n.EncryptionKey, err = readMin(r, minKey); err != nil {
			return err
		}
		err = r.Vector(func(r *tls.Reader) error {
			c, err := ReadHPKECiphertext(r)
			n.Secrets = append(n.Secrets, c)
			return err
		})
		u.Nodes = append(u.Nodes, n)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func nodeKeys(u *UpdatePath) [][]byte {
	out := make([][]byte, len(u.Nodes))
	for i, n := range u.Nodes {
		out[i] = n.EncryptionKey
	}
	return out
}

// Private is a member's private TreeKEM state: its leaf and the HPKE private
// keys it holds, by node index.
type Private struct {
	Leaf uint32
	Keys map[uint64][]byte
}

// Clone returns a copy that shares no key bytes with p.
func (p *Private) Clone() *Private {
	c := &Private{Leaf: p.Leaf, Keys: make(map[uint64][]byte, len(p.Keys))}
	for x, k := range p.Keys {
		c.Keys[x] = bytes.Clone(k)
	}
	return c
}

// Clear zeroes and drops every key.
func (p *Private) Clear() {
	for x, k := range p.Keys {
		clear(k)
		delete(p.Keys, x)
	}
}

// nodeKey derives the node key pair of a path secret (RFC 9420 section 7.4).
func nodeKey(pathSecret []byte) (priv, pub []byte, err error) {
	s, err := suite.DeriveSecret(pathSecret, "node")
	if err != nil {
		return nil, nil, err
	}
	defer clear(s)
	return suite.DeriveKeyPair(s)
}

// SetPathSecret stores the private key that the path secret of node x gives.
func (p *Private) SetPathSecret(x uint64, pathSecret []byte) error {
	if len(pathSecret) != suite.Nh {
		return fmt.Errorf("%w: path secret of %d bytes", errs.ErrInvalidArgument, len(pathSecret))
	}
	priv, _, err := nodeKey(pathSecret)
	if err != nil {
		return err
	}
	if p.Keys == nil {
		p.Keys = map[uint64][]byte{}
	}
	clear(p.Keys[x])
	p.Keys[x] = priv
	return nil
}

// Check reports an error unless every private key matches the public key of
// a non-blank node of t.
func (p *Private) Check(t *Tree) error {
	for x, priv := range p.Keys {
		if x >= t.Width() {
			return fmt.Errorf("%w: private key for node %d outside the tree", errs.ErrInvalidTree, x)
		}
		pub, err := suite.PublicKey(priv)
		if err != nil {
			return err
		}
		if want := t.encryptionKey(x); want == nil || !bytes.Equal(pub, want) {
			return fmt.Errorf("%w: private key for node %d does not match", errs.ErrInvalidTree, x)
		}
	}
	return nil
}

func (t *Tree) encryptionKey(x uint64) []byte {
	switch n := t.nodes[x]; {
	case n.Leaf != nil:
		return n.Leaf.EncryptionKey
	case n.Parent != nil:
		return n.Parent.EncryptionKey
	}
	return nil
}

// Prune deletes the keys of nodes that are blank or outside t, as a member
// must after proposals blank them (RFC 9420 section 7.5).
func (p *Private) Prune(t *Tree) {
	for x, k := range p.Keys {
		if x >= t.Width() || t.Node(x).Blank() {
			clear(k)
			delete(p.Keys, x)
		}
	}
}

// setPath blanks the direct path of leaf l, sets the filtered direct path to
// keys with parent hashes chained from the root down and no unmerged leaves,
// and returns the parent hash the leaf must carry (RFC 9420 sections 7.5, 7.9).
func (t *Tree) setPath(l uint32, path, copath []uint64, keys [][]byte) ([]byte, error) {
	// Copath subtrees are off the direct path, so their hashes do not change.
	nodes := make([]*ParentNode, len(path))
	ph := []byte{}
	for i := len(path) - 1; i >= 0; i-- {
		nodes[i] = &ParentNode{EncryptionKey: keys[i], ParentHash: ph}
		sh, err := t.hash(copath[i], nil)
		if err != nil {
			return nil, err
		}
		if ph, err = parentHash(nodes[i], sh); err != nil {
			return nil, err
		}
	}
	if err := t.blankDirectPath(l); err != nil {
		return nil, err
	}
	for i, x := range path {
		t.set(x, Node{Parent: nodes[i]})
	}
	return ph, nil
}

// Merge applies the UpdatePath u of leaf sender to t, which holds the Commit's
// proposals, with the checks of RFC 9420 sections 7.5 and 12.4.2 on its keys
// and parent hash; the leaf signature is the caller's. On error t is half
// changed: use a Clone.
func (t *Tree) Merge(sender uint32, u *UpdatePath) error {
	if t.Leaf(sender) == nil {
		return fmt.Errorf("%w: sender leaf %d is blank", errs.ErrInvalidCommit, sender)
	}
	path, copath, err := t.FilteredDirectPath(sender)
	if err != nil {
		return err
	}
	if len(u.Nodes) != len(path) {
		return fmt.Errorf("%w: UpdatePath has %d nodes, filtered direct path %d", errs.ErrInvalidCommit, len(u.Nodes), len(path))
	}
	if u.Leaf.Source != SourceCommit {
		return fmt.Errorf("%w: UpdatePath leaf_node_source %d", errs.ErrInvalidCommit, u.Leaf.Source)
	}
	if bytes.Equal(u.Leaf.EncryptionKey, t.Leaf(sender).EncryptionKey) {
		return fmt.Errorf("%w: UpdatePath leaf keeps the committer's encryption key", errs.ErrInvalidCommit)
	}
	// No UpdatePath key may appear elsewhere in the new tree (RFC 9420 section
	// 12.4.2); the sender's leaf and direct path are about to be replaced.
	d, err := treemath.DirectPath(2*uint64(sender), t.Leaves())
	if err != nil {
		return err
	}
	replaced := map[uint64]bool{2 * uint64(sender): true}
	for _, x := range d {
		replaced[x] = true
	}
	inUse := map[string]bool{}
	for x := range t.nodes {
		if k := t.encryptionKey(x); k != nil && !replaced[x] {
			inUse[string(k)] = true
		}
	}
	keys := make([][]byte, len(u.Nodes))
	for i, k := range append([][]byte{u.Leaf.EncryptionKey}, nodeKeys(u)...) {
		// Every member checks every key, so that all of them accept or refuse
		// the same UpdatePath and no member stores a key nobody can encrypt to.
		if err := suite.CheckPublicKey(k); err != nil {
			return fmt.Errorf("%w: UpdatePath encryption key %d: %w", errs.ErrInvalidCommit, i, err)
		}
		if inUse[string(k)] {
			return fmt.Errorf("%w: UpdatePath encryption key %d already in the tree", errs.ErrInvalidCommit, i)
		}
		inUse[string(k)] = true
		if i > 0 {
			keys[i-1] = bytes.Clone(k)
		}
	}
	ph, err := t.setPath(sender, path, copath, keys)
	if err != nil {
		return err
	}
	if !bytes.Equal(u.Leaf.ParentHash, ph) {
		return fmt.Errorf("%w: UpdatePath leaf parent_hash", errs.ErrInvalidCommit)
	}
	t.set(2*uint64(sender), Node{Leaf: u.Leaf.Clone()})
	return nil
}

// CheckPathCiphertexts checks that every node of u, merged into t, has one
// encrypted path secret per node of its copath child's resolution without the
// leaves in excluded (RFC 9420 section 7.6). Every member runs it on every
// node, a removed one included, so that all accept or refuse the same Commit.
func (t *Tree) CheckPathCiphertexts(sender uint32, u *UpdatePath, excluded map[uint32]bool) error {
	path, copath, err := t.FilteredDirectPath(sender)
	if err != nil {
		return err
	}
	if len(u.Nodes) != len(path) {
		return fmt.Errorf("%w: UpdatePath has %d nodes, filtered direct path %d", errs.ErrInvalidCommit, len(u.Nodes), len(path))
	}
	for k, c := range copath {
		if r := t.Resolution(c, excluded); len(u.Nodes[k].Secrets) != len(r) {
			return fmt.Errorf("%w: %d encrypted path secrets for a resolution of %d", errs.ErrInvalidCommit, len(u.Nodes[k].Secrets), len(r))
		}
	}
	return nil
}

// DecryptPath decrypts and checks priv's path secret from u, merged into t
// (RFC 9420 sections 7.5, 12.4.2), and returns it, the commit secret and the
// next private state. priv is unchanged; excluded holds the leaves the Commit
// adds and groupContext is the provisional one.
func (t *Tree) DecryptPath(sender uint32, u *UpdatePath, excluded map[uint32]bool, groupContext []byte, priv *Private) (pathSecret, commitSecret []byte, next *Private, err error) {
	path, copath, err := t.FilteredDirectPath(sender)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(u.Nodes) != len(path) {
		return nil, nil, nil, fmt.Errorf("%w: UpdatePath has %d nodes, filtered direct path %d", errs.ErrInvalidCommit, len(u.Nodes), len(path))
	}
	me := 2 * uint64(priv.Leaf)
	i := 0
	for i < len(path) && !inSubtree(me, copath[i]) {
		i++
	}
	if i == len(path) {
		return nil, nil, nil, fmt.Errorf("%w: no UpdatePath node for leaf %d", errs.ErrInvalidCommit, priv.Leaf)
	}
	if err := t.CheckPathCiphertexts(sender, u, excluded); err != nil {
		return nil, nil, nil, err
	}
	res := t.Resolution(copath[i], excluded)
	cts := u.Nodes[i].Secrets
	j := 0
	for j < len(res) && priv.Keys[res[j]] == nil {
		j++
	}
	if j == len(res) {
		return nil, nil, nil, fmt.Errorf("%w: no private key for the resolution of node %d", errs.ErrInvalidCommit, copath[i])
	}
	ps, err := suite.DecryptWithLabel(priv.Keys[res[j]], "UpdatePathNode", groupContext, cts[j].KEMOutput, cts[j].Ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(ps) != suite.Nh {
		clear(ps)
		return nil, nil, nil, fmt.Errorf("%w: path secret of %d bytes", errs.ErrInvalidCommit, len(ps))
	}
	pathSecret = ps
	next = priv.Clone()
	// Every key on the sender's direct path is outdated (RFC 9420 section 7.5).
	d, err := treemath.DirectPath(2*uint64(sender), t.Leaves())
	if err != nil {
		next.Clear()
		clear(pathSecret)
		return nil, nil, nil, err
	}
	for _, x := range d {
		clear(next.Keys[x])
		delete(next.Keys, x)
	}
	ps = bytes.Clone(ps)
	for k := i; k < len(path); k++ {
		nodePriv, nodePub, err := nodeKey(ps)
		if err == nil && !bytes.Equal(nodePub, u.Nodes[k].EncryptionKey) {
			clear(nodePriv)
			err = fmt.Errorf("%w: path secret does not derive the key of node %d", errs.ErrInvalidCommit, path[k])
		}
		var nps []byte
		if err == nil {
			next.Keys[path[k]] = nodePriv
			nps, err = suite.DeriveSecret(ps, "path")
		}
		clear(ps)
		if err != nil {
			next.Clear()
			clear(pathSecret)
			return nil, nil, nil, err
		}
		ps = nps
	}
	return pathSecret, ps, next, nil
}

// Path is the result of CreatePath.
type Path struct {
	UpdatePath *UpdatePath
	Private    *Private
	// FilteredPath and PathSecrets give the path secret of each node of the
	// filtered direct path, for the Welcome's path_secret.
	FilteredPath []uint64
	PathSecrets  [][]byte
	CommitSecret []byte
}

func (p *Path) clear() {
	p.Private.Clear()
	for _, s := range p.PathSecrets {
		clear(s)
	}
	clear(p.CommitSecret)
}

// CreatePath makes and applies an UpdatePath for leaf l whose new leaf copies
// template, or the current leaf when nil (RFC 9420 sections 7.4, 7.5, 12.4.1).
// excluded holds the leaves the Commit adds; context encodes the provisional
// GroupContext for a tree hash. On error t is half changed: use a Clone.
func (t *Tree) CreatePath(l uint32, template *LeafNode, sigPriv ed25519.PrivateKey, groupID []byte, excluded map[uint32]bool, context func(treeHash []byte) ([]byte, error)) (*Path, error) {
	if t.Leaf(l) == nil {
		return nil, fmt.Errorf("%w: leaf %d is blank", errs.ErrInvalidArgument, l)
	}
	if template == nil {
		template = t.Leaf(l)
	}
	path, copath, err := t.FilteredDirectPath(l)
	if err != nil {
		return nil, err
	}
	leafPriv, leafPub, err := suite.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	out := &Path{Private: &Private{Leaf: l, Keys: map[uint64][]byte{2 * uint64(l): leafPriv}}, FilteredPath: path}
	u, err := t.createPath(out, l, template, leafPub, path, copath, sigPriv, groupID, excluded, context)
	if err != nil {
		out.clear()
		return nil, err
	}
	out.UpdatePath = u
	return out, nil
}

func (t *Tree) createPath(out *Path, l uint32, template *LeafNode, leafPub []byte, path, copath []uint64, sigPriv ed25519.PrivateKey, groupID []byte, excluded map[uint32]bool, context func([]byte) ([]byte, error)) (*UpdatePath, error) {
	ps := make([]byte, suite.Nh)
	rand.Read(ps) // crypto/rand.Read never fails since Go 1.24
	keys := make([][]byte, len(path))
	for i, x := range path {
		priv, pub, err := nodeKey(ps)
		if err != nil {
			return nil, err
		}
		out.Private.Keys[x] = priv
		keys[i] = pub
		out.PathSecrets = append(out.PathSecrets, ps)
		if ps, err = suite.DeriveSecret(ps, "path"); err != nil {
			return nil, err
		}
	}
	out.CommitSecret = ps

	ph, err := t.setPath(l, path, copath, keys)
	if err != nil {
		return nil, err
	}
	leaf := template.Clone()
	leaf.EncryptionKey = leafPub
	leaf.Source = SourceCommit
	leaf.NotBefore, leaf.NotAfter = 0, 0
	leaf.ParentHash = ph
	if err := leaf.Sign(sigPriv, groupID, l); err != nil {
		return nil, err
	}
	t.set(2*uint64(l), Node{Leaf: leaf.Clone()})

	th, err := t.TreeHash()
	if err != nil {
		return nil, err
	}
	gc, err := context(th)
	if err != nil {
		return nil, err
	}
	u := &UpdatePath{Leaf: leaf, Nodes: make([]UpdatePathNode, len(path))}
	for i := range path {
		u.Nodes[i].EncryptionKey = keys[i]
		for _, r := range t.Resolution(copath[i], excluded) {
			kem, ct, err := suite.EncryptWithLabel(t.encryptionKey(r), "UpdatePathNode", gc, out.PathSecrets[i])
			if err != nil {
				return nil, err
			}
			u.Nodes[i].Secrets = append(u.Nodes[i].Secrets, HPKECiphertext{KEMOutput: kem, Ciphertext: ct})
		}
	}
	return u, nil
}
