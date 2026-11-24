package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// opened is a Welcome decrypted with the joiner's keys, to change and seal
// again.
type opened struct {
	kp     *message.KeyPackage
	gs     *message.GroupSecrets
	gi     *message.GroupInfo
	signer ed25519.PrivateKey
}

func openWelcome(t *testing.T, j *client, kp, welcome []byte, signer ed25519.PrivateKey) *opened {
	t.Helper()
	rec := j.keyPackageRecord(t, kp)
	m, err := message.UnmarshalMLSMessage(welcome)
	if err != nil {
		t.Fatal(err)
	}
	e := m.Welcome.Secrets[0]
	gsb, err := suite.DecryptWithLabel(rec.initPriv, "Welcome", m.Welcome.EncryptedGroupInfo, e.Secrets.KEMOutput, e.Secrets.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	gs, err := message.UnmarshalGroupSecrets(gsb)
	if err != nil {
		t.Fatal(err)
	}
	gi, err := decryptGroupInfo(m.Welcome, gs.JoinerSecret, make([]byte, suite.Nh))
	if err != nil {
		t.Fatal(err)
	}
	return &opened{kp: rec.kp, gs: gs, gi: gi, signer: signer}
}

// seal encrypts o again; pskSecret is the psk_secret of o.gs.PSKs, and
// giJoiner, when set, encrypts the GroupInfo under another joiner secret.
func (o *opened) seal(t *testing.T, pskSecret, giJoiner []byte) []byte {
	t.Helper()
	if o.signer != nil {
		tbs, _ := o.gi.TBS()
		o.gi.Signature, _ = suite.SignWithLabel(o.signer, "GroupInfoTBS", tbs)
	}
	gib, err := o.gi.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if pskSecret == nil {
		pskSecret = make([]byte, suite.Nh)
	}
	joiner := o.gs.JoinerSecret
	if giJoiner != nil {
		joiner = giJoiner
	}
	ws, _ := schedule.WelcomeSecret(joiner, pskSecret)
	key, _ := suite.ExpandWithLabel(ws, "key", nil, suite.Nk)
	nonce, _ := suite.ExpandWithLabel(ws, "nonce", nil, suite.Nn)
	w := &message.Welcome{CipherSuite: suite.ID}
	w.EncryptedGroupInfo, _ = suite.Seal(key, nonce, nil, gib)
	gsb, _ := o.gs.Marshal()
	kem, ct, err := suite.EncryptWithLabel(o.kp.InitKey, "Welcome", w.EncryptedGroupInfo, gsb)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := o.kp.Ref()
	w.Secrets = []message.EncryptedGroupSecrets{{NewMember: ref, Secrets: tree.HPKECiphertext{KEMOutput: kem, Ciphertext: ct}}}
	b, err := (&message.MLSMessage{WireFormat: message.WireWelcome, Welcome: w}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pskFunc is a PSKStore made of a function.
type pskFunc func(id *schedule.PSKID) ([]byte, error)

func (f pskFunc) PSK(id *schedule.PSKID) ([]byte, error) { return f(id) }

// TestJoinRules runs the Welcome rules W1 to W14 (RFC 9420
// section 12.4.3.1) on Welcomes for one joiner of a three-member group.
func TestJoinRules(t *testing.T) {
	w := newWorld(t, 3)
	a := w.members[0].g
	j := newClient(t)
	kp := j.keyPackage(t)
	before, _ := a.RatchetTree()
	pc := w.commit(0, CommitOptions{Add: [][]byte{kp}})
	tr, _ := a.RatchetTree()
	signer := a.s.sig
	fresh := func() *opened { return openWelcome(t, j, kp, pc.Welcome(), signer) }
	join := func(welcome, tr []byte, o JoinOptions) error {
		if o.Authenticator == nil {
			o.Config = w.cfg
		}
		_, err := Join(j.st, welcome, tr, o)
		return err
	}
	cases := []struct {
		rule   string
		build  func() ([]byte, []byte, JoinOptions)
		want   error
		reason string
	}{
		{"W1", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			k := *o.kp
			k.InitKey = bytes.Clone(k.InitKey)
			k.InitKey[0] ^= 1
			o.kp = &k
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrKeyPackageNotFound, "key package not found"},
		{"W2", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			k := *o.kp
			k.CipherSuite = 2
			rec := j.keyPackageRecord(t, kp)
			rec.kp = &k
			if _, err := storeKeyPackage(j.st, rec); err != nil {
				t.Fatal(err)
			}
			o.kp = &k
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrInvalidWelcome, "KeyPackage cipher suite differs"},
		{"W3", func() ([]byte, []byte, JoinOptions) {
			b := pc.Welcome()
			m, _ := message.UnmarshalMLSMessage(b)
			m.Welcome.Secrets[0].Secrets.Ciphertext[0] ^= 1
			out, _ := m.Marshal()
			return out, tr, JoinOptions{}
		}, errs.ErrDecrypt, "group secrets"},
		{"W4", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			o.gs.PSKs = []*schedule.PSKID{pskID("absent")}
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrPSKNotFound, "pre-shared key not found"},
		{"W4 two branch PSKs", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			b := &schedule.PSKID{Type: schedule.PSKResumption, Usage: schedule.UsageBranch, GroupID: []byte{1}, Nonce: make([]byte, 32)}
			b2 := *b
			b2.Epoch = 1
			o.gs.PSKs = []*schedule.PSKID{b, &b2}
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrInvalidWelcome, "more than one reinit or branch PSK"},
		{"W4 reinit", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			o.gs.PSKs = []*schedule.PSKID{{Type: schedule.PSKResumption, Usage: schedule.UsageReinit, GroupID: []byte{1}, Nonce: make([]byte, 32)}}
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrUnsupported, "reinitialization"},
		{"W5", func() ([]byte, []byte, JoinOptions) {
			return fresh().seal(t, nil, bytes.Repeat([]byte{3}, 32)), tr, JoinOptions{}
		}, errs.ErrDecrypt, "GroupInfo"},
		{"W6", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			_, o.signer, _ = ed25519.GenerateKey(nil)
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrSignature, "GroupInfo"},
		{"W6 blank signer", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			o.gi.Signer = 9
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrInvalidWelcome, "signer 9 is blank"},
		{"W8", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			o.gi.GroupContext.CipherSuite = 2
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrInvalidWelcome, "GroupInfo cipher suite differs"},
		{"W9", func() ([]byte, []byte, JoinOptions) {
			return pc.Welcome(), before, JoinOptions{}
		}, errs.ErrInvalidTree, "tree hash differs"},
		{"W9 MaxTreeBytes", func() ([]byte, []byte, JoinOptions) {
			return pc.Welcome(), tr, JoinOptions{Config: w.cfg, MaxTreeBytes: len(tr) - 1}
		}, errs.ErrInvalidTree, "above MaxTreeBytes"},
		{"W10", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			other := j.keyPackage(t)
			o.kp = j.keyPackageRecord(t, other).kp
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrInvalidWelcome, "no leaf is identical"},
		{"W11", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			o.gs.PathSecret = bytes.Repeat([]byte{4}, 32)
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrInvalidWelcome, "does not match"},
		{"W12", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			o.gi.ConfirmationTag[0] ^= 1
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrConfirmationTag, "confirmation tag"},
		{"W13", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			id := &schedule.PSKID{Type: schedule.PSKResumption, Usage: schedule.UsageBranch, GroupID: []byte{1}, Epoch: 5, Nonce: make([]byte, 32)}
			o.gs.PSKs = []*schedule.PSKID{id}
			v := bytes.Repeat([]byte{6}, 32)
			ps, _ := schedule.PSKSecret(o.gs.PSKs, [][]byte{v})
			cfg := w.cfg
			cfg.PSKs = pskFunc(func(*schedule.PSKID) ([]byte, error) { return bytes.Clone(v), nil })
			return o.seal(t, ps, nil), tr, JoinOptions{Config: cfg}
		}, errs.ErrInvalidWelcome, "a branch PSK in a Welcome for epoch 2, not 1"},
		{"W14", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			o.gi.GroupContext.Extensions = []tls.Extension{{Type: 0xf00a}}
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrInvalidTree, "GroupContext extension 0xf00a not supported"},
		{"policy", func() ([]byte, []byte, JoinOptions) {
			cfg := w.cfg
			cfg.Policy = refusePolicy{}
			return pc.Welcome(), tr, JoinOptions{Config: cfg}
		}, errs.ErrPolicy, "refused by policy"},
		{"tree twice", func() ([]byte, []byte, JoinOptions) {
			o := fresh()
			o.gi.Extensions = []tls.Extension{{Type: message.ExtRatchetTree, Data: tr}}
			return o.seal(t, nil, nil), tr, JoinOptions{}
		}, errs.ErrInvalidArgument, "both in the Welcome and given"},
		{"no tree", func() ([]byte, []byte, JoinOptions) {
			return pc.Welcome(), nil, JoinOptions{}
		}, errs.ErrInvalidArgument, "no ratchet tree"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			welcome, tr, o := c.build()
			wantErr(t, join(welcome, tr, o), c.want, c.reason)
		})
	}
	t.Run("W7", func(t *testing.T) {
		meta := groupKey(a.GroupID(), "meta")
		if err := j.st.Apply(Batch{Put: []KV{{Key: meta, Value: []byte{0}}}}); err != nil {
			t.Fatal(err)
		}
		wantErr(t, join(pc.Welcome(), tr, JoinOptions{}), errs.ErrGroupExists, "already exists")
		if err := j.st.Apply(Batch{Delete: [][]byte{meta}}); err != nil {
			t.Fatal(err)
		}
	})
	// The untouched Welcome still joins, and deletes the KeyPackage keys.
	ref := kpRef(t, fresh().kp)
	g, err := Join(j.st, pc.Welcome(), tr, JoinOptions{Config: w.cfg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.st.Get(keyPackageKey(ref)); !errors.Is(err, errs.ErrNotFound) {
		t.Fatalf("KeyPackage keys kept after the join: %v", err)
	}
	w.members[g.OwnLeaf()] = &client{st: j.st, g: g}
	w.check()
}

// kpRef returns the KeyPackageRef of kp.
func kpRef(t testing.TB, kp *message.KeyPackage) []byte {
	t.Helper()
	ref, err := kp.Ref()
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

// TestJoinTreeSource: JoinOptions.Tree gets an exporter of the new epoch
// before the tree is needed, and is not called when a tree is given.
func TestJoinTreeSource(t *testing.T) {
	w := newWorld(t, 2)
	a := w.members[0].g
	j1, j2 := newClient(t), newClient(t)
	pc := w.commit(0, CommitOptions{Add: [][]byte{j1.keyPackage(t), j2.keyPackage(t)}})
	tr, err := a.RatchetTree()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	var exported []byte
	o := JoinOptions{Config: w.cfg}
	o.Tree = func(export func(string, []byte, int) ([]byte, error)) ([]byte, error) {
		calls++
		exported, err = export("tree", nil, 16)
		return tr, err
	}
	refused := errors.New("no tree here")
	bad := o
	bad.Tree = func(func(string, []byte, int) ([]byte, error)) ([]byte, error) { return nil, refused }
	if _, err := Join(j1.st, pc.Welcome(), nil, bad); !errors.Is(err, refused) {
		t.Fatalf("Tree error: %v", err)
	}
	if _, err := Join(j2.st, pc.Welcome(), tr, o); err != nil || calls != 0 {
		t.Fatalf("Tree called with a tree given: %d %v", calls, err)
	}
	g, err := Join(j1.st, pc.Welcome(), nil, o)
	if err != nil {
		t.Fatal(err)
	}
	want, err := g.Export("tree", nil, 16)
	if err != nil || calls != 1 || !bytes.Equal(exported, want) {
		t.Fatalf("exporter differs from the joined epoch's: %d %v", calls, err)
	}
}

// TestJoinTreeInWelcome: a Welcome that carries the tree is joined without
// calling JoinOptions.Tree.
func TestJoinTreeInWelcome(t *testing.T) {
	w := newWorld(t, 2)
	j := newClient(t)
	pc := w.commit(0, CommitOptions{Add: [][]byte{j.keyPackage(t)}, RatchetTree: true})
	o := JoinOptions{Config: w.cfg}
	o.Tree = func(func(string, []byte, int) ([]byte, error)) ([]byte, error) {
		t.Fatal("Tree called for a Welcome that carries the tree")
		return nil, nil
	}
	if _, err := Join(j.st, pc.Welcome(), nil, o); err != nil {
		t.Fatal(err)
	}
}

// TestStagedLeaves: Leaves names the added leaves and the committer's new
// one, not the leaves the Commit keeps.
func TestStagedLeaves(t *testing.T) {
	w := newWorld(t, 3)
	j := newClient(t)
	kp := j.keyPackage(t)
	pc, err := w.members[0].g.Commit(CommitOptions{Add: [][]byte{kp}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := w.members[1].g.Process(pc.Commit())
	if err != nil {
		t.Fatal(err)
	}
	leaves := r.Commit.Leaves()
	if len(leaves) != 2 {
		t.Fatalf("%d leaves", len(leaves))
	}
	var ids []string
	for _, n := range leaves {
		ids = append(ids, string(n.Credential.Identity))
	}
	if !slices.Contains(ids, string(j.id)) || !slices.Contains(ids, string(w.members[0].id)) {
		t.Fatalf("leaves %q", ids)
	}
	r.Commit.Discard()
	if r.Commit.Leaves() != nil {
		t.Fatal("leaves of a discarded Commit")
	}
}
