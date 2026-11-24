package crosscheck

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/message"
)

// The cross-check needs other MLS implementations built outside this
// repository (README.md), so every test here runs only with
// KOLO_MLS_CROSSCHECK=1.
func enabled(t *testing.T) {
	t.Helper()
	if os.Getenv("KOLO_MLS_CROSSCHECK") != "1" {
		t.Skip("set KOLO_MLS_CROSSCHECK=1 to run the cross-check")
	}
}

type actor struct {
	c     *Client
	name  string
	state uint32
	tx    uint32
	kp    []byte
}

type world struct {
	t       *testing.T
	encrypt bool
	members []*actor
}

func (w *world) must(err error) {
	w.t.Helper()
	if err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) keyPackage(c *Client, name string) *actor {
	w.t.Helper()
	r, err := c.createKeyPackage(&createKeyPackageRequest{CipherSuite: 1, Identity: []byte(name)})
	w.must(err)
	if len(r.InitPriv) != 32 || len(r.EncryptionPriv) != 32 || len(r.SignaturePriv) != 32 {
		w.t.Fatalf("private key sizes %d %d %d", len(r.InitPriv), len(r.EncryptionPriv), len(r.SignaturePriv))
	}
	return &actor{c: c, name: name, tx: r.TransactionID, kp: r.KeyPackage}
}

func (w *world) of(name string) *actor {
	for _, m := range w.members {
		if m.name == name {
			return m
		}
	}
	w.t.Fatalf("no member %s", name)
	return nil
}

// commit runs a Commit of committer through every member and the joiners,
// then checks that all agree.
func (w *world) commit(committer string, req *commitRequest, joiners []*actor, removed ...string) {
	w.t.Helper()
	c := w.of(committer)
	req.StateID = c.state
	resp, err := c.c.commit(req)
	w.must(err)
	p, err := c.c.handlePendingCommit(&stateRequest{StateID: c.state})
	w.must(err)
	var keep []*actor
	for _, m := range w.members {
		gone := false
		for _, r := range removed {
			gone = gone || r == m.name
		}
		if m != c {
			h, err := m.c.handleCommit(&handleCommitRequest{StateID: m.state, Proposal: req.ByReference, Commit: resp.Commit})
			w.must(err)
			if !gone && !bytes.Equal(h.EpochAuthenticator, p.EpochAuthenticator) {
				w.t.Fatalf("%s epoch authenticator differs", m.name)
			}
		}
		if !gone {
			keep = append(keep, m)
		}
	}
	w.members = keep
	for _, j := range joiners {
		jr, err := j.c.joinGroup(&joinGroupRequest{TransactionID: j.tx, Welcome: resp.Welcome, EncryptHandshake: w.encrypt, RatchetTree: resp.RatchetTree})
		w.must(err)
		if !bytes.Equal(jr.EpochAuthenticator, p.EpochAuthenticator) {
			w.t.Fatalf("joiner %s epoch authenticator differs", j.name)
		}
		j.state = jr.StateID
		w.members = append(w.members, j)
	}
	w.check()
}

func (w *world) check() {
	w.t.Helper()
	var ea, exp, gc, tree []byte
	for i, m := range w.members {
		a, err := m.c.stateAuth(&stateRequest{StateID: m.state})
		w.must(err)
		e, err := m.c.export(&exportRequest{StateID: m.state, Label: "check", Context: []byte{1}, KeyLength: 32})
		w.must(err)
		s, err := m.c.groupState(&stateRequest{StateID: m.state})
		w.must(err)
		if i == 0 {
			ea, exp, gc, tree = a.StateAuthSecret, e.ExportedSecret, s.GroupContext, s.RatchetTree
			continue
		}
		if !bytes.Equal(a.StateAuthSecret, ea) || !bytes.Equal(e.ExportedSecret, exp) || !bytes.Equal(s.GroupContext, gc) || !bytes.Equal(s.RatchetTree, tree) {
			w.t.Fatalf("%s disagrees with %s", m.name, w.members[0].name)
		}
	}
}

func (w *world) propose(name string, f func(m *actor) (*proposalResponse, error)) []byte {
	w.t.Helper()
	r, err := f(w.of(name))
	w.must(err)
	return r.Proposal
}

func (w *world) messages() {
	w.t.Helper()
	for _, s := range w.members {
		for _, n := range []int{0, 1, 15, 16, 17, 255, 4097} {
			pt := bytes.Repeat([]byte{byte(n)}, n)
			aad := []byte(fmt.Sprintf("%s %d", s.name, n))
			ct, err := s.c.protect(&protectRequest{StateID: s.state, AuthenticatedData: aad, Plaintext: pt})
			w.must(err)
			for _, m := range w.members {
				if m == s {
					continue
				}
				u, err := m.c.unprotect(&unprotectRequest{StateID: m.state, Ciphertext: ct.Ciphertext})
				w.must(err)
				if !bytes.Equal(u.Plaintext, pt) || !bytes.Equal(u.AuthenticatedData, aad) {
					w.t.Fatalf("%s read from %s: wrong data", m.name, s.name)
				}
			}
		}
	}
}

// TestScenario runs every in-scope operation between two driver clients,
// as the interop runner does with two implementations.
func TestScenario(t *testing.T) {
	enabled(t)
	for _, encrypt := range []bool{false, true} {
		t.Run(fmt.Sprintf("private=%v", encrypt), func(t *testing.T) {
			w := &world{t: t, encrypt: encrypt}
			a, b := NewClient(), NewClient()
			cg, err := a.createGroup(&createGroupRequest{GroupID: []byte("group"), CipherSuite: 1, EncryptHandshake: encrypt, Identity: []byte("alice")})
			w.must(err)
			w.members = []*actor{{c: a, name: "alice", state: cg.StateID}}
			bob, carol, dave := w.keyPackage(b, "bob"), w.keyPackage(a, "carol"), w.keyPackage(b, "dave")
			w.commit("alice", &commitRequest{ByValue: []proposalDescription{{ProposalType: []byte("add"), KeyPackage: bob.kp}, {ProposalType: []byte("add"), KeyPackage: carol.kp}, {ProposalType: []byte("add"), KeyPackage: dave.kp}}}, []*actor{bob, carol, dave})

			upd := w.propose("bob", func(m *actor) (*proposalResponse, error) { return m.c.updateProposal(&stateRequest{StateID: m.state}) })
			w.commit("carol", &commitRequest{ByReference: [][]byte{upd}}, nil)
			w.commit("dave", &commitRequest{ForcePath: true}, nil)
			w.commit("bob", &commitRequest{}, nil)

			erin := w.keyPackage(a, "erin")
			add := w.propose("dave", func(m *actor) (*proposalResponse, error) {
				return m.c.addProposal(&addProposalRequest{StateID: m.state, KeyPackage: erin.kp})
			})
			w.commit("alice", &commitRequest{ByReference: [][]byte{add}, ExternalTree: true}, []*actor{erin})
			w.commit("alice", &commitRequest{ByValue: []proposalDescription{{ProposalType: []byte("remove"), RemovedID: []byte("erin")}}}, nil, "erin")
			rem := w.propose("bob", func(m *actor) (*proposalResponse, error) {
				return m.c.removeProposal(&removeProposalRequest{StateID: m.state, RemovedID: []byte("dave")})
			})
			w.commit("carol", &commitRequest{ByReference: [][]byte{rem}}, nil, "dave")

			for _, id := range []string{"psk one", "psk two"} {
				for _, m := range w.members {
					_, err := m.c.storePSK(&storePSKRequest{StateOrTransactionID: m.state, PSKID: []byte(id), PSKSecret: []byte(id + " secret")})
					w.must(err)
				}
			}
			ext := w.propose("alice", func(m *actor) (*proposalResponse, error) {
				return m.c.externalPSKProposal(&externalPSKProposalRequest{StateID: m.state, PSKID: []byte("psk one")})
			})
			w.commit("bob", &commitRequest{ByReference: [][]byte{ext}, ByValue: []proposalDescription{{ProposalType: []byte("externalPSK"), PSKID: []byte("psk two")}}}, nil)

			epoch := binary.BigEndian.Uint64(groupEpoch(t, w.of("alice")))
			res := w.propose("carol", func(m *actor) (*proposalResponse, error) {
				return m.c.resumptionPSKProposal(&resumptionPSKProposalRequest{StateID: m.state, EpochID: jsonU64(epoch - 2)})
			})
			w.commit("alice", &commitRequest{ByReference: [][]byte{res}, ByValue: []proposalDescription{{ProposalType: []byte("resumptionPSK"), EpochID: jsonU64(epoch - 1)}}, ForcePath: true}, nil)

			w.commit("bob", &commitRequest{ByValue: []proposalDescription{{ProposalType: []byte("groupContextExtensions"), Extensions: []extension{{ExtensionType: 3, ExtensionData: []byte{0, 0, 0}}}}}}, nil)
			gce := w.propose("alice", func(m *actor) (*proposalResponse, error) {
				return m.c.groupContextExtensionsProposal(&groupContextExtensionsProposalRequest{StateID: m.state})
			})
			w.commit("carol", &commitRequest{ByReference: [][]byte{gce}}, nil)
			w.messages()

			w.branch()
		})
	}
}

func groupEpoch(t *testing.T, m *actor) []byte {
	t.Helper()
	s, err := m.c.groupState(&stateRequest{StateID: m.state})
	if err != nil {
		t.Fatal(err)
	}
	gc := s.GroupContext
	// version, cipher_suite, then group_id with a one-byte length (short ids).
	n := int(gc[4])
	return gc[5+n : 5+n+8]
}

// branch starts a subgroup of every member and checks it, then checks that
// a branch with a client outside the old group is refused (RFC 9420
// section 11.3).
func (w *world) branch() {
	w.t.Helper()
	creator := w.members[0]
	var kps [][]byte
	var js []*actor
	for _, m := range w.members[1:] {
		j := w.keyPackage(m.c, m.name)
		j.state = m.state
		kps = append(kps, j.kp)
		js = append(js, j)
	}
	br, err := creator.c.createBranch(&createBranchRequest{StateID: creator.state, GroupID: []byte("branch"), KeyPackages: kps, ForcePath: true})
	w.must(err)
	sub := []*actor{{c: creator.c, name: creator.name, state: br.StateID}}
	for _, j := range js {
		h, err := j.c.handleBranch(&handleBranchRequest{StateID: j.state, TransactionID: j.tx, Welcome: br.Welcome})
		w.must(err)
		if !bytes.Equal(h.EpochAuthenticator, br.EpochAuthenticator) {
			w.t.Fatalf("%s branch epoch authenticator differs", j.name)
		}
		sub = append(sub, &actor{c: j.c, name: j.name, state: h.StateID})
	}
	old := w.members
	w.members = sub
	w.check()
	w.messages()
	w.members = old

	outsider := NewClient()
	mallory := w.keyPackage(outsider, "mallory")
	next := w.keyPackage(old[1].c, old[1].name)
	br, err = old[0].c.createBranch(&createBranchRequest{StateID: old[0].state, GroupID: []byte("branch 2"), KeyPackages: [][]byte{next.kp, mallory.kp}})
	if err == nil {
		_, err = next.c.handleBranch(&handleBranchRequest{StateID: old[1].state, TransactionID: next.tx, Welcome: br.Welcome})
	}
	if err == nil || !strings.Contains(err.Error(), "not in the old group") {
		w.t.Fatalf("branch with an outsider: %v", err)
	}
}

// TestServe checks the JSON line protocol, including errors.
func TestServe(t *testing.T) {
	enabled(t)
	in := strings.Join([]string{
		`{"id":1,"method":"Name"}`,
		`{"id":2,"method":"SupportedCiphersuites"}`,
		`{"id":3,"method":"ExternalJoin","params":{}}`,
		`{"id":4,"method":"CreateGroup","params":{"group_id":"Zw==","cipher_suite":2,"identity":"YQ=="}}`,
		`not json`,
		`{"id":6,"method":"CreateGroup","params":{"group_id":"Zw==","cipher_suite":1,"identity":"YQ=="}}`,
		`{"id":7,"method":"ResumptionPSKProposal","params":{"state_id":1,"epoch_id":"0"}}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := NewClient().Serve(strings.NewReader(in), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var got []Response
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		var r struct {
			ID     uint64          `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		got = append(got, Response{ID: r.ID, Result: string(r.Result), Error: r.Error})
	}
	want := []struct {
		id    uint64
		ok    bool
		match string
	}{
		{1, true, "kolo-mls"}, {2, true, "[1]"}, {3, false, "unsupported operation"}, {4, false, "cipher suite 2"},
		{0, false, "invalid character"}, {6, true, "state_id"}, {7, true, "proposal"},
	}
	if len(got) != len(want) {
		t.Fatalf("%d responses, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		text := g.Error
		if w.ok {
			text = g.Result.(string)
		}
		if g.ID != w.id || (g.Error == "") != w.ok || !strings.Contains(text, w.match) {
			t.Errorf("response %d: %+v, want id %d ok %v containing %q", i, g, w.id, w.ok, w.match)
		}
	}
}

// TestPeers runs the pairwise harness of the throwaway directory against
// the other implementations with a driver built from this package; see
// README.md for building that directory.
func TestPeers(t *testing.T) {
	enabled(t)
	dir := os.Getenv("KOLO_MLS_CROSSCHECK_DIR")
	if dir == "" {
		t.Fatal("KOLO_MLS_CROSSCHECK_DIR is not set")
	}
	driver := filepath.Join(t.TempDir(), "driver")
	build := exec.Command("go", "build", "-o", driver, "./driver")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build driver: %v\n%s", err, out)
	}
	cmd := exec.Command(filepath.Join(dir, "run-pairwise.sh"), driver, t.TempDir())
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
}

// TestFindingGrease checks that a KeyPackage carries GREASE values (RFC 9420 section 13.5: a
// client SHOULD include some in the capabilities lists and the extensions of KeyPackages and
// LeafNodes). It runs only with KOLO_MLS_CROSSCHECK_FINDINGS=1.
func TestFindingGrease(t *testing.T) {
	if os.Getenv("KOLO_MLS_CROSSCHECK_FINDINGS") != "1" {
		t.Skip("set KOLO_MLS_CROSSCHECK_FINDINGS=1 to run the finding reproducers")
	}
	r, err := NewClient().createKeyPackage(&createKeyPackageRequest{CipherSuite: 1, Identity: []byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	m, err := message.UnmarshalMLSMessage(r.KeyPackage)
	if err != nil {
		t.Fatal(err)
	}
	kp := m.KeyPackage
	c := kp.LeafNode.Capabilities
	var types []uint16
	for _, l := range [][]uint16{c.CipherSuites, c.Extensions, c.Proposals, c.Credentials} {
		types = append(types, l...)
	}
	for _, e := range append(kp.Extensions, kp.LeafNode.Extensions...) {
		types = append(types, e.Type)
	}
	for _, v := range types {
		if v&0x0f0f == 0x0a0a && v>>12 == (v>>4)&0x0f {
			return
		}
	}
	t.Fatalf("no GREASE value in capabilities %+v or extensions", c)
}
