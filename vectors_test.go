package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// testAuth is the Authenticator of the tests: basic credentials, the
// identity as the client id, any successor.
type testAuth struct{}

func (testAuth) Validate(c tree.Credential, _ []byte, _ Event) error {
	if c.Type != tree.CredentialBasic {
		return fmt.Errorf("credential type %#04x", c.Type)
	}
	return nil
}

func (testAuth) Successor(prev, next tree.Credential) error { return nil }

func (testAuth) ClientID(c tree.Credential) ([]byte, error) { return c.Identity, nil }

// rfcPolicy adds no rule to RFC 9420.
type rfcPolicy struct{}

func (rfcPolicy) CheckProposal(ProposalView) error { return nil }
func (rfcPolicy) CheckCommit(CommitView) error     { return nil }
func (rfcPolicy) CheckJoin(JoinView) error         { return nil }

// pskMap serves external PSKs by id.
type pskMap map[string][]byte

func (m pskMap) PSK(id *schedule.PSKID) ([]byte, error) {
	if id.Type == schedule.PSKExternal {
		if v, ok := m[string(id.ID)]; ok {
			return bytes.Clone(v), nil
		}
	}
	return nil, errs.ErrNotFound
}

// vectorConfig is the configuration of the vector runners: no bound on
// lifetimes, as the vectors carry unbounded ones, and one past
// resumption PSK kept, as passive-client-handling-commit.json refers to the
// previous epoch's.
func vectorConfig(psks PSKStore) Config {
	return Config{Authenticator: testAuth{}, Policy: rfcPolicy{}, PSKs: psks, MaxLeafLifetime: -1, ResumptionPSKs: 1}
}

type welcomeVector struct {
	CipherSuite uint16      `json:"cipher_suite"`
	InitPriv    testvec.Hex `json:"init_priv"`
	SignerPub   testvec.Hex `json:"signer_pub"`
	KeyPackage  testvec.Hex `json:"key_package"`
	Welcome     testvec.Hex `json:"welcome"`
}

// TestWelcomeVectors runs welcome.json: the vector has no ratchet tree, so
// it checks the steps of a join that need none.
func TestWelcomeVectors(t *testing.T) {
	var v []welcomeVector
	testvec.Load(t, "welcome.json", &v)
	checked, skipped := 0, 0
	for i, e := range v {
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		checked++
		kp, err := decodeKeyPackage(e.KeyPackage)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := kp.Ref()
		if err != nil {
			t.Fatal(err)
		}
		m, err := message.UnmarshalMLSMessage(e.Welcome)
		if err != nil {
			t.Fatal(err)
		}
		w := m.Welcome
		var entry *message.EncryptedGroupSecrets
		for j := range w.Secrets {
			if bytes.Equal(w.Secrets[j].NewMember, ref) {
				entry = &w.Secrets[j]
			}
		}
		if entry == nil {
			t.Fatalf("entry %d: no secrets for the KeyPackage", i)
		}
		gsb, err := suite.DecryptWithLabel(e.InitPriv, "Welcome", w.EncryptedGroupInfo, entry.Secrets.KEMOutput, entry.Secrets.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		gs, err := message.UnmarshalGroupSecrets(gsb)
		if err != nil {
			t.Fatal(err)
		}
		if len(gs.PSKs) != 0 {
			t.Fatalf("entry %d: %d PSKs", i, len(gs.PSKs))
		}
		psk := make([]byte, suite.Nh)
		gi, err := decryptGroupInfo(w, gs.JoinerSecret, psk)
		if err != nil {
			t.Fatalf("entry %d: GroupInfo with an empty AAD: %v", i, err)
		}
		// Evidence for the AAD of encrypted_group_info: any other AAD fails.
		ws, err := schedule.WelcomeSecret(gs.JoinerSecret, psk)
		if err != nil {
			t.Fatal(err)
		}
		key, err := suite.ExpandWithLabel(ws, "key", nil, suite.Nk)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := suite.ExpandWithLabel(ws, "nonce", nil, suite.Nn)
		if err != nil {
			t.Fatal(err)
		}
		for _, aad := range [][]byte{{0}, {0, 1}, w.Secrets[0].NewMember} {
			if _, err := suite.Open(key, nonce, aad, w.EncryptedGroupInfo); err == nil {
				t.Fatalf("entry %d: GroupInfo decrypts with AAD %x", i, aad)
			}
		}
		tbs, err := gi.TBS()
		if err != nil {
			t.Fatal(err)
		}
		if !suite.VerifyWithLabel(e.SignerPub, "GroupInfoTBS", tbs, gi.Signature) {
			t.Fatalf("entry %d: GroupInfo signature", i)
		}
		bad := bytes.Clone(gi.ConfirmationTag)
		bad[0] ^= 1
		for _, c := range []struct {
			tag  []byte
			want error
		}{{gi.ConfirmationTag, nil}, {bad, errs.ErrConfirmationTag}} {
			s, err := joinState(gi.GroupContext, gs.JoinerSecret, psk)
			if err != nil {
				t.Fatalf("entry %d: %v", i, err)
			}
			if err := s.confirm(c.tag); !errors.Is(err, c.want) {
				t.Fatalf("entry %d: confirmation tag: %v, want %v", i, err, c.want)
			}
		}
	}
	if checked != 1 || skipped != 6 {
		t.Fatalf("welcome.json: %d suite 1 entries checked, %d of other suites skipped; want 1 and 6", checked, skipped)
	}
}

type passiveVector struct {
	CipherSuite  uint16 `json:"cipher_suite"`
	ExternalPSKs []struct {
		ID  testvec.Hex `json:"psk_id"`
		PSK testvec.Hex `json:"psk"`
	} `json:"external_psks"`
	KeyPackage         testvec.Hex `json:"key_package"`
	SignaturePriv      testvec.Hex `json:"signature_priv"`
	EncryptionPriv     testvec.Hex `json:"encryption_priv"`
	InitPriv           testvec.Hex `json:"init_priv"`
	Welcome            testvec.Hex `json:"welcome"`
	RatchetTree        testvec.Hex `json:"ratchet_tree"`
	EpochAuthenticator testvec.Hex `json:"initial_epoch_authenticator"`
	Epochs             []struct {
		Proposals          []testvec.Hex `json:"proposals"`
		Commit             testvec.Hex   `json:"commit"`
		EpochAuthenticator testvec.Hex   `json:"epoch_authenticator"`
	} `json:"epochs"`
}

// passive joins and follows one passive-client vector and returns the
// number of Commits applied.
func passive(t *testing.T, e *passiveVector) int {
	t.Helper()
	kp, err := decodeKeyPackage(e.KeyPackage)
	if err != nil {
		t.Fatalf("key_package: %v", err)
	}
	if len(e.SignaturePriv) != ed25519.SeedSize {
		t.Fatalf("signature_priv of %d bytes", len(e.SignaturePriv))
	}
	sig := ed25519.NewKeyFromSeed(e.SignaturePriv)
	encPub, err1 := suite.PublicKey(e.EncryptionPriv)
	initPub, err2 := suite.PublicKey(e.InitPriv)
	if err1 != nil || err2 != nil || !bytes.Equal(sig.Public().(ed25519.PublicKey), kp.LeafNode.SignatureKey) ||
		!bytes.Equal(encPub, kp.LeafNode.EncryptionKey) || !bytes.Equal(initPub, kp.InitKey) {
		t.Fatal("private keys do not match the KeyPackage")
	}
	st := NewMemStore()
	if _, err := storeKeyPackage(st, &keyPackageRecord{kp: kp, initPriv: bytes.Clone(e.InitPriv), encPriv: bytes.Clone(e.EncryptionPriv), sig: sig}); err != nil {
		t.Fatal(err)
	}
	psks := pskMap{}
	for _, p := range e.ExternalPSKs {
		psks[string(p.ID)] = p.PSK
	}
	cfg := vectorConfig(psks)
	g, err := Join(st, e.Welcome, e.RatchetTree, JoinOptions{Config: cfg})
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if !bytes.Equal(epochAuth(g), e.EpochAuthenticator) {
		t.Fatal("initial epoch authenticator differs")
	}
	for i, ep := range e.Epochs {
		for j, p := range ep.Proposals {
			r, err := g.Process(p)
			if err != nil || r.ProposalRef == nil {
				t.Fatalf("epoch %d proposal %d: %v", i, j, err)
			}
		}
		r, err := g.Process(ep.Commit)
		if err != nil || r.Commit == nil {
			t.Fatalf("epoch %d commit: %v", i, err)
		}
		if err := g.Apply(r.Commit); err != nil {
			t.Fatalf("epoch %d apply: %v", i, err)
		}
		if !bytes.Equal(epochAuth(g), ep.EpochAuthenticator) {
			t.Fatalf("epoch %d: epoch authenticator differs", i)
		}
	}
	// The stored state must reopen to the same epoch.
	re, err := Open(st, g.GroupID(), cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !bytes.Equal(epochAuth(re), epochAuth(g)) || !bytes.Equal(re.GroupContext(), g.GroupContext()) {
		t.Fatal("reopened group differs")
	}
	return len(e.Epochs)
}

func runPassive(t *testing.T, file string, wantChecked, wantSkipped, wantCommits int) {
	t.Helper()
	var v []passiveVector
	testvec.Load(t, file, &v)
	checked, skipped, commits := 0, 0, 0
	for i := range v {
		if v[i].CipherSuite != suite.ID {
			skipped++
			continue
		}
		checked++
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			commits += passive(t, &v[i])
		})
	}
	if checked != wantChecked || skipped != wantSkipped || commits != wantCommits {
		t.Fatalf("%s: %d suite 1 entries, %d skipped, %d Commits; want %d, %d, %d", file, checked, skipped, commits, wantChecked, wantSkipped, wantCommits)
	}
}

func TestPassiveClientWelcome(t *testing.T) {
	runPassive(t, "passive-client-welcome.json", 8, 48, 0)
}

func TestPassiveClientHandlingCommit(t *testing.T) {
	runPassive(t, "passive-client-handling-commit.json", 13, 78, 26)
}

func TestPassiveClientRandom(t *testing.T) {
	runPassive(t, "passive-client-random.json", 1, 0, 200)
}
