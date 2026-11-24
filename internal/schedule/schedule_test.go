package schedule

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type keyScheduleEpoch struct {
	TreeHash                testvec.Hex `json:"tree_hash"`
	CommitSecret            testvec.Hex `json:"commit_secret"`
	PSKSecret               testvec.Hex `json:"psk_secret"`
	ConfirmedTranscriptHash testvec.Hex `json:"confirmed_transcript_hash"`
	GroupContext            testvec.Hex `json:"group_context"`
	JoinerSecret            testvec.Hex `json:"joiner_secret"`
	WelcomeSecret           testvec.Hex `json:"welcome_secret"`
	InitSecret              testvec.Hex `json:"init_secret"`
	SenderDataSecret        testvec.Hex `json:"sender_data_secret"`
	EncryptionSecret        testvec.Hex `json:"encryption_secret"`
	ExporterSecret          testvec.Hex `json:"exporter_secret"`
	EpochAuthenticator      testvec.Hex `json:"epoch_authenticator"`
	ExternalSecret          testvec.Hex `json:"external_secret"`
	ConfirmationKey         testvec.Hex `json:"confirmation_key"`
	MembershipKey           testvec.Hex `json:"membership_key"`
	ResumptionPSK           testvec.Hex `json:"resumption_psk"`
	ExternalPub             testvec.Hex `json:"external_pub"`
	Exporter                struct {
		Label   string      `json:"label"`
		Context testvec.Hex `json:"context"`
		Length  int         `json:"length"`
		Secret  testvec.Hex `json:"secret"`
	} `json:"exporter"`
}

func TestKeyScheduleVectors(t *testing.T) {
	var v []struct {
		CipherSuite       uint16             `json:"cipher_suite"`
		GroupID           testvec.Hex        `json:"group_id"`
		InitialInitSecret testvec.Hex        `json:"initial_init_secret"`
		Epochs            []keyScheduleEpoch `json:"epochs"`
	}
	testvec.Load(t, "key-schedule.json", &v)
	checked, skipped, epochs := 0, 0, 0
	for _, e := range v {
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		checked++
		init := e.InitialInitSecret
		for i, ep := range e.Epochs {
			epochs++
			g := GroupContext{
				CipherSuite:             e.CipherSuite,
				GroupID:                 e.GroupID,
				Epoch:                   uint64(i),
				TreeHash:                ep.TreeHash,
				ConfirmedTranscriptHash: ep.ConfirmedTranscriptHash,
			}
			gc, err := g.Marshal()
			if err != nil || !bytes.Equal(gc, ep.GroupContext) {
				t.Fatalf("epoch %d: GroupContext = %x, %v; want %x", i, gc, err, ep.GroupContext)
			}
			joiner, err := JoinerSecret(init, ep.CommitSecret, gc)
			if err != nil {
				t.Fatal(err)
			}
			welcome, s, err := Epoch(joiner, ep.PSKSecret, gc)
			if err != nil {
				t.Fatal(err)
			}
			welcomeOnly, err := WelcomeSecret(joiner, ep.PSKSecret)
			if err != nil {
				t.Fatal(err)
			}
			// external_secret is not kept by Epoch; derive it here as section 8 does.
			member, _ := suite.Extract(joiner, ep.PSKSecret)
			epochSecret, _ := suite.ExpandWithLabel(member, "epoch", gc, suite.Nh)
			external, _ := suite.DeriveSecret(epochSecret, "external")
			pub, err := ExternalPub(external)
			if err != nil {
				t.Fatal(err)
			}
			// The exporter label is the JSON text itself, although it looks
			// like hex; decoding it fails every epoch.
			exp, err := Export(s.Exporter, ep.Exporter.Label, ep.Exporter.Context, ep.Exporter.Length)
			if err != nil {
				t.Fatal(err)
			}
			for name, c := range map[string][2][]byte{
				"joiner_secret":       {joiner, ep.JoinerSecret},
				"welcome_secret":      {welcome, ep.WelcomeSecret},
				"WelcomeSecret":       {welcomeOnly, ep.WelcomeSecret},
				"init_secret":         {s.Init, ep.InitSecret},
				"sender_data_secret":  {s.SenderData, ep.SenderDataSecret},
				"encryption_secret":   {s.Encryption, ep.EncryptionSecret},
				"exporter_secret":     {s.Exporter, ep.ExporterSecret},
				"epoch_authenticator": {s.EpochAuthenticator, ep.EpochAuthenticator},
				"external_secret":     {external, ep.ExternalSecret},
				"confirmation_key":    {s.Confirmation, ep.ConfirmationKey},
				"membership_key":      {s.Membership, ep.MembershipKey},
				"resumption_psk":      {s.Resumption, ep.ResumptionPSK},
				"external_pub":        {pub, ep.ExternalPub},
				"exporter.secret":     {exp, ep.Exporter.Secret},
			} {
				if !bytes.Equal(c[0], c[1]) {
					t.Errorf("epoch %d %s = %x, want %x", i, name, c[0], c[1])
				}
			}
			init = s.Init
		}
	}
	if checked != 1 || skipped != 6 || epochs != 5 {
		t.Fatalf("key-schedule.json: %d suite 1 entries (%d epochs), %d skipped; want 1 (5), 6", checked, epochs, skipped)
	}
	t.Logf("key-schedule.json: %d suite 1 entry with %d epochs checked, 0 suite 1 skipped, %d other-suite entries skipped", checked, epochs, skipped)
}

type pskVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	PSKs        []struct {
		ID    testvec.Hex `json:"psk_id"`
		PSK   testvec.Hex `json:"psk"`
		Nonce testvec.Hex `json:"psk_nonce"`
	} `json:"psks"`
	PSKSecret testvec.Hex `json:"psk_secret"`
}

// pskSecretFigureOrder is the section 8.4 chain with the salt read from
// Figure 24, KDF.Extract(salt = psk_secret_[i-1], ikm = psk_input_[i-1]); it
// exists only to show that the vectors refuse that reading.
func pskSecretFigureOrder(ids []*PSKID, psks [][]byte) ([]byte, error) {
	zero := make([]byte, suite.Nh)
	secret := make([]byte, suite.Nh)
	for i, id := range ids {
		var w tls.Writer
		id.Write(&w)
		w.U16(uint16(i))
		w.U16(uint16(len(ids)))
		label, _ := w.Bytes()
		extracted, _ := suite.Extract(zero, psks[i])
		input, err := suite.ExpandWithLabel(extracted, "derived psk", label, suite.Nh)
		if err != nil {
			return nil, err
		}
		if secret, err = suite.Extract(secret, input); err != nil {
			return nil, err
		}
	}
	return secret, nil
}

// TestPSKSecretVectors settles which argument of the second Extract of
// RFC 9420 section 8.4 is the salt.
func TestPSKSecretVectors(t *testing.T) {
	var v []pskVector
	testvec.Load(t, "psk_secret.json", &v)
	checked, skipped, figureMatches := 0, 0, 0
	for _, e := range v {
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		checked++
		var ids []*PSKID
		var psks [][]byte
		for _, p := range e.PSKs {
			ids = append(ids, &PSKID{Type: PSKExternal, ID: p.ID, Nonce: p.Nonce})
			psks = append(psks, p.PSK)
		}
		got, err := PSKSecret(ids, psks)
		if err != nil || !bytes.Equal(got, e.PSKSecret) {
			t.Errorf("%d PSKs: psk_secret = %x, %v; want %x", len(ids), got, err, e.PSKSecret)
		}
		alt, err := pskSecretFigureOrder(ids, psks)
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) > 0 && bytes.Equal(alt, e.PSKSecret) {
			figureMatches++
		}
	}
	if checked != 11 || skipped != 66 {
		t.Fatalf("psk_secret.json: %d suite 1 entries, %d skipped; want 11 and 66", checked, skipped)
	}
	if figureMatches != 0 {
		t.Fatalf("the Figure 24 salt order also matched %d entries", figureMatches)
	}
	t.Logf("psk_secret.json: %d suite 1 entries (0 to 10 PSKs) checked, 0 suite 1 skipped, %d other-suite entries skipped; Figure 24 salt order matched 0 of 10 non-empty entries", checked, skipped)
}

// splitAuthenticatedContent splits a vector AuthenticatedContent carrying a
// Commit into ConfirmedTranscriptHashInput and confirmation_tag. It reads only
// Commits whose proposals are all references and which have no path, which is
// what transcript-hashes.json holds; anything else fails the test.
func splitAuthenticatedContent(b []byte) (input, tag []byte, err error) {
	r := tls.NewReader(b)
	steps := []func() error{
		func() error { _, err := r.U16(); return err },
		func() error { _, err := r.Opaque(); return err },
		func() error { _, err := r.U64(); return err },
		func() error {
			st, err := r.U8()
			if err != nil {
				return err
			}
			switch st {
			case 1, 2:
				_, err = r.U32()
			case 3, 4:
			default:
				err = fmt.Errorf("sender type %d", st)
			}
			return err
		},
		func() error { _, err := r.Opaque(); return err },
		func() error {
			ct, err := r.U8()
			if err == nil && ct != 3 {
				err = fmt.Errorf("content type %d is not commit", ct)
			}
			return err
		},
		func() error {
			return r.Vector(func(r *tls.Reader) error {
				typ, err := r.U8()
				if err == nil && typ != 2 {
					return fmt.Errorf("ProposalOrRef type %d", typ)
				}
				_, err = r.Opaque()
				return err
			})
		},
		func() error {
			path, err := r.Optional()
			if err == nil && path {
				err = errors.New("commit with a path")
			}
			return err
		},
		func() error { _, err := r.Opaque(); return err },
	}
	for _, f := range steps {
		if err := f(); err != nil {
			return nil, nil, err
		}
	}
	input = b[:len(b)-r.Len()]
	if tag, err = r.Opaque(); err != nil {
		return nil, nil, err
	}
	if r.Len() != 0 {
		return nil, nil, errors.New("trailing bytes")
	}
	return input, tag, nil
}

func TestTranscriptHashVectors(t *testing.T) {
	var v []struct {
		CipherSuite                  uint16      `json:"cipher_suite"`
		ConfirmationKey              testvec.Hex `json:"confirmation_key"`
		AuthenticatedContent         testvec.Hex `json:"authenticated_content"`
		InterimTranscriptHashBefore  testvec.Hex `json:"interim_transcript_hash_before"`
		ConfirmedTranscriptHashAfter testvec.Hex `json:"confirmed_transcript_hash_after"`
		InterimTranscriptHashAfter   testvec.Hex `json:"interim_transcript_hash_after"`
	}
	testvec.Load(t, "transcript-hashes.json", &v)
	checked, skipped := 0, 0
	for _, e := range v {
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		checked++
		input, tag, err := splitAuthenticatedContent(e.AuthenticatedContent)
		if err != nil {
			t.Fatal(err)
		}
		confirmed := ConfirmedTranscriptHash(e.InterimTranscriptHashBefore, input)
		if !bytes.Equal(confirmed, e.ConfirmedTranscriptHashAfter) {
			t.Errorf("confirmed_transcript_hash = %x, want %x", confirmed, e.ConfirmedTranscriptHashAfter)
		}
		if !suite.VerifyMAC(e.ConfirmationKey, e.ConfirmedTranscriptHashAfter, tag) {
			t.Error("confirmation_tag does not verify")
		}
		interim, err := InterimTranscriptHash(confirmed, tag)
		if err != nil || !bytes.Equal(interim, e.InterimTranscriptHashAfter) {
			t.Errorf("interim_transcript_hash = %x, %v; want %x", interim, err, e.InterimTranscriptHashAfter)
		}
	}
	if checked != 1 || skipped != 6 {
		t.Fatalf("transcript-hashes.json: %d suite 1 entries, %d skipped; want 1 and 6", checked, skipped)
	}
	t.Logf("transcript-hashes.json: %d suite 1 entry checked, 0 suite 1 skipped, %d other-suite entries skipped", checked, skipped)
}

func TestTranscriptHashEncoding(t *testing.T) {
	if got, want := ConfirmedTranscriptHash([]byte{1}, []byte{2, 3}), suite.Hash([]byte{1, 2, 3}); !bytes.Equal(got, want) {
		t.Fatalf("ConfirmedTranscriptHash = %x, want %x", got, want)
	}
	if got, err := InterimTranscriptHash([]byte{1}, []byte{2, 3}); err != nil || !bytes.Equal(got, suite.Hash([]byte{1, 2, 2, 3})) {
		t.Fatalf("InterimTranscriptHash = %x, %v", got, err)
	}
	// Epoch 0 starts from empty hashes (section 8.2).
	if got := ConfirmedTranscriptHash(nil, nil); !bytes.Equal(got, suite.Hash(nil)) {
		t.Fatalf("empty ConfirmedTranscriptHash = %x", got)
	}
}

func TestGroupContextCodec(t *testing.T) {
	g := GroupContext{
		CipherSuite:             1,
		GroupID:                 []byte("g"),
		Epoch:                   0x0102030405060708,
		TreeHash:                []byte{0xaa},
		ConfirmedTranscriptHash: []byte{},
		Extensions:              []tls.Extension{{Type: 0xf002, Data: []byte{1}}},
	}
	b, err := g.Marshal()
	want := "0001" + "0001" + "0167" + "0102030405060708" + "01aa" + "00" + "04f0020101"
	if err != nil || hex.EncodeToString(b) != want {
		t.Fatalf("Marshal = %x, %v; want %s", b, err, want)
	}
	var got *GroupContext
	err = tls.Decode(b, func(r *tls.Reader) (err error) {
		got, err = ReadGroupContext(r)
		return err
	})
	if err != nil || got.Epoch != g.Epoch || string(got.GroupID) != "g" || len(got.Extensions) != 1 {
		t.Fatalf("ReadGroupContext = %+v, %v", got, err)
	}
	for name, c := range map[string]struct {
		in   string
		want error
	}{
		"version 2":     {"0002" + want[4:], errs.ErrUnsupported},
		"version 0":     {"0000" + want[4:], errs.ErrUnsupported},
		"truncated":     {want[:len(want)-2], errs.ErrMalformed},
		"duplicate ext": {want[:len(want)-10] + "08f0020101f0020101", errs.ErrMalformed},
	} {
		err := tls.Decode(unhex(t, c.in), func(r *tls.Reader) error {
			_, err := ReadGroupContext(r)
			return err
		})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: error = %v, want %v", name, err, c.want)
		}
	}
	for n := range len(want) / 2 {
		_, err := ReadGroupContext(tls.NewReader(unhex(t, want)[:n]))
		if !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("prefix of %d bytes: error = %v", n, err)
		}
	}
}

func TestPSKIDCodec(t *testing.T) {
	for name, c := range map[string]struct {
		id   PSKID
		want string
	}{
		"external":   {PSKID{Type: PSKExternal, ID: []byte{1, 2}, Nonce: make([]byte, 32)}, "01" + "020102" + "20" + strings.Repeat("00", 32)},
		"resumption": {PSKID{Type: PSKResumption, Usage: UsageBranch, GroupID: []byte{9}, Epoch: 7, Nonce: make([]byte, 32)}, "02" + "03" + "0109" + "0000000000000007" + "20" + strings.Repeat("00", 32)},
	} {
		var w tls.Writer
		c.id.Write(&w)
		b, err := w.Bytes()
		if err != nil || hex.EncodeToString(b) != c.want {
			t.Errorf("%s: Write = %x, %v; want %s", name, b, err, c.want)
		}
		var got *PSKID
		err = tls.Decode(b, func(r *tls.Reader) (err error) {
			got, err = ReadPSKID(r)
			return err
		})
		if err != nil || got.Type != c.id.Type || got.Usage != c.id.Usage || got.Epoch != c.id.Epoch ||
			!bytes.Equal(got.ID, c.id.ID) || !bytes.Equal(got.GroupID, c.id.GroupID) || !bytes.Equal(got.Nonce, c.id.Nonce) {
			t.Errorf("%s: ReadPSKID = %+v, %v", name, got, err)
		}
		for n := range len(b) {
			if _, err := ReadPSKID(tls.NewReader(b[:n])); !errors.Is(err, errs.ErrMalformed) {
				t.Errorf("%s: prefix of %d bytes: error = %v", name, n, err)
			}
		}
	}
	for _, s := range []string{"00" + "00", "03" + "00", "ff" + "00"} {
		if _, err := ReadPSKID(tls.NewReader(unhex(t, s))); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("ReadPSKID(%s) error = %v", s, err)
		}
	}
}

func TestPSKSecretArguments(t *testing.T) {
	got, err := PSKSecret(nil, nil)
	if err != nil || !bytes.Equal(got, make([]byte, suite.Nh)) {
		t.Fatalf("no PSK = %x, %v; want the zero vector", got, err)
	}
	id := &PSKID{Type: PSKExternal, ID: []byte{1}, Nonce: make([]byte, suite.Nh)}
	if _, err := PSKSecret([]*PSKID{id}, nil); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Errorf("one ID, no PSK: error = %v", err)
	}
	if _, err := PSKSecret(nil, [][]byte{{1}}); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Errorf("no ID, one PSK: error = %v", err)
	}
	many := make([]*PSKID, 0x10000)
	if _, err := PSKSecret(many, make([][]byte, 0x10000)); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Errorf("65536 PSKs: error = %v", err)
	}
	// index and count are bound into each PSK input: the same PSK twice gives
	// a different secret than once.
	one, _ := PSKSecret([]*PSKID{id}, [][]byte{{5}})
	two, _ := PSKSecret([]*PSKID{id, id}, [][]byte{{5}, {5}})
	if bytes.Equal(one, two) || bytes.Equal(one, make([]byte, suite.Nh)) {
		t.Fatal("PSK chain ignores count or input")
	}
}

func TestSecretSizes(t *testing.T) {
	ok := make([]byte, suite.Nh)
	for _, n := range []int{0, 31, 33} {
		bad := make([]byte, n)
		if _, err := JoinerSecret(bad, ok, nil); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("init_secret of %d bytes: error = %v", n, err)
		}
		if _, err := JoinerSecret(ok, bad, nil); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("commit_secret of %d bytes: error = %v", n, err)
		}
		if _, _, err := Epoch(bad, ok, nil); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("joiner_secret of %d bytes: error = %v", n, err)
		}
		if _, _, err := Epoch(ok, bad, nil); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("psk_secret of %d bytes: error = %v", n, err)
		}
		if _, err := FromEpochSecret(bad); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("epoch_secret of %d bytes: error = %v", n, err)
		}
		if _, err := WelcomeSecret(bad, ok); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("WelcomeSecret joiner_secret of %d bytes: error = %v", n, err)
		}
		if _, err := WelcomeSecret(ok, bad); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("WelcomeSecret psk_secret of %d bytes: error = %v", n, err)
		}
	}
}

// Group creation starts from a random epoch_secret (section 11); every Table 4
// secret and init_secret must be a distinct DeriveSecret of it.
func TestFromEpochSecret(t *testing.T) {
	es := bytes.Repeat([]byte{3}, suite.Nh)
	s, err := FromEpochSecret(es)
	if err != nil {
		t.Fatal(err)
	}
	for label, got := range map[string][]byte{
		"sender data": s.SenderData, "encryption": s.Encryption, "exporter": s.Exporter,
		"confirm": s.Confirmation, "membership": s.Membership,
		"resumption": s.Resumption, "authentication": s.EpochAuthenticator, "init": s.Init,
	} {
		want, _ := suite.DeriveSecret(es, label)
		if !bytes.Equal(got, want) {
			t.Errorf("%s = %x, want %x", label, got, want)
		}
	}
}

func TestSecretsClear(t *testing.T) {
	s, err := FromEpochSecret(bytes.Repeat([]byte{3}, suite.Nh))
	if err != nil {
		t.Fatal(err)
	}
	s.Clear()
	for _, b := range [][]byte{s.SenderData, s.Encryption, s.Exporter, s.Confirmation, s.Membership, s.Resumption, s.EpochAuthenticator, s.Init} {
		if !bytes.Equal(b, make([]byte, suite.Nh)) {
			t.Fatal("Clear left a secret")
		}
	}
}

func TestExportArguments(t *testing.T) {
	secret := make([]byte, suite.Nh)
	if b, err := Export(secret, "l", nil, 255*suite.Nh); err != nil || len(b) != 255*suite.Nh {
		t.Fatalf("Export(8160) = %d bytes, %v", len(b), err)
	}
	if _, err := Export(secret, "l", nil, 255*suite.Nh+1); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("Export(8161) error = %v", err)
	}
	a, _ := Export(secret, "l", []byte("c"), 16)
	b, _ := Export(secret, "l", []byte("d"), 16)
	c, _ := Export(secret, "m", []byte("c"), 16)
	if bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Fatal("Export ignores its label or context")
	}
}

func FuzzGroupContext(f *testing.F) {
	f.Add(unhex(f, "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00"))
	f.Add(unhex(f, "0001000101670102030405060708"+"01aa"+"00"+"04f0020101"))
	f.Fuzz(func(t *testing.T, in []byte) {
		var g *GroupContext
		err := tls.Decode(in, func(r *tls.Reader) (err error) {
			g, err = ReadGroupContext(r)
			return err
		})
		if err != nil {
			if !errors.Is(err, errs.ErrMalformed) && !errors.Is(err, errs.ErrUnsupported) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		out, err := g.Marshal()
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("decode-encode %x = %x, %v", in, out, err)
		}
	})
}

func FuzzPSKID(f *testing.F) {
	f.Add(unhex(f, "01"+"020102"+"0103"))
	f.Add(unhex(f, "02"+"03"+"0109"+"0000000000000007"+"00"))
	f.Fuzz(func(t *testing.T, in []byte) {
		var p *PSKID
		err := tls.Decode(in, func(r *tls.Reader) (err error) {
			p, err = ReadPSKID(r)
			return err
		})
		if err != nil {
			if !errors.Is(err, errs.ErrMalformed) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		var w tls.Writer
		p.Write(&w)
		out, err := w.Bytes()
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("decode-encode %x = %x, %v", in, out, err)
		}
	})
}

// A psk_nonce shorter than any suite's KDF.Nh is refused while reading.
func TestPSKIDShortNonce(t *testing.T) {
	for _, n := range []int{0, 31} {
		var w tls.Writer
		(&PSKID{Type: PSKExternal, ID: []byte{1}, Nonce: make([]byte, n)}).Write(&w)
		b, _ := w.Bytes()
		if _, err := ReadPSKID(tls.NewReader(b)); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("nonce of %d bytes: error = %v", n, err)
		}
	}
}
