package message

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

type messagesVector struct {
	MLSWelcome                     testvec.Hex `json:"mls_welcome"`
	MLSGroupInfo                   testvec.Hex `json:"mls_group_info"`
	MLSKeyPackage                  testvec.Hex `json:"mls_key_package"`
	RatchetTree                    testvec.Hex `json:"ratchet_tree"`
	GroupSecrets                   testvec.Hex `json:"group_secrets"`
	AddProposal                    testvec.Hex `json:"add_proposal"`
	UpdateProposal                 testvec.Hex `json:"update_proposal"`
	RemoveProposal                 testvec.Hex `json:"remove_proposal"`
	PreSharedKeyProposal           testvec.Hex `json:"pre_shared_key_proposal"`
	ReInitProposal                 testvec.Hex `json:"re_init_proposal"`
	ExternalInitProposal           testvec.Hex `json:"external_init_proposal"`
	GroupContextExtensionsProposal testvec.Hex `json:"group_context_extensions_proposal"`
	Commit                         testvec.Hex `json:"commit"`
	PublicMessageApplication       testvec.Hex `json:"public_message_application"`
	PublicMessageProposal          testvec.Hex `json:"public_message_proposal"`
	PublicMessageCommit            testvec.Hex `json:"public_message_commit"`
	PrivateMessage                 testvec.Hex `json:"private_message"`
}

// codec decodes a whole value and re-encodes it.
type codec func(b []byte) ([]byte, error)

func roundTrip[T any](read func(*tls.Reader) (T, error), write func(T, *tls.Writer)) codec {
	return func(b []byte) ([]byte, error) {
		v, err := unmarshal(b, read)
		if err != nil {
			return nil, err
		}
		return marshal(func(w *tls.Writer) { write(v, w) })
	}
}

// Prefixed bodies of Add, Update and so on: the vectors hold the proposal
// body without its proposal_type, so the test prefixes it.
func proposalBody(typ uint16) codec {
	return func(b []byte) ([]byte, error) {
		var w tls.Writer
		w.U16(typ)
		w.Fixed(b)
		in, _ := w.Bytes()
		p, err := UnmarshalProposal(in)
		if err != nil {
			return nil, err
		}
		out, err := p.Marshal()
		if err != nil {
			return nil, err
		}
		return out[2:], nil
	}
}

func mlsMessage(wireFormat uint16, contentType uint8) codec {
	return func(b []byte) ([]byte, error) {
		m, err := UnmarshalMLSMessage(b)
		if err != nil {
			return nil, err
		}
		if m.WireFormat != wireFormat {
			return nil, errors.New("wrong wire format")
		}
		if contentType != 0 && m.Public.Content.ContentType != contentType {
			return nil, errors.New("wrong content type")
		}
		return m.Marshal()
	}
}

var messageCodecs = []struct {
	name  string
	field func(*messagesVector) []byte
	codec codec
}{
	{"mls_welcome", func(v *messagesVector) []byte { return v.MLSWelcome }, mlsMessage(WireWelcome, 0)},
	{"mls_group_info", func(v *messagesVector) []byte { return v.MLSGroupInfo }, mlsMessage(WireGroupInfo, 0)},
	{"mls_key_package", func(v *messagesVector) []byte { return v.MLSKeyPackage }, mlsMessage(WireKeyPackage, 0)},
	{"ratchet_tree", func(v *messagesVector) []byte { return v.RatchetTree }, func(b []byte) ([]byte, error) {
		t, err := tree.UnmarshalTree(b)
		if err != nil {
			return nil, err
		}
		return t.Marshal()
	}},
	{"group_secrets", func(v *messagesVector) []byte { return v.GroupSecrets }, roundTrip(ReadGroupSecrets, (*GroupSecrets).Write)},
	{"add_proposal", func(v *messagesVector) []byte { return v.AddProposal }, proposalBody(ProposalAdd)},
	{"update_proposal", func(v *messagesVector) []byte { return v.UpdateProposal }, proposalBody(ProposalUpdate)},
	{"remove_proposal", func(v *messagesVector) []byte { return v.RemoveProposal }, proposalBody(ProposalRemove)},
	{"pre_shared_key_proposal", func(v *messagesVector) []byte { return v.PreSharedKeyProposal }, proposalBody(ProposalPSK)},
	{"re_init_proposal", func(v *messagesVector) []byte { return v.ReInitProposal }, proposalBody(ProposalReInit)},
	{"external_init_proposal", func(v *messagesVector) []byte { return v.ExternalInitProposal }, proposalBody(ProposalExternalInit)},
	{"group_context_extensions_proposal", func(v *messagesVector) []byte { return v.GroupContextExtensionsProposal }, proposalBody(ProposalGroupContextExtensions)},
	{"commit", func(v *messagesVector) []byte { return v.Commit }, roundTrip(ReadCommit, (*Commit).Write)},
	{"public_message_application", func(v *messagesVector) []byte { return v.PublicMessageApplication }, mlsMessage(WirePublic, ContentApplication)},
	{"public_message_proposal", func(v *messagesVector) []byte { return v.PublicMessageProposal }, mlsMessage(WirePublic, ContentProposal)},
	{"public_message_commit", func(v *messagesVector) []byte { return v.PublicMessageCommit }, mlsMessage(WirePublic, ContentCommit)},
	{"private_message", func(v *messagesVector) []byte { return v.PrivateMessage }, mlsMessage(WirePrivate, 0)},
}

func loadMessages(t testing.TB) []messagesVector {
	var v []messagesVector
	testvec.Load(t, "messages.json", &v)
	return v
}

// TestMessagesVectors decodes and re-encodes every structure of every entry
// of messages.json. The file has no cipher suite field; its KeyPackages give
// 100 entries each of suites 1, 3 and 2. Ratchet trees of suite 2 have P-256
// keys, which ReadTree refuses by size; every other value must round-trip.
func TestMessagesVectors(t *testing.T) {
	v := loadMessages(t)
	if len(v) != 300 {
		t.Fatalf("messages.json has %d entries, want 300", len(v))
	}
	checked, suite1, refused := 0, 0, 0
	for i := range v {
		m, err := UnmarshalMLSMessage(v[i].MLSKeyPackage)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		cs := m.KeyPackage.CipherSuite
		if cs == 1 {
			suite1++
		}
		for _, c := range messageCodecs {
			in := c.field(&v[i])
			if len(in) == 0 {
				t.Fatalf("entry %d: %s is empty", i, c.name)
			}
			out, err := c.codec(in)
			if c.name == "ratchet_tree" && cs == 2 {
				if !errors.Is(err, errs.ErrInvalidTree) {
					t.Fatalf("entry %d: suite 2 ratchet_tree: error = %v, want ErrInvalidTree", i, err)
				}
				refused++
				continue
			}
			if err != nil {
				t.Fatalf("entry %d: %s: %v", i, c.name, err)
			}
			if !bytes.Equal(out, in) {
				t.Fatalf("entry %d: %s re-encodes differently", i, c.name)
			}
			checked++
		}
	}
	if checked != 300*17-100 || suite1 != 100 || refused != 100 {
		t.Fatalf("checked %d values (%d suite 1 entries, %d suite 2 trees refused), want %d, 100, 100", checked, suite1, refused, 300*17-100)
	}
}

func TestProposalTypes(t *testing.T) {
	kp := &KeyPackage{Version: 1, CipherSuite: 1, InitKey: []byte{1}, LeafNode: &tree.LeafNode{Credential: tree.Credential{Type: tree.CredentialBasic}, Source: tree.SourceKeyPackage}, Signature: []byte{2}}
	for _, p := range []*Proposal{
		{Type: ProposalAdd, KeyPackage: kp},
		{Type: ProposalUpdate, LeafNode: &tree.LeafNode{Credential: tree.Credential{Type: tree.CredentialBasic}, Source: tree.SourceUpdate}},
		{Type: ProposalRemove, Removed: 7},
		{Type: ProposalPSK, PSK: &schedule.PSKID{Type: schedule.PSKExternal, ID: []byte{1}, Nonce: make([]byte, 32)}},
		{Type: ProposalReInit, ReInit: &ReInit{GroupID: []byte{1}, Version: 1, CipherSuite: 1}},
		{Type: ProposalExternalInit, KEMOutput: []byte{3}},
		{Type: ProposalGroupContextExtensions, Extensions: []tls.Extension{{Type: 9}}},
	} {
		b, err := p.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnmarshalProposal(b)
		if err != nil || got.Type != p.Type {
			t.Fatalf("type %d: %v", p.Type, err)
		}
		again, _ := got.Marshal()
		if !bytes.Equal(again, b) {
			t.Fatalf("type %d re-encodes differently", p.Type)
		}
	}
	for _, typ := range []uint16{0, 8, 0x0a0a, 0xffff} {
		if _, err := UnmarshalProposal([]byte{byte(typ >> 8), byte(typ), 0}); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("proposal type %#x: error = %v", typ, err)
		}
	}
}

func TestMalformedFraming(t *testing.T) {
	v := loadMessages(t)
	pub := v[0].PublicMessageProposal
	for name, c := range map[string]struct {
		in   []byte
		want error
	}{
		"version 2":         {append([]byte{0, 2}, pub[2:]...), errs.ErrUnsupported},
		"wire format 6":     {append([]byte{0, 1, 0, 6}, pub[4:]...), errs.ErrMalformed},
		"wire format 0":     {append([]byte{0, 1, 0, 0}, pub[4:]...), errs.ErrMalformed},
		"truncated":         {pub[:len(pub)-1], errs.ErrMalformed},
		"trailing byte":     {append(append([]byte{}, pub...), 0), errs.ErrMalformed},
		"empty":             {nil, errs.ErrMalformed},
		"only version":      {[]byte{0, 1}, errs.ErrMalformed},
		"private truncated": {v[0].PrivateMessage[:len(v[0].PrivateMessage)-1], errs.ErrMalformed},
	} {
		if _, err := UnmarshalMLSMessage(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: error = %v, want %v", name, err, c.want)
		}
	}
}

func TestSenderAndContentTypes(t *testing.T) {
	base := FramedContent{GroupID: []byte{1}, Epoch: 2, Sender: Sender{Type: SenderMember, Index: 3}, ContentType: ContentApplication, ApplicationData: []byte{4}}
	for _, s := range []Sender{{Type: SenderMember, Index: 3}, {Type: SenderExternal, Index: 1}, {Type: SenderNewMemberProposal}, {Type: SenderNewMemberCommit}} {
		c := base
		c.Sender = s
		b, _ := marshal(c.Write)
		got, err := unmarshal(b, ReadFramedContent)
		if err != nil || got.Sender != s {
			t.Errorf("sender %+v: %+v, %v", s, got, err)
		}
	}
	b, _ := marshal(base.Write)
	senderAt := 1 + 1 + 8
	for _, bad := range []uint8{0, 5, 255} {
		in := bytes.Clone(b)
		in[senderAt] = bad
		if _, err := unmarshal(in, ReadFramedContent); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("sender type %d: error = %v", bad, err)
		}
	}
	typeAt := senderAt + 5 + 1
	for _, bad := range []uint8{0, 4} {
		in := bytes.Clone(b)
		in[typeAt] = bad
		if _, err := unmarshal(in, ReadFramedContent); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("content type %d: error = %v", bad, err)
		}
	}
}

func TestPrivateContentPadding(t *testing.T) {
	c := &FramedContent{ContentType: ContentApplication, ApplicationData: []byte("hi")}
	auth := &AuthData{Signature: []byte{1, 2}}
	b, err := MarshalPrivateContent(c, auth, 5)
	if err != nil {
		t.Fatal(err)
	}
	got := &FramedContent{ContentType: ContentApplication}
	a, err := UnmarshalPrivateContent(b, got)
	if err != nil || string(got.ApplicationData) != "hi" || !bytes.Equal(a.Signature, auth.Signature) {
		t.Fatalf("round trip: %v", err)
	}
	b[len(b)-1] = 1
	if _, err := UnmarshalPrivateContent(b, &FramedContent{ContentType: ContentApplication}); !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("non-zero padding: error = %v", err)
	}
	if _, err := MarshalPrivateContent(c, auth, -1); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("negative padding: error = %v", err)
	}
}

func TestCommitPathPresence(t *testing.T) {
	c := &Commit{Proposals: []ProposalOrRef{{Type: ByReference, Ref: []byte{1}}}}
	b, _ := c.Marshal()
	b[len(b)-1] = 2
	if _, err := UnmarshalCommit(b); !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("presence octet 2: error = %v", err)
	}
	for _, typ := range []byte{0, 3} {
		in := []byte{2, typ, 0, 0}
		if _, err := UnmarshalCommit(in); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("ProposalOrRefType %d: error = %v", typ, err)
		}
	}
}

func TestGroupSecretsPathSecret(t *testing.T) {
	for _, g := range []*GroupSecrets{
		{JoinerSecret: []byte{1}},
		{JoinerSecret: []byte{1}, HasPathSecret: true, PathSecret: []byte{}},
		{JoinerSecret: []byte{1}, HasPathSecret: true, PathSecret: []byte{2}, PSKs: []*schedule.PSKID{{Type: schedule.PSKResumption, Usage: schedule.UsageBranch, GroupID: []byte{3}, Epoch: 4, Nonce: make([]byte, 32)}}},
	} {
		b, _ := g.Marshal()
		got, err := UnmarshalGroupSecrets(b)
		if err != nil || got.HasPathSecret != g.HasPathSecret {
			t.Fatalf("%+v: %+v, %v", g, got, err)
		}
		again, _ := got.Marshal()
		if !bytes.Equal(again, b) {
			t.Fatal("re-encoding differs")
		}
	}
}
