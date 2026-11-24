package message

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
)

// vectorSeeds returns the values of one messages.json field, when present.
func vectorSeeds(f *testing.F, field func(*messagesVector) []byte) [][]byte {
	if !testvec.Present(f, "messages.json") {
		return nil
	}
	var out [][]byte
	for _, v := range loadMessages(f) {
		out = append(out, field(&v))
	}
	return out
}

// fuzzRoundTrip checks that decode never panics, fails only with a decoding
// error, and that every accepted input re-encodes to itself.
func fuzzRoundTrip[T any](f *testing.F, seeds [][]byte, decode func([]byte) (T, error), encode func(T) ([]byte, error)) {
	for _, s := range seeds {
		f.Add(s)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := decode(in)
		if err != nil {
			if !errors.Is(err, errs.ErrMalformed) && !errors.Is(err, errs.ErrUnsupported) && !errors.Is(err, errs.ErrInvalidTree) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		out, err := encode(v)
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("decode-encode differs: %v", err)
		}
	})
}

func FuzzMLSMessage(f *testing.F) {
	var seeds [][]byte
	for _, c := range messageCodecs {
		if c.name == "mls_welcome" || c.name == "mls_group_info" || c.name == "mls_key_package" || bytes.HasPrefix([]byte(c.name), []byte("p")) {
			seeds = append(seeds, vectorSeeds(f, c.field)...)
		}
	}
	fuzzRoundTrip(f, seeds, UnmarshalMLSMessage, (*MLSMessage).Marshal)
}

func FuzzKeyPackage(f *testing.F) {
	var seeds [][]byte
	for _, b := range vectorSeeds(f, func(v *messagesVector) []byte { return v.MLSKeyPackage }) {
		seeds = append(seeds, b[4:])
	}
	fuzzRoundTrip(f, seeds, UnmarshalKeyPackage, (*KeyPackage).Marshal)
}

func FuzzProposal(f *testing.F) {
	var seeds [][]byte
	for typ, field := range map[uint16]func(*messagesVector) []byte{
		ProposalAdd:                    func(v *messagesVector) []byte { return v.AddProposal },
		ProposalUpdate:                 func(v *messagesVector) []byte { return v.UpdateProposal },
		ProposalRemove:                 func(v *messagesVector) []byte { return v.RemoveProposal },
		ProposalPSK:                    func(v *messagesVector) []byte { return v.PreSharedKeyProposal },
		ProposalReInit:                 func(v *messagesVector) []byte { return v.ReInitProposal },
		ProposalExternalInit:           func(v *messagesVector) []byte { return v.ExternalInitProposal },
		ProposalGroupContextExtensions: func(v *messagesVector) []byte { return v.GroupContextExtensionsProposal },
	} {
		for _, b := range vectorSeeds(f, field) {
			seeds = append(seeds, append([]byte{byte(typ >> 8), byte(typ)}, b...))
		}
	}
	fuzzRoundTrip(f, seeds, UnmarshalProposal, (*Proposal).Marshal)
}

func FuzzCommit(f *testing.F) {
	fuzzRoundTrip(f, vectorSeeds(f, func(v *messagesVector) []byte { return v.Commit }), UnmarshalCommit, (*Commit).Marshal)
}

func FuzzGroupInfo(f *testing.F) {
	var seeds [][]byte
	for _, b := range vectorSeeds(f, func(v *messagesVector) []byte { return v.MLSGroupInfo }) {
		seeds = append(seeds, b[4:])
	}
	fuzzRoundTrip(f, seeds, UnmarshalGroupInfo, (*GroupInfo).Marshal)
}

func FuzzGroupSecrets(f *testing.F) {
	fuzzRoundTrip(f, vectorSeeds(f, func(v *messagesVector) []byte { return v.GroupSecrets }), UnmarshalGroupSecrets, (*GroupSecrets).Marshal)
}

func FuzzWelcome(f *testing.F) {
	var seeds [][]byte
	for _, b := range vectorSeeds(f, func(v *messagesVector) []byte { return v.MLSWelcome }) {
		seeds = append(seeds, b[4:])
	}
	fuzzRoundTrip(f, seeds, UnmarshalWelcome, func(w *Welcome) ([]byte, error) { return marshal(w.Write) })
}

func FuzzAuthenticatedContent(f *testing.F) {
	var seeds [][]byte
	for _, b := range vectorSeeds(f, func(v *messagesVector) []byte { return v.PublicMessageCommit }) {
		m, err := UnmarshalMLSMessage(b)
		if err != nil {
			continue
		}
		ac := &AuthenticatedContent{WireFormat: WirePublic, Content: m.Public.Content, Auth: m.Public.Auth}
		s, _ := ac.Marshal()
		seeds = append(seeds, s)
	}
	fuzzRoundTrip(f, seeds, UnmarshalAuthenticatedContent, (*AuthenticatedContent).Marshal)
}

func FuzzSenderData(f *testing.F) {
	fuzzRoundTrip(f, [][]byte{make([]byte, 12)}, UnmarshalSenderData, (*SenderData).Marshal)
}

func FuzzRequiredCapabilities(f *testing.F) {
	s, _ := (&RequiredCapabilities{Extensions: []uint16{3}, Proposals: []uint16{8}, Credentials: []uint16{1}}).Marshal()
	fuzzRoundTrip(f, [][]byte{s}, UnmarshalRequiredCapabilities, (*RequiredCapabilities).Marshal)
}

// FuzzPrivateContent decodes PrivateMessageContent with the content type of
// the first input byte; it re-encodes with the padding it found.
func FuzzPrivateContent(f *testing.F) {
	c := &FramedContent{ContentType: ContentProposal, Proposal: &Proposal{Type: ProposalRemove, Removed: 1}}
	b, _ := MarshalPrivateContent(c, &AuthData{Signature: []byte{1}}, 4)
	f.Add(append([]byte{ContentProposal}, b...))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) == 0 || in[0] < ContentApplication || in[0] > ContentCommit {
			return
		}
		c := &FramedContent{ContentType: in[0]}
		auth, err := UnmarshalPrivateContent(in[1:], c)
		if err != nil {
			if !errors.Is(err, errs.ErrMalformed) && !errors.Is(err, errs.ErrInvalidTree) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		bare, err := MarshalPrivateContent(c, &auth, 0)
		if err != nil {
			t.Fatal(err)
		}
		out, err := MarshalPrivateContent(c, &auth, len(in)-1-len(bare))
		if err != nil || !bytes.Equal(out, in[1:]) {
			t.Fatalf("decode-encode differs: %v", err)
		}
	})
}
