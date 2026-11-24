package message

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// TestUnknownValuesAtTheEnd: an unknown sender type, content type, wire
// format or proposal type is refused by its own check, even when the input
// ends right after it or continues as if it were known.
func TestUnknownValuesAtTheEnd(t *testing.T) {
	framed := func(sender []byte, contentType byte, body ...byte) []byte {
		b := []byte{1, 7, 0, 0, 0, 0, 0, 0, 0, 2}
		b = append(b, sender...)
		b = append(b, 0, contentType)
		return append(b, body...)
	}
	if _, err := unmarshal(framed([]byte{1, 0, 0, 0, 3}, ContentApplication, 0), ReadFramedContent); err != nil {
		t.Fatalf("valid content: %v", err)
	}
	for name, in := range map[string][]byte{
		"sender type 5":  framed([]byte{5}, ContentApplication, 0),
		"content type 0": framed([]byte{1, 0, 0, 0, 3}, 0),
	} {
		if _, err := unmarshal(in, ReadFramedContent); !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := UnmarshalMLSMessage([]byte{0, 1, 0, 6}); !errors.Is(err, errs.ErrMalformed) {
		t.Errorf("wire format 6: %v", err)
	}
	if _, err := UnmarshalProposal([]byte{0, 9}); !errors.Is(err, errs.ErrMalformed) {
		t.Errorf("proposal type 9: %v", err)
	}
}

// TestPublicMessageTagPerSender: only a member's PublicMessage carries a
// membership tag (RFC 9420 section 6.2).
func TestPublicMessageTagPerSender(t *testing.T) {
	for _, c := range []struct {
		sender Sender
		tag    []byte
	}{{Sender{Type: SenderMember, Index: 1}, bytes.Repeat([]byte{9}, 32)}, {Sender{Type: SenderExternal, Index: 0}, nil}, {Sender{Type: SenderNewMemberProposal}, nil}} {
		pm := &PublicMessage{Content: &FramedContent{GroupID: []byte{1}, Sender: c.sender, ContentType: ContentProposal, Proposal: &Proposal{Type: ProposalRemove, Removed: 1}},
			Auth: AuthData{Signature: []byte{2}}, MembershipTag: c.tag}
		b, err := (&MLSMessage{WireFormat: WirePublic, Public: pm}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		m, err := UnmarshalMLSMessage(b)
		if err != nil || !bytes.Equal(m.Public.MembershipTag, c.tag) {
			t.Fatalf("sender type %d: %v", c.sender.Type, err)
		}
	}
}

// TestTBSContextPerSender: FramedContentTBS holds the GroupContext for member
// and new_member_commit senders only (RFC 9420 section 6.1).
func TestTBSContextPerSender(t *testing.T) {
	ctx := []byte("the group context")
	for typ, with := range map[uint8]bool{SenderMember: true, SenderNewMemberCommit: true, SenderExternal: false, SenderNewMemberProposal: false} {
		c := &FramedContent{GroupID: []byte{1}, Sender: Sender{Type: typ}, ContentType: ContentApplication, ApplicationData: []byte{3}}
		tbs, err := TBS(WirePublic, c, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.HasSuffix(tbs, ctx) != with {
			t.Errorf("sender type %d: context in the TBS is %v", typ, !with)
		}
	}
}

// TestShortReferences: a ProposalRef or KeyPackageRef shorter than every
// suite's hash is refused while decoding (RFC 9420 section 17.1).
func TestShortReferences(t *testing.T) {
	for n, ok := range map[int]bool{31: false, 32: true} {
		var w tls.Writer
		w.Vector(func(w *tls.Writer) {
			w.U8(ByReference)
			w.Opaque(make([]byte, n))
		})
		w.Optional(false)
		b, _ := w.Bytes()
		if _, err := UnmarshalCommit(b); (err == nil) != ok || !ok && !errors.Is(err, errs.ErrMalformed) {
			t.Errorf("reference of %d bytes: %v", n, err)
		}
	}
}
