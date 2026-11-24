package framing

import (
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/secrettree"
)

// FuzzUnprotect feeds arbitrary MLSMessages to UnprotectPublic and
// UnprotectPrivate: no panic and a typed error.
func FuzzUnprotect(f *testing.F) {
	fx := synthetic(f)
	pm, _ := ProtectPrivate(fx.content(message.WirePrivate, remove()), fx.v.SenderDataSecret, fx.next(fx.secretTree(), secrettree.Handshake))
	b, _ := (&message.MLSMessage{WireFormat: message.WirePrivate, Private: pm}).Marshal()
	f.Add(b)
	pub, _ := ProtectPublic(fx.content(message.WirePublic, remove()), fx.v.MembershipKey, fx.context)
	b, _ = (&message.MLSMessage{WireFormat: message.WirePublic, Public: pub}).Marshal()
	f.Add(b)
	f.Fuzz(func(t *testing.T, in []byte) {
		m, err := message.UnmarshalMLSMessage(in)
		if err != nil {
			return
		}
		switch m.WireFormat {
		case message.WirePrivate:
			_, _ = OpenSenderData(m.Private, fx.v.SenderDataSecret)
			var lk *secrettree.Lookup
			if _, lk, err = UnprotectPrivate(m.Private, fx.v.SenderDataSecret, fx.secretTree(), member); err == nil {
				lk.Discard()
			}
		case message.WirePublic:
			var ac *message.AuthenticatedContent
			if ac, err = UnprotectPublic(m.Public, fx.v.MembershipKey, fx.context); err == nil {
				err = Verify(fx.v.SignaturePub, ac, fx.context)
			}
		default:
			return
		}
		if err != nil && !errors.Is(err, errs.ErrDecrypt) && !errors.Is(err, errs.ErrMalformed) && !errors.Is(err, errs.ErrMembershipTag) &&
			!errors.Is(err, errs.ErrSignature) && !errors.Is(err, errs.ErrInvalidArgument) && !errors.Is(err, errs.ErrTooFarAhead) &&
			!errors.Is(err, errs.ErrTooOld) && !errors.Is(err, errs.ErrGenerationExhausted) && !errors.Is(err, errs.ErrUnknownSender) && !errors.Is(err, errs.ErrInvalidTree) {
			t.Fatalf("untyped error %v", err)
		}
	})
}
