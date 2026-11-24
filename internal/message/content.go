package message

import (
	"fmt"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// Sender is an MLS Sender (RFC 9420 section 6); Index is the leaf_index of a
// member or the sender_index of an external sender.
type Sender struct {
	Type  uint8
	Index uint32
}

func (s Sender) write(w *tls.Writer) {
	w.U8(s.Type)
	if s.Type == SenderMember || s.Type == SenderExternal {
		w.U32(s.Index)
	}
}

func readSender(r *tls.Reader) (Sender, error) {
	var s Sender
	var err error
	if s.Type, err = r.U8(); err != nil {
		return s, err
	}
	switch s.Type {
	case SenderMember, SenderExternal:
		s.Index, err = r.U32()
	case SenderNewMemberProposal, SenderNewMemberCommit:
	default:
		err = malformed("sender type", s.Type)
	}
	return s, err
}

// FramedContent is an MLS FramedContent (RFC 9420 section 6); the body of
// its content type is set: ApplicationData, Proposal or Commit.
type FramedContent struct {
	GroupID           []byte
	Epoch             uint64
	Sender            Sender
	AuthenticatedData []byte
	ContentType       uint8
	ApplicationData   []byte
	Proposal          *Proposal
	Commit            *Commit
}

func (c *FramedContent) writeBody(w *tls.Writer) {
	switch c.ContentType {
	case ContentApplication:
		w.Opaque(c.ApplicationData)
	case ContentProposal:
		c.Proposal.Write(w)
	case ContentCommit:
		c.Commit.Write(w)
	}
}

// Write appends the encoding of c to w.
func (c *FramedContent) Write(w *tls.Writer) {
	w.Opaque(c.GroupID)
	w.U64(c.Epoch)
	c.Sender.write(w)
	w.Opaque(c.AuthenticatedData)
	w.U8(c.ContentType)
	c.writeBody(w)
}

func readContentType(r *tls.Reader) (uint8, error) {
	t, err := r.U8()
	if err != nil {
		return 0, err
	}
	if t < ContentApplication || t > ContentCommit {
		return 0, malformed("content type", t)
	}
	return t, nil
}

func (c *FramedContent) readBody(r *tls.Reader) error {
	var err error
	switch c.ContentType {
	case ContentApplication:
		c.ApplicationData, err = r.Opaque()
	case ContentProposal:
		c.Proposal, err = ReadProposal(r)
	case ContentCommit:
		c.Commit, err = ReadCommit(r)
	}
	return err
}

// ReadFramedContent reads a FramedContent.
func ReadFramedContent(r *tls.Reader) (*FramedContent, error) {
	var c FramedContent
	var err error
	if c.GroupID, err = r.Opaque(); err != nil {
		return nil, err
	}
	if c.Epoch, err = r.U64(); err != nil {
		return nil, err
	}
	if c.Sender, err = readSender(r); err != nil {
		return nil, err
	}
	if c.AuthenticatedData, err = r.Opaque(); err != nil {
		return nil, err
	}
	if c.ContentType, err = readContentType(r); err != nil {
		return nil, err
	}
	if err := c.readBody(r); err != nil {
		return nil, err
	}
	return &c, nil
}

// AuthData is an MLS FramedContentAuthData (RFC 9420 section 6.1);
// ConfirmationTag is set for commits only.
type AuthData struct {
	Signature       []byte
	ConfirmationTag []byte
}

func (a *AuthData) write(w *tls.Writer, contentType uint8) {
	w.Opaque(a.Signature)
	if contentType == ContentCommit {
		w.Opaque(a.ConfirmationTag)
	}
}

func readAuthData(r *tls.Reader, contentType uint8) (AuthData, error) {
	var a AuthData
	var err error
	if a.Signature, err = r.Opaque(); err != nil {
		return a, err
	}
	if contentType == ContentCommit {
		a.ConfirmationTag, err = r.Opaque()
	}
	return a, err
}

// AuthenticatedContent is an MLS AuthenticatedContent (RFC 9420 section 6).
type AuthenticatedContent struct {
	WireFormat uint16
	Content    *FramedContent
	Auth       AuthData
}

// Marshal returns the encoding of a.
func (a *AuthenticatedContent) Marshal() ([]byte, error) {
	return marshal(func(w *tls.Writer) {
		w.U16(a.WireFormat)
		a.Content.Write(w)
		a.Auth.write(w, a.Content.ContentType)
	})
}

// ProposalRef returns the ProposalRef of a proposal (RFC 9420 section 5.2).
func (a *AuthenticatedContent) ProposalRef() ([]byte, error) {
	b, err := a.Marshal()
	if err != nil {
		return nil, err
	}
	return suite.RefHash("MLS 1.0 Proposal Reference", b)
}

// ConfirmedTranscriptHashInput returns the ConfirmedTranscriptHashInput of a
// commit (RFC 9420 section 8.2).
func (a *AuthenticatedContent) ConfirmedTranscriptHashInput() ([]byte, error) {
	return marshal(func(w *tls.Writer) {
		w.U16(a.WireFormat)
		a.Content.Write(w)
		w.Opaque(a.Auth.Signature)
	})
}

// UnmarshalAuthenticatedContent decodes a whole AuthenticatedContent.
func UnmarshalAuthenticatedContent(b []byte) (*AuthenticatedContent, error) {
	return unmarshal(b, func(r *tls.Reader) (*AuthenticatedContent, error) {
		var a AuthenticatedContent
		var err error
		if a.WireFormat, err = r.U16(); err != nil {
			return nil, err
		}
		if a.Content, err = ReadFramedContent(r); err != nil {
			return nil, err
		}
		if a.Auth, err = readAuthData(r, a.Content.ContentType); err != nil {
			return nil, err
		}
		return &a, nil
	})
}

// TBS returns FramedContentTBS for the content as sent with wireFormat;
// context is the encoded GroupContext, used for member and new_member_commit
// senders (RFC 9420 section 6.1).
func TBS(wireFormat uint16, c *FramedContent, context []byte) ([]byte, error) {
	return marshal(func(w *tls.Writer) {
		w.U16(schedule.MLS10)
		w.U16(wireFormat)
		c.Write(w)
		if c.Sender.Type == SenderMember || c.Sender.Type == SenderNewMemberCommit {
			w.Fixed(context)
		}
	})
}

// TBM returns AuthenticatedContentTBM, the input of the membership tag
// (RFC 9420 section 6.2).
func TBM(tbs []byte, c *FramedContent, auth *AuthData) ([]byte, error) {
	return marshal(func(w *tls.Writer) {
		w.Fixed(tbs)
		auth.write(w, c.ContentType)
	})
}

// PublicMessage is an MLS PublicMessage (RFC 9420 section 6.2);
// MembershipTag is set for member senders only.
type PublicMessage struct {
	Content       *FramedContent
	Auth          AuthData
	MembershipTag []byte
}

func (p *PublicMessage) write(w *tls.Writer) {
	p.Content.Write(w)
	p.Auth.write(w, p.Content.ContentType)
	if p.Content.Sender.Type == SenderMember {
		w.Opaque(p.MembershipTag)
	}
}

func readPublicMessage(r *tls.Reader) (*PublicMessage, error) {
	var p PublicMessage
	var err error
	if p.Content, err = ReadFramedContent(r); err != nil {
		return nil, err
	}
	if p.Auth, err = readAuthData(r, p.Content.ContentType); err != nil {
		return nil, err
	}
	if p.Content.Sender.Type == SenderMember {
		if p.MembershipTag, err = r.Opaque(); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

// PrivateMessage is an MLS PrivateMessage (RFC 9420 section 6.3).
type PrivateMessage struct {
	GroupID             []byte
	Epoch               uint64
	ContentType         uint8
	AuthenticatedData   []byte
	EncryptedSenderData []byte
	Ciphertext          []byte
}

func (p *PrivateMessage) write(w *tls.Writer) {
	w.Opaque(p.GroupID)
	w.U64(p.Epoch)
	w.U8(p.ContentType)
	w.Opaque(p.AuthenticatedData)
	w.Opaque(p.EncryptedSenderData)
	w.Opaque(p.Ciphertext)
}

func readPrivateMessage(r *tls.Reader) (*PrivateMessage, error) {
	var p PrivateMessage
	var err error
	if p.GroupID, err = r.Opaque(); err != nil {
		return nil, err
	}
	if p.Epoch, err = r.U64(); err != nil {
		return nil, err
	}
	if p.ContentType, err = readContentType(r); err != nil {
		return nil, err
	}
	if p.AuthenticatedData, err = r.Opaque(); err != nil {
		return nil, err
	}
	if p.EncryptedSenderData, err = r.Opaque(); err != nil {
		return nil, err
	}
	if p.Ciphertext, err = r.Opaque(); err != nil {
		return nil, err
	}
	return &p, nil
}

// SenderDataAAD returns SenderDataAAD (RFC 9420 section 6.3.2).
func (p *PrivateMessage) SenderDataAAD() ([]byte, error) {
	return marshal(func(w *tls.Writer) {
		w.Opaque(p.GroupID)
		w.U64(p.Epoch)
		w.U8(p.ContentType)
	})
}

// ContentAAD returns PrivateContentAAD (RFC 9420 section 6.3.1).
func (p *PrivateMessage) ContentAAD() ([]byte, error) {
	return marshal(func(w *tls.Writer) {
		w.Opaque(p.GroupID)
		w.U64(p.Epoch)
		w.U8(p.ContentType)
		w.Opaque(p.AuthenticatedData)
	})
}

// SenderData is an MLS SenderData (RFC 9420 section 6.3.2).
type SenderData struct {
	Leaf       uint32
	Generation uint32
	ReuseGuard [4]byte
}

// Marshal returns the encoding of s.
func (s *SenderData) Marshal() ([]byte, error) {
	return marshal(func(w *tls.Writer) {
		w.U32(s.Leaf)
		w.U32(s.Generation)
		w.Fixed(s.ReuseGuard[:])
	})
}

// UnmarshalSenderData decodes a whole SenderData.
func UnmarshalSenderData(b []byte) (*SenderData, error) {
	return unmarshal(b, func(r *tls.Reader) (*SenderData, error) {
		var s SenderData
		var err error
		if s.Leaf, err = r.U32(); err != nil {
			return nil, err
		}
		if s.Generation, err = r.U32(); err != nil {
			return nil, err
		}
		g, err := r.Fixed(4)
		if err != nil {
			return nil, err
		}
		s.ReuseGuard = [4]byte(g)
		return &s, nil
	})
}

// MarshalPrivateContent returns PrivateMessageContent for c with auth and
// padding zero bytes (RFC 9420 section 6.3.1).
func MarshalPrivateContent(c *FramedContent, auth *AuthData, padding int) ([]byte, error) {
	if padding < 0 {
		return nil, fmt.Errorf("%w: padding %d", errs.ErrInvalidArgument, padding)
	}
	return marshal(func(w *tls.Writer) {
		c.writeBody(w)
		auth.write(w, c.ContentType)
		w.Fixed(make([]byte, padding))
	})
}

// UnmarshalPrivateContent decodes PrivateMessageContent into the body of c,
// whose ContentType is set, and returns its auth; padding must be all zero (RFC 9420
// section 6.3.1).
func UnmarshalPrivateContent(b []byte, c *FramedContent) (AuthData, error) {
	r := tls.NewReader(b)
	if err := c.readBody(r); err != nil {
		return AuthData{}, err
	}
	auth, err := readAuthData(r, c.ContentType)
	if err != nil {
		return AuthData{}, err
	}
	for r.Len() > 0 {
		if v, _ := r.U8(); v != 0 {
			return AuthData{}, fmt.Errorf("%w: padding not zero", errs.ErrMalformed)
		}
	}
	return auth, nil
}

// MLSMessage is an MLS MLSMessage (RFC 9420 section 6); the field of its
// wire format is set. Version is always mls10.
type MLSMessage struct {
	WireFormat uint16
	Public     *PublicMessage
	Private    *PrivateMessage
	Welcome    *Welcome
	GroupInfo  *GroupInfo
	KeyPackage *KeyPackage
}

// Write appends the encoding of m to w.
func (m *MLSMessage) Write(w *tls.Writer) {
	w.U16(schedule.MLS10)
	w.U16(m.WireFormat)
	switch m.WireFormat {
	case WirePublic:
		m.Public.write(w)
	case WirePrivate:
		m.Private.write(w)
	case WireWelcome:
		m.Welcome.Write(w)
	case WireGroupInfo:
		m.GroupInfo.Write(w)
	case WireKeyPackage:
		m.KeyPackage.Write(w)
	}
}

// Marshal returns the encoding of m.
func (m *MLSMessage) Marshal() ([]byte, error) {
	return marshal(m.Write)
}

// ReadMLSMessage reads an MLSMessage. A version other than mls10 is
// unsupported; an unknown wire format cannot be skipped and is malformed.
func ReadMLSMessage(r *tls.Reader) (*MLSMessage, error) {
	v, err := r.U16()
	if err != nil {
		return nil, err
	}
	if v != schedule.MLS10 {
		return nil, fmt.Errorf("%w: protocol version %d", errs.ErrUnsupported, v)
	}
	var m MLSMessage
	if m.WireFormat, err = r.U16(); err != nil {
		return nil, err
	}
	switch m.WireFormat {
	case WirePublic:
		m.Public, err = readPublicMessage(r)
	case WirePrivate:
		m.Private, err = readPrivateMessage(r)
	case WireWelcome:
		m.Welcome, err = ReadWelcome(r)
	case WireGroupInfo:
		m.GroupInfo, err = ReadGroupInfo(r)
	case WireKeyPackage:
		m.KeyPackage, err = ReadKeyPackage(r)
	default:
		err = malformed("wire format", m.WireFormat)
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// UnmarshalMLSMessage decodes a whole MLSMessage.
func UnmarshalMLSMessage(b []byte) (*MLSMessage, error) {
	return unmarshal(b, ReadMLSMessage)
}
