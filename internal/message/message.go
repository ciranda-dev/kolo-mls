// Package message reads and writes the MLS messages of RFC 9420 sections 6,
// 10, 12.1 and 12.4: MLSMessage and its framing, proposals, Commit, KeyPackage,
// GroupInfo, GroupSecrets and Welcome. It checks syntax only; the meaning of
// each field is checked by its users.
package message

import (
	"fmt"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// WireFormat values (RFC 9420 section 17.2).
const (
	WirePublic     uint16 = 1
	WirePrivate    uint16 = 2
	WireWelcome    uint16 = 3
	WireGroupInfo  uint16 = 4
	WireKeyPackage uint16 = 5
)

// ContentType values (RFC 9420 section 6).
const (
	ContentApplication uint8 = 1
	ContentProposal    uint8 = 2
	ContentCommit      uint8 = 3
)

// SenderType values (RFC 9420 section 6).
const (
	SenderMember            uint8 = 1
	SenderExternal          uint8 = 2
	SenderNewMemberProposal uint8 = 3
	SenderNewMemberCommit   uint8 = 4
)

// ProposalType values (RFC 9420 section 17.4).
const (
	ProposalAdd                    uint16 = 1
	ProposalUpdate                 uint16 = 2
	ProposalRemove                 uint16 = 3
	ProposalPSK                    uint16 = 4
	ProposalReInit                 uint16 = 5
	ProposalExternalInit           uint16 = 6
	ProposalGroupContextExtensions uint16 = 7
)

// ExtensionType values of RFC 9420 section 17.3.
const (
	ExtApplicationID        uint16 = 1
	ExtRatchetTree          uint16 = 2
	ExtRequiredCapabilities uint16 = 3
	ExtExternalPub          uint16 = 4
	ExtExternalSenders      uint16 = 5
)

// ProposalOrRefType values (RFC 9420 section 12.4).
const (
	ByValue     uint8 = 1
	ByReference uint8 = 2
)

// readRef reads a HashReference; every registered cipher suite hashes to 32
// bytes or more (RFC 9420 section 17.1), so shorter ones are refused and a
// list of references costs no more memory than its encoding.
func readRef(r *tls.Reader) ([]byte, error) {
	b, err := r.Opaque()
	if err == nil && len(b) < suite.Nh {
		err = malformed("reference of bytes", len(b))
	}
	return b, err
}

func malformed(what string, v any) error {
	return fmt.Errorf("%w: %s %v", errs.ErrMalformed, what, v)
}

// marshal returns the encoding that write produces.
func marshal(write func(w *tls.Writer)) ([]byte, error) {
	var w tls.Writer
	write(&w)
	return w.Bytes()
}

// unmarshal decodes a whole value with read and refuses trailing bytes.
func unmarshal[T any](b []byte, read func(*tls.Reader) (T, error)) (T, error) {
	var v T
	err := tls.Decode(b, func(r *tls.Reader) (err error) {
		v, err = read(r)
		return err
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return v, nil
}

// KeyPackage is an MLS KeyPackage (RFC 9420 section 10).
type KeyPackage struct {
	Version     uint16
	CipherSuite uint16
	InitKey     []byte
	LeafNode    *tree.LeafNode
	Extensions  []tls.Extension
	Signature   []byte
}

func (k *KeyPackage) writeTBS(w *tls.Writer) {
	w.U16(k.Version)
	w.U16(k.CipherSuite)
	w.Opaque(k.InitKey)
	k.LeafNode.Write(w)
	tls.WriteExtensions(w, k.Extensions)
}

// TBS returns KeyPackageTBS.
func (k *KeyPackage) TBS() ([]byte, error) {
	return marshal(k.writeTBS)
}

// Write appends the encoding of k to w.
func (k *KeyPackage) Write(w *tls.Writer) {
	k.writeTBS(w)
	w.Opaque(k.Signature)
}

// Marshal returns the encoding of k.
func (k *KeyPackage) Marshal() ([]byte, error) {
	return marshal(k.Write)
}

// Ref returns the KeyPackageRef of k (RFC 9420 section 5.2).
func (k *KeyPackage) Ref() ([]byte, error) {
	b, err := k.Marshal()
	if err != nil {
		return nil, err
	}
	return suite.RefHash("MLS 1.0 KeyPackage Reference", b)
}

// ReadKeyPackage reads a KeyPackage.
func ReadKeyPackage(r *tls.Reader) (*KeyPackage, error) {
	var k KeyPackage
	var err error
	if k.Version, err = r.U16(); err != nil {
		return nil, err
	}
	if k.CipherSuite, err = r.U16(); err != nil {
		return nil, err
	}
	if k.InitKey, err = r.Opaque(); err != nil {
		return nil, err
	}
	if k.LeafNode, err = tree.ReadLeafNode(r); err != nil {
		return nil, err
	}
	if k.Extensions, err = tls.ReadExtensions(r); err != nil {
		return nil, err
	}
	if k.Signature, err = r.Opaque(); err != nil {
		return nil, err
	}
	return &k, nil
}

// UnmarshalKeyPackage decodes a whole KeyPackage.
func UnmarshalKeyPackage(b []byte) (*KeyPackage, error) {
	return unmarshal(b, ReadKeyPackage)
}

// ReInit is an MLS ReInit proposal (RFC 9420 section 12.1.5).
type ReInit struct {
	GroupID     []byte
	Version     uint16
	CipherSuite uint16
	Extensions  []tls.Extension
}

// Proposal is an MLS Proposal (RFC 9420 section 12.1); the field of its type
// is set: KeyPackage (add), LeafNode (update), Removed (remove), PSK (psk),
// ReInit, KEMOutput (external_init) or Extensions (group_context_extensions).
type Proposal struct {
	Type       uint16
	KeyPackage *KeyPackage
	LeafNode   *tree.LeafNode
	Removed    uint32
	PSK        *schedule.PSKID
	ReInit     *ReInit
	KEMOutput  []byte
	Extensions []tls.Extension
}

// Write appends the encoding of p to w.
func (p *Proposal) Write(w *tls.Writer) {
	w.U16(p.Type)
	switch p.Type {
	case ProposalAdd:
		p.KeyPackage.Write(w)
	case ProposalUpdate:
		p.LeafNode.Write(w)
	case ProposalRemove:
		w.U32(p.Removed)
	case ProposalPSK:
		p.PSK.Write(w)
	case ProposalReInit:
		w.Opaque(p.ReInit.GroupID)
		w.U16(p.ReInit.Version)
		w.U16(p.ReInit.CipherSuite)
		tls.WriteExtensions(w, p.ReInit.Extensions)
	case ProposalExternalInit:
		w.Opaque(p.KEMOutput)
	case ProposalGroupContextExtensions:
		tls.WriteExtensions(w, p.Extensions)
	}
}

// Marshal returns the encoding of p.
func (p *Proposal) Marshal() ([]byte, error) {
	return marshal(p.Write)
}

// ReadProposal reads a Proposal. A proposal type with no select arm cannot
// be skipped, so it is malformed (RFC 9420 section 13.5).
func ReadProposal(r *tls.Reader) (*Proposal, error) {
	var p Proposal
	var err error
	if p.Type, err = r.U16(); err != nil {
		return nil, err
	}
	switch p.Type {
	case ProposalAdd:
		p.KeyPackage, err = ReadKeyPackage(r)
	case ProposalUpdate:
		p.LeafNode, err = tree.ReadLeafNode(r)
	case ProposalRemove:
		p.Removed, err = r.U32()
	case ProposalPSK:
		p.PSK, err = schedule.ReadPSKID(r)
	case ProposalReInit:
		p.ReInit, err = readReInit(r)
	case ProposalExternalInit:
		p.KEMOutput, err = r.Opaque()
	case ProposalGroupContextExtensions:
		p.Extensions, err = tls.ReadExtensions(r)
	default:
		err = malformed("proposal type", p.Type)
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func readReInit(r *tls.Reader) (*ReInit, error) {
	var ri ReInit
	var err error
	if ri.GroupID, err = r.Opaque(); err != nil {
		return nil, err
	}
	if ri.Version, err = r.U16(); err != nil {
		return nil, err
	}
	if ri.CipherSuite, err = r.U16(); err != nil {
		return nil, err
	}
	if ri.Extensions, err = tls.ReadExtensions(r); err != nil {
		return nil, err
	}
	return &ri, nil
}

// UnmarshalProposal decodes a whole Proposal.
func UnmarshalProposal(b []byte) (*Proposal, error) {
	return unmarshal(b, ReadProposal)
}

// ProposalOrRef is a proposal in a Commit, by value or by ProposalRef
// (RFC 9420 section 12.4).
type ProposalOrRef struct {
	Type     uint8
	Proposal *Proposal
	Ref      []byte
}

// Commit is an MLS Commit (RFC 9420 section 12.4); Path is nil when absent.
type Commit struct {
	Proposals []ProposalOrRef
	Path      *tree.UpdatePath
}

// Write appends the encoding of c to w.
func (c *Commit) Write(w *tls.Writer) {
	w.Vector(func(w *tls.Writer) {
		for _, p := range c.Proposals {
			w.U8(p.Type)
			if p.Type == ByValue {
				p.Proposal.Write(w)
			} else {
				w.Opaque(p.Ref)
			}
		}
	})
	w.Optional(c.Path != nil)
	if c.Path != nil {
		c.Path.Write(w)
	}
}

// Marshal returns the encoding of c.
func (c *Commit) Marshal() ([]byte, error) {
	return marshal(c.Write)
}

// ReadCommit reads a Commit.
func ReadCommit(r *tls.Reader) (*Commit, error) {
	var c Commit
	err := r.Vector(func(r *tls.Reader) error {
		var p ProposalOrRef
		var err error
		if p.Type, err = r.U8(); err != nil {
			return err
		}
		switch p.Type {
		case ByValue:
			p.Proposal, err = ReadProposal(r)
		case ByReference:
			p.Ref, err = readRef(r)
		default:
			err = malformed("ProposalOrRefType", p.Type)
		}
		c.Proposals = append(c.Proposals, p)
		return err
	})
	if err != nil {
		return nil, err
	}
	present, err := r.Optional()
	if err != nil {
		return nil, err
	}
	if present {
		if c.Path, err = tree.ReadUpdatePath(r); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// UnmarshalCommit decodes a whole Commit.
func UnmarshalCommit(b []byte) (*Commit, error) {
	return unmarshal(b, ReadCommit)
}

// GroupInfo is an MLS GroupInfo (RFC 9420 section 12.4.3).
type GroupInfo struct {
	GroupContext    *schedule.GroupContext
	Extensions      []tls.Extension
	ConfirmationTag []byte
	Signer          uint32
	Signature       []byte
}

func (g *GroupInfo) writeTBS(w *tls.Writer) {
	g.GroupContext.Write(w)
	tls.WriteExtensions(w, g.Extensions)
	w.Opaque(g.ConfirmationTag)
	w.U32(g.Signer)
}

// TBS returns GroupInfoTBS.
func (g *GroupInfo) TBS() ([]byte, error) {
	return marshal(g.writeTBS)
}

// Write appends the encoding of g to w.
func (g *GroupInfo) Write(w *tls.Writer) {
	g.writeTBS(w)
	w.Opaque(g.Signature)
}

// Marshal returns the encoding of g.
func (g *GroupInfo) Marshal() ([]byte, error) {
	return marshal(g.Write)
}

// ReadGroupInfo reads a GroupInfo.
func ReadGroupInfo(r *tls.Reader) (*GroupInfo, error) {
	var g GroupInfo
	var err error
	if g.GroupContext, err = schedule.ReadGroupContext(r); err != nil {
		return nil, err
	}
	if g.Extensions, err = tls.ReadExtensions(r); err != nil {
		return nil, err
	}
	if g.ConfirmationTag, err = r.Opaque(); err != nil {
		return nil, err
	}
	if g.Signer, err = r.U32(); err != nil {
		return nil, err
	}
	if g.Signature, err = r.Opaque(); err != nil {
		return nil, err
	}
	return &g, nil
}

// UnmarshalGroupInfo decodes a whole GroupInfo.
func UnmarshalGroupInfo(b []byte) (*GroupInfo, error) {
	return unmarshal(b, ReadGroupInfo)
}

// GroupSecrets is an MLS GroupSecrets (RFC 9420 section 12.4.3.1).
type GroupSecrets struct {
	JoinerSecret  []byte
	HasPathSecret bool
	PathSecret    []byte
	PSKs          []*schedule.PSKID
}

// Write appends the encoding of g to w.
func (g *GroupSecrets) Write(w *tls.Writer) {
	w.Opaque(g.JoinerSecret)
	w.Optional(g.HasPathSecret)
	if g.HasPathSecret {
		w.Opaque(g.PathSecret)
	}
	w.Vector(func(w *tls.Writer) {
		for _, p := range g.PSKs {
			p.Write(w)
		}
	})
}

// Marshal returns the encoding of g.
func (g *GroupSecrets) Marshal() ([]byte, error) {
	return marshal(g.Write)
}

// Clear zeroes the secrets of g.
func (g *GroupSecrets) Clear() {
	clear(g.JoinerSecret)
	clear(g.PathSecret)
}

// ReadGroupSecrets reads a GroupSecrets.
func ReadGroupSecrets(r *tls.Reader) (*GroupSecrets, error) {
	var g GroupSecrets
	var err error
	if g.JoinerSecret, err = r.Opaque(); err != nil {
		return nil, err
	}
	if g.HasPathSecret, err = r.Optional(); err != nil {
		return nil, err
	}
	if g.HasPathSecret {
		if g.PathSecret, err = r.Opaque(); err != nil {
			return nil, err
		}
	}
	err = r.Vector(func(r *tls.Reader) error {
		p, err := schedule.ReadPSKID(r)
		g.PSKs = append(g.PSKs, p)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// UnmarshalGroupSecrets decodes a whole GroupSecrets.
func UnmarshalGroupSecrets(b []byte) (*GroupSecrets, error) {
	return unmarshal(b, ReadGroupSecrets)
}

// EncryptedGroupSecrets is one entry of a Welcome (RFC 9420 section 12.4.3.1).
type EncryptedGroupSecrets struct {
	NewMember []byte
	Secrets   tree.HPKECiphertext
}

// Welcome is an MLS Welcome (RFC 9420 section 12.4.3.1).
type Welcome struct {
	CipherSuite        uint16
	Secrets            []EncryptedGroupSecrets
	EncryptedGroupInfo []byte
}

// Write appends the encoding of wm to w.
func (wm *Welcome) Write(w *tls.Writer) {
	w.U16(wm.CipherSuite)
	w.Vector(func(w *tls.Writer) {
		for _, s := range wm.Secrets {
			w.Opaque(s.NewMember)
			w.Opaque(s.Secrets.KEMOutput)
			w.Opaque(s.Secrets.Ciphertext)
		}
	})
	w.Opaque(wm.EncryptedGroupInfo)
}

// ReadWelcome reads a Welcome.
func ReadWelcome(r *tls.Reader) (*Welcome, error) {
	var wm Welcome
	var err error
	if wm.CipherSuite, err = r.U16(); err != nil {
		return nil, err
	}
	err = r.Vector(func(r *tls.Reader) error {
		var s EncryptedGroupSecrets
		var err error
		if s.NewMember, err = readRef(r); err != nil {
			return err
		}
		if s.Secrets, err = tree.ReadHPKECiphertext(r); err != nil {
			return err
		}
		wm.Secrets = append(wm.Secrets, s)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if wm.EncryptedGroupInfo, err = r.Opaque(); err != nil {
		return nil, err
	}
	return &wm, nil
}

// UnmarshalWelcome decodes a whole Welcome.
func UnmarshalWelcome(b []byte) (*Welcome, error) {
	return unmarshal(b, ReadWelcome)
}

// RequiredCapabilities is the required_capabilities extension (RFC 9420
// section 11.1).
type RequiredCapabilities struct {
	Extensions  []uint16
	Proposals   []uint16
	Credentials []uint16
}

// Marshal returns the encoding of c.
func (c *RequiredCapabilities) Marshal() ([]byte, error) {
	return marshal(func(w *tls.Writer) {
		for _, l := range [][]uint16{c.Extensions, c.Proposals, c.Credentials} {
			w.Vector(func(w *tls.Writer) {
				for _, v := range l {
					w.U16(v)
				}
			})
		}
	})
}

// UnmarshalRequiredCapabilities decodes a required_capabilities extension.
func UnmarshalRequiredCapabilities(b []byte) (*RequiredCapabilities, error) {
	return unmarshal(b, func(r *tls.Reader) (*RequiredCapabilities, error) {
		var c RequiredCapabilities
		for _, l := range []*[]uint16{&c.Extensions, &c.Proposals, &c.Credentials} {
			err := r.Vector(func(r *tls.Reader) error {
				v, err := r.U16()
				*l = append(*l, v)
				return err
			})
			if err != nil {
				return nil, err
			}
		}
		return &c, nil
	})
}
