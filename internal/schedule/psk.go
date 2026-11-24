package schedule

import (
	"fmt"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

// PSKType values (RFC 9420 section 8.4).
const (
	PSKExternal   uint8 = 1
	PSKResumption uint8 = 2
)

// ResumptionPSKUsage values (RFC 9420 section 8.4).
const (
	UsageApplication uint8 = 1
	UsageReinit      uint8 = 2
	UsageBranch      uint8 = 3
)

// PSKID is a PreSharedKeyID (RFC 9420 section 8.4). ID is set for external
// PSKs; Usage, GroupID and Epoch for resumption PSKs.
type PSKID struct {
	Type    uint8
	ID      []byte
	Usage   uint8
	GroupID []byte
	Epoch   uint64
	Nonce   []byte
}

// Write appends the encoding of p to w.
func (p *PSKID) Write(w *tls.Writer) {
	w.U8(p.Type)
	switch p.Type {
	case PSKExternal:
		w.Opaque(p.ID)
	case PSKResumption:
		w.U8(p.Usage)
		w.Opaque(p.GroupID)
		w.U64(p.Epoch)
	}
	w.Opaque(p.Nonce)
}

// ReadPSKID reads a PreSharedKeyID. A psktype with no select arm cannot be
// skipped, so it is malformed.
func ReadPSKID(r *tls.Reader) (*PSKID, error) {
	var p PSKID
	var err error
	if p.Type, err = r.U8(); err != nil {
		return nil, err
	}
	switch p.Type {
	case PSKExternal:
		if p.ID, err = r.Opaque(); err != nil {
			return nil, err
		}
	case PSKResumption:
		if p.Usage, err = r.U8(); err != nil {
			return nil, err
		}
		if p.GroupID, err = r.Opaque(); err != nil {
			return nil, err
		}
		if p.Epoch, err = r.U64(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: psktype %d", errs.ErrMalformed, p.Type)
	}
	if p.Nonce, err = r.Opaque(); err != nil {
		return nil, err
	}
	// psk_nonce is KDF.Nh bytes (RFC 9420 section 12.1.4), 32 or more in
	// every registered suite; shorter nonces are refused while reading, so a
	// list of PSK ids costs no more memory than its encoding.
	if len(p.Nonce) < suite.Nh {
		return nil, fmt.Errorf("%w: psk_nonce of %d bytes", errs.ErrMalformed, len(p.Nonce))
	}
	return &p, nil
}

// PSKSecret computes psk_secret from the PSK IDs and their values, in the
// order of the Commit or GroupSecrets (RFC 9420 section 8.4). No PSK gives
// the all-zero vector.
func PSKSecret(ids []*PSKID, psks [][]byte) ([]byte, error) {
	if len(ids) != len(psks) || len(ids) > 0xffff {
		return nil, fmt.Errorf("%w: PSK count", errs.ErrInvalidArgument)
	}
	zero := make([]byte, suite.Nh)
	secret := make([]byte, suite.Nh)
	for i, id := range ids {
		var w tls.Writer
		id.Write(&w)
		w.U16(uint16(i))
		w.U16(uint16(len(ids)))
		label, err := w.Bytes()
		if err != nil {
			return nil, err
		}
		extracted, err := suite.Extract(zero, psks[i])
		if err != nil {
			return nil, err
		}
		input, err := suite.ExpandWithLabel(extracted, "derived psk", label, suite.Nh)
		clear(extracted)
		if err != nil {
			return nil, err
		}
		// Section 8.4's formula takes psk_input as the salt and Figure 24 draws
		// psk_secret as the salt; psk_secret.json passes only with the formula.
		next, err := suite.Extract(input, secret)
		clear(input)
		clear(secret)
		if err != nil {
			return nil, err
		}
		secret = next
	}
	return secret, nil
}
