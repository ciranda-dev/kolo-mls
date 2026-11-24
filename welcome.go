package kolomls

import (
	"fmt"
	"slices"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
	"github.com/ciranda-dev/kolo-mls/internal/treemath"
)

// welcome builds the GroupInfo and the Welcome for the members a Commit adds
// (RFC 9420 section 12.4.3.1).
func welcome(ns *state, a *applied, path *tree.Path, k *keyed, tag []byte, ids []*PSKID, withTree bool) ([]byte, error) {
	gi := &message.GroupInfo{GroupContext: ns.ctx, ConfirmationTag: tag, Signer: ns.own()}
	if withTree {
		t, err := ns.tree.Marshal()
		if err != nil {
			return nil, err
		}
		gi.Extensions = []Extension{{Type: message.ExtRatchetTree, Data: t}}
	}
	gi.Extensions = withGrease(gi.Extensions, greaseValue())
	tbs, err := gi.TBS()
	if err != nil {
		return nil, err
	}
	if gi.Signature, err = suite.SignWithLabel(ns.sig, "GroupInfoTBS", tbs); err != nil {
		return nil, err
	}
	gib, err := gi.Marshal()
	if err != nil {
		return nil, err
	}
	key, err := suite.ExpandWithLabel(k.welcome, "key", nil, suite.Nk)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	nonce, err := suite.ExpandWithLabel(k.welcome, "nonce", nil, suite.Nn)
	if err != nil {
		return nil, err
	}
	w := &message.Welcome{CipherSuite: ns.ctx.CipherSuite}
	// welcome.json decrypts only with an empty AAD; RFC 9420 section
	// 12.4.3.1 names none.
	if w.EncryptedGroupInfo, err = suite.Seal(key, nonce, nil, gib); err != nil {
		return nil, err
	}
	for i, l := range a.added {
		kp := a.addedKPs[i]
		gs := &message.GroupSecrets{JoinerSecret: k.joiner, PSKs: ids}
		if path != nil {
			j := slices.Index(path.FilteredPath, treemath.CommonAncestor(2*uint64(l), 2*uint64(ns.own())))
			if j < 0 {
				return nil, fmt.Errorf("%w: no path secret for the common ancestor of leaf %d", errs.ErrInvalidCommit, l)
			}
			gs.HasPathSecret, gs.PathSecret = true, path.PathSecrets[j]
		}
		gsb, err := gs.Marshal()
		if err != nil {
			return nil, err
		}
		kem, ct, err := suite.EncryptWithLabel(kp.InitKey, "Welcome", w.EncryptedGroupInfo, gsb)
		clear(gsb)
		if err != nil {
			return nil, err
		}
		ref, err := kp.Ref()
		if err != nil {
			return nil, err
		}
		w.Secrets = append(w.Secrets, message.EncryptedGroupSecrets{NewMember: ref, Secrets: tree.HPKECiphertext{KEMOutput: kem, Ciphertext: ct}})
	}
	return (&message.MLSMessage{WireFormat: message.WireWelcome, Welcome: w}).Marshal()
}
