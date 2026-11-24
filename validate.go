package kolomls

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tree"
)

// isDefaultExtension reports an extension type of RFC 9420 section 7.2 that
// capabilities do not list.
func isDefaultExtension(t uint16) bool {
	return t >= message.ExtApplicationID && t <= message.ExtExternalSenders
}

// isDefaultProposal reports a proposal type of RFC 9420 section 7.2 that
// capabilities do not list.
func isDefaultProposal(t uint16) bool {
	return t >= message.ProposalAdd && t <= message.ProposalGroupContextExtensions
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Config) maxLifetime() time.Duration {
	if c.MaxLeafLifetime == 0 {
		return DefaultMaxLeafLifetime
	}
	return c.MaxLeafLifetime
}

func invalidLeaf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errs.ErrInvalidLeaf, fmt.Sprintf(format, a...))
}

type leafRule struct {
	source uint8
	// index is the leaf index that update and commit leaves sign.
	index uint32
	event Event
	// sending is set for a leaf this member sends: its lifetime must hold
	// now (RFC 9420 section 7.3).
	sending bool
	// skipSignature is set where the signature was already checked.
	skipSignature bool
}

// requiredCapabilities returns the required_capabilities extension of exts,
// nil when absent.
func requiredCapabilities(exts []Extension) (*message.RequiredCapabilities, error) {
	for _, e := range exts {
		if e.Type == message.ExtRequiredCapabilities {
			rc, err := message.UnmarshalRequiredCapabilities(e.Data)
			if err != nil {
				return nil, fmt.Errorf("required_capabilities: %w", err)
			}
			return rc, nil
		}
	}
	return nil, nil
}

// supports reports an error unless the capabilities of n meet the group's
// required_capabilities and list every non-default GroupContext extension
// (RFC 9420 sections 7.3, 11.1, 13.4).
func supports(n *LeafNode, exts []Extension, rc *message.RequiredCapabilities) error {
	caps := &n.Capabilities
	for _, e := range exts {
		if !isDefaultExtension(e.Type) && !slices.Contains(caps.Extensions, e.Type) {
			return invalidLeaf("GroupContext extension %#04x not supported", e.Type)
		}
	}
	if rc == nil {
		return nil
	}
	for _, t := range rc.Extensions {
		if !isDefaultExtension(t) && !slices.Contains(caps.Extensions, t) {
			return invalidLeaf("required extension %#04x not supported", t)
		}
	}
	for _, t := range rc.Proposals {
		if !isDefaultProposal(t) && !slices.Contains(caps.Proposals, t) {
			return invalidLeaf("required proposal type %#04x not supported", t)
		}
	}
	for _, t := range rc.Credentials {
		if !slices.Contains(caps.Credentials, t) {
			return invalidLeaf("required credential type %#04x not supported", t)
		}
	}
	return nil
}

// checkLeaf runs the checks of RFC 9420 section 7.3 that concern one leaf;
// those across members are in checkMembers.
func (c *Config) checkLeaf(n *LeafNode, r leafRule, ctx *GroupContext) error {
	if n.Source != r.source {
		return invalidLeaf("leaf_node_source %d, want %d", n.Source, r.source)
	}
	if err := suite.CheckPublicKey(n.EncryptionKey); err != nil {
		return fmt.Errorf("%w: encryption key: %w", errs.ErrInvalidLeaf, err)
	}
	if len(n.SignatureKey) != ed25519.PublicKeySize {
		return invalidLeaf("signature key of %d bytes", len(n.SignatureKey))
	}
	if !r.skipSignature && !n.VerifySignature(ctx.GroupID, r.index) {
		return invalidLeaf("signature")
	}
	if err := c.Authenticator.Validate(n.Credential, bytes.Clone(n.SignatureKey), r.event); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrCredential, err)
	}
	caps := &n.Capabilities
	if !slices.Contains(caps.Versions, schedule.MLS10) || !slices.Contains(caps.CipherSuites, ctx.CipherSuite) {
		return invalidLeaf("capabilities lack the group's version or cipher suite")
	}
	if !slices.Contains(caps.Credentials, n.Credential.Type) {
		return invalidLeaf("capabilities lack the leaf's own credential type")
	}
	for _, e := range n.Extensions {
		if !isDefaultExtension(e.Type) && !slices.Contains(caps.Extensions, e.Type) {
			return invalidLeaf("leaf extension %#04x not in its capabilities", e.Type)
		}
	}
	rc, err := requiredCapabilities(ctx.Extensions)
	if err != nil {
		return fmt.Errorf("%w: %w", errs.ErrInvalidLeaf, err)
	}
	if err := supports(n, ctx.Extensions, rc); err != nil {
		return err
	}
	if n.Source == tree.SourceKeyPackage {
		if n.NotBefore > n.NotAfter {
			return invalidLeaf("lifetime ends before it starts")
		}
		if m := c.maxLifetime(); m > 0 && n.NotAfter-n.NotBefore > uint64(m/time.Second) {
			return invalidLeaf("lifetime longer than %v", m)
		}
		if r.sending {
			now := c.now().Unix()
			if now < 0 || uint64(now) < n.NotBefore || uint64(now) > n.NotAfter {
				return invalidLeaf("not valid now")
			}
		}
	}
	return nil
}

// checkMembers runs the checks of RFC 9420 section 7.3 across members: unique
// keys and every credential type in use supported by all; with all set, also
// every member's support of the group's extensions (section 12.1.7).
func checkMembers(t *tree.Tree, ctx *GroupContext, all bool) error {
	sigs := map[string]bool{}
	keys := map[string]bool{}
	types := map[uint16]bool{}
	var leaves []*LeafNode
	var rc *message.RequiredCapabilities
	if all {
		var err error
		if rc, err = requiredCapabilities(ctx.Extensions); err != nil {
			return fmt.Errorf("%w: %w", errs.ErrInvalidLeaf, err)
		}
	}
	for _, x := range t.NonBlank() {
		n := t.Node(x)
		key := n.Leaf
		if n.Parent != nil {
			if keys[string(n.Parent.EncryptionKey)] {
				return fmt.Errorf("%w: encryption key of node %d not unique", errs.ErrInvalidTree, x)
			}
			keys[string(n.Parent.EncryptionKey)] = true
			continue
		}
		if sigs[string(key.SignatureKey)] {
			return invalidLeaf("signature key of leaf %d not unique", x/2)
		}
		sigs[string(key.SignatureKey)] = true
		if keys[string(key.EncryptionKey)] {
			return invalidLeaf("encryption key of leaf %d not unique", x/2)
		}
		keys[string(key.EncryptionKey)] = true
		types[key.Credential.Type] = true
		leaves = append(leaves, key)
		if all {
			if err := supports(key, ctx.Extensions, rc); err != nil {
				return err
			}
		}
	}
	for _, n := range leaves {
		for typ := range types {
			if !slices.Contains(n.Capabilities.Credentials, typ) {
				return invalidLeaf("a member does not support credential type %#04x in use", typ)
			}
		}
	}
	return nil
}

func invalidKeyPackage(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errs.ErrInvalidKeyPackage, fmt.Sprintf(format, a...))
}

// checkKeyPackage runs the checks of RFC 9420 section 10.1 for a group with
// GroupContext ctx.
func (c *Config) checkKeyPackage(kp *message.KeyPackage, ctx *GroupContext, ev Event, sending bool) error {
	if kp.Version != schedule.MLS10 || kp.CipherSuite != ctx.CipherSuite {
		return invalidKeyPackage("version %d and cipher suite %#04x do not match the group", kp.Version, kp.CipherSuite)
	}
	if err := suite.CheckPublicKey(kp.InitKey); err != nil {
		return fmt.Errorf("%w: init key: %w", errs.ErrInvalidKeyPackage, err)
	}
	if err := c.checkLeaf(kp.LeafNode, leafRule{source: tree.SourceKeyPackage, event: ev, sending: sending}, ctx); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrInvalidKeyPackage, err)
	}
	tbs, err := kp.TBS()
	if err != nil {
		return err
	}
	if !suite.VerifyWithLabel(kp.LeafNode.SignatureKey, "KeyPackageTBS", tbs, kp.Signature) {
		return invalidKeyPackage("signature")
	}
	if bytes.Equal(kp.LeafNode.EncryptionKey, kp.InitKey) {
		return invalidKeyPackage("init key equals the leaf encryption key")
	}
	for _, e := range kp.Extensions {
		if !isDefaultExtension(e.Type) && !slices.Contains(kp.LeafNode.Capabilities.Extensions, e.Type) {
			return invalidKeyPackage("extension %#04x not in the leaf's capabilities", e.Type)
		}
	}
	return nil
}

// uniqueExtensions refuses an extension list of this member with two
// extensions of one type, which every peer would refuse (RFC 9420 section
// 13.4).
func uniqueExtensions(lists ...[]Extension) error {
	for _, l := range lists {
		seen := map[uint16]bool{}
		for _, e := range l {
			if seen[e.Type] {
				return fmt.Errorf("%w: two extensions of type %#04x", errs.ErrInvalidArgument, e.Type)
			}
			seen[e.Type] = true
		}
	}
	return nil
}
