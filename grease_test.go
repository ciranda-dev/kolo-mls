package kolomls

import (
	"errors"
	"slices"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/errs"
	"github.com/ciranda-dev/kolo-mls/internal/message"
	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/tls"
)

func TestGreaseValues(t *testing.T) {
	seen := map[uint16]bool{}
	for range 2000 {
		v := greaseValue()
		if !isGrease(v) {
			t.Fatalf("%#04x is not a GREASE value", v)
		}
		seen[v] = true
	}
	if len(seen) != 15 {
		t.Fatalf("%d of the 15 GREASE values drawn", len(seen))
	}
	for _, v := range []uint16{0x0A0B, 0x1A2A, 0xFAFA, 0x0B0A, 0xF001} {
		if isGrease(v) {
			t.Errorf("%#04x taken for GREASE", v)
		}
	}
}

// TestGreaseSent: a KeyPackage carries a GREASE value in each capabilities
// list of RFC 9420 section 13.5, and a GREASE extension, listed in the
// capabilities, in its own and its leaf's extensions; a GroupInfo carries a
// GREASE extension; both are accepted.
func TestGreaseSent(t *testing.T) {
	c := newClient(t)
	kp, err := decodeKeyPackage(c.keyPackage(t))
	if err != nil {
		t.Fatal(err)
	}
	caps := kp.LeafNode.Capabilities
	for name, l := range map[string][]uint16{"cipher suites": caps.CipherSuites, "extensions": caps.Extensions, "proposals": caps.Proposals, "credentials": caps.Credentials} {
		n := 0
		for _, v := range l {
			if isGrease(v) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: %d GREASE values in %#04x", name, n, l)
		}
	}
	for _, exts := range [][]tls.Extension{kp.Extensions, kp.LeafNode.Extensions} {
		if len(exts) != 1 || !isGrease(exts[0].Type) || !slices.Contains(caps.Extensions, exts[0].Type) {
			t.Fatalf("KeyPackage and leaf extensions %+v %+v", kp.Extensions, kp.LeafNode.Extensions)
		}
	}
	for _, v := range caps.Versions {
		if isGrease(v) {
			t.Fatal("GREASE in the versions")
		}
	}
	ctx := &schedule.GroupContext{CipherSuite: suite.ID, GroupID: []byte("g")}
	kc := testConfig()
	if err := kc.checkKeyPackage(kp, ctx, EventKeyPackage, true); err != nil {
		t.Fatal(err)
	}

	var joins []JoinView
	cfg := testConfig()
	cfg.Policy = viewPolicy{views: new([]ProposalView), joins: &joins}
	w := newWorldWith(t, 2, cfg)
	j := newClient(t)
	joins = nil
	pc := w.commit(0, CommitOptions{Add: [][]byte{j.keyPackage(t)}})
	rt, err := w.members[0].g.RatchetTree()
	if err != nil {
		t.Fatal(err)
	}
	g, err := Join(j.st, pc.Welcome(), rt, JoinOptions{Config: w.cfg})
	if err != nil {
		t.Fatal(err)
	}
	if len(joins) != 1 || len(joins[0].InfoExtensions) != 1 || !isGrease(joins[0].InfoExtensions[0].Type) {
		t.Fatalf("GroupInfo extensions %+v", joins)
	}
	for _, e := range g.Extensions() {
		if isGrease(e.Type) {
			t.Fatal("GREASE in the GroupContext")
		}
	}
}

// TestGreaseReceived: GREASE values in another client's capabilities are
// ignored, while an unknown value that is not GREASE and that the group
// requires is still refused.
func TestGreaseReceived(t *testing.T) {
	c := newClient(t)
	kp, _ := decodeKeyPackage(c.keyPackage(t))
	n := kp.LeafNode
	if err := supports(n, nil, &message.RequiredCapabilities{}); err != nil {
		t.Fatal(err)
	}
	for _, rc := range []*message.RequiredCapabilities{{Extensions: []uint16{0x0B0B}}, {Proposals: []uint16{0x0B0B}}, {Credentials: []uint16{0x0B0B}}} {
		if err := supports(n, nil, rc); !errors.Is(err, errs.ErrInvalidLeaf) {
			t.Errorf("required %+v: %v", rc, err)
		}
	}
	if err := supports(n, []tls.Extension{{Type: 0x0B0B}}, nil); !errors.Is(err, errs.ErrInvalidLeaf) {
		t.Errorf("GroupContext extension 0x0b0b: %v", err)
	}
}

// TestGreaseGiven: a GREASE extension the caller gives is the only one
// added to a KeyPackage, and the KeyPackage is accepted.
func TestGreaseGiven(t *testing.T) {
	given := func(o *KeyPackageOptions) {
		o.Capabilities.Extensions = []uint16{0x5A5A}
		o.Extensions = []tls.Extension{{Type: 0x5A5A, Data: []byte("x")}}
		o.LeafExtensions = []tls.Extension{{Type: 0x5A5A}}
	}
	_, b := keyPackageFor(t, []byte("g"), newClient(t).sig, given)
	kp, err := decodeKeyPackage(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.Extensions) != 1 || string(kp.Extensions[0].Data) != "x" || len(kp.LeafNode.Extensions) != 1 || !slices.Contains(kp.LeafNode.Capabilities.Extensions, 0x5A5A) {
		t.Fatalf("extensions %+v %+v", kp.Extensions, kp.LeafNode.Extensions)
	}
	ctx := &schedule.GroupContext{CipherSuite: suite.ID, GroupID: []byte("g")}
	kc := testConfig()
	if err := kc.checkKeyPackage(kp, ctx, EventKeyPackage, true); err != nil {
		t.Fatalf("a KeyPackage with GREASE extensions: %v", err)
	}
}
