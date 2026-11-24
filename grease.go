package kolomls

import (
	"crypto/rand"
	"slices"
)

// greaseValue returns a random value of the 15 that RFC 9420 section 13.5
// reserves in every registry: 0x0A0A, 0x1A1A, ..., 0xEAEA.
func greaseValue() uint16 {
	var b [1]byte
	rand.Read(b[:])
	n := uint16(b[0] % 15)
	return n<<12 | n<<4 | 0x0A0A
}

// isGrease reports a value reserved by RFC 9420 section 13.5.
func isGrease(v uint16) bool {
	return v&0x0F0F == 0x0A0A && v>>12 == v>>4&0x0F && v>>12 < 0xF
}

// greaseCapabilities adds a random GREASE value to the lists of c that RFC
// 9420 section 13.5 names, and returns the one added to the extensions.
func greaseCapabilities(c *Capabilities) uint16 {
	c.CipherSuites = addMissing(c.CipherSuites, greaseValue())
	c.Proposals = addMissing(c.Proposals, greaseValue())
	c.Credentials = addMissing(c.Credentials, greaseValue())
	ext := greaseValue()
	c.Extensions = addMissing(c.Extensions, ext)
	return ext
}

// withGrease returns exts with an empty extension of type t added, unless
// exts already holds a GREASE extension.
func withGrease(exts []Extension, t uint16) []Extension {
	if slices.ContainsFunc(exts, func(e Extension) bool { return isGrease(e.Type) }) {
		return exts
	}
	return append(slices.Clone(exts), Extension{Type: t, Data: []byte{}})
}
