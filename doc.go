// Package kolomls is group end-to-end encryption by the MLS standard (RFC 9420)
// for cipher suite 0x0001, on the Go standard library only. Packages cred,
// settle and braid add the Kolo credential, the rules of a Kolo group's member
// devices and its admins' side over kolo-braid; backendstore keeps groups in a
// kolo-store Backend.
//
// A member makes a KeyPackage with NewKeyPackage and starts a group with
// Create. Group.Commit adds members, ApplyPending makes the Commit the new
// epoch, and each added member enters with Join from the Welcome and the
// ratchet tree. Group.Encrypt and Group.Process carry the messages. State
// lives in a Store the caller provides; NewMemStore is the in-memory one.
//
// Experimental. The API may change before v1.0.0.
package kolomls
