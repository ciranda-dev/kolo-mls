// Package errs holds the sentinel errors of the internal packages, so that
// package kolomls can export the same values for errors.Is.
package errs

import "errors"

var (
	// ErrMalformed reports input that is not the canonical encoding.
	ErrMalformed = errors.New("kolomls: malformed encoding")
	// ErrTooLong reports a vector longer than a variable-size length can hold.
	ErrTooLong = errors.New("kolomls: vector longer than 2^30 - 1 bytes")
	// ErrInvalidArgument reports a key, size, index or count out of range.
	ErrInvalidArgument = errors.New("kolomls: invalid argument")
	// ErrUnsupported reports a valid value this implementation does not support.
	ErrUnsupported = errors.New("kolomls: unsupported")
	// ErrDecrypt reports a failed decryption.
	ErrDecrypt = errors.New("kolomls: decryption failed")
	// ErrInvalidTree reports a ratchet tree that breaks a rule of RFC 9420.
	ErrInvalidTree = errors.New("kolomls: invalid ratchet tree")
	// ErrInvalidCommit reports an UpdatePath or Commit that breaks a rule of RFC 9420.
	ErrInvalidCommit = errors.New("kolomls: invalid commit")
	// ErrTooFarAhead reports a generation beyond the forward bound of a ratchet.
	ErrTooFarAhead = errors.New("kolomls: generation too far ahead")
	// ErrTooOld reports a generation below the out-of-order window of a ratchet.
	ErrTooOld = errors.New("kolomls: generation too old")
	// ErrReplay reports a generation whose key was already used.
	ErrReplay = errors.New("kolomls: generation already used")
	// ErrGenerationExhausted reports a ratchet that has used every generation.
	ErrGenerationExhausted = errors.New("kolomls: generations exhausted")
)
