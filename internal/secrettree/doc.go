// Package secrettree implements the secret tree and the sender ratchets of
// RFC 9420 section 9, with the deletion schedule of section 9.2 and the
// receiver bounds of section 15.3. Peek and PeekNext look up a key without
// changing the tree; Commit applies the lookup once the message is
// authenticated or sent, so a forged message consumes nothing. Changes and
// Records give the stored form, one record per kept node and per leaf in
// use, and Load rebuilds a tree from it. Errors are those of internal/errs
// and never hold a secret.
package secrettree
