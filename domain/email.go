package domain

import "strings"

// NormalizeEmail returns the canonical stored form of an email address:
// trimmed of surrounding whitespace and lowercased.
//
// It exists because twelve handler call sites were already doing exactly this
// — signup, login, magic link, forgot/reset, bearer, admin-create, social
// login, SSO and SCIM all fold before they look anything up — while the
// repositories underneath them did not. repo.CreateUser is public API and
// wrote whatever it was handed, and Postgres carried a case-SENSITIVE
// UNIQUE (email) over a case-sensitive `WHERE email = $1`. The invariant held
// for exactly as long as every caller remembered it.
//
// One mixed-case row breaks two things at once: its owner can no longer log in
// (their address is folded on the way in and stops matching what is stored),
// and the folded form of their address becomes free for anybody else to
// register — a shadow account for an identity that is already taken, on a
// deployment where email IS the identity.
//
// Every repository backend now applies this on write AND on lookup, so the
// guarantee no longer depends on caller discipline. It is deliberately only
// case and whitespace: no plus-address stripping, no dot folding, no
// Unicode-confusable mapping. Those change which addresses are considered the
// same account, which is a policy decision an auth library should not make
// silently on an operator's behalf; this only canonicalises a form that is
// already the same address by RFC 5321 (the domain is case-insensitive) and by
// the settled practice of every mailbox provider (the local part in effect is
// too).
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
