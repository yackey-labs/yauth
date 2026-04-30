package passkey

import (
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/yackey-labs/yauth-go/domain"
)

// passkeyUser adapts *domain.User + the user's stored credentials onto the
// webauthn.User interface expected by go-webauthn. WebAuthn requires an
// opaque, stable user handle of up to 64 bytes; we use the user's UUID
// string bytes directly so the handle round-trips through any storage that
// preserves bytes.
type passkeyUser struct {
	user  *domain.User
	creds []webauthn.Credential
}

// newPasskeyUser wraps a domain user and its decoded credentials.
func newPasskeyUser(u *domain.User, creds []webauthn.Credential) *passkeyUser {
	return &passkeyUser{user: u, creds: creds}
}

// WebAuthnID implements webauthn.User. We use the user UUID's UTF-8 bytes,
// which fit in well under the 64-byte limit.
func (p *passkeyUser) WebAuthnID() []byte {
	return []byte(p.user.ID)
}

// WebAuthnName implements webauthn.User. Email is the human-typed handle.
func (p *passkeyUser) WebAuthnName() string {
	return p.user.Email
}

// WebAuthnDisplayName implements webauthn.User. Falls back to email if the
// optional display name is not set.
func (p *passkeyUser) WebAuthnDisplayName() string {
	if p.user.DisplayName != nil && *p.user.DisplayName != "" {
		return *p.user.DisplayName
	}
	return p.user.Email
}

// WebAuthnCredentials implements webauthn.User.
func (p *passkeyUser) WebAuthnCredentials() []webauthn.Credential {
	return p.creds
}
