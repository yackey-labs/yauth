// Package memrepo is a pure-Go in-memory implementation of repo.Repository.
//
// It is intended for zero-config quickstart usage and for the repo conformance
// harness — it has no persistence and is not suitable for production. All data
// lives in process-local maps protected by a single sync.RWMutex (memory ops
// are sub-microsecond, so finer-grained locking buys nothing).
//
// Lookup methods returning (*T, error) return (nil, yautherr.ErrNotFound) on
// not-found; they never return (nil, nil).
package memrepo

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo"
)

var _ repo.Repository = (*Repo)(nil)

// Repo is the in-memory backend. The zero value is not usable; use New.
type Repo struct {
	mu sync.RWMutex

	// Users keyed by ID; emailIdx maps email -> user ID for O(1) lookup.
	users    map[string]*domain.User
	emailIdx map[string]string

	// Sessions keyed by ID; sessionTokenIdx maps token hash -> session ID.
	sessions        map[string]*domain.Session
	sessionTokenIdx map[string]string

	// Passwords keyed by user ID.
	passwords map[string]*domain.Password

	// passwordHistory keyed by user ID, oldest first appended at the end.
	passwordHistory map[string][]*domain.PasswordHistory

	// EmailVerifications keyed by ID; emailVerifTokenIdx maps token hash -> id.
	emailVerifs        map[string]*domain.EmailVerification
	emailVerifTokenIdx map[string]string

	// PasswordResets keyed by ID; passwordResetTokenIdx maps token hash -> id.
	passwordResets        map[string]*domain.PasswordReset
	passwordResetTokenIdx map[string]string

	// Audit log rows in insertion order.
	auditLog []*domain.AuditLog

	// Challenges keyed by key.
	challenges map[string]*domain.Challenge

	// RateLimit windows keyed by key.
	rateLimits map[string]*rateLimitState

	// Revocations keyed by jti.
	revocations map[string]time.Time

	// MagicLinks keyed by ID; magicLinkTokenIdx maps token hash -> id.
	magicLinks        map[string]*domain.MagicLink
	magicLinkTokenIdx map[string]string

	// Passkeys keyed by ID.
	passkeys map[string]*domain.WebauthnCredential

	// TOTP secrets keyed by ID.
	totp map[string]*domain.TOTPSecret

	// BackupCodes keyed by ID.
	backupCodes map[string]*domain.BackupCode

	// OAuthAccounts keyed by ID.
	oauthAccounts map[string]*domain.OAuthAccount

	// OAuthState keyed by state token.
	oauthStates map[string]*domain.OAuthState

	// RefreshTokens keyed by ID; refreshTokenIdx maps token hash -> id.
	refreshTokens   map[string]*domain.RefreshToken
	refreshTokenIdx map[string]string

	// APIKeys keyed by ID; apiKeyPrefixIdx maps prefix -> id.
	apiKeys         map[string]*domain.APIKey
	apiKeyPrefixIdx map[string]string

	// OAuth2 clients keyed by ID; oauth2ClientIDIdx maps client_id -> id.
	oauth2Clients     map[string]*domain.OAuth2Client
	oauth2ClientIDIdx map[string]string

	// AuthorizationCodes keyed by ID; authCodeHashIdx maps code hash -> id.
	authCodes       map[string]*domain.AuthorizationCode
	authCodeHashIdx map[string]string

	// Consents keyed by ID.
	consents map[string]*domain.Consent

	// DeviceCodes keyed by ID; deviceCodeHashIdx maps device-code hash -> id.
	deviceCodes       map[string]*domain.DeviceCode
	deviceCodeHashIdx map[string]string

	// OIDCNonces keyed by ID; oidcNonceHashIdx maps nonce hash -> id.
	oidcNonces       map[string]*domain.OIDCNonce
	oidcNonceHashIdx map[string]string

	// AccountLocks keyed by ID; accountLockUserIdx maps user ID -> lock ID.
	accountLocks       map[string]*domain.AccountLock
	accountLockUserIdx map[string]string

	// UnlockTokens keyed by ID; unlockTokenHashIdx maps token hash -> id.
	unlockTokens       map[string]*domain.UnlockToken
	unlockTokenHashIdx map[string]string

	// Webhooks keyed by ID.
	webhooks          map[string]*domain.Webhook
	webhookDeliveries []*domain.WebhookDelivery

	// Scheduled webhook retries keyed by ID. Claimed rows are removed
	// from the map under the same write lock that returned them, which
	// is the in-memory analogue of FOR UPDATE SKIP LOCKED.
	webhookRetries map[string]*domain.ScheduledWebhookRetry

	// Organizations keyed by ID; orgSlugIdx maps lowercased slug -> id
	// (the case-insensitive uniqueness invariant lives in this index).
	organizations map[string]*domain.Organization
	orgSlugIdx    map[string]string

	// Memberships keyed by ID; membershipOrgUserIdx maps
	// "<orgID>:<userID>" -> membership ID for the (org_id, user_id)
	// uniqueness check.
	memberships          map[string]*domain.Membership
	membershipOrgUserIdx map[string]string

	// Invitations keyed by ID; invitationTokenIdx maps token hash ->
	// invitation ID.
	invitations        map[string]*domain.Invitation
	invitationTokenIdx map[string]string

	// OrganizationDomains keyed by ID; orgDomainNameIdx maps the
	// lowercased canonical domain string to the row id. This is the
	// app-wide UNIQUE(domain) index from yauth #90 — duplicate-domain
	// inserts surface as ErrConflict here in the in-memory shape, and
	// as a unique-violation in gormrepo.
	orgDomains       map[string]*domain.OrganizationDomain
	orgDomainNameIdx map[string]string

	// OrganizationPolicies keyed by organization_id (one row per org
	// — there is no separate primary id). yauth #92 / yauth-go #21.
	orgPolicies map[string]*domain.OrganizationPolicy

	// SsoConnections keyed by ID. yauth #93 / yauth-go #23.
	ssoConnections map[string]*domain.SsoConnection

	// ExternalIdentities keyed by ID. extIdentityProviderIdx maps
	// "<provider>|<external_id>" -> identity ID for the unique-pair
	// invariant.
	extIdentities          map[string]*domain.ExternalIdentity
	extIdentityProviderIdx map[string]string

	// SsoLoginStates keyed by the state token.
	ssoLoginStates map[string]*domain.SsoLoginState

	// Groups keyed by ID. groupMembers[groupID][userID] = joinedAt;
	// clientGroups[clientID][groupID] = assignedAt.
	groups       map[string]*domain.Group
	groupMembers map[string]map[string]time.Time
	clientGroups map[string]map[string]time.Time
}

// rateLimitState is a fixed-window counter row.
type rateLimitState struct {
	count       int
	windowStart time.Time
}

// New returns an empty in-memory repository.
func New() *Repo {
	return &Repo{
		users:                  make(map[string]*domain.User),
		emailIdx:               make(map[string]string),
		sessions:               make(map[string]*domain.Session),
		sessionTokenIdx:        make(map[string]string),
		passwords:              make(map[string]*domain.Password),
		passwordHistory:        make(map[string][]*domain.PasswordHistory),
		emailVerifs:            make(map[string]*domain.EmailVerification),
		emailVerifTokenIdx:     make(map[string]string),
		passwordResets:         make(map[string]*domain.PasswordReset),
		passwordResetTokenIdx:  make(map[string]string),
		challenges:             make(map[string]*domain.Challenge),
		rateLimits:             make(map[string]*rateLimitState),
		revocations:            make(map[string]time.Time),
		magicLinks:             make(map[string]*domain.MagicLink),
		magicLinkTokenIdx:      make(map[string]string),
		passkeys:               make(map[string]*domain.WebauthnCredential),
		totp:                   make(map[string]*domain.TOTPSecret),
		backupCodes:            make(map[string]*domain.BackupCode),
		oauthAccounts:          make(map[string]*domain.OAuthAccount),
		oauthStates:            make(map[string]*domain.OAuthState),
		refreshTokens:          make(map[string]*domain.RefreshToken),
		refreshTokenIdx:        make(map[string]string),
		apiKeys:                make(map[string]*domain.APIKey),
		apiKeyPrefixIdx:        make(map[string]string),
		oauth2Clients:          make(map[string]*domain.OAuth2Client),
		oauth2ClientIDIdx:      make(map[string]string),
		authCodes:              make(map[string]*domain.AuthorizationCode),
		authCodeHashIdx:        make(map[string]string),
		consents:               make(map[string]*domain.Consent),
		deviceCodes:            make(map[string]*domain.DeviceCode),
		deviceCodeHashIdx:      make(map[string]string),
		oidcNonces:             make(map[string]*domain.OIDCNonce),
		oidcNonceHashIdx:       make(map[string]string),
		accountLocks:           make(map[string]*domain.AccountLock),
		accountLockUserIdx:     make(map[string]string),
		unlockTokens:           make(map[string]*domain.UnlockToken),
		unlockTokenHashIdx:     make(map[string]string),
		webhooks:               make(map[string]*domain.Webhook),
		webhookRetries:         make(map[string]*domain.ScheduledWebhookRetry),
		organizations:          make(map[string]*domain.Organization),
		orgSlugIdx:             make(map[string]string),
		memberships:            make(map[string]*domain.Membership),
		membershipOrgUserIdx:   make(map[string]string),
		invitations:            make(map[string]*domain.Invitation),
		invitationTokenIdx:     make(map[string]string),
		orgDomains:             make(map[string]*domain.OrganizationDomain),
		orgDomainNameIdx:       make(map[string]string),
		orgPolicies:            make(map[string]*domain.OrganizationPolicy),
		ssoConnections:         make(map[string]*domain.SsoConnection),
		extIdentities:          make(map[string]*domain.ExternalIdentity),
		extIdentityProviderIdx: make(map[string]string),
		ssoLoginStates:         make(map[string]*domain.SsoLoginState),
		groups:                 make(map[string]*domain.Group),
		groupMembers:           make(map[string]map[string]time.Time),
		clientGroups:           make(map[string]map[string]time.Time),
	}
}

// Cleanup removes expired ephemeral rows (sessions, magic links, email
// verifications, password resets, OAuth state, challenges, revocations,
// authorization codes, device codes, unlock tokens) so long-running tests
// don't leak memory. Callers may invoke it periodically; it acquires the
// write lock once.
func (r *Repo) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()

	for id, s := range r.sessions {
		if !s.ExpiresAt.UTC().After(now) {
			delete(r.sessionTokenIdx, s.TokenHash)
			delete(r.sessions, id)
		}
	}
	for id, ev := range r.emailVerifs {
		if !ev.ExpiresAt.UTC().After(now) {
			delete(r.emailVerifTokenIdx, ev.TokenHash)
			delete(r.emailVerifs, id)
		}
	}
	for id, pr := range r.passwordResets {
		if !pr.ExpiresAt.UTC().After(now) {
			delete(r.passwordResetTokenIdx, pr.TokenHash)
			delete(r.passwordResets, id)
		}
	}
	for k, c := range r.challenges {
		if !c.ExpiresAt.UTC().After(now) {
			delete(r.challenges, k)
		}
	}
	for k, exp := range r.revocations {
		if !exp.UTC().After(now) {
			delete(r.revocations, k)
		}
	}
	for id, m := range r.magicLinks {
		if !m.ExpiresAt.UTC().After(now) {
			delete(r.magicLinkTokenIdx, m.TokenHash)
			delete(r.magicLinks, id)
		}
	}
	for s, st := range r.oauthStates {
		if !st.ExpiresAt.UTC().After(now) {
			delete(r.oauthStates, s)
		}
	}
	for id, ac := range r.authCodes {
		if !ac.ExpiresAt.UTC().After(now) {
			delete(r.authCodeHashIdx, ac.CodeHash)
			delete(r.authCodes, id)
		}
	}
	for id, dc := range r.deviceCodes {
		if !dc.ExpiresAt.UTC().After(now) {
			delete(r.deviceCodeHashIdx, dc.DeviceCodeHash)
			delete(r.deviceCodes, id)
		}
	}
	for id, ut := range r.unlockTokens {
		if !ut.ExpiresAt.UTC().After(now) {
			delete(r.unlockTokenHashIdx, ut.TokenHash)
			delete(r.unlockTokens, id)
		}
	}
	// SSO login states are short-lived (<10 min). yauth #93 / yauth-go #23.
	for s, st := range r.ssoLoginStates {
		if !st.ExpiresAt.UTC().After(now) {
			delete(r.ssoLoginStates, s)
		}
	}
}

func ensureCtx(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// cloneUser returns a shallow value copy with a fresh pointer.
func cloneUser(u *domain.User) *domain.User {
	if u == nil {
		return nil
	}
	c := *u
	return &c
}

func cloneSession(s *domain.Session) *domain.Session {
	if s == nil {
		return nil
	}
	c := *s
	return &c
}

func clonePassword(p *domain.Password) *domain.Password {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

func cloneEmailVerification(v *domain.EmailVerification) *domain.EmailVerification {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func clonePasswordReset(p *domain.PasswordReset) *domain.PasswordReset {
	if p == nil {
		return nil
	}
	c := *p
	if p.UsedAt != nil {
		t := *p.UsedAt
		c.UsedAt = &t
	}
	return &c
}

func cloneChallenge(c *domain.Challenge) *domain.Challenge {
	if c == nil {
		return nil
	}
	cc := *c
	return &cc
}

func cloneMagicLink(m *domain.MagicLink) *domain.MagicLink {
	if m == nil {
		return nil
	}
	c := *m
	return &c
}

func clonePasskey(p *domain.WebauthnCredential) *domain.WebauthnCredential {
	if p == nil {
		return nil
	}
	c := *p
	if p.LastUsedAt != nil {
		t := *p.LastUsedAt
		c.LastUsedAt = &t
	}
	if len(p.Credential) > 0 {
		c.Credential = append([]byte(nil), p.Credential...)
	}
	return &c
}

func cloneTOTP(t *domain.TOTPSecret) *domain.TOTPSecret {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func cloneBackupCode(b *domain.BackupCode) *domain.BackupCode {
	if b == nil {
		return nil
	}
	c := *b
	return &c
}

func cloneOAuthAccount(o *domain.OAuthAccount) *domain.OAuthAccount {
	if o == nil {
		return nil
	}
	c := *o
	if o.ExpiresAt != nil {
		t := *o.ExpiresAt
		c.ExpiresAt = &t
	}
	return &c
}

func cloneOAuthState(s *domain.OAuthState) *domain.OAuthState {
	if s == nil {
		return nil
	}
	c := *s
	return &c
}

func cloneRefreshToken(t *domain.RefreshToken) *domain.RefreshToken {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func cloneAPIKey(k *domain.APIKey) *domain.APIKey {
	if k == nil {
		return nil
	}
	c := *k
	if k.UserID != nil {
		v := *k.UserID
		c.UserID = &v
	}
	if k.OrganizationID != nil {
		v := *k.OrganizationID
		c.OrganizationID = &v
	}
	if k.Role != nil {
		v := *k.Role
		c.Role = &v
	}
	if k.ExpiresAt != nil {
		t := *k.ExpiresAt
		c.ExpiresAt = &t
	}
	if k.LastUsedAt != nil {
		t := *k.LastUsedAt
		c.LastUsedAt = &t
	}
	if len(k.Scopes) > 0 {
		c.Scopes = append([]byte(nil), k.Scopes...)
	}
	return &c
}

func cloneOAuth2Client(o *domain.OAuth2Client) *domain.OAuth2Client {
	if o == nil {
		return nil
	}
	c := *o
	if o.BannedAt != nil {
		t := *o.BannedAt
		c.BannedAt = &t
	}
	if len(o.RedirectURIs) > 0 {
		c.RedirectURIs = append([]byte(nil), o.RedirectURIs...)
	}
	if len(o.GrantTypes) > 0 {
		c.GrantTypes = append([]byte(nil), o.GrantTypes...)
	}
	if len(o.Scopes) > 0 {
		c.Scopes = append([]byte(nil), o.Scopes...)
	}
	return &c
}

func cloneAuthorizationCode(a *domain.AuthorizationCode) *domain.AuthorizationCode {
	if a == nil {
		return nil
	}
	c := *a
	if len(a.Scopes) > 0 {
		c.Scopes = append([]byte(nil), a.Scopes...)
	}
	return &c
}

func cloneConsent(c *domain.Consent) *domain.Consent {
	if c == nil {
		return nil
	}
	cc := *c
	if len(c.Scopes) > 0 {
		cc.Scopes = append([]byte(nil), c.Scopes...)
	}
	return &cc
}

func cloneDeviceCode(d *domain.DeviceCode) *domain.DeviceCode {
	if d == nil {
		return nil
	}
	c := *d
	if d.LastPolledAt != nil {
		t := *d.LastPolledAt
		c.LastPolledAt = &t
	}
	if len(d.Scopes) > 0 {
		c.Scopes = append([]byte(nil), d.Scopes...)
	}
	return &c
}

func cloneOIDCNonce(n *domain.OIDCNonce) *domain.OIDCNonce {
	if n == nil {
		return nil
	}
	c := *n
	return &c
}

func cloneAccountLock(a *domain.AccountLock) *domain.AccountLock {
	if a == nil {
		return nil
	}
	c := *a
	if a.LockedUntil != nil {
		t := *a.LockedUntil
		c.LockedUntil = &t
	}
	return &c
}

func cloneUnlockToken(u *domain.UnlockToken) *domain.UnlockToken {
	if u == nil {
		return nil
	}
	c := *u
	return &c
}

func cloneWebhook(w *domain.Webhook) *domain.Webhook {
	if w == nil {
		return nil
	}
	c := *w
	if len(w.Events) > 0 {
		c.Events = append([]byte(nil), w.Events...)
	}
	return &c
}

func cloneWebhookDelivery(d *domain.WebhookDelivery) *domain.WebhookDelivery {
	if d == nil {
		return nil
	}
	c := *d
	if len(d.Payload) > 0 {
		c.Payload = append([]byte(nil), d.Payload...)
	}
	if d.StatusCode != nil {
		v := *d.StatusCode
		c.StatusCode = &v
	}
	if d.ResponseBody != nil {
		v := *d.ResponseBody
		c.ResponseBody = &v
	}
	return &c
}

func cloneAuditLog(a *domain.AuditLog) *domain.AuditLog {
	if a == nil {
		return nil
	}
	c := *a
	if len(a.Metadata) > 0 {
		c.Metadata = append([]byte(nil), a.Metadata...)
	}
	return &c
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
