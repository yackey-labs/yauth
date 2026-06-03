package gormrepo

import (
	"encoding/json"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
)

// strFromBytes packs raw JSON bytes into the *string column shape used by
// SQLite/PG TEXT JSON columns. Empty input becomes nil.
func strFromBytes(b json.RawMessage) *string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	return &s
}

func rawJSONToBytes(s *string) json.RawMessage {
	if s == nil {
		return nil
	}
	return json.RawMessage(*s)
}

// --- Challenge ---

// Challenge mirrors yauth_challenges.
type Challenge struct {
	Key       string    `gorm:"column:key;primaryKey"`
	Value     string    `gorm:"column:value;not null"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null"`
}

func (Challenge) TableName() string { return "yauth_challenges" }

func (m *Challenge) toDomain() domain.Challenge {
	return domain.Challenge{
		Key:       m.Key,
		Value:     m.Value,
		ExpiresAt: m.ExpiresAt.UTC(),
	}
}

// --- RateLimit ---

// RateLimit mirrors yauth_rate_limits.
type RateLimit struct {
	Key         string    `gorm:"column:key;primaryKey"`
	Count       int       `gorm:"column:count;not null;default:1"`
	WindowStart time.Time `gorm:"column:window_start;not null"`
}

func (RateLimit) TableName() string { return "yauth_rate_limits" }

// --- Revocation ---

// Revocation mirrors yauth_revocations.
type Revocation struct {
	Key       string    `gorm:"column:key;primaryKey"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null"`
}

func (Revocation) TableName() string { return "yauth_revocations" }

// --- OAuthState ---

// OAuthState mirrors yauth_oauth_states.
type OAuthState struct {
	State       string    `gorm:"column:state;primaryKey"`
	Provider    string    `gorm:"column:provider;not null"`
	RedirectURL *string   `gorm:"column:redirect_url"`
	ExpiresAt   time.Time `gorm:"column:expires_at;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
}

func (OAuthState) TableName() string { return "yauth_oauth_states" }

func (m *OAuthState) toDomain() domain.OAuthState {
	return domain.OAuthState{
		State:       m.State,
		Provider:    m.Provider,
		RedirectURL: m.RedirectURL,
		ExpiresAt:   m.ExpiresAt.UTC(),
		CreatedAt:   m.CreatedAt.UTC(),
	}
}

func oauthStateFromDomain(in domain.NewOAuthState) OAuthState {
	return OAuthState{
		State:       in.State,
		Provider:    in.Provider,
		RedirectURL: in.RedirectURL,
		ExpiresAt:   in.ExpiresAt.UTC(),
		CreatedAt:   in.CreatedAt.UTC(),
	}
}

// --- MagicLink ---

// MagicLink mirrors yauth_magic_links.
type MagicLink struct {
	ID        string    `gorm:"column:id;primaryKey"`
	Email     string    `gorm:"column:email;not null;index"`
	TokenHash string    `gorm:"column:token_hash;not null;uniqueIndex"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null"`
	Used      bool      `gorm:"column:used;not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (MagicLink) TableName() string { return "yauth_magic_links" }

func (m *MagicLink) toDomain() domain.MagicLink {
	return domain.MagicLink{
		ID:        m.ID,
		Email:     m.Email,
		TokenHash: m.TokenHash,
		ExpiresAt: m.ExpiresAt.UTC(),
		Used:      m.Used,
		CreatedAt: m.CreatedAt.UTC(),
	}
}

func magicLinkFromDomain(in domain.NewMagicLink) MagicLink {
	return MagicLink{
		ID:        in.ID,
		Email:     in.Email,
		TokenHash: in.TokenHash,
		ExpiresAt: in.ExpiresAt.UTC(),
		Used:      false,
		CreatedAt: in.CreatedAt.UTC(),
	}
}

// --- OAuth2Client ---

// OAuth2Client mirrors yauth_oauth2_clients.
type OAuth2Client struct {
	ID                      string     `gorm:"column:id;primaryKey"`
	ClientID                string     `gorm:"column:client_id;not null;uniqueIndex"`
	ClientSecretHash        *string    `gorm:"column:client_secret_hash"`
	RedirectURIs            string     `gorm:"column:redirect_uris;type:text;not null"`
	ClientName              *string    `gorm:"column:client_name"`
	GrantTypes              string     `gorm:"column:grant_types;type:text;not null"`
	Scopes                  *string    `gorm:"column:scopes;type:text"`
	IsPublic                bool       `gorm:"column:is_public;not null"`
	CreatedAt               time.Time  `gorm:"column:created_at;not null"`
	TokenEndpointAuthMethod *string    `gorm:"column:token_endpoint_auth_method"`
	PublicKeyPEM            *string    `gorm:"column:public_key_pem;type:text"`
	JWKSURI                 *string    `gorm:"column:jwks_uri"`
	BannedAt                *time.Time `gorm:"column:banned_at"`
	BannedReason            *string    `gorm:"column:banned_reason"`
	EnforceGroupAssignment  bool       `gorm:"column:enforce_group_assignment;not null;default:false"`

	// No DB-level default: MySQL forbids DEFAULT on TEXT/JSON columns. The value
	// is always set in oauth2ClientFromDomain (empty -> "[]"), so NOT NULL holds.
	PostLogoutRedirectURIs           string     `gorm:"column:post_logout_redirect_uris;type:text;not null"`
	BackchannelLogoutURI             *string    `gorm:"column:backchannel_logout_uri;type:text"`
	BackchannelLogoutSessionRequired bool       `gorm:"column:backchannel_logout_session_required;not null;default:false"`
	DynamicallyRegistered            bool       `gorm:"column:dynamically_registered;not null;default:false"`
	LastUsedAt                       *time.Time `gorm:"column:last_used_at"`
}

func (OAuth2Client) TableName() string { return "yauth_oauth2_clients" }

func (m *OAuth2Client) toDomain() domain.OAuth2Client {
	plru := m.PostLogoutRedirectURIs
	if plru == "" {
		plru = "[]"
	}
	return domain.OAuth2Client{
		ID:                      m.ID,
		ClientID:                m.ClientID,
		ClientSecretHash:        m.ClientSecretHash,
		RedirectURIs:            json.RawMessage(m.RedirectURIs),
		ClientName:              m.ClientName,
		GrantTypes:              json.RawMessage(m.GrantTypes),
		Scopes:                  rawJSONToBytes(m.Scopes),
		IsPublic:                m.IsPublic,
		CreatedAt:               m.CreatedAt.UTC(),
		TokenEndpointAuthMethod: m.TokenEndpointAuthMethod,
		PublicKeyPEM:            m.PublicKeyPEM,
		JWKSURI:                 m.JWKSURI,
		BannedAt:                ptrUTC(m.BannedAt),
		BannedReason:            m.BannedReason,
		EnforceGroupAssignment:  m.EnforceGroupAssignment,

		PostLogoutRedirectURIs:           json.RawMessage(plru),
		BackchannelLogoutURI:             m.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: m.BackchannelLogoutSessionRequired,
		DynamicallyRegistered:            m.DynamicallyRegistered,
		LastUsedAt:                       ptrUTC(m.LastUsedAt),
	}
}

func oauth2ClientFromDomain(in domain.NewOAuth2Client) OAuth2Client {
	plru := string(in.PostLogoutRedirectURIs)
	if plru == "" {
		plru = "[]"
	}
	return OAuth2Client{
		ID:                      in.ID,
		ClientID:                in.ClientID,
		ClientSecretHash:        in.ClientSecretHash,
		RedirectURIs:            string(in.RedirectURIs),
		ClientName:              in.ClientName,
		GrantTypes:              string(in.GrantTypes),
		Scopes:                  strFromBytes(in.Scopes),
		IsPublic:                in.IsPublic,
		CreatedAt:               in.CreatedAt.UTC(),
		TokenEndpointAuthMethod: in.TokenEndpointAuthMethod,
		PublicKeyPEM:            in.PublicKeyPEM,
		JWKSURI:                 in.JWKSURI,
		EnforceGroupAssignment:  in.EnforceGroupAssignment,

		PostLogoutRedirectURIs:           plru,
		BackchannelLogoutURI:             in.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: in.BackchannelLogoutSessionRequired,
		DynamicallyRegistered:            in.DynamicallyRegistered,
	}
}

// --- Webhook ---

// Webhook mirrors yauth_webhooks.
type Webhook struct {
	ID        string    `gorm:"column:id;primaryKey"`
	URL       string    `gorm:"column:url;not null"`
	Secret    string    `gorm:"column:secret;not null"`
	Events    string    `gorm:"column:events;type:text;not null"`
	Active    bool      `gorm:"column:active;not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
}

func (Webhook) TableName() string { return "yauth_webhooks" }

func (m *Webhook) toDomain() domain.Webhook {
	return domain.Webhook{
		ID:        m.ID,
		URL:       m.URL,
		Secret:    m.Secret,
		Events:    json.RawMessage(m.Events),
		Active:    m.Active,
		CreatedAt: m.CreatedAt.UTC(),
		UpdatedAt: m.UpdatedAt.UTC(),
	}
}

func webhookFromDomain(in domain.NewWebhook) Webhook {
	return Webhook{
		ID:        in.ID,
		URL:       in.URL,
		Secret:    in.Secret,
		Events:    string(in.Events),
		Active:    in.Active,
		CreatedAt: in.CreatedAt.UTC(),
		UpdatedAt: in.UpdatedAt.UTC(),
	}
}

// --- OIDCNonce ---

// OIDCNonce mirrors yauth_oidc_nonces.
type OIDCNonce struct {
	ID                  string    `gorm:"column:id;primaryKey"`
	NonceHash           string    `gorm:"column:nonce_hash;not null;uniqueIndex"`
	AuthorizationCodeID string    `gorm:"column:authorization_code_id;not null"`
	CreatedAt           time.Time `gorm:"column:created_at;not null"`
}

func (OIDCNonce) TableName() string { return "yauth_oidc_nonces" }

func (m *OIDCNonce) toDomain() domain.OIDCNonce {
	return domain.OIDCNonce{
		ID:                  m.ID,
		NonceHash:           m.NonceHash,
		AuthorizationCodeID: m.AuthorizationCodeID,
		CreatedAt:           m.CreatedAt.UTC(),
	}
}

func oidcNonceFromDomain(in domain.NewOIDCNonce) OIDCNonce {
	return OIDCNonce{
		ID:                  in.ID,
		NonceHash:           in.NonceHash,
		AuthorizationCodeID: in.AuthorizationCodeID,
		CreatedAt:           in.CreatedAt.UTC(),
	}
}

// --- WebauthnCredential ---

// WebauthnCredential mirrors yauth_webauthn_credentials.
type WebauthnCredential struct {
	ID         string     `gorm:"column:id;primaryKey"`
	UserID     string     `gorm:"column:user_id;index"`
	Name       string     `gorm:"column:name;not null"`
	AAGUID     *string    `gorm:"column:aaguid"`
	DeviceName *string    `gorm:"column:device_name"`
	Credential string     `gorm:"column:credential;type:text;not null"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null"`
	LastUsedAt *time.Time `gorm:"column:last_used_at"`
}

func (WebauthnCredential) TableName() string { return "yauth_webauthn_credentials" }

func (m *WebauthnCredential) toDomain() domain.WebauthnCredential {
	return domain.WebauthnCredential{
		ID:         m.ID,
		UserID:     m.UserID,
		Name:       m.Name,
		AAGUID:     m.AAGUID,
		DeviceName: m.DeviceName,
		Credential: json.RawMessage(m.Credential),
		CreatedAt:  m.CreatedAt.UTC(),
		LastUsedAt: ptrUTC(m.LastUsedAt),
	}
}

func webauthnCredentialFromDomain(in domain.NewWebauthnCredential) WebauthnCredential {
	return WebauthnCredential{
		ID:         in.ID,
		UserID:     in.UserID,
		Name:       in.Name,
		AAGUID:     in.AAGUID,
		DeviceName: in.DeviceName,
		Credential: string(in.Credential),
		CreatedAt:  in.CreatedAt.UTC(),
	}
}

// --- TOTPSecret ---

// TOTPSecret mirrors yauth_totp_secrets.
type TOTPSecret struct {
	ID              string    `gorm:"column:id;primaryKey"`
	UserID          string    `gorm:"column:user_id;uniqueIndex"`
	EncryptedSecret string    `gorm:"column:encrypted_secret;not null"`
	Verified        bool      `gorm:"column:verified;not null"`
	CreatedAt       time.Time `gorm:"column:created_at;not null"`
}

func (TOTPSecret) TableName() string { return "yauth_totp_secrets" }

func (m *TOTPSecret) toDomain() domain.TOTPSecret {
	return domain.TOTPSecret{
		ID:              m.ID,
		UserID:          m.UserID,
		EncryptedSecret: m.EncryptedSecret,
		Verified:        m.Verified,
		CreatedAt:       m.CreatedAt.UTC(),
	}
}

func totpFromDomain(in domain.NewTOTPSecret) TOTPSecret {
	return TOTPSecret{
		ID:              in.ID,
		UserID:          in.UserID,
		EncryptedSecret: in.EncryptedSecret,
		Verified:        in.Verified,
		CreatedAt:       in.CreatedAt.UTC(),
	}
}

// --- BackupCode ---

// BackupCode mirrors yauth_backup_codes.
type BackupCode struct {
	ID        string    `gorm:"column:id;primaryKey"`
	UserID    string    `gorm:"column:user_id;index"`
	CodeHash  string    `gorm:"column:code_hash;not null"`
	Used      bool      `gorm:"column:used;not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (BackupCode) TableName() string { return "yauth_backup_codes" }

func (m *BackupCode) toDomain() domain.BackupCode {
	return domain.BackupCode{
		ID:        m.ID,
		UserID:    m.UserID,
		CodeHash:  m.CodeHash,
		Used:      m.Used,
		CreatedAt: m.CreatedAt.UTC(),
	}
}

func backupCodeFromDomain(in domain.NewBackupCode) BackupCode {
	return BackupCode{
		ID:        in.ID,
		UserID:    in.UserID,
		CodeHash:  in.CodeHash,
		Used:      in.Used,
		CreatedAt: in.CreatedAt.UTC(),
	}
}

// --- OAuthAccount ---

// OAuthAccount mirrors yauth_oauth_accounts.
type OAuthAccount struct {
	ID              string     `gorm:"column:id;primaryKey"`
	UserID          string     `gorm:"column:user_id;index"`
	Provider        string     `gorm:"column:provider;not null;index"`
	ProviderUserID  string     `gorm:"column:provider_user_id;not null"`
	AccessTokenEnc  *string    `gorm:"column:access_token_enc;type:text"`
	RefreshTokenEnc *string    `gorm:"column:refresh_token_enc;type:text"`
	CreatedAt       time.Time  `gorm:"column:created_at;not null"`
	ExpiresAt       *time.Time `gorm:"column:expires_at"`
	UpdatedAt       time.Time  `gorm:"column:updated_at;not null"`
}

func (OAuthAccount) TableName() string { return "yauth_oauth_accounts" }

func (m *OAuthAccount) toDomain() domain.OAuthAccount {
	return domain.OAuthAccount{
		ID:              m.ID,
		UserID:          m.UserID,
		Provider:        m.Provider,
		ProviderUserID:  m.ProviderUserID,
		AccessTokenEnc:  m.AccessTokenEnc,
		RefreshTokenEnc: m.RefreshTokenEnc,
		CreatedAt:       m.CreatedAt.UTC(),
		ExpiresAt:       ptrUTC(m.ExpiresAt),
		UpdatedAt:       m.UpdatedAt.UTC(),
	}
}

func oauthAccountFromDomain(in domain.NewOAuthAccount) OAuthAccount {
	return OAuthAccount{
		ID:              in.ID,
		UserID:          in.UserID,
		Provider:        in.Provider,
		ProviderUserID:  in.ProviderUserID,
		AccessTokenEnc:  in.AccessTokenEnc,
		RefreshTokenEnc: in.RefreshTokenEnc,
		CreatedAt:       in.CreatedAt.UTC(),
		ExpiresAt:       ptrUTC(in.ExpiresAt),
		UpdatedAt:       in.UpdatedAt.UTC(),
	}
}

// --- RefreshToken ---

// RefreshToken mirrors yauth_refresh_tokens.
type RefreshToken struct {
	ID        string    `gorm:"column:id;primaryKey"`
	UserID    string    `gorm:"column:user_id;index"`
	TokenHash string    `gorm:"column:token_hash;not null;uniqueIndex"`
	FamilyID  string    `gorm:"column:family_id;not null;index"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null"`
	Revoked   bool      `gorm:"column:revoked;not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (RefreshToken) TableName() string { return "yauth_refresh_tokens" }

func (m *RefreshToken) toDomain() domain.RefreshToken {
	return domain.RefreshToken{
		ID:        m.ID,
		UserID:    m.UserID,
		TokenHash: m.TokenHash,
		FamilyID:  m.FamilyID,
		ExpiresAt: m.ExpiresAt.UTC(),
		Revoked:   m.Revoked,
		CreatedAt: m.CreatedAt.UTC(),
	}
}

func refreshTokenFromDomain(in domain.NewRefreshToken) RefreshToken {
	return RefreshToken{
		ID:        in.ID,
		UserID:    in.UserID,
		TokenHash: in.TokenHash,
		FamilyID:  in.FamilyID,
		ExpiresAt: in.ExpiresAt.UTC(),
		Revoked:   in.Revoked,
		CreatedAt: in.CreatedAt.UTC(),
	}
}

// --- APIKey ---

// APIKey mirrors yauth_api_keys.
//
// Ownership is encoded by the (UserID, OrganizationID) nullable pair:
// exactly one of the two is non-nil per row (yauth #91 / yauth-go #19).
// Backends MUST enforce the invariant — gormrepo relies on the
// validation in CreateAPIKey + an application-level CHECK; the in-
// memory backend rejects mismatched inputs with
// yautherr.ErrInvalidRequest.
type APIKey struct {
	ID              string     `gorm:"column:id;primaryKey"`
	UserID          *string    `gorm:"column:user_id;index"`
	OrganizationID  *string    `gorm:"column:organization_id;index"`
	KeyPrefix       string     `gorm:"column:key_prefix;not null;uniqueIndex"`
	KeyHash         string     `gorm:"column:key_hash;not null"`
	Name            string     `gorm:"column:name;not null"`
	Scopes          *string    `gorm:"column:scopes;type:text"`
	Role            *string    `gorm:"column:role"`
	LastUsedAt      *time.Time `gorm:"column:last_used_at"`
	ExpiresAt       *time.Time `gorm:"column:expires_at"`
	CreatedAt       time.Time  `gorm:"column:created_at;not null"`
	CreatedByUserID string     `gorm:"column:created_by_user_id;not null;index"`
}

func (APIKey) TableName() string { return "yauth_api_keys" }

func (m *APIKey) toDomain() domain.APIKey {
	return domain.APIKey{
		ID:              m.ID,
		UserID:          strPtrCopy(m.UserID),
		OrganizationID:  strPtrCopy(m.OrganizationID),
		KeyPrefix:       m.KeyPrefix,
		KeyHash:         m.KeyHash,
		Name:            m.Name,
		Scopes:          rawJSONToBytes(m.Scopes),
		Role:            strPtrCopy(m.Role),
		LastUsedAt:      ptrUTC(m.LastUsedAt),
		ExpiresAt:       ptrUTC(m.ExpiresAt),
		CreatedAt:       m.CreatedAt.UTC(),
		CreatedByUserID: m.CreatedByUserID,
	}
}

func apiKeyFromDomain(in domain.NewAPIKey) APIKey {
	return APIKey{
		ID:              in.ID,
		UserID:          strPtrCopy(in.UserID),
		OrganizationID:  strPtrCopy(in.OrganizationID),
		KeyPrefix:       in.KeyPrefix,
		KeyHash:         in.KeyHash,
		Name:            in.Name,
		Scopes:          strFromBytes(in.Scopes),
		Role:            strPtrCopy(in.Role),
		ExpiresAt:       ptrUTC(in.ExpiresAt),
		CreatedAt:       in.CreatedAt.UTC(),
		CreatedByUserID: in.CreatedByUserID,
	}
}

// strPtrCopy duplicates a *string for safe ownership transfer.
func strPtrCopy(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// --- AuthorizationCode ---

// AuthorizationCode mirrors yauth_authorization_codes.
type AuthorizationCode struct {
	ID                  string    `gorm:"column:id;primaryKey"`
	CodeHash            string    `gorm:"column:code_hash;not null;uniqueIndex"`
	ClientID            string    `gorm:"column:client_id;not null"`
	UserID              string    `gorm:"column:user_id;index"`
	Scopes              *string   `gorm:"column:scopes;type:text"`
	RedirectURI         string    `gorm:"column:redirect_uri;not null"`
	CodeChallenge       string    `gorm:"column:code_challenge;not null"`
	CodeChallengeMethod string    `gorm:"column:code_challenge_method;not null"`
	ExpiresAt           time.Time `gorm:"column:expires_at;not null"`
	Used                bool      `gorm:"column:used;not null"`
	Nonce               *string   `gorm:"column:nonce"`
	CreatedAt           time.Time `gorm:"column:created_at;not null"`
}

func (AuthorizationCode) TableName() string { return "yauth_authorization_codes" }

func (m *AuthorizationCode) toDomain() domain.AuthorizationCode {
	return domain.AuthorizationCode{
		ID:                  m.ID,
		CodeHash:            m.CodeHash,
		ClientID:            m.ClientID,
		UserID:              m.UserID,
		Scopes:              rawJSONToBytes(m.Scopes),
		RedirectURI:         m.RedirectURI,
		CodeChallenge:       m.CodeChallenge,
		CodeChallengeMethod: m.CodeChallengeMethod,
		ExpiresAt:           m.ExpiresAt.UTC(),
		Used:                m.Used,
		Nonce:               m.Nonce,
		CreatedAt:           m.CreatedAt.UTC(),
	}
}

func authorizationCodeFromDomain(in domain.NewAuthorizationCode) AuthorizationCode {
	return AuthorizationCode{
		ID:                  in.ID,
		CodeHash:            in.CodeHash,
		ClientID:            in.ClientID,
		UserID:              in.UserID,
		Scopes:              strFromBytes(in.Scopes),
		RedirectURI:         in.RedirectURI,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		ExpiresAt:           in.ExpiresAt.UTC(),
		Used:                in.Used,
		Nonce:               in.Nonce,
		CreatedAt:           in.CreatedAt.UTC(),
	}
}

// --- Consent ---

// Consent mirrors yauth_consents.
type Consent struct {
	ID        string    `gorm:"column:id;primaryKey"`
	UserID    string    `gorm:"column:user_id;index"`
	ClientID  string    `gorm:"column:client_id;not null"`
	Scopes    *string   `gorm:"column:scopes;type:text"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (Consent) TableName() string { return "yauth_consents" }

func (m *Consent) toDomain() domain.Consent {
	return domain.Consent{
		ID:        m.ID,
		UserID:    m.UserID,
		ClientID:  m.ClientID,
		Scopes:    rawJSONToBytes(m.Scopes),
		CreatedAt: m.CreatedAt.UTC(),
	}
}

func consentFromDomain(in domain.NewConsent) Consent {
	return Consent{
		ID:        in.ID,
		UserID:    in.UserID,
		ClientID:  in.ClientID,
		Scopes:    strFromBytes(in.Scopes),
		CreatedAt: in.CreatedAt.UTC(),
	}
}

// --- DeviceCode ---

// DeviceCode mirrors yauth_device_codes.
type DeviceCode struct {
	ID             string     `gorm:"column:id;primaryKey"`
	DeviceCodeHash string     `gorm:"column:device_code_hash;not null;uniqueIndex"`
	UserCode       string     `gorm:"column:user_code;not null;uniqueIndex"`
	ClientID       string     `gorm:"column:client_id;not null"`
	Scopes         *string    `gorm:"column:scopes;type:text"`
	UserID         *string    `gorm:"column:user_id"`
	Status         string     `gorm:"column:status;not null;default:pending"`
	Interval       int        `gorm:"column:interval;not null;default:5"`
	ExpiresAt      time.Time  `gorm:"column:expires_at;not null"`
	LastPolledAt   *time.Time `gorm:"column:last_polled_at"`
	CreatedAt      time.Time  `gorm:"column:created_at;not null"`
}

func (DeviceCode) TableName() string { return "yauth_device_codes" }

func (m *DeviceCode) toDomain() domain.DeviceCode {
	return domain.DeviceCode{
		ID:             m.ID,
		DeviceCodeHash: m.DeviceCodeHash,
		UserCode:       m.UserCode,
		ClientID:       m.ClientID,
		Scopes:         rawJSONToBytes(m.Scopes),
		UserID:         m.UserID,
		Status:         m.Status,
		Interval:       m.Interval,
		ExpiresAt:      m.ExpiresAt.UTC(),
		LastPolledAt:   ptrUTC(m.LastPolledAt),
		CreatedAt:      m.CreatedAt.UTC(),
	}
}

func deviceCodeFromDomain(in domain.NewDeviceCode) DeviceCode {
	return DeviceCode{
		ID:             in.ID,
		DeviceCodeHash: in.DeviceCodeHash,
		UserCode:       in.UserCode,
		ClientID:       in.ClientID,
		Scopes:         strFromBytes(in.Scopes),
		UserID:         in.UserID,
		Status:         in.Status,
		Interval:       in.Interval,
		ExpiresAt:      in.ExpiresAt.UTC(),
		CreatedAt:      in.CreatedAt.UTC(),
	}
}

// --- AccountLock ---

// AccountLock mirrors yauth_account_locks.
type AccountLock struct {
	ID           string     `gorm:"column:id;primaryKey"`
	UserID       string     `gorm:"column:user_id;uniqueIndex"`
	FailedCount  int        `gorm:"column:failed_count;not null;default:0"`
	LockedUntil  *time.Time `gorm:"column:locked_until"`
	LockCount    int        `gorm:"column:lock_count;not null;default:0"`
	LockedReason *string    `gorm:"column:locked_reason"`
	CreatedAt    time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt    time.Time  `gorm:"column:updated_at;not null"`
}

func (AccountLock) TableName() string { return "yauth_account_locks" }

func (m *AccountLock) toDomain() domain.AccountLock {
	return domain.AccountLock{
		ID:           m.ID,
		UserID:       m.UserID,
		FailedCount:  m.FailedCount,
		LockedUntil:  ptrUTC(m.LockedUntil),
		LockCount:    m.LockCount,
		LockedReason: m.LockedReason,
		CreatedAt:    m.CreatedAt.UTC(),
		UpdatedAt:    m.UpdatedAt.UTC(),
	}
}

func accountLockFromDomain(in domain.NewAccountLock) AccountLock {
	return AccountLock{
		ID:           in.ID,
		UserID:       in.UserID,
		FailedCount:  in.FailedCount,
		LockedUntil:  ptrUTC(in.LockedUntil),
		LockCount:    in.LockCount,
		LockedReason: in.LockedReason,
		CreatedAt:    in.CreatedAt.UTC(),
		UpdatedAt:    in.UpdatedAt.UTC(),
	}
}

// --- UnlockToken ---

// UnlockToken mirrors yauth_unlock_tokens.
type UnlockToken struct {
	ID        string    `gorm:"column:id;primaryKey"`
	UserID    string    `gorm:"column:user_id;index"`
	TokenHash string    `gorm:"column:token_hash;not null;uniqueIndex"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (UnlockToken) TableName() string { return "yauth_unlock_tokens" }

func (m *UnlockToken) toDomain() domain.UnlockToken {
	return domain.UnlockToken{
		ID:        m.ID,
		UserID:    m.UserID,
		TokenHash: m.TokenHash,
		ExpiresAt: m.ExpiresAt.UTC(),
		CreatedAt: m.CreatedAt.UTC(),
	}
}

func unlockTokenFromDomain(in domain.NewUnlockToken) UnlockToken {
	return UnlockToken{
		ID:        in.ID,
		UserID:    in.UserID,
		TokenHash: in.TokenHash,
		ExpiresAt: in.ExpiresAt.UTC(),
		CreatedAt: in.CreatedAt.UTC(),
	}
}

// --- WebhookDelivery ---

// WebhookDelivery mirrors yauth_webhook_deliveries.
type WebhookDelivery struct {
	ID           string    `gorm:"column:id;primaryKey"`
	WebhookID    string    `gorm:"column:webhook_id;index"`
	EventType    string    `gorm:"column:event_type;not null"`
	Payload      string    `gorm:"column:payload;type:text;not null"`
	StatusCode   *int16    `gorm:"column:status_code"`
	ResponseBody *string   `gorm:"column:response_body;type:text"`
	Success      bool      `gorm:"column:success;not null"`
	Attempt      int       `gorm:"column:attempt;not null;default:1"`
	CreatedAt    time.Time `gorm:"column:created_at;not null"`
}

func (WebhookDelivery) TableName() string { return "yauth_webhook_deliveries" }

func (m *WebhookDelivery) toDomain() domain.WebhookDelivery {
	return domain.WebhookDelivery{
		ID:           m.ID,
		WebhookID:    m.WebhookID,
		EventType:    m.EventType,
		Payload:      json.RawMessage(m.Payload),
		StatusCode:   m.StatusCode,
		ResponseBody: m.ResponseBody,
		Success:      m.Success,
		Attempt:      m.Attempt,
		CreatedAt:    m.CreatedAt.UTC(),
	}
}

func webhookDeliveryFromDomain(in domain.NewWebhookDelivery) WebhookDelivery {
	return WebhookDelivery{
		ID:           in.ID,
		WebhookID:    in.WebhookID,
		EventType:    in.EventType,
		Payload:      string(in.Payload),
		StatusCode:   in.StatusCode,
		ResponseBody: in.ResponseBody,
		Success:      in.Success,
		Attempt:      in.Attempt,
		CreatedAt:    in.CreatedAt.UTC(),
	}
}

// --- WebhookRetry ---

// WebhookRetry mirrors yauth_webhook_retries — the persisted queue of
// scheduled retries. NotBefore is the earliest time a claimer may pick
// the row up; an index on it keeps ClaimDueRetries fast under load.
type WebhookRetry struct {
	ID        string    `gorm:"column:id;primaryKey"`
	WebhookID string    `gorm:"column:webhook_id;index;not null"`
	EventType string    `gorm:"column:event_type;not null"`
	Payload   []byte    `gorm:"column:payload;not null"`
	Attempt   int       `gorm:"column:attempt;not null"`
	NotBefore time.Time `gorm:"column:not_before;not null;index"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (WebhookRetry) TableName() string { return "yauth_webhook_retries" }

func (m *WebhookRetry) toDomain() domain.ScheduledWebhookRetry {
	out := domain.ScheduledWebhookRetry{
		ID:        m.ID,
		WebhookID: m.WebhookID,
		EventType: m.EventType,
		Attempt:   m.Attempt,
		NotBefore: m.NotBefore.UTC(),
		CreatedAt: m.CreatedAt.UTC(),
	}
	if len(m.Payload) > 0 {
		out.Payload = append([]byte(nil), m.Payload...)
	}
	return out
}

func webhookRetryFromDomain(in domain.NewScheduledWebhookRetry) WebhookRetry {
	row := WebhookRetry{
		ID:        in.ID,
		WebhookID: in.WebhookID,
		EventType: in.EventType,
		Attempt:   in.Attempt,
		NotBefore: in.NotBefore.UTC(),
		CreatedAt: in.CreatedAt.UTC(),
	}
	if len(in.Payload) > 0 {
		row.Payload = append([]byte(nil), in.Payload...)
	}
	return row
}
