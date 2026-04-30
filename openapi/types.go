// Package openapi declares the OpenAPI 3.1 spec for every yauth-go
// HTTP route by hand. The plugins themselves are net/http-based and do
// not flow through huma.Operation; instead this package uses huma's
// schema/registry primitives to keep the spec authored in idiomatic Go
// (the equivalent of Rust's utoipa annotations).
//
// Add a route by:
//  1. defining its request/response struct in this file (one per shape),
//  2. registering it in declareSchemas,
//  3. adding an operation to the appropriate per-plugin block in spec.go.
package openapi

import "time"

// errorPayload mirrors the runtime error envelope used by every plugin:
//
//	{"error": {"code": "INVALID_REQUEST", "message": "..."}}
type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// errorBody is the top-level error envelope wrapping errorPayload.
type errorBody struct {
	Error errorPayload `json:"error"`
}

// userJSON is the canonical user shape returned by registration / login /
// session endpoints. It deliberately omits admin-only fields (banned_*).
type userJSON struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"`
}

// adminUserJSON adds the admin-relevant fields to userJSON. Returned by
// the /admin/users endpoints.
type adminUserJSON struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	DisplayName   *string    `json:"display_name,omitempty"`
	EmailVerified bool       `json:"email_verified"`
	Role          string     `json:"role"`
	Banned        bool       `json:"banned"`
	BannedReason  *string    `json:"banned_reason,omitempty"`
	BannedUntil   *time.Time `json:"banned_until,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// --- email-password ---------------------------------------------------

// sessionUserJSON is the flat user shape returned by /session, /me and
// the various login endpoints. Mirrors the Rust spec.
type sessionUserJSON struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	DisplayName   *string  `json:"display_name,omitempty"`
	EmailVerified bool     `json:"email_verified"`
	Role          string   `json:"role"`
	Banned        bool     `json:"banned"`
	AuthMethod    string   `json:"auth_method"`
	Scopes        []string `json:"scopes"`
}

type emailPasswordRegisterRequest struct {
	Email       string  `json:"email"`
	Password    string  `json:"password"`
	DisplayName *string `json:"display_name,omitempty"`
}
type emailPasswordRegisterResponse struct {
	Message string `json:"message"`
}
type emailPasswordLoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me,omitempty"`
}
type emailPasswordLoginResponse struct {
	User userJSON `json:"user"`
}
type emailPasswordLoginMfaResponse struct {
	RequireMfa       bool   `json:"require_mfa"`
	PendingSessionID string `json:"pending_session_id"`
}
type emailPasswordSessionResponse sessionUserJSON
type emailPasswordChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}
type emailPasswordChangePasswordResponse struct {
	Message string `json:"message"`
}

type emailPasswordPatchMeRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
}

type emailPasswordPatchMeResponse sessionUserJSON

// --- email verification + password reset extras ---

type emailVerifyRequest struct {
	Token string `json:"token"`
}
type emailVerifyResponse struct {
	Message string `json:"message"`
}
type emailResendVerificationRequest struct {
	Email string `json:"email"`
}
type emailResendVerificationResponse struct {
	Message string `json:"message"`
}
type emailForgotPasswordRequest struct {
	Email string `json:"email"`
}
type emailForgotPasswordResponse struct {
	Message string `json:"message"`
}
type emailResetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}
type emailResetPasswordResponse struct {
	Message string `json:"message"`
}

type oauth2RegisterRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	JWKSURI                 string   `json:"jwks_uri,omitempty"`
}

type oauth2RegisterResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
}

// --- bearer -----------------------------------------------------------

type bearerTokenRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Scope    string `json:"scope,omitempty"`
}
type bearerTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}
type bearerRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}
type bearerRevokeRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// --- api-key ----------------------------------------------------------

type apiKeyJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}
// apiKeyListResponse: GET /api-keys returns a bare array of apiKeyJSON.
// Documented inline via huma.Schema{Type:"array", Items:...}.

type apiKeyCreateRequest struct {
	Name          string   `json:"name"`
	Scopes        []string `json:"scopes,omitempty"`
	ExpiresInDays *int     `json:"expires_in_days,omitempty"`
}
type apiKeyCreateResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"`
	Scopes    []string   `json:"scopes"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Key       string     `json:"key"`
}

// --- magic-link -------------------------------------------------------

type magicLinkSendRequest struct {
	Email string `json:"email"`
}
type magicLinkSendResponse struct {
	Message string `json:"message"`
}
type magicLinkVerifyRequest struct {
	Token string `json:"token"`
}
type magicLinkVerifyResponse struct {
	UserID        string  `json:"user_id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
}

// --- lockout ----------------------------------------------------------

type lockoutUnlockRequest struct {
	Token string `json:"token"`
}
type lockoutUnlockResponse struct {
	Message string `json:"message"`
}
type lockoutUnlockReqRequest struct {
	Email string `json:"email"`
}
type lockoutUnlockReqResponse struct {
	Message string `json:"message"`
}
type lockoutLockedAccountJSON struct {
	UserID       string  `json:"user_id"`
	Email        string  `json:"email"`
	FailedCount  int     `json:"failed_count"`
	LockedUntil  *string `json:"locked_until,omitempty"`
	LockedReason *string `json:"locked_reason,omitempty"`
	LockCount    int     `json:"lock_count"`
}
type lockoutStateResponse struct {
	Locked []lockoutLockedAccountJSON `json:"locked"`
}

// --- status -----------------------------------------------------------

type statusResponse struct {
	Plugins []string `json:"plugins"`
	Version string   `json:"version"`
}

// configResponse mirrors the Rust shape returned by GET /config: only
// the operator-toggled flags clients need.
type configResponse struct {
	AllowSignups             bool `json:"allow_signups"`
	RequireEmailVerification bool `json:"require_email_verification"`
}

// --- admin ------------------------------------------------------------

type adminListUsersResponse struct {
	Users   []adminUserJSON `json:"users"`
	Total   int64           `json:"total"`
	Page    int             `json:"page"`
	PerPage int             `json:"per_page"`
}
type adminPatchUserRequest struct {
	DisplayName   *string `json:"display_name,omitempty"`
	Role          *string `json:"role,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"`
}
type adminBanRequest struct {
	Reason string     `json:"reason"`
	Until  *time.Time `json:"until,omitempty"`
}
type adminImpersonateResponse adminUserJSON
type adminDeleteSessionsResponse struct {
	Deleted int64 `json:"deleted"`
}
type adminAuditEntryJSON struct {
	ID        string  `json:"id"`
	UserID    *string `json:"user_id,omitempty"`
	EventType string  `json:"event_type"`
	// Metadata is the audit log row's serialized metadata; expressed as a
	// free-form object.
	Metadata  map[string]any `json:"metadata,omitempty"`
	IPAddress *string        `json:"ip_address,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}
type adminListAuditResponse struct {
	Entries []adminAuditEntryJSON `json:"entries"`
}

type adminSessionJSON struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	IPAddress *string   `json:"ip_address,omitempty"`
	UserAgent *string   `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type adminListSessionsResponse struct {
	Sessions []adminSessionJSON `json:"sessions"`
	Total    int64              `json:"total"`
	Page     int                `json:"page"`
	PerPage  int                `json:"per_page"`
}

// --- mfa --------------------------------------------------------------

type mfaSetupResponse struct {
	Secret      string   `json:"secret"`
	OTPAuthURL  string   `json:"otpauth_url"`
	BackupCodes []string `json:"backup_codes"`
}
type mfaConfirmRequest struct {
	Code string `json:"code"`
}
type mfaMessageResponse struct {
	Message string `json:"message"`
}
type mfaBackupCodesCountResponse struct {
	Remaining int `json:"remaining"`
}
type mfaRegenerateResponse struct {
	BackupCodes []string `json:"backup_codes"`
}
type mfaVerifyRequest struct {
	PendingSessionID string `json:"pending_session_id"`
	Code             string `json:"code"`
}
type mfaVerifyResponse struct {
	UserID        string  `json:"user_id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
}

// --- passkey ----------------------------------------------------------

// passkeyOptions is intentionally typed as a free-form object — the
// underlying webauthn library returns CredentialCreation /
// CredentialAssertion structs whose precise schema is large and
// browser-driven. Documenting them as `object` is sufficient for client
// generation since the consumer just round-trips the value to navigator
// .credentials.create / .get.
type passkeyOptions = map[string]any

type passkeyRegisterBeginResponse struct {
	ChallengeID string         `json:"challenge_id"`
	Options     passkeyOptions `json:"options"`
}
type passkeyRegisterFinishRequest struct {
	Name       string         `json:"name,omitempty"`
	Credential map[string]any `json:"credential"`
}
type passkeyRegisterFinishResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}
type passkeyLoginBeginRequest struct {
	Email string `json:"email,omitempty"`
}
type passkeyLoginBeginResponse struct {
	ChallengeID string         `json:"challenge_id"`
	Options     passkeyOptions `json:"options"`
}
type passkeyLoginFinishRequest struct {
	ChallengeID string         `json:"challenge_id"`
	Credential  map[string]any `json:"credential"`
}
type passkeyLoginFinishResponse struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"`
}
type passkeyJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	AAGUID     *string    `json:"aaguid,omitempty"`
	DeviceName *string    `json:"device_name,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// passkeyListResponse: GET /passkeys returns a bare array of passkeyJSON.

// --- oauth ------------------------------------------------------------

type oauthCallbackResponse struct {
	UserID        string  `json:"user_id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
}
type oauthAccountJSON struct {
	Provider       string     `json:"provider"`
	ProviderUserID string     `json:"provider_user_id"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}
// oauthCallbackBody is the JSON body for POST /oauth/{provider}/callback
// (Rust parity).
type oauthCallbackBody struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// oauthListAccountsResponse: GET /oauth/accounts returns a bare array
// of oauthAccountJSON.

type oauthLinkResponse struct {
	AuthURL string `json:"auth_url"`
}

// --- webhooks ---------------------------------------------------------

type webhookJSON struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// webhookListResponse: GET /webhooks returns a bare array of webhookJSON.

type webhookCreateRequest struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret,omitempty"`
}
type webhookUpdateRequest struct {
	URL    *string   `json:"url,omitempty"`
	Events *[]string `json:"events,omitempty"`
	Active *bool     `json:"active,omitempty"`
	Secret *string   `json:"secret,omitempty"`
}
type webhookDeliveryJSON struct {
	ID           string    `json:"id"`
	WebhookID    string    `json:"webhook_id"`
	EventType    string    `json:"event_type"`
	StatusCode   *int16    `json:"status_code,omitempty"`
	ResponseBody *string   `json:"response_body,omitempty"`
	Success      bool      `json:"success"`
	Attempt      int       `json:"attempt"`
	CreatedAt    time.Time `json:"created_at"`
}

// webhookListDeliveriesResponse: GET /webhooks/{id}/deliveries returns
// a bare array of webhookDeliveryJSON.

// webhookShowResponse wraps a webhook with its recent deliveries; used
// by GET /webhooks/{id} per Rust parity.
type webhookShowResponse struct {
	Webhook          webhookJSON           `json:"webhook"`
	RecentDeliveries []webhookDeliveryJSON `json:"recent_deliveries"`
}

// --- asymjwt: jwks ----------------------------------------------------

// jwksKey is a single JSON Web Key entry. The exact contents depend on
// kty (RSA vs EC) — RSA exposes n,e while EC exposes crv,x,y. This
// schema is intentionally permissive because tooling that consumes JWKS
// already understands the union.
type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}
type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

// --- oidc -------------------------------------------------------------

type oidcDiscoveryDoc struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                    string   `json:"token_endpoint,omitempty"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
}
type oidcUserInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
}

// --- oauth2 server ----------------------------------------------------

type oauth2ConsentClient struct {
	ID   string  `json:"id"`
	Name *string `json:"name,omitempty"`
}
type oauth2ConsentPayload struct {
	Client    oauth2ConsentClient `json:"client"`
	Scopes    []string            `json:"scopes"`
	CSRFToken string              `json:"csrf_token"`
	RequestID string              `json:"request_id"`
}
type oauth2AuthorizeRedirect struct {
	RedirectURL string `json:"redirect_url"`
}
type oauth2ConsentRequest struct {
	RequestID string `json:"request_id"`
	CSRFToken string `json:"csrf_token"`
	Approved  bool   `json:"approved"`
}
type oauth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}
type oauth2IntrospectResponse struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Sub      string `json:"sub,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
	Iat      int64  `json:"iat,omitempty"`
	Iss      string `json:"iss,omitempty"`
	TokenTyp string `json:"token_type,omitempty"`
}
type oauth2ClientJSON struct {
	ID                      string    `json:"id"`
	ClientID                string    `json:"client_id"`
	Name                    *string   `json:"name,omitempty"`
	RedirectURIs            []string  `json:"redirect_uris"`
	GrantTypes              []string  `json:"grant_types"`
	Scopes                  []string  `json:"scopes"`
	IsPublic                bool      `json:"is_public"`
	TokenEndpointAuthMethod *string   `json:"token_endpoint_auth_method,omitempty"`
	JWKSURI                 *string   `json:"jwks_uri,omitempty"`
	HasPublicKey            bool      `json:"has_public_key"`
	Banned                  bool      `json:"banned"`
	BannedReason            *string   `json:"banned_reason,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
}
type oauth2CreateClientRequest struct {
	Name                    *string  `json:"name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	Scopes                  []string `json:"scopes"`
	IsPublic                bool     `json:"is_public"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method,omitempty"`
	PublicKeyPEM            *string  `json:"public_key_pem,omitempty"`
	JWKSURI                 *string  `json:"jwks_uri,omitempty"`
}
type oauth2CreateClientResponse struct {
	Client       oauth2ClientJSON `json:"client"`
	ClientSecret *string          `json:"client_secret,omitempty"`
}
type oauth2PatchClientRequest struct {
	Banned       *bool   `json:"banned,omitempty"`
	BannedReason *string `json:"banned_reason,omitempty"`
	PublicKeyPEM *string `json:"public_key_pem,omitempty"`
}
type oauth2BannedClientsResponse struct {
	Banned []oauth2ClientJSON `json:"banned"`
}
type oauth2DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}
type oauth2DeviceVerifyRequest struct {
	UserCode string `json:"user_code"`
}
type oauth2DeviceVerifyResponse struct {
	Status string `json:"status"`
}
