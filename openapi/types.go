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
	ID            string           `json:"id"`
	Email         string           `json:"email"`
	DisplayName   *string          `json:"display_name,omitempty"`
	EmailVerified bool             `json:"email_verified"`
	Role          string           `json:"role"`
	Banned        bool             `json:"banned"`
	AuthMethod    string           `json:"auth_method"`
	Scopes        []string         `json:"scopes"`
	// yauth #89: active-org claim surfaced on AuthUser.
	ActiveOrgID *string             `json:"active_org_id,omitempty"`
	OrgRole     *string             `json:"org_role,omitempty"`
	AllOrgs     []orgMembershipJSON `json:"all_orgs,omitempty"`
}

// orgMembershipJSON is a compact membership descriptor surfaced on
// sessionUserJSON.all_orgs (yauth #89). Distinct from membershipJSON
// (the full /organizations/{id}/members payload) — only the fields a
// client needs to render an org switcher.
type orgMembershipJSON struct {
	OrganizationID string `json:"organization_id"`
	Role           string `json:"role"`
}

type emailPasswordRegisterRequest struct {
	Email       string  `json:"email"`
	Password    string  `json:"password"`
	DisplayName *string `json:"display_name,omitempty"`
}

// emailPasswordRegisterResponse returns either the user (when no email
// verification is required) or a {message} prompt directing the caller
// to check their inbox. The User pointer is omitted when only the
// message applies.
type emailPasswordRegisterResponse struct {
	User    *userJSON `json:"user,omitempty"`
	Message string    `json:"message,omitempty"`
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

// emailPasswordSessionResponse wraps the session user under `user` so
// session metadata (expires_at, last_seen_at) can be added later
// without breaking clients.
type emailPasswordSessionResponse struct {
	User      sessionUserJSON `json:"user"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
}
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

// emailPasswordPatchMeResponse returns the updated user wrapped under
// `user` so additional metadata fields can be added non-breakingly.
type emailPasswordPatchMeResponse struct {
	User sessionUserJSON `json:"user"`
}

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

// oauth2RegisterRequest mirrors RFC 7591 §2 dynamic client registration.
type oauth2RegisterRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	JWKSURI                 string   `json:"jwks_uri,omitempty"`
}

// oauth2RegisterResponse mirrors RFC 7591 §3 dynamic client registration
// response, including the one-time client_secret (omitted for public
// clients) and registration access token.
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

// apiKeyListResponse wraps the GET /api-keys list with pagination
// metadata. Wrapping (instead of a bare array) preserves forward
// compatibility for adding fields later without breaking clients.
type apiKeyListResponse struct {
	Items   []apiKeyJSON `json:"items"`
	Total   int64        `json:"total"`
	Page    int          `json:"page"`
	PerPage int          `json:"per_page"`
}

type apiKeyCreateRequest struct {
	Name          string   `json:"name"`
	Scopes        []string `json:"scopes,omitempty"`
	ExpiresInDays *int     `json:"expires_in_days,omitempty"`
}

// apiKeyCreateResponse splits the persisted-key metadata from the
// one-time plaintext secret so client code can't accidentally log the
// whole envelope. The plaintext is shown ONCE (in `secret`) and is
// unrecoverable thereafter.
type apiKeyCreateResponse struct {
	APIKey apiKeyJSON `json:"api_key"`
	Secret string     `json:"secret"`
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

// magicLinkVerifyResponse wraps the verified user under `user`. The
// inner shape mirrors the other auth endpoints' user representation.
type magicLinkVerifyResponse struct {
	User userJSON `json:"user"`
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

// adminImpersonateResponse wraps the impersonated user under `user`
// alongside the impersonator's own identity, so audit-aware clients can
// surface "you are X impersonating Y" UI without a separate fetch.
type adminImpersonateResponse struct {
	User         adminUserJSON `json:"user"`
	Impersonator *userJSON     `json:"impersonator,omitempty"`
}
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

// mfaSetupResponse includes a pre-rendered qr_code (data URL) alongside
// the otpauth_url. Many clients (especially CLI / mobile) prefer the
// pre-rendered QR over importing a render library; the otpauth_url is
// kept for clients that want to render their own.
type mfaSetupResponse struct {
	Secret      string   `json:"secret"`
	OTPAuthURL  string   `json:"otpauth_url"`
	QRCode      string   `json:"qr_code"`
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

// mfaVerifyResponse wraps the verified user under `user` for forward
// compatibility (future MFA metadata can be added at the top level).
type mfaVerifyResponse struct {
	User userJSON `json:"user"`
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

// passkeyLoginFinishResponse wraps the authenticated user under `user`.
type passkeyLoginFinishResponse struct {
	User userJSON `json:"user"`
}
type passkeyJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	AAGUID     *string    `json:"aaguid,omitempty"`
	DeviceName *string    `json:"device_name,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// passkeyListResponse wraps GET /passkeys with pagination metadata.
type passkeyListResponse struct {
	Items   []passkeyJSON `json:"items"`
	Total   int64         `json:"total"`
	Page    int           `json:"page"`
	PerPage int           `json:"per_page"`
}

// --- oauth ------------------------------------------------------------

// oauthCallbackResponse wraps the authenticated user under `user`.
type oauthCallbackResponse struct {
	User userJSON `json:"user"`
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

// oauthListAccountsResponse wraps GET /oauth/accounts with pagination
// metadata.
type oauthListAccountsResponse struct {
	Items   []oauthAccountJSON `json:"items"`
	Total   int64              `json:"total"`
	Page    int                `json:"page"`
	PerPage int                `json:"per_page"`
}

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

// webhookListResponse wraps GET /webhooks with pagination metadata.
type webhookListResponse struct {
	Items   []webhookJSON `json:"items"`
	Total   int64         `json:"total"`
	Page    int           `json:"page"`
	PerPage int           `json:"per_page"`
}

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

// webhookListDeliveriesResponse wraps GET /webhooks/{id}/deliveries
// with pagination metadata.
type webhookListDeliveriesResponse struct {
	Items   []webhookDeliveryJSON `json:"items"`
	Total   int64                 `json:"total"`
	Page    int                   `json:"page"`
	PerPage int                   `json:"per_page"`
}

// webhookShowResponse used to embed recent_deliveries inline; we now
// expose only the webhook itself and direct clients to the dedicated
// /webhooks/{id}/deliveries endpoint for delivery history.
type webhookShowResponse struct {
	Webhook webhookJSON `json:"webhook"`
}

// webhookTestResponse acknowledges a queued test delivery and returns
// the delivery ID so callers can poll /deliveries.
type webhookTestResponse struct {
	DeliveryQueued string `json:"delivery_queued"`
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

// --- organizations + RBAC (yauth #87 / #88 ports) ---

type organizationJSON struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	DisplayName *string `json:"display_name,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

type membershipJSON struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	UserID         string  `json:"user_id"`
	Role           string  `json:"role"`
	Status         string  `json:"status"`
	JoinedAt       *string `json:"joined_at,omitempty"`
	CreatedAt      string  `json:"created_at"`
}

type invitationJSON struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	ExpiresAt      string `json:"expires_at"`
	CreatedAt      string `json:"created_at"`
}

type createOrgRequest struct {
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	DisplayName *string `json:"display_name,omitempty"`
}

type updateOrgRequest struct {
	Name        *string `json:"name,omitempty"`
	Slug        *string `json:"slug,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
}

type createInvitationRequest struct {
	Email string  `json:"email"`
	Role  *string `json:"role,omitempty"`
}

type createInvitationResponse struct {
	Invitation invitationJSON `json:"invitation"`
	Token      string         `json:"token"`
}

type acceptInvitationRequest struct {
	Token string `json:"token"`
}

// changeRoleRequest is the body of POST
// /organizations/{id}/members/{user_id}/role.
type changeRoleRequest struct {
	Role string `json:"role"`
}

// transferOwnershipRequest is the body of POST
// /organizations/{id}/transfer-ownership.
type transferOwnershipRequest struct {
	NewOwnerUserID string `json:"new_owner_user_id"`
}

// listPermissionsResponseJSON is the canonical wire shape for the
// GET /organizations/{id}/permissions response. Distinct from the
// plugins/organizations/rbac_handlers.go internal struct so the openapi
// package owns its own (necessarily uppercased) field names.
type listPermissionsResponseJSON struct {
	OrganizationID string   `json:"organization_id"`
	Role           string   `json:"role"`
	Permissions    []string `json:"permissions"`
}

// --- per-org auth policy (yauth #92 port) ---------------------------------

// policyResponse is the wire shape returned by GET /organizations/{id}/policy
// and PATCH /organizations/{id}/policy.
type policyResponse struct {
	OrganizationID         string   `json:"organization_id"`
	MFARequired            bool     `json:"mfa_required"`
	MFAGracePeriodDays     int32    `json:"mfa_grace_period_days"`
	IPAllowlist            []string `json:"ip_allowlist"`
	AllowedAuthMethods     []string `json:"allowed_auth_methods"`
	SessionBinding         string   `json:"session_binding"`
	MaxSessionDurationSecs *int64   `json:"max_session_duration_secs,omitempty"`
	IdleTimeoutSecs        *int64   `json:"idle_timeout_secs,omitempty"`
	MaxConcurrentSessions  *int32   `json:"max_concurrent_sessions,omitempty"`
	CreatedAt              string   `json:"created_at"`
	UpdatedAt              string   `json:"updated_at"`
}

// updatePolicyRequest is the body of PATCH /organizations/{id}/policy.
// Every field is optional; omitted fields are left unchanged.
type updatePolicyRequest struct {
	MFARequired            *bool     `json:"mfa_required,omitempty"`
	MFAGracePeriodDays     *int32    `json:"mfa_grace_period_days,omitempty"`
	IPAllowlist            *[]string `json:"ip_allowlist,omitempty"`
	AllowedAuthMethods     *[]string `json:"allowed_auth_methods,omitempty"`
	SessionBinding         *string   `json:"session_binding,omitempty"`
	MaxSessionDurationSecs *int64    `json:"max_session_duration_secs,omitempty"`
	IdleTimeoutSecs        *int64    `json:"idle_timeout_secs,omitempty"`
	MaxConcurrentSessions  *int32    `json:"max_concurrent_sessions,omitempty"`
}

// --- verified domains + JIT membership (yauth #90 port) -------------------

// domainResponse is the wire shape returned by GET /organizations/{id}/domains
// and PATCH /organizations/{id}/domains/{did}.
type domainResponse struct {
	ID                    string  `json:"id"`
	OrganizationID        string  `json:"organization_id"`
	Domain                string  `json:"domain"`
	Status                string  `json:"status"`
	AutoJoinOnSignup      bool    `json:"auto_join_on_signup"`
	DefaultRoleOnAutoJoin string  `json:"default_role_on_auto_join"`
	RequireEmailVerified  bool    `json:"require_email_verified"`
	VerifiedAt            *string `json:"verified_at,omitempty"`
	LastCheckedAt         *string `json:"last_checked_at,omitempty"`
	CreatedAt             string  `json:"created_at"`
	UpdatedAt             string  `json:"updated_at"`
}

// createDomainRequest is the body of POST /organizations/{id}/domains.
type createDomainRequest struct {
	Domain                string  `json:"domain"`
	AutoJoinOnSignup      *bool   `json:"auto_join_on_signup,omitempty"`
	DefaultRoleOnAutoJoin *string `json:"default_role_on_auto_join,omitempty"`
	RequireEmailVerified  *bool   `json:"require_email_verified,omitempty"`
}

// createDomainResponse is the body of POST /organizations/{id}/domains —
// wraps the claim plus the one-time verification token clients must
// publish as a `_yauth-domain-verify.<domain>` TXT record.
type createDomainResponse struct {
	Domain             domainResponse `json:"domain"`
	VerificationToken  string         `json:"verification_token"`
	DNSRecordName      string         `json:"dns_record_name"`
}

// updateDomainRequest is the body of PATCH /organizations/{id}/domains/{did}.
type updateDomainRequest struct {
	AutoJoinOnSignup      *bool   `json:"auto_join_on_signup,omitempty"`
	DefaultRoleOnAutoJoin *string `json:"default_role_on_auto_join,omitempty"`
	RequireEmailVerified  *bool   `json:"require_email_verified,omitempty"`
}

// verifyDomainResponse is the body of POST
// /organizations/{id}/domains/{did}/verify.
type verifyDomainResponse struct {
	Domain   domainResponse `json:"domain"`
	Verified bool           `json:"verified"`
}

// --- active-org switcher (yauth #89 port) ----------------------------------

// setActiveOrgRequest is the body of POST /sessions/active-org.
type setActiveOrgRequest struct {
	OrganizationID string `json:"organization_id"`
}

// activeOrgEntry is one entry in the caller's membership list returned
// from the active-org endpoints. The role for the currently-active org
// is read from the entry whose `organization_id` matches the response's
// top-level `active_org_id` — there is no top-level `role` field.
type activeOrgEntry struct {
	OrganizationID string  `json:"organization_id"`
	Role           string  `json:"role"`
	DisplayName    *string `json:"display_name,omitempty"`
	Slug           *string `json:"slug,omitempty"`
}

// activeOrgResponse is the response shape for all three /sessions/active-org
// endpoints (GET/POST/DELETE). `active_org_id` is null when cleared or
// the user has no memberships. `bearer_access_token` is populated ONLY
// for bearer-auth callers on switch: cookie sessions update server-side
// and need no token rotation, while JWT bearer requires a freshly-issued
// token carrying the new `org`/`role`/`orgs` claims.
type activeOrgResponse struct {
	ActiveOrgID       *string          `json:"active_org_id,omitempty"`
	BearerAccessToken *string          `json:"bearer_access_token,omitempty"`
	Orgs              []activeOrgEntry `json:"orgs"`
}
