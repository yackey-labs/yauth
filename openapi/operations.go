package openapi

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// addEmailPassword wires the five email-password endpoints. Routes are
// declared at their unprefixed canonical paths; downstream tooling and
// the typescript client treat the embedder's mount prefix as a baseUrl.
func addEmailPassword(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/register",
		Tags: []string{"email-password"}, OperationID: "emailPasswordRegister",
		Summary:     "Register a new user",
		Description: "Creates a user, hashes the password with Argon2id, issues a session cookie.",
		Security:    secNone(),
		RequestBody: jsonRequestBody(emailPasswordRegisterRequest{}, "Email + password"),
		Responses: map[string]*huma.Response{
			"201": jsonResponse("User created.", emailPasswordRegisterResponse{}),
			"400": errorResponse("Invalid email or weak password."),
			"409": errorResponse("Email already registered."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/login",
		Tags: []string{"email-password"}, OperationID: "emailPasswordLogin",
		Summary:     "Verify password and start a session",
		Description: "On success returns the user; if MFA is enabled returns require_mfa + pending_session_id.",
		Security:    secNone(),
		RequestBody: jsonRequestBody(emailPasswordLoginRequest{}, "Credentials"),
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Authenticated. Session cookie set unless MFA is required.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: &huma.Schema{
						OneOf: []*huma.Schema{schemaRef(emailPasswordLoginResponse{}), schemaRef(emailPasswordLoginMfaResponse{})},
					}},
				},
			},
			"401": errorResponse("Invalid credentials."),
			"403": errorResponse("User banned or email-not-verified."),
			"429": errorResponse("Account locked (lockout plugin)."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/logout",
		Tags: []string{"email-password"}, OperationID: "emailPasswordLogout",
		Summary:  "Revoke the current session",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Session deleted, cookie cleared."),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/session",
		Tags: []string{"email-password"}, OperationID: "emailPasswordSession",
		Summary:  "Return the current authenticated user",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Active session.", emailPasswordSessionResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/change-password",
		Tags: []string{"email-password"}, OperationID: "emailPasswordChangePassword",
		Summary:     "Rotate the caller's password",
		Description: "Verifies the old password, stores the new hash, revokes other sessions, re-issues a fresh cookie for the caller.",
		Security:    secCookie(),
		RequestBody: jsonRequestBody(emailPasswordChangePasswordRequest{}, "Old + new password"),
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Password changed."),
			"400": errorResponse("New password too weak."),
			"401": errorResponse("Old password incorrect."),
		},
	})
}

func addBearer(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/token",
		Tags: []string{"bearer"}, OperationID: "bearerIssueToken",
		Summary:     "Exchange email+password for an access+refresh token pair",
		Security:    secNone(),
		RequestBody: jsonRequestBody(bearerTokenRequest{}, "Credentials"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Token pair.", bearerTokenResponse{}),
			"401": errorResponse("Invalid credentials."),
			"403": errorResponse("User banned."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/token/refresh",
		Tags: []string{"bearer"}, OperationID: "bearerRefresh",
		Summary:     "Rotate the refresh token; re-mint access+refresh",
		Description: "Reuse of a previously rotated refresh token revokes the entire family.",
		Security:    secNone(),
		RequestBody: jsonRequestBody(bearerRefreshRequest{}, "Refresh token"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Fresh token pair.", bearerTokenResponse{}),
			"401": errorResponse("Invalid grant or reuse detected."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/token/revoke",
		Tags: []string{"bearer"}, OperationID: "bearerRevoke",
		Summary:     "Revoke a refresh-token family",
		Security:    secAny(),
		RequestBody: jsonRequestBody(bearerRevokeRequest{}, "Refresh token to revoke"),
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Family revoked or already absent (idempotent)."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Refresh token belongs to a different user."),
		},
	})
}

func addAPIKey(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/api-keys",
		Tags: []string{"api-key"}, OperationID: "apiKeyList",
		Summary:  "List the caller's API keys (no secrets)",
		Security: secAny(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("List of keys.", apiKeyListResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/api-keys",
		Tags: []string{"api-key"}, OperationID: "apiKeyCreate",
		Summary:     "Create a new API key (plaintext returned once)",
		Security:    secAny(),
		RequestBody: jsonRequestBody(apiKeyCreateRequest{}, "Name, optional scopes, optional expiry"),
		Responses: map[string]*huma.Response{
			"201": jsonResponse("Key created. The `key` field is the plaintext, shown once.", apiKeyCreateResponse{}),
			"400": errorResponse("Missing name or invalid expiry."),
			"401": errorResponse("Not authenticated."),
			"409": errorResponse("Per-user key cap reached."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/api-keys/{id}",
		Tags: []string{"api-key"}, OperationID: "apiKeyDelete",
		Summary:    "Revoke an API key the caller owns",
		Security:   secAny(),
		Parameters: []*huma.Param{pathParam("id", "API key id")},
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Key deleted."),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("Key not found or not owned by caller."),
		},
	})
}

func addMagicLink(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/magic-link/send",
		Tags: []string{"magic-link"}, OperationID: "magicLinkSend",
		Summary:     "Email a single-use sign-in link",
		Description: "Always responds 200 to prevent user enumeration; the link is delivered via the configured Mailer.",
		Security:    secNone(),
		RequestBody: jsonRequestBody(magicLinkSendRequest{}, "Email address"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Acknowledged.", magicLinkSendResponse{}),
			"400": errorResponse("Invalid email."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/magic-link/verify",
		Tags: []string{"magic-link"}, OperationID: "magicLinkVerify",
		Summary:     "Exchange a magic-link token for a session",
		Security:    secNone(),
		RequestBody: jsonRequestBody(magicLinkVerifyRequest{}, "Magic-link token"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Session issued; cookie set.", magicLinkVerifyResponse{}),
			"401": errorResponse("Token invalid, expired, or already consumed."),
			"403": errorResponse("User banned."),
		},
	})
}

func addLockout(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/unlock",
		Tags: []string{"lockout"}, OperationID: "lockoutUnlock",
		Summary:     "Consume an unlock token to clear an account lock",
		Security:    secNone(),
		RequestBody: jsonRequestBody(lockoutUnlockRequest{}, "Unlock token"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Account unlocked.", lockoutUnlockResponse{}),
			"401": errorResponse("Invalid token."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/unlock/request",
		Tags: []string{"lockout"}, OperationID: "lockoutUnlockRequest",
		Summary:     "Email a single-use unlock token",
		Description: "Always responds 200 to prevent user enumeration.",
		Security:    secNone(),
		RequestBody: jsonRequestBody(lockoutUnlockReqRequest{}, "Email address"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Acknowledged.", lockoutUnlockReqResponse{}),
			"400": errorResponse("Invalid email."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/lockout/state",
		Tags: []string{"lockout"}, OperationID: "lockoutState",
		Summary:  "List currently locked accounts (admin)",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Locked accounts.", lockoutStateResponse{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not admin."),
		},
	})
}

func addStatus(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/status",
		Tags: []string{"status"}, OperationID: "status",
		Summary:  "Return the names of registered plugins (admin)",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Plugin names + version.", statusResponse{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not admin."),
		},
	})
}

func addAdmin(api *huma.OpenAPI) {
	listParams := []*huma.Param{
		queryIntParam("limit", "Page size (default 50, capped at 100)."),
		queryIntParam("offset", "Pagination offset."),
		queryStringParam("search", "Substring match on email or display_name."),
	}
	auditParams := []*huma.Param{
		queryIntParam("limit", "Page size."),
		queryIntParam("offset", "Pagination offset."),
		queryStringParam("user_id", "Filter to a single user."),
		queryStringParam("type", "Filter to a single event_type."),
	}
	idParam := pathParam("id", "User id")

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/admin/users",
		Tags: []string{"admin"}, OperationID: "adminListUsers",
		Summary:    "List users with optional search/pagination",
		Security:   secCookie(),
		Parameters: listParams,
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Users + total count.", adminListUsersResponse{}),
			"403": errorResponse("Caller is not admin."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/admin/users/{id}",
		Tags: []string{"admin"}, OperationID: "adminGetUser",
		Summary:    "Fetch a single user",
		Security:   secCookie(),
		Parameters: []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("User.", adminUserJSON{}),
			"403": errorResponse("Caller is not admin."),
			"404": errorResponse("User not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPatch, Path: "/admin/users/{id}",
		Tags: []string{"admin"}, OperationID: "adminPatchUser",
		Summary:     "Update display_name and/or role",
		Security:    secCookie(),
		Parameters:  []*huma.Param{idParam},
		RequestBody: jsonRequestBody(adminPatchUserRequest{}, "Fields to update"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Updated user.", adminUserJSON{}),
			"403": errorResponse("Caller is not admin."),
			"404": errorResponse("User not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/admin/users/{id}/ban",
		Tags: []string{"admin"}, OperationID: "adminBanUser",
		Summary:     "Ban a user; revokes their sessions",
		Security:    secCookie(),
		Parameters:  []*huma.Param{idParam},
		RequestBody: jsonRequestBody(adminBanRequest{}, "Reason + optional until"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Banned user.", adminUserJSON{}),
			"400": errorResponse("Reason missing."),
			"403": errorResponse("Caller is not admin."),
			"404": errorResponse("User not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/admin/users/{id}/unban",
		Tags: []string{"admin"}, OperationID: "adminUnbanUser",
		Summary:    "Lift a previous ban",
		Security:   secCookie(),
		Parameters: []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Unbanned user.", adminUserJSON{}),
			"403": errorResponse("Caller is not admin."),
			"404": errorResponse("User not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/admin/users/{id}/impersonate",
		Tags: []string{"admin"}, OperationID: "adminImpersonate",
		Summary:    "Issue a session cookie for the target user",
		Security:   secCookie(),
		Parameters: []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Session issued for the target user.", adminImpersonateResponse{}),
			"403": errorResponse("Caller is not admin."),
			"404": errorResponse("User not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/admin/users/{id}/sessions",
		Tags: []string{"admin"}, OperationID: "adminDeleteUserSessions",
		Summary:    "Revoke every session for a user",
		Security:   secCookie(),
		Parameters: []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Number of revoked sessions.", adminDeleteSessionsResponse{}),
			"403": errorResponse("Caller is not admin."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/admin/audit",
		Tags: []string{"admin"}, OperationID: "adminListAudit",
		Summary:    "List audit-log entries with optional filters",
		Security:   secCookie(),
		Parameters: auditParams,
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Audit log page.", adminListAuditResponse{}),
			"403": errorResponse("Caller is not admin."),
		},
	})
}

func addMFA(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/totp/setup",
		Tags: []string{"mfa"}, OperationID: "mfaTOTPSetup",
		Summary:     "Provision a new TOTP secret + backup codes (unverified)",
		Description: "Wipes any prior secret/backup codes for this user, then issues a fresh QR + backup-code set.",
		Security:    secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("TOTP material; verify with /totp/confirm.", mfaSetupResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/totp/confirm",
		Tags: []string{"mfa"}, OperationID: "mfaTOTPConfirm",
		Summary:     "Verify the freshly-provisioned TOTP and activate it",
		Security:    secCookie(),
		RequestBody: jsonRequestBody(mfaConfirmRequest{}, "Six-digit TOTP code"),
		Responses: map[string]*huma.Response{
			"204": emptyResponse("TOTP activated."),
			"400": errorResponse("No pending setup."),
			"401": errorResponse("Invalid code."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/totp",
		Tags: []string{"mfa"}, OperationID: "mfaTOTPDelete",
		Summary:  "Remove the user's TOTP secret + backup codes",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Removed."),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/backup-codes",
		Tags: []string{"mfa"}, OperationID: "mfaBackupCodesCount",
		Summary:  "Return the count of unused backup codes",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Unused backup-code count.", mfaBackupCodesCountResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/backup-codes/regenerate",
		Tags: []string{"mfa"}, OperationID: "mfaRegenerateBackupCodes",
		Summary:  "Replace the user's backup codes; returns the new set once",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Fresh backup codes (shown once).", mfaRegenerateResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/verify",
		Tags: []string{"mfa"}, OperationID: "mfaVerify",
		Summary:     "Consume a pending session (TOTP or backup code)",
		Security:    secNone(),
		RequestBody: jsonRequestBody(mfaVerifyRequest{}, "pending_session_id + code"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("MFA verified; session cookie set.", mfaVerifyResponse{}),
			"401": errorResponse("Invalid code or pending session."),
		},
	})
}

func addPasskey(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/passkeys/register/begin",
		Tags: []string{"passkey"}, OperationID: "passkeyRegisterBegin",
		Summary:  "Start passkey registration; return CredentialCreation options",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Options.", passkeyRegisterBeginResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/passkeys/register/finish",
		Tags: []string{"passkey"}, OperationID: "passkeyRegisterFinish",
		Summary:     "Verify attestation and store the new credential",
		Security:    secCookie(),
		RequestBody: jsonRequestBody(passkeyRegisterFinishRequest{}, "Authenticator response"),
		Responses: map[string]*huma.Response{
			"201": jsonResponse("Stored credential.", passkeyRegisterFinishResponse{}),
			"400": errorResponse("Invalid attestation or expired challenge."),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/passkey/login/begin",
		Tags: []string{"passkey"}, OperationID: "passkeyLoginBegin",
		Summary:     "Start a passkey assertion; supports discoverable flow",
		Security:    secNone(),
		RequestBody: jsonRequestBody(passkeyLoginBeginRequest{}, "Optional email hint"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Options.", passkeyLoginBeginResponse{}),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/passkey/login/finish",
		Tags: []string{"passkey"}, OperationID: "passkeyLoginFinish",
		Summary:     "Verify the assertion and start a session",
		Security:    secNone(),
		RequestBody: jsonRequestBody(passkeyLoginFinishRequest{}, "Authenticator response"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Session issued.", passkeyLoginFinishResponse{}),
			"400": errorResponse("Invalid challenge or response."),
			"401": errorResponse("Verification failed."),
			"403": errorResponse("User banned."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/passkeys",
		Tags: []string{"passkey"}, OperationID: "passkeyList",
		Summary:  "List the caller's stored passkeys",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Passkeys.", passkeyListResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/passkeys/{id}",
		Tags: []string{"passkey"}, OperationID: "passkeyDelete",
		Summary:    "Delete one of the caller's passkeys",
		Security:   secCookie(),
		Parameters: []*huma.Param{pathParam("id", "Passkey id")},
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Deleted."),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("Passkey not found."),
		},
	})
}

func addOAuth(api *huma.OpenAPI) {
	providerParam := pathParam("provider", "Registered provider name (e.g. google, github).")
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/oauth/{provider}/authorize",
		Tags: []string{"oauth"}, OperationID: "oauthAuthorize",
		Summary:     "Begin authorization-code flow; redirects to provider",
		Description: "Persists state and redirects (302) the user-agent to the provider's authorization endpoint.",
		Security:    secNone(),
		Parameters:  []*huma.Param{providerParam, queryStringParam("redirect_url", "Optional URL to navigate to after callback.")},
		Responses: map[string]*huma.Response{
			"302": emptyResponse("Redirect to provider."),
			"404": errorResponse("Unknown provider."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/oauth/{provider}/callback",
		Tags: []string{"oauth"}, OperationID: "oauthCallback",
		Summary:    "Exchange the auth code; create or attach the user; issue a session",
		Security:   secNone(),
		Parameters: []*huma.Param{providerParam, queryStringParam("code", "Authorization code."), queryStringParam("state", "State stored at /authorize.")},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Linked or new user; session cookie set.", oauthCallbackResponse{}),
			"302": emptyResponse("Redirect (when redirect_url was supplied at /authorize)."),
			"400": errorResponse("Invalid request, state, or provider error."),
			"403": errorResponse("User banned or user mismatch on link flow."),
			"502": errorResponse("Provider exchange or userinfo failed."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/oauth/accounts",
		Tags: []string{"oauth"}, OperationID: "oauthListAccounts",
		Summary:  "List the caller's linked OAuth accounts",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Linked accounts.", oauthListAccountsResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/oauth/{provider}",
		Tags: []string{"oauth"}, OperationID: "oauthUnlink",
		Summary:    "Unlink a provider; refuses if it would lock out the caller",
		Security:   secCookie(),
		Parameters: []*huma.Param{providerParam},
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Unlinked."),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("No link for that provider."),
			"409": errorResponse("Removing this would leave the caller with no auth method."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/oauth/{provider}/link",
		Tags: []string{"oauth"}, OperationID: "oauthLink",
		Summary:    "Start a link flow for an already-authenticated user",
		Security:   secCookie(),
		Parameters: []*huma.Param{providerParam, queryStringParam("redirect_url", "Optional URL to navigate to after callback.")},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("URL the caller redirects the user-agent to.", oauthLinkResponse{}),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("Unknown provider."),
			"409": errorResponse("Provider already linked."),
		},
	})
}

func addWebhooks(api *huma.OpenAPI) {
	idParam := pathParam("id", "Webhook id")
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/webhooks",
		Tags: []string{"webhooks"}, OperationID: "webhookList",
		Summary:  "List webhooks (admin)",
		Security: secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Webhooks.", webhookListResponse{}),
			"403": errorResponse("Caller is not admin."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/webhooks",
		Tags: []string{"webhooks"}, OperationID: "webhookCreate",
		Summary:     "Create a webhook; secret is returned exactly once",
		Security:    secCookie(),
		RequestBody: jsonRequestBody(webhookCreateRequest{}, "URL + event filter + active flag"),
		Responses: map[string]*huma.Response{
			"201": jsonResponse("Webhook + plaintext secret.", webhookJSON{}),
			"400": errorResponse("Invalid payload."),
			"403": errorResponse("Caller is not admin."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/webhooks/{id}",
		Tags: []string{"webhooks"}, OperationID: "webhookGet",
		Summary:    "Fetch a single webhook (no secret)",
		Security:   secCookie(),
		Parameters: []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Webhook.", webhookJSON{}),
			"403": errorResponse("Caller is not admin."),
			"404": errorResponse("Not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPatch, Path: "/webhooks/{id}",
		Tags: []string{"webhooks"}, OperationID: "webhookUpdate",
		Summary:     "Update url/events/active and optionally rotate the secret",
		Security:    secCookie(),
		Parameters:  []*huma.Param{idParam},
		RequestBody: jsonRequestBody(webhookUpdateRequest{}, "Partial update"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Updated webhook (rotated secret returned only when rotate_secret=true).", webhookJSON{}),
			"403": errorResponse("Caller is not admin."),
			"404": errorResponse("Not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/webhooks/{id}",
		Tags: []string{"webhooks"}, OperationID: "webhookDelete",
		Summary:    "Delete a webhook",
		Security:   secCookie(),
		Parameters: []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Deleted."),
			"403": errorResponse("Caller is not admin."),
			"404": errorResponse("Not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/webhooks/{id}/deliveries",
		Tags: []string{"webhooks"}, OperationID: "webhookListDeliveries",
		Summary:    "List recent delivery attempts for a webhook",
		Security:   secCookie(),
		Parameters: []*huma.Param{idParam, queryIntParam("limit", "Max rows (default 100, capped at 1000).")},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Delivery rows.", webhookListDeliveriesResponse{}),
			"403": errorResponse("Caller is not admin."),
			"404": errorResponse("Not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/webhooks/{id}/test",
		Tags: []string{"webhooks"}, OperationID: "webhookTest",
		Summary:    "Enqueue a synthetic webhook.test delivery",
		Security:   secCookie(),
		Parameters: []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"202": jsonResponse("Delivery queued.", webhookTestResponse{}),
			"403": errorResponse("Caller is not admin."),
			"404": errorResponse("Not found."),
			"503": errorResponse("Dispatcher shutting down."),
		},
	})
}

func addAsymJWT(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/.well-known/jwks.json",
		Tags: []string{"asymmetric-jwt"}, OperationID: "asymJWKS",
		Summary:     "Public JWKS document for the loaded asymmetric signer",
		Description: "Returned even when no caller is authenticated; suited to relying parties verifying tokens out of band.",
		Security:    secNone(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("JWKS.", jwksDocument{}),
			"500": errorResponse("Signer unavailable."),
		},
	})
}

func addOIDC(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/.well-known/openid-configuration",
		Tags: []string{"oidc"}, OperationID: "oidcDiscovery",
		Summary:  "OpenID Provider discovery document",
		Security: secNone(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Discovery.", oidcDiscoveryDoc{}),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/userinfo",
		Tags: []string{"oidc"}, OperationID: "oidcUserInfo",
		Summary:  "Standard OIDC UserInfo for the authenticated caller",
		Security: secAny(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("UserInfo.", oidcUserInfoResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
}

func addOAuth2Server(api *huma.OpenAPI) {
	idParam := pathParam("id", "client_id")

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/oauth2/clients",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2ListBannedClients",
		Summary:     "List banned OAuth2 clients (admin)",
		Description: "The repository surface only exposes a banned-clients list; non-banned clients are fetched individually by client_id.",
		Security:    secCookie(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Banned clients.", oauth2BannedClientsResponse{}),
			"403": errorResponse("Caller is not admin."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/oauth2/clients",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2CreateClient",
		Summary:     "Register a new OAuth2 client (admin)",
		Description: "For confidential clients (is_public=false) a fresh client_secret is generated and returned exactly once.",
		Security:    secCookie(),
		RequestBody: jsonRequestBody(oauth2CreateClientRequest{}, "Client registration"),
		Responses: map[string]*huma.Response{
			"201": jsonResponse("Client + one-time secret.", oauth2CreateClientResponse{}),
			"400": errorResponse("Invalid payload."),
			"403": errorResponse("Caller is not admin."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/oauth2/clients/{id}",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2GetClient",
		Summary:    "Fetch a registered OAuth2 client",
		Security:   secCookie(),
		Parameters: []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Client.", oauth2ClientJSON{}),
			"400": errorResponse("Client not found."),
			"403": errorResponse("Caller is not admin."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPatch, Path: "/oauth2/clients/{id}",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2PatchClient",
		Summary:     "Ban / unban or rotate the public key of a client (admin)",
		Security:    secCookie(),
		Parameters:  []*huma.Param{idParam},
		RequestBody: jsonRequestBody(oauth2PatchClientRequest{}, "Partial update"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Updated client.", oauth2ClientJSON{}),
			"403": errorResponse("Caller is not admin."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/oauth2/clients/{id}",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2DeleteClient",
		Summary:     "Soft-delete (ban) a client",
		Description: "Hard delete is not exposed because issued tokens still reference the client.",
		Security:    secCookie(),
		Parameters:  []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Banned."),
			"400": errorResponse("Client not found."),
			"403": errorResponse("Caller is not admin."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/oauth2/authorize",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2Authorize",
		Summary:  "Authorization endpoint — returns either a redirect URL or a consent payload",
		Security: secCookie(),
		Parameters: []*huma.Param{
			queryStringParam("response_type", "Must be \"code\"."),
			queryStringParam("client_id", "Registered client_id."),
			queryStringParam("redirect_uri", "One of the client's registered redirect URIs."),
			queryStringParam("code_challenge", "PKCE challenge."),
			queryStringParam("code_challenge_method", "PKCE method (S256 only)."),
			queryStringParam("state", "Caller-supplied state echoed in the redirect."),
			queryStringParam("nonce", "OIDC nonce; included in id_token."),
			queryStringParam("scope", "Space-separated requested scopes."),
		},
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Either {redirect_url} (consent already granted) or a consent payload that the UI must POST back via /oauth2/consent.",
				Content: map[string]*huma.MediaType{"application/json": {Schema: &huma.Schema{
					OneOf: []*huma.Schema{schemaRef(oauth2AuthorizeRedirect{}), schemaRef(oauth2ConsentPayload{})},
				}}},
			},
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/oauth2/consent",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2Consent",
		Summary:     "Approve or deny a pending /authorize",
		Security:    secCookie(),
		RequestBody: jsonRequestBody(oauth2ConsentRequest{}, "Consent decision"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Redirect URL with code or error.", oauth2AuthorizeRedirect{}),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/oauth2/token",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2Token",
		Summary:     "Token endpoint (RFC 6749 §3.2)",
		Description: "Accepts authorization_code, refresh_token, client_credentials, and urn:ietf:params:oauth:grant-type:device_code grants. Body is application/x-www-form-urlencoded or application/json.",
		Security:    secNone(),
		RequestBody: &huma.RequestBody{
			Description: "Form or JSON body with grant_type and grant-specific fields.",
			Required:    true,
			Content: map[string]*huma.MediaType{
				"application/x-www-form-urlencoded": {Schema: &huma.Schema{Type: "object"}},
				"application/json":                  {Schema: &huma.Schema{Type: "object"}},
			},
		},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Token bundle.", oauth2TokenResponse{}),
			"400": errorResponse("invalid_request / unsupported_grant_type / etc."),
			"401": errorResponse("invalid_client."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/oauth2/revoke",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2Revoke",
		Summary:     "RFC 7009 revocation",
		Description: "Idempotent: unknown / already-revoked / malformed tokens still return 200.",
		Security:    secNone(),
		RequestBody: &huma.RequestBody{
			Required: true,
			Content:  map[string]*huma.MediaType{"application/x-www-form-urlencoded": {Schema: &huma.Schema{Type: "object"}}},
		},
		Responses: map[string]*huma.Response{
			"200": emptyResponse("Always — RFC 7009 idempotency."),
			"401": errorResponse("invalid_client."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/oauth2/introspect",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2Introspect",
		Summary:     "RFC 7662 token introspection",
		Description: "Caller authenticates as a confidential client.",
		Security:    secNone(),
		RequestBody: &huma.RequestBody{
			Required: true,
			Content:  map[string]*huma.MediaType{"application/x-www-form-urlencoded": {Schema: &huma.Schema{Type: "object"}}},
		},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Introspection result.", oauth2IntrospectResponse{}),
			"401": errorResponse("invalid_client."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/oauth2/device_authorization",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2DeviceAuthorization",
		Summary:  "RFC 8628 device-authorization endpoint",
		Security: secNone(),
		RequestBody: &huma.RequestBody{
			Required: true,
			Content:  map[string]*huma.MediaType{"application/x-www-form-urlencoded": {Schema: &huma.Schema{Type: "object"}}},
		},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("device_code + user_code pair.", oauth2DeviceAuthResponse{}),
			"400": errorResponse("invalid_request."),
			"401": errorResponse("invalid_client."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/oauth2/device",
		Tags: []string{"oauth2-server"}, OperationID: "oauth2DeviceVerify",
		Summary:     "User-facing endpoint to enter a user_code (RFC 8628)",
		Security:    secCookie(),
		RequestBody: jsonRequestBody(oauth2DeviceVerifyRequest{}, "user_code"),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Approved.", oauth2DeviceVerifyResponse{}),
			"400": errorResponse("invalid_request."),
			"401": errorResponse("Not authenticated."),
		},
	})
}
