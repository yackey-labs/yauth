//! Route metadata for TypeScript client generation.
//!
//! Each plugin defines its own route metadata function, and `all_route_meta()`
//! aggregates them respecting feature gates. This module is used by
//! `axum-ts-client` to generate typed TypeScript API clients.

use axum_ts_client::{RouteCollection, api_routes};

/// Core routes (always available): session, logout, profile update.
pub fn core_routes() -> RouteCollection {
    api_routes! {
        getSession: GET "/session" [auth]
            -> AuthUser;
        logout: POST "/logout" [auth];
        updateProfile: PATCH "/me" [auth]
            body: UpdateProfileRequest -> AuthUser;
    }
}

/// Email/password plugin routes.
#[cfg(feature = "email-password")]
pub fn email_password_routes() -> RouteCollection {
    api_routes! {
        @group emailPassword

        register: POST "/register"
            body: RegisterRequest -> MessageResponse;
        login: POST "/login"
            body: LoginRequest;
        verifyEmail: POST "/verify-email"
            body: VerifyEmailRequest -> MessageResponse;
        resendVerification: POST "/resend-verification"
            body: ResendVerificationRequest -> MessageResponse;
        forgotPassword: POST "/forgot-password"
            body: ForgotPasswordRequest -> MessageResponse;
        resetPassword: POST "/reset-password"
            body: ResetPasswordRequest -> MessageResponse;
        changePassword: POST "/change-password" [auth]
            body: ChangePasswordRequest -> MessageResponse;
    }
}

/// Passkey (WebAuthn) plugin routes.
#[cfg(feature = "passkey")]
pub fn passkey_routes() -> RouteCollection {
    api_routes! {
        @group passkey

        loginBegin: POST "/passkey/login/begin"
            body: PasskeyLoginBeginRequest;
        loginFinish: POST "/passkey/login/finish"
            body: PasskeyLoginFinishRequest;
        registerBegin: POST "/passkeys/register/begin" [auth];
        registerFinish: POST "/passkeys/register/finish" [auth]
            body: RegisterFinishRequest;
        list: GET "/passkeys" [auth]
            -> PasskeyInfo;
        delete: DELETE "/passkeys/{id}" [auth];
    }
}

/// MFA (TOTP + backup codes) plugin routes.
#[cfg(feature = "mfa")]
pub fn mfa_routes() -> RouteCollection {
    api_routes! {
        @group mfa

        setup: POST "/mfa/totp/setup" [auth]
            -> SetupTotpResponse;
        confirm: POST "/mfa/totp/confirm" [auth]
            body: ConfirmTotpRequest -> MfaMessageResponse;
        disable: DELETE "/mfa/totp" [auth]
            -> MfaMessageResponse;
        verify: POST "/mfa/verify"
            body: VerifyMfaRequest -> MfaAuthResponse;
        getBackupCodeCount: GET "/mfa/backup-codes" [auth]
            -> BackupCodeCountResponse;
        regenerateBackupCodes: POST "/mfa/backup-codes/regenerate" [auth]
            -> BackupCodesResponse;
    }
}

/// OAuth plugin routes.
#[cfg(feature = "oauth")]
pub fn oauth_routes() -> RouteCollection {
    api_routes! {
        @group oauth

        authorize: GET "/oauth/{provider}/authorize" [redirect]
            query: AuthorizeQuery;
        callback: POST "/oauth/{provider}/callback"
            body: CallbackBody -> OAuthAuthResponse;
        accounts: GET "/oauth/accounts" [auth]
            -> OAuthAccountResponse;
        unlink: DELETE "/oauth/{provider}" [auth];
        link: POST "/oauth/{provider}/link" [auth]
            -> AuthorizeResponse;
    }
}

/// Bearer token (JWT) plugin routes.
#[cfg(feature = "bearer")]
pub fn bearer_routes() -> RouteCollection {
    api_routes! {
        @group bearer

        getToken: POST "/token"
            body: TokenRequest -> TokenResponse;
        refresh: POST "/token/refresh"
            body: RefreshRequest -> TokenResponse;
        revoke: POST "/token/revoke" [auth]
            body: RevokeRequest;
    }
}

/// API key plugin routes.
#[cfg(feature = "api-key")]
pub fn api_key_routes() -> RouteCollection {
    api_routes! {
        @group apiKeys

        create: POST "/api-keys" [auth]
            body: CreateApiKeyRequest -> CreateApiKeyResponse;
        list: GET "/api-keys" [auth]
            -> ApiKeyResponse;
        delete: DELETE "/api-keys/{id}" [auth];
    }
}

/// Magic link plugin routes.
#[cfg(feature = "magic-link")]
pub fn magic_link_routes() -> RouteCollection {
    api_routes! {
        @group magicLink

        send: POST "/magic-link/send"
            body: MagicLinkSendRequest -> MagicLinkMessageResponse;
        verify: POST "/magic-link/verify"
            body: MagicLinkVerifyRequest;
    }
}

/// Admin plugin routes.
#[cfg(feature = "admin")]
pub fn admin_routes() -> RouteCollection {
    api_routes! {
        @group admin

        listUsers: GET "/admin/users" [auth]
            query: ListUsersQuery;
        getUser: GET "/admin/users/{id}" [auth]
            -> AuthUser;
        updateUser: PUT "/admin/users/{id}" [auth]
            body: UpdateUserRequest -> AuthUser;
        deleteUser: DELETE "/admin/users/{id}" [auth];
        banUser: POST "/admin/users/{id}/ban" [auth]
            body: BanRequest -> AuthUser;
        unbanUser: POST "/admin/users/{id}/unban" [auth]
            -> AuthUser;
        impersonate: POST "/admin/users/{id}/impersonate" [auth];
        listSessions: GET "/admin/sessions" [auth]
            query: ListSessionsQuery;
        deleteSession: DELETE "/admin/sessions/{id}" [auth];
    }
}

/// OAuth2 Authorization Server plugin routes.
#[cfg(feature = "oauth2-server")]
pub fn oauth2_server_routes() -> RouteCollection {
    api_routes! {
        @group oauth2Server

        metadata: GET "/.well-known/oauth-authorization-server";
        authorize: GET "/authorize";
        authorizeConsent: POST "/authorize";
        token: POST "/token";
        register: POST "/register";
    }
}

/// Aggregate all route metadata, respecting feature gates.
#[allow(unused_mut)]
pub fn all_route_meta() -> RouteCollection {
    let mut routes = core_routes();

    #[cfg(feature = "email-password")]
    routes.extend(email_password_routes());

    #[cfg(feature = "passkey")]
    routes.extend(passkey_routes());

    #[cfg(feature = "mfa")]
    routes.extend(mfa_routes());

    #[cfg(feature = "oauth")]
    routes.extend(oauth_routes());

    #[cfg(feature = "bearer")]
    routes.extend(bearer_routes());

    #[cfg(feature = "api-key")]
    routes.extend(api_key_routes());

    #[cfg(feature = "magic-link")]
    routes.extend(magic_link_routes());

    #[cfg(feature = "admin")]
    routes.extend(admin_routes());

    #[cfg(feature = "oauth2-server")]
    routes.extend(oauth2_server_routes());

    routes
}
