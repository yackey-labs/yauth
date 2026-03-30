//! OpenAPI specification builder for the yauth API.
//!
//! Builds a complete OpenAPI 3.1 spec from type schemas (via `utoipa::ToSchema`)
//! and route metadata. This replaces the previous `axfetchum`-based client
//! generation — the spec is written to `openapi.json` and then consumed by
//! `orval` to produce the TypeScript client.

use utoipa::openapi::path::{
    HttpMethod, OperationBuilder, ParameterBuilder, ParameterIn, PathItemBuilder,
};
use utoipa::openapi::request_body::RequestBodyBuilder;
use utoipa::openapi::response::ResponseBuilder;
use utoipa::openapi::{
    ComponentsBuilder, ContentBuilder, InfoBuilder, OpenApiBuilder, PathsBuilder, RefOr,
};

/// Helper to create a JSON content reference to a schema component.
fn json_ref(schema_name: &str) -> utoipa::openapi::Content {
    ContentBuilder::new()
        .schema(Some(RefOr::Ref(utoipa::openapi::Ref::new(format!(
            "#/components/schemas/{schema_name}"
        )))))
        .build()
}

/// Helper to create an operation with common settings.
fn op(operation_id: &str, tag: &str) -> OperationBuilder {
    OperationBuilder::new()
        .operation_id(Some(operation_id))
        .tag(tag)
}

/// Adds a path parameter (e.g., `{id}`, `{provider}`) to an operation.
fn with_path_param(builder: OperationBuilder, name: &str) -> OperationBuilder {
    builder.parameter(
        ParameterBuilder::new()
            .name(name)
            .parameter_in(ParameterIn::Path)
            .required(utoipa::openapi::Required::True)
            .schema(Some(RefOr::T(
                utoipa::openapi::ObjectBuilder::new()
                    .schema_type(utoipa::openapi::schema::Type::String)
                    .build()
                    .into(),
            )))
            .build(),
    )
}

/// Adds a JSON request body referencing a schema component.
fn with_body(builder: OperationBuilder, schema_name: &str) -> OperationBuilder {
    builder.request_body(Some(
        RequestBodyBuilder::new()
            .content("application/json", json_ref(schema_name))
            .required(Some(utoipa::openapi::Required::True))
            .build(),
    ))
}

/// Adds a 200 response referencing a schema component.
fn with_response(builder: OperationBuilder, schema_name: &str) -> OperationBuilder {
    builder.response(
        "200",
        ResponseBuilder::new()
            .description("Success")
            .content("application/json", json_ref(schema_name))
            .build(),
    )
}

/// Adds a 200 response with an array of schema components.
fn with_array_response(builder: OperationBuilder, schema_name: &str) -> OperationBuilder {
    builder.response(
        "200",
        ResponseBuilder::new()
            .description("Success")
            .content(
                "application/json",
                ContentBuilder::new()
                    .schema(Some(RefOr::T(
                        utoipa::openapi::ArrayBuilder::new()
                            .items(RefOr::Ref(utoipa::openapi::Ref::new(format!(
                                "#/components/schemas/{schema_name}"
                            ))))
                            .build()
                            .into(),
                    )))
                    .build(),
            )
            .build(),
    )
}

/// Adds a 200 response with no body.
fn with_empty_response(builder: OperationBuilder) -> OperationBuilder {
    builder.response("200", ResponseBuilder::new().description("Success").build())
}

/// Register all schema components from `ToSchema` derives.
fn register_schemas(builder: ComponentsBuilder) -> ComponentsBuilder {
    use crate::middleware::{AuthMethod, AuthUser};
    use crate::plugins::{AuthConfigResponse, UpdateProfileRequest};

    let mut b = builder
        .schema_from::<AuthUser>()
        .schema_from::<AuthMethod>()
        .schema_from::<AuthConfigResponse>()
        .schema_from::<UpdateProfileRequest>();

    #[cfg(feature = "email-password")]
    {
        use crate::plugins::email_password::*;
        b = b
            .schema_from::<RegisterRequest>()
            .schema_from::<LoginRequest>()
            .schema_from::<MessageResponse>()
            .schema_from::<VerifyEmailRequest>()
            .schema_from::<ResendVerificationRequest>()
            .schema_from::<ForgotPasswordRequest>()
            .schema_from::<ResetPasswordRequest>()
            .schema_from::<ChangePasswordRequest>();
    }

    #[cfg(feature = "passkey")]
    {
        use crate::plugins::passkey::*;
        b = b
            .schema_from::<PasskeyLoginBeginRequest>()
            .schema_from::<PasskeyLoginFinishRequest>()
            .schema_from::<RegisterFinishRequest>()
            .schema_from::<PasskeyInfo>();
    }

    #[cfg(feature = "mfa")]
    {
        use crate::plugins::mfa::*;
        b = b
            .schema_from::<ConfirmTotpRequest>()
            .schema_from::<VerifyMfaRequest>()
            .schema_from::<SetupTotpResponse>()
            .schema_from::<MfaMessageResponse>()
            .schema_from::<BackupCodeCountResponse>()
            .schema_from::<BackupCodesResponse>()
            .schema_from::<MfaAuthResponse>();
    }

    #[cfg(feature = "oauth")]
    {
        use crate::plugins::oauth::*;
        b = b
            .schema_from::<AuthorizeQuery>()
            .schema_from::<CallbackBody>()
            .schema_from::<OAuthAuthResponse>()
            .schema_from::<OAuthAccountResponse>()
            .schema_from::<AuthorizeResponse>();
    }

    #[cfg(feature = "bearer")]
    {
        use crate::plugins::bearer::*;
        b = b
            .schema_from::<TokenRequest>()
            .schema_from::<RefreshRequest>()
            .schema_from::<RevokeRequest>()
            .schema_from::<TokenResponse>();
    }

    #[cfg(feature = "api-key")]
    {
        use crate::plugins::api_key::*;
        b = b
            .schema_from::<CreateApiKeyRequest>()
            .schema_from::<CreateApiKeyResponse>()
            .schema_from::<ApiKeyResponse>();
    }

    #[cfg(feature = "magic-link")]
    {
        use crate::plugins::magic_link::*;
        b = b
            .schema_from::<MagicLinkSendRequest>()
            .schema_from::<MagicLinkVerifyRequest>()
            .schema_from::<MagicLinkMessageResponse>();
    }

    #[cfg(feature = "admin")]
    {
        use crate::plugins::admin::*;
        b = b
            .schema_from::<ListUsersQuery>()
            .schema_from::<ListSessionsQuery>()
            .schema_from::<UpdateUserRequest>()
            .schema_from::<BanRequest>();
    }

    #[cfg(feature = "webhooks")]
    {
        use crate::plugins::webhooks::*;
        b = b
            .schema_from::<CreateWebhookRequest>()
            .schema_from::<UpdateWebhookRequest>()
            .schema_from::<WebhookResponse>()
            .schema_from::<WebhookDetailResponse>()
            .schema_from::<WebhookDeliveryResponse>();
    }

    #[cfg(feature = "account-lockout")]
    {
        use crate::plugins::account_lockout::*;
        b = b
            .schema_from::<RequestUnlockRequest>()
            .schema_from::<UnlockAccountRequest>()
            .schema_from::<AccountLockoutMessageResponse>();
    }

    b
}

/// Core routes (always available).
fn core_paths(builder: PathsBuilder) -> PathsBuilder {
    builder
        .path(
            "/config",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("getConfig", "core")
                        .pipe(|b| with_response(b, "AuthConfigResponse"))
                        .build(),
                )
                .build(),
        )
        .path(
            "/session",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("getSession", "core")
                        .pipe(|b| with_response(b, "AuthUser"))
                        .security(utoipa::openapi::security::SecurityRequirement::new::<
                            &str,
                            [&str; 0],
                            &str,
                        >("cookieAuth", []))
                        .build(),
                )
                .build(),
        )
        .path(
            "/logout",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("logout", "core")
                        .pipe(with_empty_response)
                        .security(utoipa::openapi::security::SecurityRequirement::new::<
                            &str,
                            [&str; 0],
                            &str,
                        >("cookieAuth", []))
                        .build(),
                )
                .build(),
        )
        .path(
            "/me",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Patch,
                    op("updateProfile", "core")
                        .pipe(|b| with_body(b, "UpdateProfileRequest"))
                        .pipe(|b| with_response(b, "AuthUser"))
                        .security(utoipa::openapi::security::SecurityRequirement::new::<
                            &str,
                            [&str; 0],
                            &str,
                        >("cookieAuth", []))
                        .build(),
                )
                .build(),
        )
}

/// Email/password plugin paths.
#[cfg(feature = "email-password")]
fn email_password_paths(builder: PathsBuilder) -> PathsBuilder {
    builder
        .path(
            "/register",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_register", "emailPassword"),
                            "MessageResponse",
                        ),
                        "RegisterRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/login",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("emailPassword_login", "emailPassword")),
                        "LoginRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/verify-email",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_verifyEmail", "emailPassword"),
                            "MessageResponse",
                        ),
                        "VerifyEmailRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/resend-verification",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_resendVerification", "emailPassword"),
                            "MessageResponse",
                        ),
                        "ResendVerificationRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/forgot-password",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_forgotPassword", "emailPassword"),
                            "MessageResponse",
                        ),
                        "ForgotPasswordRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/reset-password",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_resetPassword", "emailPassword"),
                            "MessageResponse",
                        ),
                        "ResetPasswordRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/change-password",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_changePassword", "emailPassword"),
                            "MessageResponse",
                        ),
                        "ChangePasswordRequest",
                    )
                    .security(utoipa::openapi::security::SecurityRequirement::new::<
                        &str,
                        [&str; 0],
                        &str,
                    >("cookieAuth", []))
                    .build(),
                )
                .build(),
        )
}

/// Passkey plugin paths.
#[cfg(feature = "passkey")]
fn passkey_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "cookieAuth",
            [],
        )
    };

    builder
        .path(
            "/passkey/login/begin",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("passkey_loginBegin", "passkey")),
                        "PasskeyLoginBeginRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/passkey/login/finish",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("passkey_loginFinish", "passkey")),
                        "PasskeyLoginFinishRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/passkeys/register/begin",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("passkey_registerBegin", "passkey")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/passkeys/register/finish",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("passkey_registerFinish", "passkey")),
                        "RegisterFinishRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/passkeys",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("passkey_list", "passkey")
                        .pipe(|b| with_array_response(b, "PasskeyInfo"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/passkeys/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("passkey_delete", "passkey"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// MFA plugin paths.
#[cfg(feature = "mfa")]
fn mfa_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "cookieAuth",
            [],
        )
    };

    builder
        .path(
            "/mfa/totp/setup",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("mfa_setup", "mfa")
                        .pipe(|b| with_response(b, "SetupTotpResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/mfa/totp/confirm",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("mfa_confirm", "mfa"), "MfaMessageResponse"),
                        "ConfirmTotpRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/mfa/totp",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    op("mfa_disable", "mfa")
                        .pipe(|b| with_response(b, "MfaMessageResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/mfa/verify",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("mfa_verify", "mfa"), "MfaAuthResponse"),
                        "VerifyMfaRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/mfa/backup-codes",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("mfa_getBackupCodeCount", "mfa")
                        .pipe(|b| with_response(b, "BackupCodeCountResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/mfa/backup-codes/regenerate",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("mfa_regenerateBackupCodes", "mfa")
                        .pipe(|b| with_response(b, "BackupCodesResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// OAuth plugin paths.
#[cfg(feature = "oauth")]
fn oauth_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "cookieAuth",
            [],
        )
    };

    builder
        .path(
            "/oauth/{provider}/authorize",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("oauth_authorize", "oauth"), "provider")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/{provider}/callback",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(
                        with_body(
                            with_response(op("oauth_callback", "oauth"), "OAuthAuthResponse"),
                            "CallbackBody",
                        ),
                        "provider",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/oauth/accounts",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oauth_accounts", "oauth")
                        .pipe(|b| with_array_response(b, "OAuthAccountResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/{provider}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("oauth_unlink", "oauth"), "provider")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/{provider}/link",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(op("oauth_link", "oauth"), "provider")
                        .pipe(|b| with_response(b, "AuthorizeResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// Bearer token plugin paths.
#[cfg(feature = "bearer")]
fn bearer_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "cookieAuth",
            [],
        )
    };

    builder
        .path(
            "/token",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("bearer_getToken", "bearer"), "TokenResponse"),
                        "TokenRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/token/refresh",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("bearer_refresh", "bearer"), "TokenResponse"),
                        "RefreshRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/token/revoke",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("bearer_revoke", "bearer")),
                        "RevokeRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
}

/// API key plugin paths.
#[cfg(feature = "api-key")]
fn api_key_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "cookieAuth",
            [],
        )
    };

    builder
        .path(
            "/api-keys",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("apiKeys_create", "apiKeys"), "CreateApiKeyResponse"),
                        "CreateApiKeyRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Get,
                    op("apiKeys_list", "apiKeys")
                        .pipe(|b| with_array_response(b, "ApiKeyResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/api-keys/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("apiKeys_delete", "apiKeys"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// Magic link plugin paths.
#[cfg(feature = "magic-link")]
fn magic_link_paths(builder: PathsBuilder) -> PathsBuilder {
    builder
        .path(
            "/magic-link/send",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("magicLink_send", "magicLink"),
                            "MagicLinkMessageResponse",
                        ),
                        "MagicLinkSendRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/magic-link/verify",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("magicLink_verify", "magicLink")),
                        "MagicLinkVerifyRequest",
                    )
                    .build(),
                )
                .build(),
        )
}

/// Admin plugin paths.
#[cfg(feature = "admin")]
fn admin_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "cookieAuth",
            [],
        )
    };

    builder
        .path(
            "/admin/users",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("admin_listUsers", "admin")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("admin_getUser", "admin"), "id")
                        .pipe(|b| with_response(b, "AuthUser"))
                        .security(auth_req())
                        .build(),
                )
                .operation(
                    HttpMethod::Put,
                    with_path_param(
                        with_body(
                            with_response(op("admin_updateUser", "admin"), "AuthUser"),
                            "UpdateUserRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("admin_deleteUser", "admin"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}/ban",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(
                        with_body(
                            with_response(op("admin_banUser", "admin"), "AuthUser"),
                            "BanRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}/unban",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(op("admin_unbanUser", "admin"), "id")
                        .pipe(|b| with_response(b, "AuthUser"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}/impersonate",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(op("admin_impersonate", "admin"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/admin/sessions",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("admin_listSessions", "admin")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/admin/sessions/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("admin_deleteSession", "admin"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// OAuth2 server plugin paths.
#[cfg(feature = "oauth2-server")]
fn oauth2_server_paths(builder: PathsBuilder) -> PathsBuilder {
    builder
        .path(
            "/.well-known/oauth-authorization-server",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oauth2Server_metadata", "oauth2Server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/authorize",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oauth2Server_authorize", "oauth2Server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_authorizeConsent", "oauth2Server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/token",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_token", "oauth2Server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/introspect",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_introspect", "oauth2Server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/revoke",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_revoke", "oauth2Server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/register",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_register", "oauth2Server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/device/code",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_deviceAuthorize", "oauth2Server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/device",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oauth2Server_deviceVerify", "oauth2Server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_deviceApprove", "oauth2Server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
}

/// Webhooks plugin paths.
#[cfg(feature = "webhooks")]
fn webhook_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "cookieAuth",
            [],
        )
    };

    builder
        .path(
            "/webhooks",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("webhooks_create", "webhooks"), "WebhookResponse"),
                        "CreateWebhookRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Get,
                    op("webhooks_list", "webhooks")
                        .pipe(|b| with_array_response(b, "WebhookResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/webhooks/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("webhooks_get", "webhooks"), "id")
                        .pipe(|b| with_response(b, "WebhookDetailResponse"))
                        .security(auth_req())
                        .build(),
                )
                .operation(
                    HttpMethod::Put,
                    with_path_param(
                        with_body(
                            with_response(op("webhooks_update", "webhooks"), "WebhookResponse"),
                            "UpdateWebhookRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("webhooks_delete", "webhooks"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/webhooks/{id}/test",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(op("webhooks_test", "webhooks"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// Account lockout plugin paths.
#[cfg(feature = "account-lockout")]
fn account_lockout_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "cookieAuth",
            [],
        )
    };

    builder
        .path(
            "/account/request-unlock",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("accountLockout_requestUnlock", "accountLockout"),
                            "AccountLockoutMessageResponse",
                        ),
                        "RequestUnlockRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/account/unlock",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("accountLockout_unlock", "accountLockout"),
                            "AccountLockoutMessageResponse",
                        ),
                        "UnlockAccountRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}/unlock",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(op("accountLockout_adminUnlock", "accountLockout"), "id")
                        .pipe(|b| with_response(b, "AccountLockoutMessageResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// OIDC plugin paths.
#[cfg(feature = "oidc")]
fn oidc_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "cookieAuth",
            [],
        )
    };

    builder
        .path(
            "/.well-known/openid-configuration",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oidc_openidConfiguration", "oidc")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/.well-known/jwks.json",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oidc_jwks", "oidc").pipe(with_empty_response).build(),
                )
                .build(),
        )
        .path(
            "/userinfo",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oidc_userinfo", "oidc")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// Build the complete OpenAPI specification for yauth.
#[allow(unused_mut)]
pub fn build_openapi_spec() -> utoipa::openapi::OpenApi {
    let info = InfoBuilder::new()
        .title("yauth API")
        .version(env!("CARGO_PKG_VERSION"))
        .description(Some(
            "Modular, plugin-based authentication API for Axum applications.",
        ))
        .build();

    let components = register_schemas(ComponentsBuilder::new()).build();

    let mut paths = core_paths(PathsBuilder::new());

    #[cfg(feature = "email-password")]
    {
        paths = email_password_paths(paths);
    }

    #[cfg(feature = "passkey")]
    {
        paths = passkey_paths(paths);
    }

    #[cfg(feature = "mfa")]
    {
        paths = mfa_paths(paths);
    }

    #[cfg(feature = "oauth")]
    {
        paths = oauth_paths(paths);
    }

    #[cfg(feature = "bearer")]
    {
        paths = bearer_paths(paths);
    }

    #[cfg(feature = "api-key")]
    {
        paths = api_key_paths(paths);
    }

    #[cfg(feature = "magic-link")]
    {
        paths = magic_link_paths(paths);
    }

    #[cfg(feature = "admin")]
    {
        paths = admin_paths(paths);
    }

    #[cfg(feature = "oauth2-server")]
    {
        paths = oauth2_server_paths(paths);
    }

    #[cfg(feature = "webhooks")]
    {
        paths = webhook_paths(paths);
    }

    #[cfg(feature = "account-lockout")]
    {
        paths = account_lockout_paths(paths);
    }

    #[cfg(feature = "oidc")]
    {
        paths = oidc_paths(paths);
    }

    OpenApiBuilder::new()
        .info(info)
        .paths(paths.build())
        .components(Some(components))
        .build()
}

/// Helper trait for fluent builder chaining.
trait Pipe: Sized {
    fn pipe(self, f: impl FnOnce(Self) -> Self) -> Self {
        f(self)
    }
}
impl Pipe for OperationBuilder {}
