pub mod audit_log;
pub mod sessions;
pub mod users;

#[cfg(feature = "email-password")]
pub mod email_verifications;
#[cfg(feature = "email-password")]
pub mod password_resets;
#[cfg(feature = "email-password")]
pub mod passwords;

#[cfg(feature = "passkey")]
pub mod webauthn_credentials;

#[cfg(feature = "mfa")]
pub mod backup_codes;
#[cfg(feature = "mfa")]
pub mod totp_secrets;

#[cfg(feature = "oauth")]
pub mod oauth_accounts;
#[cfg(feature = "oauth")]
pub mod oauth_states;

#[cfg(feature = "api-key")]
pub mod api_keys;

#[cfg(feature = "bearer")]
pub mod refresh_tokens;
