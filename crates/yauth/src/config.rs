use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YAuthConfig {
    pub base_url: String,
    pub session_cookie_name: String,
    #[serde(with = "duration_secs")]
    pub session_ttl: Duration,
    pub cookie_domain: Option<String>,
    pub secure_cookies: bool,
    pub trusted_origins: Vec<String>,
    pub smtp: Option<SmtpConfig>,
    /// When true, the first registered user automatically gets the "admin" role.
    #[serde(default)]
    pub auto_admin_first_user: bool,
}

impl Default for YAuthConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:3000".into(),
            session_cookie_name: "session".into(),
            session_ttl: Duration::from_secs(7 * 24 * 3600),
            cookie_domain: None,
            secure_cookies: false,
            trusted_origins: vec!["http://localhost:3000".into()],
            smtp: None,
            auto_admin_first_user: false,
        }
    }
}

mod duration_secs {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub from: String,
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailPasswordConfig {
    pub min_password_length: usize,
    pub require_email_verification: bool,
    pub hibp_check: bool,
}

#[cfg(feature = "email-password")]
impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            min_password_length: 8,
            require_email_verification: true,
            hibp_check: true,
        }
    }
}

#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyConfig {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
}

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    pub issuer: String,
    pub backup_code_count: usize,
}

#[cfg(feature = "mfa")]
impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            issuer: "YAuth".into(),
            backup_code_count: 10,
        }
    }
}

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub providers: Vec<OAuthProviderConfig>,
}

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: Vec<String>,
    /// Optional URL to fetch user emails (e.g. GitHub's /user/emails).
    /// Used as fallback when the userinfo endpoint doesn't return an email.
    #[serde(default)]
    pub emails_url: Option<String>,
}

#[cfg(feature = "magic-link")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkConfig {
    #[serde(with = "duration_secs")]
    pub link_ttl: Duration,
    pub allow_signup: bool,
    pub default_role: Option<String>,
}

#[cfg(feature = "magic-link")]
impl Default for MagicLinkConfig {
    fn default() -> Self {
        Self {
            link_ttl: Duration::from_secs(5 * 60),
            allow_signup: true,
            default_role: None,
        }
    }
}

#[cfg(feature = "bearer")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BearerConfig {
    pub jwt_secret: String,
    #[serde(with = "duration_secs")]
    pub access_token_ttl: Duration,
    #[serde(with = "duration_secs")]
    pub refresh_token_ttl: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let config = YAuthConfig::default();
        assert_eq!(config.session_cookie_name, "session");
        assert_eq!(config.session_ttl, Duration::from_secs(604800));
        assert!(!config.secure_cookies);
        assert!(config.smtp.is_none());
        assert!(!config.auto_admin_first_user);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = YAuthConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: YAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.base_url, config.base_url);
        assert_eq!(parsed.session_ttl, config.session_ttl);
    }

    #[test]
    fn duration_serde_as_seconds() {
        let config = YAuthConfig {
            session_ttl: Duration::from_secs(3600),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("3600"));
        let parsed: YAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_ttl, Duration::from_secs(3600));
    }

    #[cfg(feature = "email-password")]
    #[test]
    fn email_password_config_defaults() {
        let config = EmailPasswordConfig::default();
        assert_eq!(config.min_password_length, 8);
        assert!(config.require_email_verification);
        assert!(config.hibp_check);
    }

    #[cfg(feature = "mfa")]
    #[test]
    fn mfa_config_defaults() {
        let config = MfaConfig::default();
        assert_eq!(config.issuer, "YAuth");
        assert_eq!(config.backup_code_count, 10);
    }
}
