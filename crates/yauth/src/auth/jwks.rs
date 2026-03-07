//! JWKS (JSON Web Key Set) generation for RS256/ES256 asymmetric JWT signing.
//! When the bearer plugin uses asymmetric signing, this module generates the
//! public key set for `GET /.well-known/jwks.json`.

use serde::Serialize;

use crate::config::BearerConfig;

/// A JSON Web Key Set.
#[derive(Debug, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// A JSON Web Key (public key only).
#[derive(Debug, Serialize)]
pub struct Jwk {
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// Generate JWKS from the bearer config. For HS256, returns an empty key set
/// (symmetric keys should not be published). For RS256/ES256, returns the public key.
pub fn generate_jwks(config: &BearerConfig) -> Jwks {
    // Currently yauth uses HS256 only. JWKS is returned as empty since
    // symmetric keys should never be published. When RS256/ES256 support
    // is added, this function will extract the public key from the PEM
    // and construct the appropriate JWK.
    //
    // For now, this provides the endpoint structure and will return an
    // empty keyset that signals "no public keys available".
    let _ = config;
    Jwks { keys: vec![] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_jwks_for_hs256() {
        let config = BearerConfig {
            jwt_secret: "test-secret".into(),
            access_token_ttl: std::time::Duration::from_secs(900),
            refresh_token_ttl: std::time::Duration::from_secs(86400),
            audience: None,
        };
        let jwks = generate_jwks(&config);
        assert!(jwks.keys.is_empty());
    }

    #[test]
    fn jwks_serializes_correctly() {
        let jwks = Jwks { keys: vec![] };
        let json = serde_json::to_string(&jwks).unwrap();
        assert!(json.contains("\"keys\":[]"));
    }
}
