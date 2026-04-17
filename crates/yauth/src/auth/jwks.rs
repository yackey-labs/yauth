//! JWKS (JSON Web Key Set) generation for RS256/ES256 asymmetric JWT signing.
//!
//! When `BearerConfig::signing_algorithm` is HS256 (the default), JWKS is an
//! empty key set — symmetric keys must never be published. When RS256 or
//! ES256 is configured, the server's parsed public key is published here so
//! resource servers in other trust domains can validate issued tokens.

use serde::Serialize;

/// A JSON Web Key Set.
#[derive(Debug, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// A JSON Web Key (public key only).
#[derive(Debug, Clone, Serialize)]
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

impl Jwk {
    /// Build an RSA JWK from the base64url-encoded modulus and exponent.
    pub fn rsa(n: &str, e: &str, kid: &str) -> Self {
        Self {
            kty: "RSA".into(),
            alg: "RS256".into(),
            use_: "sig".into(),
            kid: kid.into(),
            n: Some(n.into()),
            e: Some(e.into()),
            crv: None,
            x: None,
            y: None,
        }
    }

    /// Build an EC P-256 JWK from the base64url-encoded coordinates.
    pub fn ec_p256(x: &str, y: &str, kid: &str) -> Self {
        Self {
            kty: "EC".into(),
            alg: "ES256".into(),
            use_: "sig".into(),
            kid: kid.into(),
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: Some(x.into()),
            y: Some(y.into()),
        }
    }
}

/// Generate JWKS from the current auth state.
///
/// For HS256 (symmetric), returns an empty key set — symmetric keys are
/// never published. For RS256 / ES256, returns the public JWK derived from
/// the user-configured signing key.
pub fn generate_jwks(state: &crate::state::YAuthState) -> Jwks {
    let _ = state;

    #[cfg(feature = "asymmetric-jwt")]
    if let Some(ref keys) = state.signing_keys {
        return Jwks {
            keys: vec![keys.jwk.clone()],
        };
    }

    Jwks { keys: vec![] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_serializes_correctly() {
        let jwks = Jwks { keys: vec![] };
        let json = serde_json::to_string(&jwks).unwrap();
        assert!(json.contains("\"keys\":[]"));
    }

    #[test]
    fn rsa_jwk_shape() {
        let jwk = Jwk::rsa("MODULUS", "AQAB", "kid1");
        let json = serde_json::to_string(&jwk).unwrap();
        assert!(json.contains("\"kty\":\"RSA\""));
        assert!(json.contains("\"alg\":\"RS256\""));
        assert!(json.contains("\"n\":\"MODULUS\""));
        assert!(json.contains("\"e\":\"AQAB\""));
        assert!(json.contains("\"kid\":\"kid1\""));
        assert!(!json.contains("\"crv\""));
    }

    #[test]
    fn ec_jwk_shape() {
        let jwk = Jwk::ec_p256("XCOORD", "YCOORD", "kid2");
        let json = serde_json::to_string(&jwk).unwrap();
        assert!(json.contains("\"kty\":\"EC\""));
        assert!(json.contains("\"alg\":\"ES256\""));
        assert!(json.contains("\"crv\":\"P-256\""));
        assert!(json.contains("\"x\":\"XCOORD\""));
        assert!(json.contains("\"y\":\"YCOORD\""));
        assert!(!json.contains("\"n\""));
    }
}
