//! In-memory registry of `private_key_jwt` client public keys.
//!
//! Populated at dynamic-client-registration time (RFC 7591) when a client
//! sets `token_endpoint_auth_method=private_key_jwt`. The token endpoint
//! consults this registry to validate `client_assertion` JWTs (RFC 7523).
//!
//! **Persistence**: this storage is process-local. A DB-backed store is a
//! follow-up; for now users who need persistence across restarts should
//! reseed the registry from config during server startup.

#![cfg(all(feature = "asymmetric-jwt", feature = "oauth2-server"))]

use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey};

/// A registered client's public signing material. Parsed once at registration
/// so the token endpoint doesn't re-parse PEMs on every assertion. Cloneable
/// (cheap, `Arc`-backed) so callers can pull the key out from under the
/// registry RwLock and release the lock before awaiting.
#[derive(Clone)]
pub struct ClientKey {
    pub decoding_key: Arc<DecodingKey>,
    pub alg: Algorithm,
    /// Original PEM — kept only to be returned by admin list endpoints (M4).
    /// Never logged.
    pub public_key_pem: String,
}

impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("alg", &self.alg)
            .field("public_key_pem", &"<redacted>")
            .finish()
    }
}

impl ClientKey {
    /// Parse a PEM-encoded public key. Tries RSA (RS256) first, then EC
    /// (ES256). Returns an actionable error if neither works.
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        if let Ok(dk) = DecodingKey::from_rsa_pem(pem.as_bytes()) {
            return Ok(Self {
                decoding_key: Arc::new(dk),
                alg: Algorithm::RS256,
                public_key_pem: pem.to_string(),
            });
        }
        if let Ok(dk) = DecodingKey::from_ec_pem(pem.as_bytes()) {
            return Ok(Self {
                decoding_key: Arc::new(dk),
                alg: Algorithm::ES256,
                public_key_pem: pem.to_string(),
            });
        }
        Err(
            "Failed to parse public_key_pem as RSA or EC (P-256). Supply a SPKI PEM \
             (-----BEGIN PUBLIC KEY-----) in PKCS#8 format."
                .to_string(),
        )
    }
}
