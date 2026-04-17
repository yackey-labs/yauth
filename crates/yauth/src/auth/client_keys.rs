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

use jsonwebtoken::{Algorithm, DecodingKey};

/// A parsed client public signing key. Constructed per-assertion from the
/// `public_key_pem` stored on the `yauth_oauth2_clients` row; the Redis
/// decorator already in front of `Oauth2ClientRepository::find_by_client_id`
/// caches the fetched row, so the PEM parse is the only extra cost on the
/// hot path.
pub struct ClientKey {
    pub decoding_key: DecodingKey,
    pub alg: Algorithm,
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
                decoding_key: dk,
                alg: Algorithm::RS256,
                public_key_pem: pem.to_string(),
            });
        }
        if let Ok(dk) = DecodingKey::from_ec_pem(pem.as_bytes()) {
            return Ok(Self {
                decoding_key: dk,
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
