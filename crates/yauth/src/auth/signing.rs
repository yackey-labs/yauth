//! Shared JWT signing and verification primitives.
//!
//! Centralizes the alg dispatch so HS256, RS256, and ES256 tokens all flow
//! through a single code path. Byte-stable for HS256 deployments (no `kid`
//! header emitted when the default HS256 alg is configured) — existing
//! integrations see zero wire change.

#![cfg(feature = "bearer")]

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::BearerConfig;

/// Error returned by signing / verification helpers. Kept stringly-typed
/// to match the existing `validate_jwt*` surface.
pub type SigningError = String;

/// Parsed signing material — built once from `BearerConfig` at `YAuthBuilder::build()`
/// time. Stashed on `YAuthState` so every request avoids re-parsing PEMs.
#[cfg(feature = "asymmetric-jwt")]
pub struct SigningKeys {
    pub alg: crate::config::SigningAlgorithm,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub kid: String,
    pub jwk: crate::auth::jwks::Jwk,
}

#[cfg(feature = "asymmetric-jwt")]
impl SigningKeys {
    /// Parse the PEM from `config.signing_key_pem` and cache encoding +
    /// decoding keys, a JWK for publication, and the `kid` for the header.
    /// Rejects PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) — users must
    /// convert to PKCS#8 for stable parser support.
    pub fn from_config(config: &BearerConfig) -> Result<Option<Self>, SigningError> {
        use crate::config::SigningAlgorithm;

        match config.signing_algorithm {
            SigningAlgorithm::Hs256 => Ok(None),
            SigningAlgorithm::Rs256 => Self::from_rsa(config).map(Some),
            SigningAlgorithm::Es256 => Self::from_ec(config).map(Some),
        }
    }

    fn from_rsa(config: &BearerConfig) -> Result<Self, SigningError> {
        use base64::Engine;
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
        use rsa::traits::PublicKeyParts;

        let pem = config
            .signing_key_pem
            .as_ref()
            .ok_or_else(|| "RS256 configured but signing_key_pem is missing".to_string())?;

        if pem.contains("-----BEGIN RSA PRIVATE KEY-----") {
            return Err(
                "PKCS#1 RSA keys are not supported — convert to PKCS#8 (BEGIN PRIVATE KEY)"
                    .to_string(),
            );
        }

        let private = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| format!("Failed to parse RSA PKCS#8 PEM: {e}"))?;
        let public = rsa::RsaPublicKey::from(&private);

        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| format!("jsonwebtoken rejected RSA PEM: {e}"))?;
        let public_pem = public
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| format!("Failed to encode RSA public PEM: {e}"))?;
        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|e| format!("jsonwebtoken rejected RSA public PEM: {e}"))?;

        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let jwk = crate::auth::jwks::Jwk::rsa(&n, &e, "");
        let kid = config.kid.clone().unwrap_or_else(|| rsa_thumbprint(&e, &n));
        let jwk = crate::auth::jwks::Jwk {
            kid: kid.clone(),
            ..jwk
        };

        Ok(Self {
            alg: crate::config::SigningAlgorithm::Rs256,
            encoding_key,
            decoding_key,
            kid,
            jwk,
        })
    }

    fn from_ec(config: &BearerConfig) -> Result<Self, SigningError> {
        use base64::Engine;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};

        let pem = config
            .signing_key_pem
            .as_ref()
            .ok_or_else(|| "ES256 configured but signing_key_pem is missing".to_string())?;

        let secret = p256::SecretKey::from_pkcs8_pem(pem)
            .map_err(|e| format!("Failed to parse EC PKCS#8 PEM: {e}"))?;
        let public = secret.public_key();

        let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes())
            .map_err(|e| format!("jsonwebtoken rejected EC PEM: {e}"))?;
        let public_pem = public
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|e| format!("Failed to encode EC public PEM: {e}"))?;
        let decoding_key = DecodingKey::from_ec_pem(public_pem.as_bytes())
            .map_err(|e| format!("jsonwebtoken rejected EC public PEM: {e}"))?;

        let encoded = public.to_encoded_point(false);
        let x = encoded
            .x()
            .ok_or_else(|| "EC public key missing X coordinate".to_string())?;
        let y = encoded
            .y()
            .ok_or_else(|| "EC public key missing Y coordinate".to_string())?;
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
        let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y);
        let kid = config
            .kid
            .clone()
            .unwrap_or_else(|| ec_thumbprint(&x_b64, &y_b64));
        let jwk = crate::auth::jwks::Jwk::ec_p256(&x_b64, &y_b64, &kid);

        Ok(Self {
            alg: crate::config::SigningAlgorithm::Es256,
            encoding_key,
            decoding_key,
            kid,
            jwk,
        })
    }
}

/// RFC 7638 JWK thumbprint for RSA keys: SHA-256 over the canonical JSON
/// `{"e":"...","kty":"RSA","n":"..."}` (alphabetic key order, no whitespace).
#[cfg(feature = "asymmetric-jwt")]
fn rsa_thumbprint(e: &str, n: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    let canonical = format!("{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}");
    let hash = sha2::Sha256::digest(canonical.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// RFC 7638 JWK thumbprint for EC P-256 keys: canonical JSON
/// `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`.
#[cfg(feature = "asymmetric-jwt")]
fn ec_thumbprint(x: &str, y: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    let hash = sha2::Sha256::digest(canonical.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Sign a set of claims with the configured algorithm. HS256 tokens produced
/// by this helper are byte-identical to pre-M2 output — no `kid` header
/// unless the user explicitly sets one.
pub fn sign_jwt<T: Serialize>(
    claims: &T,
    state: &crate::state::YAuthState,
) -> Result<String, SigningError> {
    #[cfg(feature = "asymmetric-jwt")]
    if let Some(ref keys) = state.signing_keys {
        let mut header = Header::new(alg_to_jwt(keys.alg));
        header.kid = Some(keys.kid.clone());
        return jsonwebtoken::encode(&header, claims, &keys.encoding_key)
            .map_err(|e| format!("JWT encode failed: {e}"));
    }

    // HS256 path — byte-stable with pre-M2.
    let header = Header::new(Algorithm::HS256);
    let config = &state.bearer_config;
    if config.kid_override_set() {
        let mut header = header;
        header.kid = config.kid_override();
        return jsonwebtoken::encode(
            &header,
            claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
        )
        .map_err(|e| format!("JWT encode failed: {e}"));
    }
    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| format!("JWT encode failed: {e}"))
}

/// Verify a JWT and deserialize into the caller's claim struct. Reads the
/// token header to confirm `alg` matches the server's configured alg
/// (defense against alg-confusion attacks) before dispatching to the right
/// decoding key.
pub fn decode_jwt<T: DeserializeOwned>(
    token: &str,
    state: &crate::state::YAuthState,
    required_claims: &[&'static str],
) -> Result<TokenData<T>, SigningError> {
    let header = jsonwebtoken::decode_header(token).map_err(|e| format!("bad JWT header: {e}"))?;

    let config = &state.bearer_config;
    let expected_alg = configured_alg(state);
    if header.alg != expected_alg {
        return Err(format!(
            "unexpected alg {:?}; server configured for {:?}",
            header.alg, expected_alg
        ));
    }

    let mut validation = Validation::new(expected_alg);
    validation.validate_exp = true;
    if !required_claims.is_empty() {
        validation.set_required_spec_claims(required_claims);
    }
    if let Some(ref expected_aud) = config.audience {
        validation.set_audience(&[expected_aud]);
    } else {
        validation.validate_aud = false;
    }

    #[cfg(feature = "asymmetric-jwt")]
    if let Some(ref keys) = state.signing_keys {
        return decode::<T>(token, &keys.decoding_key, &validation)
            .map_err(|e| format!("JWT validation failed: {e}"));
    }

    decode::<T>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| format!("JWT validation failed: {e}"))
}

fn configured_alg(state: &crate::state::YAuthState) -> Algorithm {
    #[cfg(feature = "asymmetric-jwt")]
    if let Some(ref keys) = state.signing_keys {
        return alg_to_jwt(keys.alg);
    }
    #[cfg(not(feature = "asymmetric-jwt"))]
    let _ = state;
    Algorithm::HS256
}

#[cfg(feature = "asymmetric-jwt")]
fn alg_to_jwt(alg: crate::config::SigningAlgorithm) -> Algorithm {
    match alg {
        crate::config::SigningAlgorithm::Hs256 => Algorithm::HS256,
        crate::config::SigningAlgorithm::Rs256 => Algorithm::RS256,
        crate::config::SigningAlgorithm::Es256 => Algorithm::ES256,
    }
}

// ── BearerConfig extension traits ─────────────────────────────────────────

impl BearerConfig {
    /// Whether the user explicitly set a `kid` override for HS256 tokens.
    /// Used to keep HS256 byte-stable when no override is set.
    #[inline]
    fn kid_override_set(&self) -> bool {
        #[cfg(feature = "asymmetric-jwt")]
        {
            self.kid.is_some()
        }
        #[cfg(not(feature = "asymmetric-jwt"))]
        {
            false
        }
    }

    #[inline]
    fn kid_override(&self) -> Option<String> {
        #[cfg(feature = "asymmetric-jwt")]
        {
            self.kid.clone()
        }
        #[cfg(not(feature = "asymmetric-jwt"))]
        {
            None
        }
    }
}
