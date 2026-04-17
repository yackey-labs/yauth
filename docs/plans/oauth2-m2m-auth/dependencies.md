# Dependencies

## Existing (no changes for M1)

- `jsonwebtoken`@10 (latest: 10.3.0) — Already in workspace with `rust_crypto` feature. Supports HS256 today; the same crate handles RS256/ES256 via `EncodingKey::from_rsa_pem` / `from_ec_pem` and `DecodingKey::from_rsa_pem` / `from_ec_pem` with no version bump.
- `serde_json` (workspace) — Used in M1 for `MachineCaller.custom_claims: serde_json::Map<String, Value>`.
- `uuid`@1.x with `v7` — Used for `jti` generation. No change.
- `chrono` (workspace) — Used for token TTL math. No change.

## To Add (M2 — asymmetric signing only)

- `rsa`@0.9 (latest: 0.10.0-rc.17) — Pin to **0.9 stable**. Needed to parse RSA PEM into a `RsaPublicKey` and extract modulus (`n`) + exponent (`e`) for JWK publication. `jsonwebtoken` does not expose those primitives. Alternative considered: `josekit` (heavier, pulls in OpenSSL), or hand-rolled ASN.1 parsing via `simple_asn1` (fragile). Link: <https://docs.rs/rsa/0.9>
  - Reason for not picking 0.10: it's release-candidate. yauth ships to crates.io — RC deps would block downstream users.
  - ⚠️ Use the `pkcs1` and `pkcs8` re-exports from `rsa` (`rsa::pkcs1::DecodeRsaPublicKey`, `rsa::pkcs8::DecodePublicKey`) — do not add separate `pkcs1` / `pkcs8` crates.
- `p256`@0.13 (latest: 0.14.0-rc.8) — Pin to **0.13 stable**. Needed for ES256: parse EC PEM and extract uncompressed point (`x`, `y`) for JWK. Alternative: `ring` (BoringSSL bindings — heavier and harder to cross-compile). Link: <https://docs.rs/p256/0.13>
  - Reason for not picking 0.14: RC, same reasoning as `rsa`.
- `base64`@0.22 (latest: 0.22.1) — Already a transitive dep, but make it a direct dep of the `bearer` feature so `URL_SAFE_NO_PAD` encoding for JWK `n`/`e`/`x`/`y` is explicit.

All M2 additions go behind a new feature flag `asymmetric-jwt` (default off) so existing HS256-only deployments take zero new compile cost.

## To Add (M3 — `private_key_jwt` client auth)

No new crates. Reuses `jsonwebtoken` for assertion validation and `rsa` / `p256` from M2 for parsing the client's registered public key.

## Approach Decisions

- **JWK key parameter extraction**: use the `rsa` + `p256` crates' PEM decoders and re-export the components, rather than embedding ASN.1/DER parsing in yauth. Reason: those crates are RustCrypto-maintained, audited, and already a transitive dep of `jsonwebtoken@10` with `rust_crypto` — no new audit surface.
- **Feature flag `asymmetric-jwt`**: split out so HS256-only deployments don't pay for `rsa`/`p256` compile time. `oauth2-server` and `oidc` continue to compile without it; JWKS endpoint returns the empty key set when the feature is off (current behavior).
- **`kid` derivation**: SHA-256 over the canonical JWK JSON (per RFC 7638 thumbprint), base64url-encoded. Deterministic so users don't need to set `kid` manually unless they want to.
- **Key storage**: PEM string in `BearerConfig` (loaded by the user from file or env). Yauth does not read paths or files itself — keeps the library boundary clean and matches the "user owns the pool" precedent.
- **Multiple keys / rotation**: out of scope for this work. M2 supports a single active key; rotation is a future ticket. JWKS is a `Vec<Jwk>` so rotation is additive.
