use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use password_hash::{PasswordHash, SaltString};
use rand::rngs::OsRng;

/// Synchronous password hashing — only for use in non-async contexts (e.g. startup, tests).
pub fn hash_password_sync(password: &str) -> Result<String, password_hash::Error> {
    let _span = tracing::info_span!("yauth.password_hash").entered();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// Synchronous password verification — only for use in non-async contexts (e.g. tests).
pub fn verify_password_sync(password: &str, hash: &str) -> Result<bool, password_hash::Error> {
    let _span = tracing::info_span!("yauth.password_verify").entered();
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Async password hashing that offloads CPU-intensive Argon2 to a blocking thread.
pub async fn hash_password(password: &str) -> Result<String, password_hash::Error> {
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || hash_password_sync(&password))
        .await
        .expect("password hash task panicked")
}

/// Async password verification that offloads CPU-intensive Argon2 to a blocking thread.
pub async fn verify_password(password: &str, hash: &str) -> Result<bool, password_hash::Error> {
    let password = password.to_owned();
    let hash = hash.to_owned();
    tokio::task::spawn_blocking(move || verify_password_sync(&password, &hash))
        .await
        .expect("password verify task panicked")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_correct_password() {
        let hash = hash_password_sync("my-secure-password").unwrap();
        assert!(verify_password_sync("my-secure-password", &hash).unwrap());
    }

    #[test]
    fn verify_wrong_password_returns_false() {
        let hash = hash_password_sync("correct-password").unwrap();
        assert!(!verify_password_sync("wrong-password", &hash).unwrap());
    }

    #[test]
    fn hash_is_argon2id() {
        let hash = hash_password_sync("test").unwrap();
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn different_hashes_for_same_password() {
        let h1 = hash_password_sync("same-password").unwrap();
        let h2 = hash_password_sync("same-password").unwrap();
        // Different salts → different hashes
        assert_ne!(h1, h2);
        // But both verify
        assert!(verify_password_sync("same-password", &h1).unwrap());
        assert!(verify_password_sync("same-password", &h2).unwrap());
    }

    #[test]
    fn verify_against_invalid_hash_format_errors() {
        assert!(verify_password_sync("test", "not-a-hash").is_err());
    }

    #[test]
    fn empty_password_hashes_and_verifies() {
        let hash = hash_password_sync("").unwrap();
        assert!(verify_password_sync("", &hash).unwrap());
        assert!(!verify_password_sync("not-empty", &hash).unwrap());
    }
}
