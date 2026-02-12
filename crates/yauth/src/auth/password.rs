use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use password_hash::{PasswordHash, SaltString};
use rand::rngs::OsRng;

pub fn hash_password(password: &str) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_correct_password() {
        let hash = hash_password("my-secure-password").unwrap();
        assert!(verify_password("my-secure-password", &hash).unwrap());
    }

    #[test]
    fn verify_wrong_password_returns_false() {
        let hash = hash_password("correct-password").unwrap();
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn hash_is_argon2id() {
        let hash = hash_password("test").unwrap();
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn different_hashes_for_same_password() {
        let h1 = hash_password("same-password").unwrap();
        let h2 = hash_password("same-password").unwrap();
        // Different salts → different hashes
        assert_ne!(h1, h2);
        // But both verify
        assert!(verify_password("same-password", &h1).unwrap());
        assert!(verify_password("same-password", &h2).unwrap());
    }

    #[test]
    fn verify_against_invalid_hash_format_errors() {
        assert!(verify_password("test", "not-a-hash").is_err());
    }

    #[test]
    fn empty_password_hashes_and_verifies() {
        let hash = hash_password("").unwrap();
        assert!(verify_password("", &hash).unwrap());
        assert!(!verify_password("not-empty", &hash).unwrap());
    }
}
