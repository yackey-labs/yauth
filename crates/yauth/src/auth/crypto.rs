use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a cryptographically random 32-byte hex token.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 hash of a token for storage.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Timing-safe comparison of two byte slices.
///
/// Always iterates through the longer of the two inputs to avoid
/// leaking length information via timing side-channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_diff = a.len() ^ b.len();
    let mut result = len_diff as u8;
    // Iterate through all bytes of the longer slice. For indices beyond
    // the shorter slice, use 0xFF vs 0x00 to accumulate a difference
    // without short-circuiting.
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let x = if i < a.len() { a[i] } else { 0xFF };
        let y = if i < b.len() { b[i] } else { 0x00 };
        result |= x ^ y;
    }
    result == 0 && len_diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_token_is_64_hex_chars() {
        let token = generate_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_token_is_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
    }

    #[test]
    fn hash_token_is_deterministic() {
        let token = "test-token-value";
        let h1 = hash_token(token);
        let h2 = hash_token(token);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_token_is_64_hex_chars() {
        let hash = hash_token("anything");
        assert_eq!(hash.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_token_different_inputs_differ() {
        assert_ne!(hash_token("a"), hash_token("b"));
    }

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_different_content() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
        assert!(!constant_time_eq(b"longer", b"short"));
    }

    #[test]
    fn constant_time_eq_single_bit_diff() {
        let a = b"\x00\x00\x00";
        let b = b"\x00\x01\x00";
        assert!(!constant_time_eq(a, b));
    }
}
