/// Strip null bytes and trim whitespace from user input.
pub fn sanitize(s: &str) -> String {
    s.replace('\0', "").trim().to_string()
}

/// Sanitize a password: strip null bytes only. Passwords are NOT trimmed
/// because leading/trailing whitespace is valid password entropy.
pub fn sanitize_password(s: &str) -> String {
    s.replace('\0', "")
}

/// Maximum allowed email length (RFC 5321 limits the path to 254 chars).
const MAX_EMAIL_LENGTH: usize = 254;

/// Basic email validation: non-empty, exactly one `@`, non-empty local and domain parts,
/// the domain contains at least one `.`, length is bounded, and no dangerous characters.
pub fn is_valid_email(email: &str) -> bool {
    if email.len() > MAX_EMAIL_LENGTH {
        return false;
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    if local.is_empty() || local.len() > 64 || domain.is_empty() {
        return false;
    }
    // Reject characters that could cause injection in HTML/logs
    if local.contains('<') || local.contains('>') {
        return false;
    }
    // TLD must be at least 2 characters
    if let Some(tld) = domain.rsplit('.').next()
        && tld.len() < 2
    {
        return false;
    }
    domain.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_null_bytes() {
        assert_eq!(sanitize("hello\0world"), "helloworld");
    }

    #[test]
    fn sanitize_trims_whitespace() {
        assert_eq!(sanitize("  hello  "), "hello");
    }

    #[test]
    fn sanitize_strips_null_and_trims() {
        assert_eq!(sanitize(" \0foo\0 "), "foo");
    }

    #[test]
    fn sanitize_empty_string() {
        assert_eq!(sanitize(""), "");
    }

    #[test]
    fn sanitize_password_preserves_whitespace() {
        assert_eq!(sanitize_password("  hello  "), "  hello  ");
    }

    #[test]
    fn sanitize_password_strips_null_bytes() {
        assert_eq!(sanitize_password("pass\0word"), "password");
    }

    #[test]
    fn valid_email_basic() {
        assert!(is_valid_email("user@example.com"));
    }

    #[test]
    fn invalid_email_no_at() {
        assert!(!is_valid_email("userexample.com"));
    }

    #[test]
    fn invalid_email_multiple_at() {
        assert!(!is_valid_email("user@@example.com"));
    }

    #[test]
    fn invalid_email_empty_local() {
        assert!(!is_valid_email("@example.com"));
    }

    #[test]
    fn invalid_email_empty_domain() {
        assert!(!is_valid_email("user@"));
    }

    #[test]
    fn invalid_email_no_dot_in_domain() {
        assert!(!is_valid_email("user@localhost"));
    }

    #[test]
    fn invalid_email_empty_string() {
        assert!(!is_valid_email(""));
    }

    #[test]
    fn invalid_email_too_long() {
        let long_local = "a".repeat(1000);
        let email = format!("{}@example.com", long_local);
        assert!(!is_valid_email(&email));
    }

    #[test]
    fn invalid_email_html_injection() {
        assert!(!is_valid_email("user+<script>@example.com"));
    }

    #[test]
    fn invalid_email_single_char_tld() {
        assert!(!is_valid_email("admin@internal.x"));
    }
}
