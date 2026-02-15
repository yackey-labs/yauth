/// Strip null bytes and trim whitespace from user input.
pub fn sanitize(s: &str) -> String {
    s.replace('\0', "").trim().to_string()
}

/// Basic email validation: non-empty, exactly one `@`, non-empty local and domain parts,
/// and the domain contains at least one `.`.
pub fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    !local.is_empty() && !domain.is_empty() && domain.contains('.')
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
}
