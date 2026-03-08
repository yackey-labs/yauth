use sha1::{Digest, Sha1};
use tracing::{info, warn};

/// Check if a password has been found in data breaches using the
/// HaveIBeenPwned Passwords API with k-anonymity.
///
/// Returns Ok(count) where count is the number of breaches, or 0 if not found.
/// Returns Err only on network/parse errors — callers should treat errors as
/// "unable to check" rather than blocking registration.
pub async fn check_password_breach(password: &str) -> Result<u64, String> {
    use tracing::Instrument;

    let parent_span = tracing::Span::current();
    let child_span = tracing::info_span!(
        "yauth.hibp_check",
        otel.kind = "Client",
        http.request.method = "GET",
        yauth.hibp.breach_count = tracing::field::Empty,
    );

    async {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = format!("{:X}", hasher.finalize());

        let prefix = &hash[..5];
        let suffix = &hash[5..];

        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

        let client = reqwest::Client::builder()
            .user_agent("yauth-security-check")
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("HIBP API request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("HIBP API returned status {}", response.status()));
        }

        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read HIBP response: {}", e))?;

        for line in body.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 && parts[0].trim().eq_ignore_ascii_case(suffix) {
                let count: u64 = parts[1].trim().parse().unwrap_or(1);
                // Record on both the child span and the parent SERVER span
                tracing::Span::current().record("yauth.hibp.breach_count", count);
                parent_span.record("yauth.hibp.breach_count", count);
                info!(
                    event = "hibp_password_breached",
                    breach_count = count,
                    "Password found in {} data breaches",
                    count
                );
                return Ok(count);
            }
        }

        // Record zero breaches
        tracing::Span::current().record("yauth.hibp.breach_count", 0u64);
        parent_span.record("yauth.hibp.breach_count", 0u64);

        Ok(0)
    }
    .instrument(child_span)
    .await
}

/// Parse a HIBP response body to find a matching suffix, returning the breach count.
#[cfg(test)]
fn parse_hibp_response(suffix: &str, body: &str) -> u64 {
    for line in body.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() == 2 && parts[0].trim().eq_ignore_ascii_case(suffix) {
            return parts[1].trim().parse().unwrap_or(1);
        }
    }
    0
}

/// Check password and return a user-friendly error message if breached.
/// Returns None if password is safe, Some(message) if breached.
/// On API errors, logs a warning and returns None (fail-open to not block registration).
pub async fn validate_password_not_breached(password: &str) -> Option<String> {
    match check_password_breach(password).await {
        Ok(0) => None,
        Ok(count) => Some(format!(
            "This password has been found in {} data breach{}. Please choose a different password.",
            count,
            if count == 1 { "" } else { "es" }
        )),
        Err(e) => {
            warn!(
                event = "hibp_check_failed",
                error = %e,
                "Failed to check HaveIBeenPwned API, allowing registration"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RESPONSE: &str = "\
0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n\
011053FD0102E94D6AE2F8B83D76FAF94F6:3\r\n\
012A7CA357541F0AC487871FEEC1891C49C:2\r\n\
0136E006E24E7D152139815FB0FC6A50B15:5";

    #[test]
    fn parse_finds_matching_suffix() {
        let count = parse_hibp_response("011053FD0102E94D6AE2F8B83D76FAF94F6", SAMPLE_RESPONSE);
        assert_eq!(count, 3);
    }

    #[test]
    fn parse_returns_zero_when_not_found() {
        let count = parse_hibp_response("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0", SAMPLE_RESPONSE);
        assert_eq!(count, 0);
    }

    #[test]
    fn parse_case_insensitive() {
        let count = parse_hibp_response("011053fd0102e94d6ae2f8b83d76faf94f6", SAMPLE_RESPONSE);
        assert_eq!(count, 3);
    }

    #[test]
    fn parse_empty_body() {
        assert_eq!(parse_hibp_response("anything", ""), 0);
    }

    #[test]
    fn sha1_prefix_suffix_split() {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(b"password");
        let hash = format!("{:X}", hasher.finalize());
        assert_eq!(hash.len(), 40);
        let prefix = &hash[..5];
        let suffix = &hash[5..];
        assert_eq!(prefix.len(), 5);
        assert_eq!(suffix.len(), 35);
    }
}
