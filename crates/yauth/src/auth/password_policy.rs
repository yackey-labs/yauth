use crate::config::PasswordPolicyConfig;

/// Top 100 most common passwords (subset of SecLists). Checked when
/// `disallow_common_passwords` is enabled.
const COMMON_PASSWORDS: &[&str] = &[
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "1234567890",
    "michael",
    "654321",
    "superman",
    "1qaz2wsx",
    "7777777",
    "121212",
    "000000",
    "qazwsx",
    "123qwe",
    "killer",
    "trustno1",
    "jordan",
    "jennifer",
    "zxcvbnm",
    "asdfgh",
    "hunter",
    "buster",
    "soccer",
    "harley",
    "batman",
    "andrew",
    "tigger",
    "sunshine",
    "iloveyou",
    "2000",
    "charlie",
    "robert",
    "thomas",
    "hockey",
    "ranger",
    "daniel",
    "starwars",
    "klaster",
    "112233",
    "george",
    "computer",
    "michelle",
    "jessica",
    "pepper",
    "1111",
    "zxcvbn",
    "555555",
    "11111111",
    "131313",
    "freedom",
    "777777",
    "pass",
    "maggie",
    "159753",
    "aaaaaa",
    "ginger",
    "princess",
    "joshua",
    "cheese",
    "amanda",
    "summer",
    "love",
    "ashley",
    "nicole",
    "chelsea",
    "biteme",
    "matthew",
    "access",
    "yankees",
    "987654321",
    "dallas",
    "austin",
    "thunder",
    "taylor",
    "matrix",
    "mobilemail",
    "admin",
    "passwd",
    "welcome",
    "passw0rd",
    "password1",
    "p@ssw0rd",
];

/// Validate a password against the configured policy. Returns a list of violations
/// (empty = password is valid).
pub fn validate(password: &str, config: &PasswordPolicyConfig) -> Vec<String> {
    let mut violations = Vec::new();

    if password.len() > config.max_length {
        violations.push(format!(
            "Password must be at most {} characters",
            config.max_length
        ));
    }

    if config.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        violations.push("Password must contain at least one uppercase letter".into());
    }

    if config.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        violations.push("Password must contain at least one lowercase letter".into());
    }

    if config.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        violations.push("Password must contain at least one digit".into());
    }

    if config.require_special
        && !password
            .chars()
            .any(|c| !c.is_alphanumeric() && c.is_ascii())
    {
        violations.push("Password must contain at least one special character".into());
    }

    if config.disallow_common_passwords
        && COMMON_PASSWORDS.contains(&password.to_lowercase().as_str())
    {
        violations.push("This password is too common. Please choose a different one.".into());
    }

    violations
}

/// Check if a password matches any of the given historical password hashes.
pub fn check_password_history(password: &str, history_hashes: &[String]) -> bool {
    for hash in history_hashes {
        if crate::auth::password::verify_password(password, hash).unwrap_or(false) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_policy() -> PasswordPolicyConfig {
        PasswordPolicyConfig {
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            disallow_common_passwords: true,
            password_history_count: 0,
        }
    }

    #[test]
    fn valid_password_passes() {
        let violations = validate("MyP@ssw0rd!", &strict_policy());
        assert!(violations.is_empty(), "violations: {:?}", violations);
    }

    #[test]
    fn missing_uppercase() {
        let violations = validate("myp@ssw0rd!", &strict_policy());
        assert!(violations.iter().any(|v| v.contains("uppercase")));
    }

    #[test]
    fn missing_lowercase() {
        let violations = validate("MYP@SSW0RD!", &strict_policy());
        assert!(violations.iter().any(|v| v.contains("lowercase")));
    }

    #[test]
    fn missing_digit() {
        let violations = validate("MyP@ssword!", &strict_policy());
        assert!(violations.iter().any(|v| v.contains("digit")));
    }

    #[test]
    fn missing_special() {
        let violations = validate("MyPassw0rd", &strict_policy());
        assert!(violations.iter().any(|v| v.contains("special")));
    }

    #[test]
    fn too_long() {
        let long = "a".repeat(200);
        let violations = validate(&long, &strict_policy());
        assert!(violations.iter().any(|v| v.contains("at most")));
    }

    #[test]
    fn common_password_rejected() {
        let policy = PasswordPolicyConfig {
            disallow_common_passwords: true,
            ..Default::default()
        };
        let violations = validate("password", &policy);
        assert!(violations.iter().any(|v| v.contains("common")));
    }

    #[test]
    fn common_password_case_insensitive() {
        let policy = PasswordPolicyConfig {
            disallow_common_passwords: true,
            ..Default::default()
        };
        let violations = validate("PASSWORD", &policy);
        assert!(violations.iter().any(|v| v.contains("common")));
    }

    #[test]
    fn default_policy_allows_reasonable_password() {
        let violations = validate("reasonablepassword123", &PasswordPolicyConfig::default());
        assert!(violations.is_empty());
    }

    #[test]
    fn disabled_policy_allows_anything() {
        let policy = PasswordPolicyConfig {
            max_length: 999,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            disallow_common_passwords: false,
            password_history_count: 0,
        };
        let violations = validate("a", &policy);
        assert!(violations.is_empty());
    }
}
