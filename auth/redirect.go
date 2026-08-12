package auth

import "strings"

// SafeRedirect filters a caller-supplied redirect target against an
// allow-list of absolute URL prefixes. It returns the input unchanged when the
// target is safe, and "" when it is not — callers fall back to their own
// default landing page rather than honouring an attacker-controlled URL.
//
// It is the single implementation shared by every plugin that accepts a
// `redirect_url` query parameter (oauth, sso_oidc, sso_saml). Those three
// carried byte-identical copies of the algorithm, which is how a bypass could
// be fixed in one and stay open in the other two.
//
// Two classes of input are refused before the allow-list is consulted at all:
//
//   - Anything containing a C0 control character or DEL. Browsers STRIP tab,
//     LF and CR from a URL before parsing it (WHATWG URL, "URL parsing"), so
//     "/\n/evil.com" is parsed as "//evil.com" — a protocol-relative URL to
//     another origin. The value reaches the browser byte-for-byte because it
//     is emitted through a huma `header:"Location"` field rather than
//     http.Redirect, so nothing upstream normalises it. Refusing control bytes
//     outright also closes response-splitting via the Location header.
//
//   - A host-relative path whose leading slashes include a BACKSLASH. The
//     WHATWG "relative slash" state treats \ as /, so "/\evil.com" is parsed
//     as "//evil.com" and navigates to https://evil.com/. The pre-existing
//     check tested only for a literal "//" prefix and let every backslash form
//     through.
//
// Host-relative paths ("/dashboard") are always allowed: they cannot escape
// the origin. Absolute URLs must match an allow-list entry exactly, or match
// it as a strict prefix where the following byte is a path terminator — so
// "https://app.example.com" does not admit "https://app.example.com.evil.com".
func SafeRedirect(in string, allowed []string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	if hasControlBytes(in) {
		return ""
	}
	// Normalise backslashes to forward slashes for the PREFIX TEST ONLY; the
	// returned value is always the untouched input, so a legitimate path that
	// happens to contain a backslash deeper in is unaffected.
	norm := strings.ReplaceAll(in, `\`, "/")
	if strings.HasPrefix(norm, "/") && !strings.HasPrefix(norm, "//") {
		return in
	}
	for _, entry := range allowed {
		if entry == "" {
			continue
		}
		if in == entry {
			return in
		}
		// Strict prefix: the byte after the prefix must be a path terminator
		// so "https://app.example.com" cannot match
		// "https://app.example.com.evil.com/...".
		if strings.HasPrefix(in, entry) {
			rest := in[len(entry):]
			if rest == "" || rest[0] == '/' || rest[0] == '?' || rest[0] == '#' {
				return in
			}
		}
	}
	return ""
}

// hasControlBytes reports whether s contains any C0 control character or DEL.
func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
