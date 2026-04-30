// Package hibp implements the HaveIBeenPwned Passwords API
// k-anonymity password-breach check.
//
// Callers SHA-1 the candidate password, send only the first five
// characters of the hex digest (the "k-anonymity prefix") to
// api.pwnedpasswords.com/range/<prefix>, and search the response for
// the remaining 35-character suffix to learn how many breaches
// the password appears in. The plaintext password and full hash are
// never transmitted.
//
// CheckPwned returns a count > 0 when the password is breached.
// Network or HTTP-level errors are returned to the caller; the typical
// integration is fail-open (treat errors as count=0 + log) so a
// transient HIBP outage does not block all registrations.
package hibp

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultEndpoint is the production HIBP range API.
const DefaultEndpoint = "https://api.pwnedpasswords.com/range/"

// DefaultUserAgent is the User-Agent header sent on outbound HIBP
// requests. The HIBP API requires a non-empty UA.
const DefaultUserAgent = "yauth-go-security-check"

// DefaultTimeout is the per-request timeout used when a Checker is
// constructed without a custom *http.Client.
const DefaultTimeout = 5 * time.Second

// Checker performs k-anonymity password-breach lookups against the
// HIBP range API. The zero value uses sensible defaults; populate
// fields to override the endpoint or HTTP client.
type Checker struct {
	// Endpoint is the base URL the prefix is appended to. Empty =
	// DefaultEndpoint.
	Endpoint string
	// Client is the HTTP client used for the range request. Nil = a
	// fresh http.Client with DefaultTimeout.
	Client *http.Client
	// UserAgent is the User-Agent header. Empty = DefaultUserAgent.
	UserAgent string
}

// CheckPwned hashes password with SHA-1, queries the HIBP range API
// for the matching prefix, and returns the breach count for the full
// hash (0 if the password is not present in the response).
//
// Errors are reserved for genuine failures (network, non-2xx HTTP,
// malformed body). The plaintext password is not transmitted.
func (c *Checker) CheckPwned(ctx context.Context, password string) (int, error) {
	prefix, suffix := hashAndSplit(password)

	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	ua := c.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+prefix, nil)
	if err != nil {
		return 0, fmt.Errorf("hibp: build request: %w", err)
	}
	req.Header.Set("User-Agent", ua)
	// Add-Padding asks HIBP to pad the response with random
	// chaff suffixes, hardening against correlation attacks on the
	// prefix endpoint.
	req.Header.Set("Add-Padding", "true")

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("hibp: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("hibp: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("hibp: read body: %w", err)
	}
	return parseResponse(suffix, string(body)), nil
}

// hashAndSplit returns (uppercase prefix, uppercase suffix) of the
// SHA-1 hex digest of password. The prefix is the first 5 chars; the
// suffix is the remaining 35.
func hashAndSplit(password string) (string, string) {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // SHA-1 is required by the HIBP API contract.
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	return hash[:5], hash[5:]
}

// parseResponse scans body for "<suffix>:<count>" and returns the
// matched count (case-insensitive on the suffix). 0 means not found.
// Padding rows (count=0) are honored — i.e., padding never produces a
// false positive because any count==0 line is indistinguishable from
// "not found".
func parseResponse(suffix, body string) int {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		gotSuffix := line[:colon]
		if !strings.EqualFold(gotSuffix, suffix) {
			continue
		}
		gotCount := strings.TrimSpace(line[colon+1:])
		n, err := strconv.Atoi(gotCount)
		if err != nil {
			return 1
		}
		return n
	}
	return 0
}
