// replay.go — process-local replay cache for assertion IDs.
//
// Defense-in-depth against duplicate SAMLResponse delivery within the
// NotOnOrAfter window. crewjam/saml already tracks outstanding request
// IDs for the SP-initiated path; the replay cache covers the IdP-
// initiated path (where there is no request to bind to) and the case
// where an attacker captures a valid Response and replays it inside
// the validity window.
//
// Entries are keyed by (issuer || "\x00" || assertion_id) so two IdPs
// that happen to issue the same ID never collide. Eviction is lazy:
// expired entries are dropped on the next Seen() call after the TTL.
//
// The cache is process-local. Multi-instance deployments accept that
// a determined attacker who lands on a different process within the
// validity window can replay once — that's an acceptable tradeoff for
// not introducing a shared cache dependency. A future Redis-backed
// implementation can drop in by mirroring the interface.
package ssosaml

import (
	"sync"
	"time"
)

type replayCache struct {
	ttl time.Duration
	mu  sync.Mutex
	// Map value is the expiry time; absence means "never seen".
	seen map[string]time.Time
}

func newReplayCache(ttl time.Duration) *replayCache {
	return &replayCache{ttl: ttl, seen: make(map[string]time.Time)}
}

// seenKey composes the lookup key. issuer + assertionID. \x00 byte
// separator picked because it cannot appear in either field (issuers
// are URIs, assertion IDs are XML NCNames).
func seenKey(issuer, assertionID string) string {
	return issuer + "\x00" + assertionID
}

// Seen records an assertion-id + issuer pair as observed. Returns true
// if the pair was already present (and therefore a replay). Returns
// false on the first observation.
//
// The validUntil argument is the assertion's NotOnOrAfter; entries
// live until validUntil + ttl (we keep them around for the configured
// TTL after natural expiry, defending against a clock-skew window).
func (c *replayCache) Seen(issuer, assertionID string, validUntil time.Time) bool {
	if assertionID == "" {
		// A missing ID is the IdP's bug, but we cannot dedupe what
		// has no name. Caller should reject the assertion outright.
		return false
	}
	key := seenKey(issuer, assertionID)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked(now)
	if _, ok := c.seen[key]; ok {
		return true
	}
	exp := validUntil.Add(c.ttl)
	// Defensive: never store an entry that's already expired (would
	// be immediately gc'd, but explicit beats implicit).
	if exp.Before(now) {
		exp = now.Add(c.ttl)
	}
	c.seen[key] = exp
	return false
}

// gcLocked drops expired entries. Cheap O(n) sweep; the cache is
// expected to hold at most a few thousand entries at steady state.
func (c *replayCache) gcLocked(now time.Time) {
	for k, exp := range c.seen {
		if exp.Before(now) {
			delete(c.seen, k)
		}
	}
}

// Len returns the current entry count. Test-only helper.
func (c *replayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
