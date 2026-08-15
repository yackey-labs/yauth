// jwks_stale_bound_test.go — the cached JWKS has no expiry date.
//
// jwksCache.refresh serves the cached set whenever the fetch fails:
//
//	set, err := fetchJWKS(ctx, c.client, url)
//	if err != nil {
//	    if ok { return entry.set, nil }   // <- no age bound
//	    return nil, err
//	}
//
// ttl and cooldown govern only the happy path — how often a REACHABLE IdP is
// re-read. Once the IdP stops answering, that branch is the whole policy, and
// it has no upper limit. The set stays trusted for the life of the process.
//
// Why that is a security property and not merely a staleness bug: this cache
// is the key material behind verifyIDToken, which is the entire trust boundary
// for an SSO login. Revocation of an upstream signing key is published by
// REMOVING it from the JWKS document — that is the only mechanism OIDC gives an
// IdP. So an attacker holding a compromised key that the IdP has since retired
// needs exactly one thing to keep using it: for yauth's fetch of the JWKS URL
// to keep failing. They already have a position that let them take the key;
// making one URL unreachable from the yauth host is not a higher bar. The
// refresh path answers "IdP unreachable" and "this key was revoked" identically,
// and picks the insecure reading forever.
//
// The fix is an absolute bound: serve a stale set through a transient outage,
// refuse it once the outage stops being transient. Both halves are asserted
// here — a bound that also breaks the transient case would be a worse bug than
// the one being fixed.
package ssooidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// flakyJWKS is an IdP JWKS endpoint that can be switched to failing, so a test
// can model an outage that starts after the document has been cached.
type flakyJWKS struct {
	url     string
	failing atomic.Bool
	hits    atomic.Int64
}

func newFlakyJWKS(t *testing.T) *flakyJWKS {
	t.Helper()
	s := newIDTokenSigner(t)
	f := &flakyJWKS{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.hits.Add(1)
		if f.failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		set := jwk.NewSet()
		k, err := jwk.Import(&s.key.PublicKey)
		if err != nil {
			t.Error(err)
			return
		}
		_ = k.Set(jwk.KeyIDKey, s.kid)
		_ = k.Set(jwk.AlgorithmKey, jwa.RS256())
		_ = set.AddKey(k)
		buf, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf)
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// TestJWKSCache_RefusesAStaleSetOnceTheStalenessBoundElapses is the refusal.
//
// The IdP answers once, then goes dark permanently. Past the bound the cache
// must report the failure rather than keep vouching for key material it can no
// longer confirm.
func TestJWKSCache_RefusesAStaleSetOnceTheStalenessBoundElapses(t *testing.T) {
	idp := newFlakyJWKS(t)
	const maxStale = 60 * time.Millisecond
	c := newJWKSCache(time.Nanosecond, time.Nanosecond, maxStale, &http.Client{Timeout: 5 * time.Second}, nil)
	ctx := context.Background()

	if _, err := c.get(ctx, idp.url, ""); err != nil {
		t.Fatalf("seed fetch should succeed: %v", err)
	}
	idp.failing.Store(true)

	// Past the bound the cached document is no longer evidence of anything.
	time.Sleep(maxStale + 90*time.Millisecond)
	if _, err := c.get(ctx, idp.url, ""); err == nil {
		t.Fatal("cache served a JWKS it had been unable to re-confirm for longer than the staleness bound; " +
			"a signing key the IdP has revoked stays trusted for as long as an attacker keeps the JWKS URL failing")
	}
}

// TestJWKSCache_ServesAStaleSetThroughATransientOutage is the positive control,
// and it is the reason the fix is a BOUND rather than a refusal.
//
// Without this, "fail closed on any fetch error" would pass the test above
// while turning every hiccup at the IdP — a redeploy, a 502 from a CDN — into a
// site-wide login outage. That trade is not worth making and this pins it.
func TestJWKSCache_ServesAStaleSetThroughATransientOutage(t *testing.T) {
	idp := newFlakyJWKS(t)
	c := newJWKSCache(time.Nanosecond, time.Nanosecond, time.Hour, &http.Client{Timeout: 5 * time.Second}, nil)
	ctx := context.Background()

	if _, err := c.get(ctx, idp.url, ""); err != nil {
		t.Fatalf("seed fetch should succeed: %v", err)
	}
	idp.failing.Store(true)

	set, err := c.get(ctx, idp.url, "")
	if err != nil {
		t.Fatalf("a transient IdP failure must not cascade into a login outage: %v", err)
	}
	if set == nil || set.Len() == 0 {
		t.Fatal("expected the cached key set to be served during the outage")
	}
	if idp.hits.Load() < 2 {
		t.Fatalf("expected the cache to have attempted a re-fetch, got %d hits", idp.hits.Load())
	}
}

// TestJWKSCache_RecoversWhenTheIdPReturns proves the bound is not a one-way
// latch: an entry refused as too stale must be replaced the moment the IdP
// answers again, without operator intervention.
func TestJWKSCache_RecoversWhenTheIdPReturns(t *testing.T) {
	idp := newFlakyJWKS(t)
	const maxStale = 60 * time.Millisecond
	c := newJWKSCache(time.Nanosecond, time.Nanosecond, maxStale, &http.Client{Timeout: 5 * time.Second}, nil)
	ctx := context.Background()

	if _, err := c.get(ctx, idp.url, ""); err != nil {
		t.Fatalf("seed fetch should succeed: %v", err)
	}
	idp.failing.Store(true)
	time.Sleep(maxStale + 90*time.Millisecond)
	if _, err := c.get(ctx, idp.url, ""); err == nil {
		t.Fatal("expected refusal past the bound")
	}

	idp.failing.Store(false)
	set, err := c.get(ctx, idp.url, "")
	if err != nil {
		t.Fatalf("cache should recover once the IdP answers again: %v", err)
	}
	if set == nil || set.Len() == 0 {
		t.Fatal("expected a freshly fetched key set after recovery")
	}
}
