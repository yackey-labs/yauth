package ssooidc

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func ssoTestKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("test-key-test-key-test-key-test!"))
	return k
}

func TestMapGroupToRole(t *testing.T) {
	if got := mapGroupToRole([]string{"x", "admins"}, map[string]string{"admins": "owner"}); got != "owner" {
		t.Fatalf("matched group: got %q want owner", got)
	}
	if got := mapGroupToRole([]string{"x"}, map[string]string{"admins": "owner"}); got != "" {
		t.Fatalf("no match: got %q want empty", got)
	}
	if got := mapGroupToRole(nil, map[string]string{"admins": "owner"}); got != "" {
		t.Fatalf("no groups: got %q want empty", got)
	}
}

// SeedConnection must encrypt the client_secret at rest and round-trip the
// config (incl. group→role) through the connection codec.
func TestSeedConnectionRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	now := time.Now().UTC()
	org, err := r.CreateOrganization(ctx, domain.NewOrganization{ID: uuid.NewString(), Name: "o", Slug: "o", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	key := ssoTestKey()
	conn, err := SeedConnection(ctx, r, key, SeedConnectionInput{
		OrganizationID:         org.ID,
		Name:                   "idp",
		JitProvisioningEnabled: true,
		DefaultRoleOnJit:       "viewer",
		OIDC: OidcConnectionConfig{
			DiscoveryURL: "https://idp/.well-known/openid-configuration",
			ClientID:     "cid",
			ClientSecret: "supersecret",
			Scopes:       []string{"openid", "groups"},
			// "owner" would be refused by the config validator (the owner ceiling);
			// this test is about the codec round-tripping the map at all.
			ClaimMappings: ClaimMappings{Email: "email", Groups: "groups", GroupToRole: map[string]string{"admins": "admin"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if conn.Status != domain.ConnectionStatusActive {
		t.Fatalf("status = %q, want active", conn.Status)
	}
	// The stored config must not contain the plaintext secret.
	if string(conn.Config) == "" || containsPlaintext(conn.Config, "supersecret") {
		t.Fatalf("client_secret not encrypted at rest")
	}
	got, err := unmarshalOidcConfig(key, conn.Config)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientSecret != "supersecret" {
		t.Fatalf("secret round-trip: got %q", got.ClientSecret)
	}
	if got.ClientID != "cid" {
		t.Fatalf("client_id: got %q", got.ClientID)
	}
	if got.ClaimMappings.GroupToRole["admins"] != "admin" {
		t.Fatalf("group→role lost: %+v", got.ClaimMappings)
	}
}

func containsPlaintext(b []byte, s string) bool {
	return len(b) > 0 && len(s) > 0 && bytesContains(b, []byte(s))
}

func bytesContains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

// JIT must never fail (or actually demote) when it would strip the last owner.
func TestUpsertMembershipNeverDemotesOwner(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	host := newFakeHost(r, "http://idp")
	p := &ssoOIDCPlugin{}
	now := time.Now().UTC()
	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{ID: uuid.NewString(), Name: "o", Slug: "o", CreatedAt: now, UpdatedAt: now})
	u, _ := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "a@b.test", Role: "admin", EmailVerified: true, CreatedAt: now, UpdatedAt: now})
	if _, err := r.CreateMembership(ctx, domain.NewMembership{ID: uuid.NewString(), OrganizationID: org.ID, UserID: u.ID, Role: auth.RoleOwner, Status: domain.MembershipActive, JoinedAt: &now, CreatedAt: now, UpdatedAt: now,
		OwnerRoleAuthorized: true, // test fixture: seeds state directly, bypassing the handler layer
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.upsertMembership(ctx, host, org.ID, u.ID, "viewer"); err != nil {
		t.Fatalf("upsert (owner→viewer) must be a no-op, got error: %v", err)
	}
	m, err := r.GetMembershipByOrgUser(ctx, org.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m.Role != auth.RoleOwner {
		t.Fatalf("owner was demoted to %q", m.Role)
	}
}

// A brand-new SSO user gets a membership at the JIT role.
func TestUpsertMembershipCreatesForNewUser(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	host := newFakeHost(r, "http://idp")
	p := &ssoOIDCPlugin{}
	now := time.Now().UTC()
	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{ID: uuid.NewString(), Name: "o", Slug: "o", CreatedAt: now, UpdatedAt: now})
	u, _ := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "new@b.test", Role: "member", EmailVerified: true, CreatedAt: now, UpdatedAt: now})
	if err := p.upsertMembership(ctx, host, org.ID, u.ID, "viewer"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	m, err := r.GetMembershipByOrgUser(ctx, org.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || m.Role != "viewer" {
		t.Fatalf("membership = %+v, want role viewer", m)
	}
}

// Federate is idempotent: a second call with the same IdP returns the existing
// connection rather than registering a duplicate. (Uses SeedConnection to plant
// the first one, then asserts Federate short-circuits before any HTTP.)
func TestFederateIdempotentReturnsExisting(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	now := time.Now().UTC()
	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{ID: uuid.NewString(), Name: "o", Slug: "o", CreatedAt: now, UpdatedAt: now})
	key := ssoTestKey()
	disco := "https://idp.test/.well-known/openid-configuration"
	first, err := SeedConnection(ctx, r, key, SeedConnectionInput{
		OrganizationID: org.ID, Name: "idp",
		OIDC: OidcConnectionConfig{DiscoveryURL: disco, ClientID: "cid", ClientSecret: "s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// No HTTPClient/endpoint reachable — if Federate tried to register it would
	// fail; idempotency must short-circuit and return the existing connection.
	got, err := Federate(ctx, r, key, FederateInput{DiscoveryURL: disco, OrganizationID: org.ID, ConnectionName: "idp", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("idempotent Federate should not error: %v", err)
	}
	if got.ID != first.ID {
		t.Fatalf("Federate returned a new connection %s, want existing %s", got.ID, first.ID)
	}
}
