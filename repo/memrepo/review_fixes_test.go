package memrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

func TestDeleteUser_RefusesLastOwnerAndKeepsOrgKeys(t *testing.T) {
	ctx := context.Background()
	r := New()
	now := time.Now().UTC()
	for _, id := range []string{"u1", "u2"} {
		if _, err := r.CreateUser(ctx, domain.NewUser{ID: id, Email: id + "@x.io", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.CreateOrganization(ctx, newOrgInput("o1", "o1", "o1")); err != nil {
		t.Fatal(err)
	}
	mk := func(id, uid string) {
		if _, err := r.CreateMembership(ctx, domain.NewMembership{ID: id, OrganizationID: "o1", UserID: uid,
			Role: "owner", Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now, OwnerRoleAuthorized: true}); err != nil {
			t.Fatal(err)
		}
	}
	mk("m1", "u1")
	org := "o1"
	if err := r.CreateAPIKey(ctx, domain.NewAPIKey{ID: "k1", OrganizationID: &org, KeyPrefix: "p1", KeyHash: "h",
		Name: "scim", CreatedAt: now, CreatedByUserID: "u1"}); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteUser(ctx, "u1"); !errors.Is(err, yautherr.ErrOwnerProtected) {
		t.Fatalf("sole owner delete: want ErrOwnerProtected, got %v", err)
	}
	mk("m2", "u2")
	if err := r.DeleteUser(ctx, "u1"); err != nil {
		t.Fatalf("co-owned delete: %v", err)
	}
	if _, ok := r.apiKeys["k1"]; !ok {
		t.Fatal("org-scoped key minted by the deleted user must survive")
	}
}

func TestUpdateGroup_ClearFlags(t *testing.T) {
	ctx := context.Background()
	r := New()
	now := time.Now().UTC()
	d, e := "d", "e"
	if _, err := r.CreateGroup(ctx, domain.NewGroup{ID: "g", OrganizationID: "o", Name: "n", Description: &d, ExternalID: &e, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	g, err := r.UpdateGroup(ctx, "g", domain.UpdateGroup{ClearDescription: true, ClearExternalID: true})
	if err != nil {
		t.Fatal(err)
	}
	if g.Description != nil || g.ExternalID != nil {
		t.Fatalf("not cleared: %+v", g)
	}
}

func TestDeviceCode_PendingCannotBeConsumed(t *testing.T) {
	ctx := context.Background()
	r := New()
	now := time.Now().UTC()
	if err := r.CreateDeviceCode(ctx, domain.NewDeviceCode{ID: "d", DeviceCodeHash: "h", UserCode: "u", ClientID: "c",
		Status: "pending", Interval: 5, ExpiresAt: now.Add(time.Minute), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateDeviceCodeStatus(ctx, "d", "consumed", nil); !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("pending->consumed must lose, got %v", err)
	}
	if err := r.UpdateDeviceCodeStatus(ctx, "d", "approved", nil); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateDeviceCodeStatus(ctx, "d", "consumed", nil); err != nil {
		t.Fatal(err)
	}
}
