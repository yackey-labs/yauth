package apikey

// Group repository stubs so *fakeRepo satisfies repo.Repository. This package's
// tests don't exercise groups; tests that do use repo/memrepo instead.

import (
	"context"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

func (*fakeRepo) CreateGroup(context.Context, domain.NewGroup) (domain.Group, error) {
	return domain.Group{}, nil
}
func (*fakeRepo) GetGroupByID(context.Context, string) (*domain.Group, error) {
	return nil, yautherr.ErrNotFound
}
func (*fakeRepo) GetGroupByOrgAndName(context.Context, string, string) (*domain.Group, error) {
	return nil, yautherr.ErrNotFound
}
func (*fakeRepo) GetGroupByOrgAndExternalID(context.Context, string, string) (*domain.Group, error) {
	return nil, yautherr.ErrNotFound
}
func (*fakeRepo) ListGroupsByOrg(context.Context, string) ([]*domain.Group, error) { return nil, nil }
func (*fakeRepo) UpdateGroup(context.Context, string, domain.UpdateGroup) (domain.Group, error) {
	return domain.Group{}, yautherr.ErrNotFound
}
func (*fakeRepo) DeleteGroup(context.Context, string) error                       { return nil }
func (*fakeRepo) AddGroupMember(context.Context, string, string, time.Time) error { return nil }
func (*fakeRepo) RemoveGroupMember(context.Context, string, string) error         { return nil }
func (*fakeRepo) ListGroupMembers(context.Context, string) ([]*domain.User, error) {
	return nil, nil
}
func (*fakeRepo) ListGroupsForUser(context.Context, string, string) ([]*domain.Group, error) {
	return nil, nil
}
func (*fakeRepo) IsGroupMember(context.Context, string, string) (bool, error) { return false, nil }
func (*fakeRepo) AssignClientGroup(context.Context, string, string, time.Time) error {
	return nil
}
func (*fakeRepo) UnassignClientGroup(context.Context, string, string) error { return nil }
func (*fakeRepo) ListClientGroups(context.Context, string) ([]*domain.Group, error) {
	return nil, nil
}
func (*fakeRepo) UserInAssignedGroup(context.Context, string, string) (bool, error) {
	return false, nil
}
func (*fakeRepo) SetClientEnforceGroupAssignment(context.Context, string, bool) error { return nil }

func (*fakeRepo) ListGroupNamesForUser(context.Context, string) ([]string, error) {
	return nil, nil
}

func (*fakeRepo) AssignClientRole(context.Context, domain.NewClientRoleAssignment) error { return nil }
func (*fakeRepo) UnassignClientRole(context.Context, string) error                       { return nil }
func (*fakeRepo) ListClientRoleAssignments(context.Context, string) ([]*domain.ClientRoleAssignment, error) {
	return nil, nil
}
func (*fakeRepo) ResolveUserRolesForClient(context.Context, string, string) ([]string, error) {
	return nil, nil
}
func (*fakeRepo) ListOAuth2Clients(context.Context) ([]*domain.OAuth2Client, error) { return nil, nil }

func (*fakeRepo) RevokeAllUserRefreshTokens(context.Context, string) (int64, error) { return 0, nil }
