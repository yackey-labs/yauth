package apikey

// OIDC-logout repository stubs so *fakeRepo satisfies repo.Repository. This
// package's tests don't exercise logout; tests that do use repo/memrepo.

import (
	"context"
	"encoding/json"

	"github.com/yackey-labs/yauth-go/domain"
)

func (*fakeRepo) ListConsentsByUserID(context.Context, string) ([]*domain.Consent, error) {
	return nil, nil
}

func (*fakeRepo) SetOAuth2ClientLogout(context.Context, string, json.RawMessage, *string, bool) (bool, error) {
	return false, nil
}

func (*fakeRepo) ListOAuth2ClientsWithBackchannelLogoutURI(context.Context) ([]*domain.OAuth2Client, error) {
	return nil, nil
}
