package passkey

// OIDC-logout repository stubs so *fakeRepo satisfies repo.Repository. This
// package's tests don't exercise logout; tests that do use repo/memrepo.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/yackey-labs/yauth/domain"
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

func (*fakeRepo) ListAllSsoConnections(context.Context) ([]*domain.SsoConnection, error) {
	return nil, nil
}

func (*fakeRepo) TouchOAuth2ClientLastUsed(context.Context, string, time.Time) error { return nil }

func (*fakeRepo) PurgeStaleDynamicClients(context.Context, time.Time) ([]string, error) {
	return nil, nil
}
