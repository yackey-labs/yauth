package memrepo

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- OAuth2Client ---

func (r *Repo) CreateOAuth2Client(ctx context.Context, input domain.NewOAuth2Client) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.oauth2ClientIDIdx[input.ClientID]; dup {
		return yautherr.ErrConflict
	}
	if _, dup := r.oauth2Clients[input.ID]; dup {
		return yautherr.ErrConflict
	}
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	c := &domain.OAuth2Client{
		ID:                      input.ID,
		ClientID:                input.ClientID,
		ClientSecretHash:        input.ClientSecretHash,
		ClientName:              input.ClientName,
		IsPublic:                input.IsPublic,
		CreatedAt:               created.UTC(),
		TokenEndpointAuthMethod: input.TokenEndpointAuthMethod,
		PublicKeyPEM:            input.PublicKeyPEM,
		JWKSURI:                 input.JWKSURI,
		EnforceGroupAssignment:  input.EnforceGroupAssignment,

		BackchannelLogoutURI:             input.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: input.BackchannelLogoutSessionRequired,
		DynamicallyRegistered:            input.DynamicallyRegistered,
	}
	if len(input.PostLogoutRedirectURIs) > 0 {
		c.PostLogoutRedirectURIs = append([]byte(nil), input.PostLogoutRedirectURIs...)
	} else {
		c.PostLogoutRedirectURIs = json.RawMessage("[]")
	}
	if len(input.RedirectURIs) > 0 {
		c.RedirectURIs = append([]byte(nil), input.RedirectURIs...)
	}
	if len(input.GrantTypes) > 0 {
		c.GrantTypes = append([]byte(nil), input.GrantTypes...)
	}
	if len(input.Scopes) > 0 {
		c.Scopes = append([]byte(nil), input.Scopes...)
	}
	r.oauth2Clients[c.ID] = c
	r.oauth2ClientIDIdx[c.ClientID] = c.ID
	return nil
}

func (r *Repo) GetOAuth2ClientByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.oauth2ClientIDIdx[clientID]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneOAuth2Client(r.oauth2Clients[id]), nil
}

func (r *Repo) SetOAuth2ClientBanned(ctx context.Context, clientID string, bannedAt *time.Time, reason *string) (bool, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.oauth2ClientIDIdx[clientID]
	if !ok {
		return false, nil
	}
	c := r.oauth2Clients[id]
	if bannedAt != nil {
		t := bannedAt.UTC()
		c.BannedAt = &t
	} else {
		c.BannedAt = nil
	}
	c.BannedReason = reason
	return true, nil
}

func (r *Repo) RotateOAuth2ClientPublicKey(ctx context.Context, clientID string, publicKeyPEM *string) (bool, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.oauth2ClientIDIdx[clientID]
	if !ok {
		return false, nil
	}
	r.oauth2Clients[id].PublicKeyPEM = publicKeyPEM
	return true, nil
}

func (r *Repo) ListBannedOAuth2Clients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	matches := make([]*domain.OAuth2Client, 0)
	for _, c := range r.oauth2Clients {
		if c.BannedAt != nil {
			matches = append(matches, c)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].BannedAt.After(*matches[j].BannedAt)
	})
	out := make([]*domain.OAuth2Client, len(matches))
	for i := range matches {
		out[i] = cloneOAuth2Client(matches[i])
	}
	return out, nil
}

func (r *Repo) ListOAuth2Clients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.OAuth2Client, 0, len(r.oauth2Clients))
	for _, c := range r.oauth2Clients {
		out = append(out, cloneOAuth2Client(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (r *Repo) SetOAuth2ClientLogout(ctx context.Context, clientID string, postLogoutRedirectURIs json.RawMessage, backchannelLogoutURI *string, sessionRequired bool) (bool, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.oauth2ClientIDIdx[clientID]
	if !ok {
		return false, nil
	}
	c := r.oauth2Clients[id]
	if len(postLogoutRedirectURIs) > 0 {
		c.PostLogoutRedirectURIs = append([]byte(nil), postLogoutRedirectURIs...)
	} else {
		c.PostLogoutRedirectURIs = json.RawMessage("[]")
	}
	if backchannelLogoutURI != nil {
		s := *backchannelLogoutURI
		c.BackchannelLogoutURI = &s
	} else {
		c.BackchannelLogoutURI = nil
	}
	c.BackchannelLogoutSessionRequired = sessionRequired
	return true, nil
}

func (r *Repo) ListOAuth2ClientsWithBackchannelLogoutURI(ctx context.Context) ([]*domain.OAuth2Client, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.OAuth2Client, 0)
	for _, c := range r.oauth2Clients {
		if c.BackchannelLogoutURI != nil && *c.BackchannelLogoutURI != "" {
			out = append(out, cloneOAuth2Client(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (r *Repo) TouchOAuth2ClientLastUsed(ctx context.Context, clientID string, at time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.oauth2ClientIDIdx[clientID]
	if !ok {
		return nil
	}
	t := at.UTC()
	r.oauth2Clients[id].LastUsedAt = &t
	return nil
}

func (r *Repo) PurgeStaleDynamicClients(ctx context.Context, cutoff time.Time) ([]string, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff = cutoff.UTC()
	swept := make([]string, 0)
	for id, c := range r.oauth2Clients {
		if !c.DynamicallyRegistered || !c.IsPublic || c.BannedAt != nil {
			continue
		}
		last := c.CreatedAt
		if c.LastUsedAt != nil {
			last = *c.LastUsedAt
		}
		if !last.Before(cutoff) {
			continue
		}
		swept = append(swept, c.ClientID)
		// Delete dependents by client_id, then the client row + index.
		for cid, cons := range r.consents {
			if cons.ClientID == c.ClientID {
				delete(r.consents, cid)
			}
		}
		for acid, ac := range r.authCodes {
			if ac.ClientID == c.ClientID {
				delete(r.authCodeHashIdx, ac.CodeHash)
				delete(r.authCodes, acid)
			}
		}
		for dcid, dc := range r.deviceCodes {
			if dc.ClientID == c.ClientID {
				delete(r.deviceCodeHashIdx, dc.DeviceCodeHash)
				delete(r.deviceCodes, dcid)
			}
		}
		delete(r.oauth2ClientIDIdx, c.ClientID)
		delete(r.oauth2Clients, id)
	}
	return swept, nil
}

// --- AuthorizationCode ---

func (r *Repo) CreateAuthorizationCode(ctx context.Context, input domain.NewAuthorizationCode) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	a := &domain.AuthorizationCode{
		ID:                  input.ID,
		CodeHash:            input.CodeHash,
		ClientID:            input.ClientID,
		UserID:              input.UserID,
		RedirectURI:         input.RedirectURI,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		ExpiresAt:           input.ExpiresAt.UTC(),
		Used:                input.Used,
		Nonce:               input.Nonce,
		CreatedAt:           created.UTC(),
	}
	if len(input.Scopes) > 0 {
		a.Scopes = append([]byte(nil), input.Scopes...)
	}
	r.authCodes[a.ID] = a
	r.authCodeHashIdx[a.CodeHash] = a.ID
	return nil
}

func (r *Repo) GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.authCodeHashIdx[codeHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	a := r.authCodes[id]
	if a.Used {
		return nil, yautherr.ErrNotFound
	}
	if !a.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	return cloneAuthorizationCode(a), nil
}

func (r *Repo) ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.authCodeHashIdx[codeHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	a := r.authCodes[id]
	if a.Used {
		return nil, yautherr.ErrNotFound
	}
	if !a.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	a.Used = true
	return cloneAuthorizationCode(a), nil
}

func (r *Repo) MarkAuthorizationCodeUsed(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.authCodes[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	a.Used = true
	return nil
}

// --- Consent ---

func (r *Repo) CreateConsent(ctx context.Context, input domain.NewConsent) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	c := &domain.Consent{
		ID:        input.ID,
		UserID:    input.UserID,
		ClientID:  input.ClientID,
		CreatedAt: created.UTC(),
	}
	if len(input.Scopes) > 0 {
		c.Scopes = append([]byte(nil), input.Scopes...)
	}
	r.consents[c.ID] = c
	return nil
}

func (r *Repo) GetConsentByUserAndClient(ctx context.Context, userID, clientID string) (*domain.Consent, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.consents {
		if c.UserID == userID && c.ClientID == clientID {
			return cloneConsent(c), nil
		}
	}
	return nil, yautherr.ErrNotFound
}

func (r *Repo) ListConsentsByUserID(ctx context.Context, userID string) ([]*domain.Consent, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Consent, 0)
	for _, c := range r.consents {
		if c.UserID == userID {
			out = append(out, cloneConsent(c))
		}
	}
	return out, nil
}

func (r *Repo) UpdateConsentScopes(ctx context.Context, id string, scopes []byte) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.consents[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	if len(scopes) > 0 {
		c.Scopes = append([]byte(nil), scopes...)
	} else {
		c.Scopes = nil
	}
	return nil
}

// --- DeviceCode ---

func (r *Repo) CreateDeviceCode(ctx context.Context, input domain.NewDeviceCode) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	d := &domain.DeviceCode{
		ID:             input.ID,
		DeviceCodeHash: input.DeviceCodeHash,
		UserCode:       input.UserCode,
		ClientID:       input.ClientID,
		UserID:         input.UserID,
		Status:         input.Status,
		Interval:       input.Interval,
		ExpiresAt:      input.ExpiresAt.UTC(),
		CreatedAt:      created.UTC(),
	}
	if len(input.Scopes) > 0 {
		d.Scopes = append([]byte(nil), input.Scopes...)
	}
	r.deviceCodes[d.ID] = d
	r.deviceCodeHashIdx[d.DeviceCodeHash] = d.ID
	return nil
}

func (r *Repo) GetDeviceCodeByUserCodePending(ctx context.Context, userCode string) (*domain.DeviceCode, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, d := range r.deviceCodes {
		if d.UserCode != userCode || d.Status != "pending" {
			continue
		}
		if !d.ExpiresAt.UTC().After(time.Now().UTC()) {
			return nil, yautherr.ErrNotFound
		}
		return cloneDeviceCode(d), nil
	}
	return nil, yautherr.ErrNotFound
}

func (r *Repo) GetDeviceCodeByDeviceCodeHash(ctx context.Context, deviceCodeHash string) (*domain.DeviceCode, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.deviceCodeHashIdx[deviceCodeHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneDeviceCode(r.deviceCodes[id]), nil
}

func (r *Repo) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.deviceCodes[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	d.Status = status
	if userID != nil {
		d.UserID = userID
	}
	return nil
}

func (r *Repo) UpdateDeviceCodeLastPolled(ctx context.Context, id string, at time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.deviceCodes[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	t := at.UTC()
	d.LastPolledAt = &t
	return nil
}

func (r *Repo) UpdateDeviceCodeInterval(ctx context.Context, id string, interval int) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.deviceCodes[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	d.Interval = interval
	return nil
}

// --- OIDCNonce ---

func (r *Repo) CreateOIDCNonce(ctx context.Context, input domain.NewOIDCNonce) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	n := &domain.OIDCNonce{
		ID:                  input.ID,
		NonceHash:           input.NonceHash,
		AuthorizationCodeID: input.AuthorizationCodeID,
		CreatedAt:           created.UTC(),
	}
	r.oidcNonces[n.ID] = n
	r.oidcNonceHashIdx[n.NonceHash] = n.ID
	return nil
}

func (r *Repo) GetOIDCNonceByHash(ctx context.Context, nonceHash string) (*domain.OIDCNonce, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.oidcNonceHashIdx[nonceHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneOIDCNonce(r.oidcNonces[id]), nil
}

func (r *Repo) DeleteOIDCNonce(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.oidcNonces[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	delete(r.oidcNonceHashIdx, n.NonceHash)
	delete(r.oidcNonces, id)
	return nil
}
