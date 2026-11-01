package memrepo

import (
	"context"
	"sort"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- User ---

func (r *Repo) CreateUser(ctx context.Context, input domain.NewUser) (domain.User, error) {
	_ = ensureCtx(ctx)
	// Fold at the store, not at the caller. See domain.NormalizeEmail: every
	// handler already did this, the repository did not, and the repository is
	// public API that embedders call directly.
	input.Email = domain.NormalizeEmail(input.Email)
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, dup := r.emailIdx[input.Email]; dup {
		return domain.User{}, yautherr.ErrUserExists
	}
	if _, dup := r.users[input.ID]; dup {
		return domain.User{}, yautherr.ErrUserExists
	}

	now := time.Now().UTC()
	created := input.CreatedAt
	if created.IsZero() {
		created = now
	}
	updated := input.UpdatedAt
	if updated.IsZero() {
		updated = now
	}

	u := &domain.User{
		ID:                 input.ID,
		Email:              input.Email,
		DisplayName:        input.DisplayName,
		EmailVerified:      input.EmailVerified,
		Role:               input.Role,
		Banned:             input.Banned,
		BannedReason:       input.BannedReason,
		BannedUntil:        input.BannedUntil,
		SuspendedAt:        input.SuspendedAt,
		SuspendedReason:    input.SuspendedReason,
		ActivatesAt:        input.ActivatesAt,
		MustChangePassword: input.MustChangePassword,
		CreatedAt:          created.UTC(),
		UpdatedAt:          updated.UTC(),
	}
	if u.BannedUntil != nil {
		t := u.BannedUntil.UTC()
		u.BannedUntil = &t
	}
	r.users[u.ID] = u
	r.emailIdx[u.Email] = u.ID
	return *cloneUser(u), nil
}

func (r *Repo) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneUser(u), nil
}

func (r *Repo) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.emailIdx[domain.NormalizeEmail(email)]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	u := r.users[id]
	return cloneUser(u), nil
}

func (r *Repo) UpdateUser(ctx context.Context, id string, changes domain.UpdateUser) (domain.User, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()

	u, ok := r.users[id]
	if !ok {
		return domain.User{}, yautherr.ErrNotFound
	}

	if changes.Email != nil {
		folded := domain.NormalizeEmail(*changes.Email)
		changes.Email = &folded
	}
	if changes.Email != nil && *changes.Email != u.Email {
		if other, dup := r.emailIdx[*changes.Email]; dup && other != id {
			return domain.User{}, yautherr.ErrUserExists
		}
		delete(r.emailIdx, u.Email)
		u.Email = *changes.Email
		r.emailIdx[u.Email] = id
	}
	if changes.DisplayName != nil {
		u.DisplayName = *changes.DisplayName
	}
	if changes.EmailVerified != nil {
		u.EmailVerified = *changes.EmailVerified
	}
	if changes.Role != nil {
		u.Role = *changes.Role
	}
	if changes.Banned != nil {
		u.Banned = *changes.Banned
	}
	if changes.BannedReason != nil {
		u.BannedReason = *changes.BannedReason
	}
	if changes.BannedUntil != nil {
		if v := *changes.BannedUntil; v != nil {
			t := v.UTC()
			u.BannedUntil = &t
		} else {
			u.BannedUntil = nil
		}
	}
	if changes.SuspendedAt != nil {
		if v := *changes.SuspendedAt; v != nil {
			t := v.UTC()
			u.SuspendedAt = &t
		} else {
			u.SuspendedAt = nil
		}
	}
	if changes.SuspendedReason != nil {
		u.SuspendedReason = *changes.SuspendedReason
	}
	if changes.ActivatesAt != nil {
		if v := *changes.ActivatesAt; v != nil {
			t := v.UTC()
			u.ActivatesAt = &t
		} else {
			u.ActivatesAt = nil
		}
	}
	if changes.UpdatedAt != nil {
		u.UpdatedAt = changes.UpdatedAt.UTC()
	}
	return *cloneUser(u), nil
}

func (r *Repo) SetUserMustChangePassword(ctx context.Context, userID string, must bool) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return yautherr.ErrNotFound
	}
	u.MustChangePassword = must
	u.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *Repo) DeleteUser(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	delete(r.emailIdx, u.Email)
	delete(r.users, id)
	// Explicit cascade: memrepo holds no foreign keys either, so every
	// user-owned row must be removed by hand, mirroring pgxrepo's
	// DeleteUser cascade. Audit log rows deliberately survive (the trail
	// must outlive the user); challenges, rate-limit windows and
	// revocations are keyed by opaque caller-chosen keys rather than the
	// user id, and OAuth/SSO login-state rows carry no user column and
	// expire in minutes — none of those are user-mapped.
	for sid, s := range r.sessions {
		if s.UserID == id {
			delete(r.sessionTokenIdx, s.TokenHash)
			delete(r.sessions, sid)
		}
	}
	for rid, rt := range r.refreshTokens {
		if rt.UserID == id {
			delete(r.refreshTokenIdx, rt.TokenHash)
			delete(r.refreshTokens, rid)
		}
	}
	for kid, k := range r.apiKeys {
		if (k.UserID != nil && *k.UserID == id) || k.CreatedByUserID == id {
			delete(r.apiKeyPrefixIdx, k.KeyPrefix)
			delete(r.apiKeys, kid)
		}
	}
	for oid, oa := range r.oauthAccounts {
		if oa.UserID == id {
			delete(r.oauthAccounts, oid)
		}
	}
	for cid, c := range r.consents {
		if c.UserID == id {
			delete(r.consents, cid)
		}
	}
	for mid, m := range r.memberships {
		if m.UserID == id {
			delete(r.membershipOrgUserIdx, membershipKey(m.OrganizationID, m.UserID))
			delete(r.memberships, mid)
		}
	}
	for _, members := range r.groupMembers {
		delete(members, id)
	}
	for aid, a := range r.clientRoles {
		if a.UserID != nil && *a.UserID == id {
			delete(r.clientRoles, aid)
		}
	}
	for pid, p := range r.passkeys {
		if p.UserID == id {
			delete(r.passkeys, pid)
		}
	}
	for tid, ts := range r.totp {
		if ts.UserID == id {
			delete(r.totp, tid)
		}
	}
	for bid, b := range r.backupCodes {
		if b.UserID == id {
			delete(r.backupCodes, bid)
		}
	}
	delete(r.passwords, id)
	delete(r.passwordHistory, id)
	for eid, ev := range r.emailVerifs {
		if ev.UserID == id {
			delete(r.emailVerifTokenIdx, ev.TokenHash)
			delete(r.emailVerifs, eid)
		}
	}
	for pid, pr := range r.passwordResets {
		if pr.UserID == id {
			delete(r.passwordResetTokenIdx, pr.TokenHash)
			delete(r.passwordResets, pid)
		}
	}
	if lid, ok := r.accountLockUserIdx[id]; ok {
		delete(r.accountLockUserIdx, id)
		delete(r.accountLocks, lid)
	}
	for tid, ut := range r.unlockTokens {
		if ut.UserID == id {
			delete(r.unlockTokenHashIdx, ut.TokenHash)
			delete(r.unlockTokens, tid)
		}
	}
	for aid, ac := range r.authCodes {
		if ac.UserID == id {
			delete(r.authCodeHashIdx, ac.CodeHash)
			// Nonces are keyed by authorization code, not by user; drop
			// the ones anchored to a deleted code.
			for nid, n := range r.oidcNonces {
				if n.AuthorizationCodeID == aid {
					delete(r.oidcNonceHashIdx, n.NonceHash)
					delete(r.oidcNonces, nid)
				}
			}
			delete(r.authCodes, aid)
		}
	}
	for did, dc := range r.deviceCodes {
		if dc.UserID != nil && *dc.UserID == id {
			delete(r.deviceCodeHashIdx, dc.DeviceCodeHash)
			delete(r.deviceCodes, did)
		}
	}
	for mlid, ml := range r.magicLinks {
		if ml.Email == u.Email {
			delete(r.magicLinkTokenIdx, ml.TokenHash)
			delete(r.magicLinks, mlid)
		}
	}
	// Cascade external identities (yauth #93 / yauth-go #23). The
	// (provider, external_id) -> id index must be kept consistent.
	for eid, ext := range r.extIdentities {
		if ext.UserID == id {
			delete(r.extIdentityProviderIdx, ext.Provider+"|"+ext.ExternalID)
			delete(r.extIdentities, eid)
		}
	}
	return nil
}

func (r *Repo) AnyUserExists(ctx context.Context) (bool, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.users) > 0, nil
}

func (r *Repo) ListUsers(ctx context.Context, search string, limit, offset int) ([]*domain.User, int64, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()

	matches := make([]*domain.User, 0, len(r.users))
	for _, u := range r.users {
		if search != "" {
			disp := ""
			if u.DisplayName != nil {
				disp = *u.DisplayName
			}
			if !containsFold(u.Email, search) && !containsFold(disp, search) {
				continue
			}
		}
		matches = append(matches, u)
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})

	total := int64(len(matches))
	if offset > 0 {
		if offset >= len(matches) {
			return []*domain.User{}, total, nil
		}
		matches = matches[offset:]
	}
	if limit > 0 && limit < len(matches) {
		matches = matches[:limit]
	}
	out := make([]*domain.User, len(matches))
	for i := range matches {
		out[i] = cloneUser(matches[i])
	}
	return out, total, nil
}
