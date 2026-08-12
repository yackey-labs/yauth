package mfa

import (
	"context"

	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
)

// challengeVerifier is the plugin.MFAVerifier this plugin publishes on the
// host. It exists so a plugin that finishes a login WITHOUT a cookie
// session — bearer's POST /token, whose caller is a native client that
// cannot carry one — can complete the very same pending-session challenge
// /mfa/verify consumes, without importing this package or holding the TOTP
// encryption key.
type challengeVerifier struct {
	p    *mfaPlugin
	host plugin.PluginHost
	repo repo.Repository
}

// VerifyPendingChallenge implements plugin.MFAVerifier. It walks the same
// two steps as handleVerify — consume the pending session, then check the
// code against TOTP and the backup codes — and deliberately collapses
// "unknown pending session" and "wrong code" into a single ok=false so the
// caller cannot tell them apart.
//
// A wrong code emits login.failed HERE rather than in the caller: this is
// the one place both completion paths pass through, so MFA brute force is
// counted by lockout whether the challenge came from the cookie login or
// from /token, and a future caller cannot forget to report it.
func (v *challengeVerifier) VerifyPendingChallenge(ctx context.Context, pendingSessionID, code string) (string, bool, error) {
	userID, found, err := v.p.consumePendingSession(ctx, v.repo, pendingSessionID)
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, nil
	}
	ok, err := v.p.verifyCode(ctx, v.repo, userID, code)
	if err != nil {
		return "", false, err
	}
	if !ok {
		emitMFAFailed(ctx, v.host, userID)
		return "", false, nil
	}
	return userID, true, nil
}

var _ plugin.MFAVerifier = (*challengeVerifier)(nil)
