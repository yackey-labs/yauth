package redisrepo

// Key formatters for the Redis cache.
//
// All keys are namespaced under Options.KeyPrefix (default "yauth:") so a
// single Redis instance can host caches for multiple yauth tenants without
// collisions.
//
// Layout:
//   {prefix}cached:session:{token_hash}     — string (JSON-encoded *domain.Session)
//   {prefix}cached:session_neg:{token_hash} — string ("1") for negative cache
//   {prefix}cached:user_sessions:{user_id}  — set of token hashes (for fan-out invalidation)
//   {prefix}cached:challenge:{key}          — string (JSON-encoded *domain.Challenge)
//   {prefix}cached:challenge_neg:{key}      — string ("1") negative cache
//   {prefix}rate:{key}                      — counter (Redis is source of truth)
//   {prefix}revoked:{jti}                   — string ("1")
//   {prefix}cached:revoked_neg:{jti}        — string ("1") negative cache

func (r *Repo) sessionKey(tokenHash string) string {
	return r.opts.KeyPrefix + "cached:session:" + tokenHash
}

func (r *Repo) sessionNegKey(tokenHash string) string {
	return r.opts.KeyPrefix + "cached:session_neg:" + tokenHash
}

func (r *Repo) userSessionsKey(userID string) string {
	return r.opts.KeyPrefix + "cached:user_sessions:" + userID
}

func (r *Repo) challengeKey(key string) string {
	return r.opts.KeyPrefix + "cached:challenge:" + key
}

func (r *Repo) challengeNegKey(key string) string {
	return r.opts.KeyPrefix + "cached:challenge_neg:" + key
}

func (r *Repo) rateKey(key string) string {
	return r.opts.KeyPrefix + "rate:" + key
}

func (r *Repo) revokedKey(jti string) string {
	return r.opts.KeyPrefix + "revoked:" + jti
}

func (r *Repo) revokedNegKey(jti string) string {
	return r.opts.KeyPrefix + "cached:revoked_neg:" + jti
}
