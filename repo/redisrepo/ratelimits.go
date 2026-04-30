package redisrepo

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yackey-labs/yauth-go/domain"
)

// rateLimitScript is an atomic INCR + conditional EXPIRE.
//
// The first INCR on a fresh key sets the TTL in the same script
// invocation, closing the gap where a crash between INCR and a separate
// EXPIRE could leave a counter without a TTL — that would permanently
// rate-limit the key.
//
// Returns: { count, ttl_seconds }. ttl=-2 means "key does not exist".
const rateLimitScript = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
`

var rateLimitLua = redis.NewScript(rateLimitScript)

// CheckRateLimit uses Redis as the source of truth for the fixed-window
// counter. On Redis failure we fall back to the inner repo so the caller
// remains fail-open (per RateLimitRepository contract).
func (r *Repo) CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (domain.RateLimitResult, error) {
	ctx = ctxOrBackground(ctx)

	windowSecs := int64(window / time.Second)
	if windowSecs <= 0 {
		windowSecs = 1
	}

	res, err := rateLimitLua.Run(ctx, r.client, []string{r.rateKey(key)}, windowSecs).Result()
	if err != nil {
		r.warn("rate limit check: redis script error: %v (falling back)", err)
		return r.Repository.CheckRateLimit(ctx, key, limit, window)
	}

	arr, ok := res.([]any)
	if !ok || len(arr) != 2 {
		r.warn("rate limit check: unexpected redis script result %T (falling back)", res)
		return r.Repository.CheckRateLimit(ctx, key, limit, window)
	}
	count, _ := arr[0].(int64)
	ttl, _ := arr[1].(int64)

	if int(count) > limit {
		retry := ttl
		if retry < 0 {
			retry = 0
		}
		return domain.RateLimitResult{
			Allowed:    false,
			Remaining:  0,
			RetryAfter: time.Duration(retry) * time.Second,
		}, nil
	}
	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}
	return domain.RateLimitResult{
		Allowed:    true,
		Remaining:  remaining,
		RetryAfter: 0,
	}, nil
}
