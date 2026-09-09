package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limit is a fixed-window quota.
type Limit struct {
	Requests int
	Window   time.Duration
}

// Rate limits applied to the credential endpoints. The per-account limit is
// what actually stops credential stuffing: an attacker rotating through a
// botnet defeats a per-IP limit, but every attempt still lands on one account.
// The per-IP limit stops a single host from sweeping many accounts.
var (
	LoginPerAccount  = Limit{Requests: 5, Window: 15 * time.Minute}
	LoginPerIP       = Limit{Requests: 20, Window: 15 * time.Minute}
	RegisterPerIP    = Limit{Requests: 5, Window: time.Hour}
	PasswordChangeIP = Limit{Requests: 10, Window: time.Hour}
)

type RateLimiter struct {
	rdb *redis.Client
}

func NewRateLimiter(rdb *redis.Client) *RateLimiter { return &RateLimiter{rdb: rdb} }

// incrementAndExpire counts a hit and sets the window TTL in one atomic step.
// Doing this as INCR followed by EXPIRE would leave a counter with no TTL — and
// therefore a permanent lockout — if the process died in between.
var incrementAndExpire = redis.NewScript(`
	local count = redis.call('INCR', KEYS[1])
	if count == 1 then
		redis.call('PEXPIRE', KEYS[1], ARGV[1])
	end
	return {count, redis.call('PTTL', KEYS[1])}
`)

// Allow records an attempt and reports whether it is within quota, along with
// how long the caller must wait once it is not.
func (rl *RateLimiter) Allow(ctx context.Context, key string, limit Limit) (bool, time.Duration, error) {
	res, err := incrementAndExpire.Run(ctx, rl.rdb, []string{"rl:" + key}, limit.Window.Milliseconds()).Slice()
	if err != nil {
		return false, 0, fmt.Errorf("rate limit %s: %w", key, err)
	}
	if len(res) != 2 {
		return false, 0, fmt.Errorf("rate limit %s: unexpected reply", key)
	}

	count, _ := res[0].(int64)
	ttlMillis, _ := res[1].(int64)

	if count > int64(limit.Requests) {
		retryAfter := time.Duration(ttlMillis) * time.Millisecond
		if retryAfter < 0 {
			retryAfter = limit.Window
		}
		return false, retryAfter, nil
	}
	return true, 0, nil
}

// Reset clears a counter. Called after a successful login so a user who
// finally remembers their password is not still locked out.
func (rl *RateLimiter) Reset(ctx context.Context, key string) error {
	if err := rl.rdb.Del(ctx, "rl:"+key).Err(); err != nil {
		return fmt.Errorf("reset rate limit %s: %w", key, err)
	}
	return nil
}
