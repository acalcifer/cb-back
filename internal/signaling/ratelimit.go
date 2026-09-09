package signaling

import "time"

// Inbound message budget for one connection.
//
// ICE candidates arrive in bursts of tens during negotiation, so the bucket is
// deep enough to absorb a normal call setup. Sustained traffic well past that
// is not a client that is negotiating — it is one flooding the room, which
// matters more now that any signed-in user can join any room.
const (
	messageBurst      = 120
	messagesPerSecond = 60
)

// tokenBucket meters messages without a timer or goroutine: tokens accrue from
// elapsed time on each call.
type tokenBucket struct {
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
}

func newTokenBucket(capacity, ratePerSecond float64, now time.Time) *tokenBucket {
	return &tokenBucket{tokens: capacity, capacity: capacity, rate: ratePerSecond, last: now}
}

// allow consumes one token, reporting false when the budget is exhausted.
func (b *tokenBucket) allow(now time.Time) bool {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
