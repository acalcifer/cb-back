package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	sessionKeyPrefix  = "sess:"
	userIndexPrefix   = "user_sess:"
	wsTicketPrefix    = "ws_ticket:"
	tokenBytes        = 32
	touchGranularity  = time.Minute
	maxSessionsPerUsr = 20
)

var (
	ErrSessionNotFound = errors.New("auth: session not found")
	ErrTicketNotFound  = errors.New("auth: websocket ticket not found or already used")
)

// Session is the server-side record behind an opaque token. The token itself
// is never stored: Redis holds only its SHA-256, so a leaked snapshot cannot be
// replayed against the API.
type Session struct {
	ID         string    `json:"-"`
	UserID     string    `json:"user_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
}

type SessionStore struct {
	rdb         *redis.Client
	idleTTL     time.Duration
	absoluteTTL time.Duration
	ticketTTL   time.Duration
}

func NewSessionStore(rdb *redis.Client, idleTTL, absoluteTTL, ticketTTL time.Duration) *SessionStore {
	return &SessionStore{rdb: rdb, idleTTL: idleTTL, absoluteTTL: absoluteTTL, ticketTTL: ticketTTL}
}

// Create issues a new session and returns the bearer token exactly once. The
// caller must hand it to the client immediately; it cannot be recovered later.
func (s *SessionStore) Create(ctx context.Context, userID, ip, userAgent string) (string, Session, error) {
	token, err := newToken()
	if err != nil {
		return "", Session{}, err
	}

	now := time.Now().UTC()
	sess := Session{
		ID:         hashToken(token),
		UserID:     userID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.absoluteTTL),
		LastSeenAt: now,
		IP:         ip,
		UserAgent:  truncate(userAgent, 512),
	}

	payload, err := json.Marshal(sess)
	if err != nil {
		return "", Session{}, fmt.Errorf("marshal session: %w", err)
	}

	key := sessionKeyPrefix + sess.ID
	index := userIndexPrefix + userID

	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, key, payload, s.ttlFor(sess, now))
	pipe.SAdd(ctx, index, sess.ID)
	pipe.Expire(ctx, index, s.absoluteTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", Session{}, fmt.Errorf("store session: %w", err)
	}

	// Best-effort cap on concurrent sessions per account, so a stuffing run
	// that lands cannot accumulate unlimited footholds.
	s.trimSessions(ctx, userID)

	return token, sess, nil
}

// Get resolves a token, deleting and rejecting anything past its absolute
// expiry. Redis TTLs handle idle expiry; this covers the absolute bound, which
// a sliding TTL alone would never enforce.
func (s *SessionStore) Get(ctx context.Context, token string) (Session, error) {
	id := hashToken(token)

	raw, err := s.rdb.Get(ctx, sessionKeyPrefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, ErrSessionNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("read session: %w", err)
	}

	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return Session{}, fmt.Errorf("decode session: %w", err)
	}
	sess.ID = id

	if time.Now().UTC().After(sess.ExpiresAt) {
		if err := s.revokeByID(ctx, sess.UserID, id); err != nil {
			return Session{}, err
		}
		return Session{}, ErrSessionNotFound
	}
	return sess, nil
}

// Touch slides the idle window forward. It skips writes finer than
// touchGranularity so a busy client does not turn every request into a Redis
// round trip.
func (s *SessionStore) Touch(ctx context.Context, sess Session) error {
	now := time.Now().UTC()
	if now.Sub(sess.LastSeenAt) < touchGranularity {
		return nil
	}
	sess.LastSeenAt = now

	payload, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := s.rdb.Set(ctx, sessionKeyPrefix+sess.ID, payload, s.ttlFor(sess, now)).Err(); err != nil {
		return fmt.Errorf("refresh session: %w", err)
	}
	return nil
}

// Revoke drops a single session. Revoking an unknown token is not an error:
// logout must be idempotent.
func (s *SessionStore) Revoke(ctx context.Context, token string) error {
	id := hashToken(token)

	raw, err := s.rdb.Get(ctx, sessionKeyPrefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read session: %w", err)
	}

	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		// Unparseable value: drop the key anyway rather than leave it behind.
		return s.rdb.Del(ctx, sessionKeyPrefix+id).Err()
	}
	return s.revokeByID(ctx, sess.UserID, id)
}

// RevokeAllForUser invalidates every session for an account. This is what a
// password change calls: a credential change must not leave an attacker's
// existing session alive.
func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string, exceptToken string) (int, error) {
	index := userIndexPrefix + userID

	ids, err := s.rdb.SMembers(ctx, index).Result()
	if err != nil {
		return 0, fmt.Errorf("list sessions: %w", err)
	}

	keep := ""
	if exceptToken != "" {
		keep = hashToken(exceptToken)
	}

	keys := make([]string, 0, len(ids))
	remaining := make([]any, 0, 1)
	for _, id := range ids {
		if id == keep {
			remaining = append(remaining, id)
			continue
		}
		keys = append(keys, sessionKeyPrefix+id)
	}

	pipe := s.rdb.TxPipeline()
	if len(keys) > 0 {
		pipe.Del(ctx, keys...)
	}
	pipe.Del(ctx, index)
	if len(remaining) > 0 {
		pipe.SAdd(ctx, index, remaining...)
		pipe.Expire(ctx, index, s.absoluteTTL)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("revoke sessions: %w", err)
	}
	return len(keys), nil
}

// IssueWSTicket mints a single-use, short-lived credential for opening a
// websocket.
//
// Browsers cannot set headers on a WebSocket handshake, so without this a
// browser client must rely on the session cookie — which breaks the moment the
// API lives on a different origin than the page. The ticket closes that gap
// without putting a long-lived token in a URL, where it would land in proxy and
// server logs.
func (s *SessionStore) IssueWSTicket(ctx context.Context, userID string) (string, time.Duration, error) {
	ticket, err := newToken()
	if err != nil {
		return "", 0, err
	}
	if err := s.rdb.Set(ctx, wsTicketPrefix+hashToken(ticket), userID, s.ticketTTL).Err(); err != nil {
		return "", 0, fmt.Errorf("store ticket: %w", err)
	}
	return ticket, s.ticketTTL, nil
}

// RedeemWSTicket exchanges a ticket for its user id and destroys it in the
// same round trip, so a ticket captured from a log or a shared URL is already
// spent.
func (s *SessionStore) RedeemWSTicket(ctx context.Context, ticket string) (string, error) {
	userID, err := s.rdb.GetDel(ctx, wsTicketPrefix+hashToken(ticket)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrTicketNotFound
	}
	if err != nil {
		return "", fmt.Errorf("redeem ticket: %w", err)
	}
	return userID, nil
}

func (s *SessionStore) revokeByID(ctx context.Context, userID, id string) error {
	pipe := s.rdb.TxPipeline()
	pipe.Del(ctx, sessionKeyPrefix+id)
	if userID != "" {
		pipe.SRem(ctx, userIndexPrefix+userID, id)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// trimSessions prunes index entries whose session keys have already expired,
// then drops the oldest surviving sessions above the per-user cap.
func (s *SessionStore) trimSessions(ctx context.Context, userID string) {
	index := userIndexPrefix + userID

	ids, err := s.rdb.SMembers(ctx, index).Result()
	if err != nil || len(ids) <= maxSessionsPerUsr {
		return
	}

	type entry struct {
		id      string
		created time.Time
	}
	var live []entry
	var stale []any

	for _, id := range ids {
		raw, err := s.rdb.Get(ctx, sessionKeyPrefix+id).Bytes()
		if errors.Is(err, redis.Nil) {
			stale = append(stale, id)
			continue
		}
		if err != nil {
			return
		}
		var sess Session
		if err := json.Unmarshal(raw, &sess); err != nil {
			stale = append(stale, id)
			continue
		}
		live = append(live, entry{id: id, created: sess.CreatedAt})
	}

	for len(live) > maxSessionsPerUsr {
		oldest := 0
		for i, e := range live {
			if e.created.Before(live[oldest].created) {
				oldest = i
			}
		}
		if err := s.rdb.Del(ctx, sessionKeyPrefix+live[oldest].id).Err(); err != nil {
			return
		}
		stale = append(stale, live[oldest].id)
		live = append(live[:oldest], live[oldest+1:]...)
	}

	if len(stale) > 0 {
		_ = s.rdb.SRem(ctx, index, stale...).Err()
	}
}

// ttlFor never lets the idle window outlive the absolute expiry.
func (s *SessionStore) ttlFor(sess Session, now time.Time) time.Duration {
	remaining := sess.ExpiresAt.Sub(now)
	if remaining < s.idleTTL {
		return remaining
	}
	return s.idleTTL
}

func newToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
