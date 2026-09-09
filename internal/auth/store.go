package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const uniqueViolation = "23505"

var (
	ErrUserNotFound  = errors.New("auth: user not found")
	ErrEmailTaken    = errors.New("auth: email already registered")
	ErrUserDisabled  = errors.New("auth: user is disabled")
	ErrNoCredentials = errors.New("auth: user has no password credential")
)

type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	DisplayName   string    `json:"display_name"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	disabled      bool
}

type UserStore struct {
	pool *pgxpool.Pool
}

func NewUserStore(pool *pgxpool.Pool) *UserStore { return &UserStore{pool: pool} }

// Create inserts the account and its password credential atomically: a user
// row without a credential would be an account nobody can log into and nobody
// can re-register.
func (s *UserStore) Create(ctx context.Context, email, displayName, passwordHash string) (User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var u User
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email, display_name)
		VALUES ($1, $2)
		RETURNING id::text, email::text, display_name, email_verified, created_at`,
		email, displayName,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.EmailVerified, &u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("insert user: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO password_credentials (user_id, password_hash)
		VALUES ($1, $2)`, u.ID, passwordHash); err != nil {
		return User{}, fmt.Errorf("insert credential: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("commit: %w", err)
	}
	return u, nil
}

// ByEmailWithCredential returns the account and its stored hash for login.
func (s *UserStore) ByEmailWithCredential(ctx context.Context, email string) (User, string, error) {
	var u User
	var hash *string

	err := s.pool.QueryRow(ctx, `
		SELECT u.id::text, u.email::text, u.display_name, u.email_verified, u.created_at,
		       u.disabled_at IS NOT NULL, c.password_hash
		FROM users u
		LEFT JOIN password_credentials c ON c.user_id = u.id
		WHERE u.email = $1`, email,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.EmailVerified, &u.CreatedAt, &u.disabled, &hash)

	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, "", ErrUserNotFound
	}
	if err != nil {
		return User{}, "", fmt.Errorf("select user: %w", err)
	}
	if hash == nil {
		return u, "", ErrNoCredentials
	}
	return u, *hash, nil
}

func (s *UserStore) ByID(ctx context.Context, id string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, email::text, display_name, email_verified, created_at, disabled_at IS NOT NULL
		FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.EmailVerified, &u.CreatedAt, &u.disabled)

	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("select user: %w", err)
	}
	if u.disabled {
		return User{}, ErrUserDisabled
	}
	return u, nil
}

// CredentialByUserID returns the stored hash, used when confirming the current
// password before changing it.
func (s *UserStore) CredentialByUserID(ctx context.Context, userID string) (string, error) {
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT password_hash FROM password_credentials WHERE user_id = $1`, userID).Scan(&hash)

	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoCredentials
	}
	if err != nil {
		return "", fmt.Errorf("select credential: %w", err)
	}
	return hash, nil
}

// UpdatePassword replaces the stored hash. Used both for password changes and
// for transparently upgrading a hash whose cost parameters are out of date.
func (s *UserStore) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE password_credentials
		SET password_hash = $2, updated_at = now()
		WHERE user_id = $1`, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("update credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNoCredentials
	}
	return nil
}

// AuthEvent is one row of the authentication audit trail.
type AuthEvent struct {
	UserID    string
	Email     string
	Event     string
	IP        string
	UserAgent string
}

// RecordEvent appends to the audit trail. Callers treat failures as
// non-fatal — losing an audit row must not block a legitimate login — but they
// are logged, because a silent gap in this table is exactly what an
// investigation cannot afford.
func (s *UserStore) RecordEvent(ctx context.Context, e AuthEvent) error {
	var userID, email, ip any
	if e.UserID != "" {
		userID = e.UserID
	}
	if e.Email != "" {
		email = e.Email
	}
	// inet rejects a bare port-less hostname, so only pass parseable addresses.
	if parsed := net.ParseIP(e.IP); parsed != nil {
		ip = parsed.String()
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth_events (user_id, email, event, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5)`,
		userID, email, e.Event, ip, truncate(e.UserAgent, 512))
	if err != nil {
		return fmt.Errorf("insert auth event: %w", err)
	}
	return nil
}

// NormalizeEmail lower-cases and trims an address so that lookups, the unique
// index and rate-limit keys all agree on one spelling.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
