package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	// ErrInvalidCredentials is returned for every failed login regardless of
	// cause — unknown email, wrong password, disabled account. Distinguishing
	// them would turn the login endpoint into an account-enumeration oracle.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrInvalidEmail       = errors.New("auth: invalid email address")
	ErrInvalidDisplayName = errors.New("auth: display name must be 1-100 characters")
)

// RateLimitError reports that a caller exceeded a quota.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("auth: rate limited, retry in %s", e.RetryAfter.Round(time.Second))
}

type Service struct {
	users    *UserStore
	sessions *SessionStore
	limiter  *RateLimiter
	logger   *slog.Logger
}

func NewService(users *UserStore, sessions *SessionStore, limiter *RateLimiter, logger *slog.Logger) *Service {
	return &Service{users: users, sessions: sessions, limiter: limiter, logger: logger}
}

type Credentials struct {
	Email       string
	Password    string
	DisplayName string
	IP          string
	UserAgent   string
}

// Register creates an account and logs it in.
//
// Note: a duplicate email returns ErrEmailTaken, which does reveal that the
// address is registered. Removing that signal requires email verification —
// respond identically either way and send a "you already have an account"
// mail. Until then, RegisterPerIP is what keeps the endpoint from being used
// to enumerate an address list in bulk.
func (s *Service) Register(ctx context.Context, in Credentials) (User, string, Session, error) {
	if err := s.check(ctx, "register:ip:"+in.IP, RegisterPerIP); err != nil {
		return User{}, "", Session{}, err
	}

	email, err := validateEmail(in.Email)
	if err != nil {
		return User{}, "", Session{}, err
	}
	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		displayName, _, _ = strings.Cut(email, "@")
	}
	if n := utf8.RuneCountInString(displayName); n < 1 || n > 100 {
		return User{}, "", Session{}, ErrInvalidDisplayName
	}
	if err := ValidatePassword(in.Password); err != nil {
		return User{}, "", Session{}, err
	}

	hash, err := HashPassword(ctx, in.Password)
	if err != nil {
		return User{}, "", Session{}, err
	}

	user, err := s.users.Create(ctx, email, displayName, hash)
	if err != nil {
		return User{}, "", Session{}, err
	}

	s.record(ctx, AuthEvent{UserID: user.ID, Email: email, Event: "register", IP: in.IP, UserAgent: in.UserAgent})

	token, sess, err := s.sessions.Create(ctx, user.ID, in.IP, in.UserAgent)
	if err != nil {
		return User{}, "", Session{}, err
	}
	return user, token, sess, nil
}

// Login verifies credentials and issues a session.
func (s *Service) Login(ctx context.Context, in Credentials) (User, string, Session, error) {
	email := NormalizeEmail(in.Email)

	// Both counters are consumed on every attempt, before the password is
	// checked, so a caller cannot probe for free.
	if err := s.check(ctx, "login:ip:"+in.IP, LoginPerIP); err != nil {
		return User{}, "", Session{}, err
	}
	accountKey := "login:account:" + email
	if err := s.check(ctx, accountKey, LoginPerAccount); err != nil {
		s.record(ctx, AuthEvent{Email: email, Event: "login_rate_limited", IP: in.IP, UserAgent: in.UserAgent})
		return User{}, "", Session{}, err
	}

	user, hash, err := s.users.ByEmailWithCredential(ctx, email)
	switch {
	case errors.Is(err, ErrUserNotFound), errors.Is(err, ErrNoCredentials):
		// Spend the same CPU as a real verification so response time does not
		// distinguish "no such account" from "wrong password".
		DummyVerify(ctx, in.Password)
		s.record(ctx, AuthEvent{Email: email, Event: "login_failed_unknown_user", IP: in.IP, UserAgent: in.UserAgent})
		return User{}, "", Session{}, ErrInvalidCredentials
	case err != nil:
		return User{}, "", Session{}, err
	}

	if user.disabled {
		DummyVerify(ctx, in.Password)
		s.record(ctx, AuthEvent{UserID: user.ID, Email: email, Event: "login_failed_disabled", IP: in.IP, UserAgent: in.UserAgent})
		return User{}, "", Session{}, ErrInvalidCredentials
	}

	match, needsRehash, err := VerifyPassword(ctx, hash, in.Password)
	if err != nil {
		s.logger.Error("stored password hash is unusable", "user", user.ID, "error", err)
		return User{}, "", Session{}, ErrInvalidCredentials
	}
	if !match {
		s.record(ctx, AuthEvent{UserID: user.ID, Email: email, Event: "login_failed_bad_password", IP: in.IP, UserAgent: in.UserAgent})
		return User{}, "", Session{}, ErrInvalidCredentials
	}

	// The password is correct here, so this is the one moment the plaintext is
	// available to re-hash under stronger parameters.
	if needsRehash {
		if upgraded, err := HashPassword(ctx, in.Password); err != nil {
			s.logger.Warn("rehash failed", "user", user.ID, "error", err)
		} else if err := s.users.UpdatePassword(ctx, user.ID, upgraded); err != nil {
			s.logger.Warn("store rehashed password failed", "user", user.ID, "error", err)
		} else {
			s.logger.Info("password hash upgraded to current parameters", "user", user.ID)
		}
	}

	if err := s.limiter.Reset(ctx, accountKey); err != nil {
		s.logger.Warn("reset login counter failed", "error", err)
	}

	token, sess, err := s.sessions.Create(ctx, user.ID, in.IP, in.UserAgent)
	if err != nil {
		return User{}, "", Session{}, err
	}

	s.record(ctx, AuthEvent{UserID: user.ID, Email: email, Event: "login", IP: in.IP, UserAgent: in.UserAgent})
	return user, token, sess, nil
}

func (s *Service) Logout(ctx context.Context, token string, e AuthEvent) error {
	if err := s.sessions.Revoke(ctx, token); err != nil {
		return err
	}
	e.Event = "logout"
	s.record(ctx, e)
	return nil
}

func (s *Service) LogoutAll(ctx context.Context, userID string, e AuthEvent) (int, error) {
	n, err := s.sessions.RevokeAllForUser(ctx, userID, "")
	if err != nil {
		return 0, err
	}
	e.Event = "logout_all"
	s.record(ctx, e)
	return n, nil
}

// ChangePassword requires the current password and then revokes every other
// session, so a password change actually evicts an attacker who already has
// one rather than leaving their session live.
func (s *Service) ChangePassword(ctx context.Context, userID, current, next, keepToken string, e AuthEvent) error {
	if err := s.check(ctx, "password:ip:"+e.IP, PasswordChangeIP); err != nil {
		return err
	}

	hash, err := s.users.CredentialByUserID(ctx, userID)
	if err != nil {
		return err
	}

	match, _, err := VerifyPassword(ctx, hash, current)
	if err != nil || !match {
		e.Event = "password_change_failed"
		s.record(ctx, e)
		return ErrInvalidCredentials
	}

	if err := ValidatePassword(next); err != nil {
		return err
	}

	updated, err := HashPassword(ctx, next)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, userID, updated); err != nil {
		return err
	}

	if _, err := s.sessions.RevokeAllForUser(ctx, userID, keepToken); err != nil {
		return err
	}

	e.Event = "password_changed"
	s.record(ctx, e)
	return nil
}

func (s *Service) Sessions() *SessionStore { return s.sessions }
func (s *Service) Users() *UserStore       { return s.users }

func (s *Service) check(ctx context.Context, key string, limit Limit) error {
	allowed, retryAfter, err := s.limiter.Allow(ctx, key, limit)
	if err != nil {
		// Fail closed: if the limiter is unavailable we cannot tell a normal
		// request from an attack, and the credential endpoints are exactly
		// where guessing must stay expensive.
		return fmt.Errorf("rate limiter unavailable: %w", err)
	}
	if !allowed {
		return &RateLimitError{RetryAfter: retryAfter}
	}
	return nil
}

// record writes an audit row. Failures are logged, never propagated: losing an
// audit row must not fail the user's request.
func (s *Service) record(ctx context.Context, e AuthEvent) {
	if err := s.users.RecordEvent(ctx, e); err != nil {
		s.logger.Error("record auth event failed", "event", e.Event, "error", err)
	}
}

func validateEmail(raw string) (string, error) {
	email := NormalizeEmail(raw)
	if len(email) < 3 || len(email) > 254 {
		return "", ErrInvalidEmail
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", ErrInvalidEmail
	}
	// ParseAddress accepts "Name <a@b>"; only the bare address is acceptable.
	if addr.Address != email || addr.Name != "" {
		return "", ErrInvalidEmail
	}
	if strings.Count(email, "@") != 1 {
		return "", ErrInvalidEmail
	}
	local, domain, _ := strings.Cut(email, "@")
	if local == "" || domain == "" || !strings.Contains(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", ErrInvalidEmail
	}
	return email, nil
}
