package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"cb-back/internal/httpx"
)

type contextKey struct{}

var identityKey contextKey

// Identity is the authenticated caller attached to a request context.
type Identity struct {
	User    User
	Session Session
	Token   string
}

// FromContext returns the authenticated identity, if the request passed
// through Require.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey).(Identity)
	return id, ok
}

type Middleware struct {
	svc          *Service
	logger       *slog.Logger
	cookieName   string
	cookieDomain string
	cookieSecure bool
	idleTTL      time.Duration
	absoluteTTL  time.Duration
	trustProxy   bool
}

type MiddlewareOptions struct {
	CookieName   string
	CookieDomain string
	CookieSecure bool
	IdleTTL      time.Duration
	AbsoluteTTL  time.Duration
	TrustProxy   bool
}

func NewMiddleware(svc *Service, logger *slog.Logger, opts MiddlewareOptions) *Middleware {
	return &Middleware{
		svc:          svc,
		logger:       logger,
		cookieName:   opts.CookieName,
		cookieDomain: opts.CookieDomain,
		cookieSecure: opts.CookieSecure,
		idleTTL:      opts.IdleTTL,
		absoluteTTL:  opts.AbsoluteTTL,
		trustProxy:   opts.TrustProxy,
	}
}

// Require rejects unauthenticated requests and attaches the identity for
// handlers downstream.
func (m *Middleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := m.identify(r)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrUserDisabled) {
				// The cookie is stale or the account is gone; clear it so the
				// browser stops sending a token that will never work again.
				m.ClearCookie(w)
				httpx.Error(w, m.logger, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
				return
			}
			m.logger.Error("authentication failed", "error", err)
			httpx.Error(w, m.logger, http.StatusInternalServerError, "internal_error", "")
			return
		}

		// Slide the idle window forward; a failure here must not log the user
		// out mid-request.
		if err := m.svc.sessions.Touch(r.Context(), id.Session); err != nil {
			m.logger.Warn("refresh session failed", "error", err)
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
	})
}

// AuthenticateWS resolves the identity for a websocket upgrade, accepting a
// single-use ticket in addition to the usual token sources. It satisfies the
// authenticator the signaling package depends on.
func (m *Middleware) AuthenticateWS(ctx context.Context, r *http.Request) (string, string, error) {
	if ticket := r.URL.Query().Get("ticket"); ticket != "" {
		userID, err := m.svc.sessions.RedeemWSTicket(ctx, ticket)
		if err != nil {
			return "", "", err
		}
		user, err := m.svc.users.ByID(ctx, userID)
		if err != nil {
			return "", "", err
		}
		return user.ID, user.DisplayName, nil
	}

	id, err := m.identify(r)
	if err != nil {
		return "", "", err
	}
	return id.User.ID, id.User.DisplayName, nil
}

func (m *Middleware) identify(r *http.Request) (Identity, error) {
	token := m.tokenFrom(r)
	if token == "" {
		return Identity{}, ErrSessionNotFound
	}

	sess, err := m.svc.sessions.Get(r.Context(), token)
	if err != nil {
		return Identity{}, err
	}

	// Re-read the user on every request rather than trusting the session
	// snapshot, so disabling an account takes effect immediately instead of
	// when its sessions happen to expire.
	user, err := m.svc.users.ByID(r.Context(), sess.UserID)
	if err != nil {
		return Identity{}, err
	}

	return Identity{User: user, Session: sess, Token: token}, nil
}

// tokenFrom prefers the Authorization header, which native clients use, and
// falls back to the cookie that browsers send.
func (m *Middleware) tokenFrom(r *http.Request) string {
	if header := r.Header.Get("Authorization"); header != "" {
		if scheme, value, found := strings.Cut(header, " "); found && strings.EqualFold(scheme, "Bearer") {
			return strings.TrimSpace(value)
		}
		return ""
	}
	if cookie, err := r.Cookie(m.cookieName); err == nil {
		return cookie.Value
	}
	return ""
}

// ClientIP resolves the address used for audit rows and rate limiting.
func (m *Middleware) ClientIP(r *http.Request) string { return httpx.ClientIP(r, m.trustProxy) }

// SetCookie writes the session cookie.
//
// HttpOnly keeps the token out of reach of JavaScript, so an XSS bug cannot
// exfiltrate it and no frontend code ever handles it. Secure keeps it off
// plaintext connections. SameSite=Lax stops it riding along with cross-site
// POSTs, which is the first half of the CSRF defence — httpx.CSRF is the
// second.
//
// The cookie expires with the idle window rather than the absolute cap, so the
// browser stops presenting a token the server would refuse anyway. It never
// outlives the session it refers to.
func (m *Middleware) SetCookie(w http.ResponseWriter, token string, sessionExpiry time.Time) {
	expires := time.Now().Add(m.idleTTL)
	if !sessionExpiry.IsZero() && sessionExpiry.Before(expires) {
		expires = sessionExpiry
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    token,
		Path:     "/",
		Domain:   m.cookieDomain,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   m.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// RefreshCookie re-issues the cookie so its lifetime slides with the session's
// idle window.
//
// Without this the server-side session keeps sliding while the browser copy
// still expires on the schedule set at login, and a user who visits every few
// days is signed out anyway when that original deadline passes.
//
// Only cookie-authenticated requests are refreshed: a bearer client stores its
// own token and has no cookie to update.
func (m *Middleware) RefreshCookie(w http.ResponseWriter, r *http.Request, id Identity) {
	if r.Header.Get("Authorization") != "" {
		return
	}
	if _, err := r.Cookie(m.cookieName); err != nil {
		return
	}
	m.SetCookie(w, id.Token, id.Session.ExpiresAt)
}

func (m *Middleware) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   m.cookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
