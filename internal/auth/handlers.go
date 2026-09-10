package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"cb-back/internal/httpx"
)

const maxBodyBytes = 4 << 10

// Handlers exposes the credential endpoints.
type Handlers struct {
	svc    *Service
	mw     *Middleware
	logger *slog.Logger
}

func NewHandlers(svc *Service, mw *Middleware, logger *slog.Logger) *Handlers {
	return &Handlers{svc: svc, mw: mw, logger: logger}
}

// Routes registers the auth surface on mux. Endpoints that need a session are
// wrapped in require so the mux carries no unauthenticated path by accident.
func (h *Handlers) Routes(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.HandleFunc("POST /api/auth/register", h.register)
	mux.HandleFunc("POST /api/auth/login", h.login)
	mux.HandleFunc("POST /api/auth/logout", h.logout)

	mux.Handle("GET /api/auth/me", require(http.HandlerFunc(h.me)))
	mux.Handle("POST /api/auth/logout-all", require(http.HandlerFunc(h.logoutAll)))
	mux.Handle("POST /api/auth/password", require(http.HandlerFunc(h.changePassword)))
	mux.Handle("POST /api/auth/ws-ticket", require(http.HandlerFunc(h.wsTicket)))

	mux.Handle("GET /api/users", require(http.HandlerFunc(h.contacts)))
}

const contactsLimit = 200

// contacts is the address book. Like the room directory it shows display names
// to any signed-in user and never email addresses, so it is readable without
// becoming an enumeration endpoint for account identifiers people log in with.
func (h *Handlers) contacts(w http.ResponseWriter, r *http.Request) {
	id, ok := FromContext(r.Context())
	if !ok {
		httpx.Error(w, h.logger, http.StatusUnauthorized, "unauthenticated", "")
		return
	}

	list, err := h.svc.users.Contacts(r.Context(), id.User.ID, contactsLimit)
	if err != nil {
		h.logger.Error("list contacts failed", "error", err)
		httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	httpx.JSON(w, h.logger, http.StatusOK, map[string]any{"users": list})
}

// deliveryMode decides where the session token goes.
//
// Browsers must use "cookie": an HttpOnly cookie is unreadable from
// JavaScript, so an XSS bug cannot steal the session. Native clients ask for
// "bearer" and store the token in the Keychain or Keystore, where no cookie
// jar exists. The token is only ever put in a response body on explicit
// request, so a browser never receives a copy it could leak.
type deliveryMode string

const (
	modeCookie deliveryMode = "cookie"
	modeBearer deliveryMode = "bearer"
)

type credentialsRequest struct {
	Email       string       `json:"email"`
	Password    string       `json:"password"`
	DisplayName string       `json:"display_name,omitempty"`
	Mode        deliveryMode `json:"mode,omitempty"`
}

type sessionResponse struct {
	User      User      `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"token,omitempty"`
	TokenType string    `json:"token_type,omitempty"`
}

func (h *Handlers) register(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if err := httpx.DecodeJSON(w, r, maxBodyBytes, &req); err != nil {
		httpx.Error(w, h.logger, http.StatusBadRequest, "invalid_body", "expected a JSON object")
		return
	}

	user, token, sess, err := h.svc.Register(r.Context(), Credentials{
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: req.DisplayName,
		IP:          h.mw.ClientIP(r),
		UserAgent:   r.UserAgent(),
	})
	if err != nil {
		h.writeAuthError(w, err)
		return
	}

	h.writeSession(w, req.Mode, user, token, sess, http.StatusCreated)
}

func (h *Handlers) login(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if err := httpx.DecodeJSON(w, r, maxBodyBytes, &req); err != nil {
		httpx.Error(w, h.logger, http.StatusBadRequest, "invalid_body", "expected a JSON object")
		return
	}

	user, token, sess, err := h.svc.Login(r.Context(), Credentials{
		Email:     req.Email,
		Password:  req.Password,
		IP:        h.mw.ClientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.writeAuthError(w, err)
		return
	}

	h.writeSession(w, req.Mode, user, token, sess, http.StatusOK)
}

// logout is deliberately unauthenticated: an expired or already-revoked token
// should still clear the client's cookie rather than return 401.
func (h *Handlers) logout(w http.ResponseWriter, r *http.Request) {
	token := h.mw.tokenFrom(r)
	if token != "" {
		if err := h.svc.Logout(r.Context(), token, AuthEvent{
			IP:        h.mw.ClientIP(r),
			UserAgent: r.UserAgent(),
		}); err != nil {
			h.logger.Error("logout failed", "error", err)
			httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
			return
		}
	}

	h.mw.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) logoutAll(w http.ResponseWriter, r *http.Request) {
	id, ok := FromContext(r.Context())
	if !ok {
		httpx.Error(w, h.logger, http.StatusUnauthorized, "unauthenticated", "")
		return
	}

	revoked, err := h.svc.LogoutAll(r.Context(), id.User.ID, AuthEvent{
		UserID:    id.User.ID,
		Email:     id.User.Email,
		IP:        h.mw.ClientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.logger.Error("logout-all failed", "error", err)
		httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	h.mw.ClearCookie(w)
	httpx.JSON(w, h.logger, http.StatusOK, map[string]int{"revoked": revoked})
}

// me is the endpoint the app calls on start-up to answer "am I still signed
// in?". It also re-issues the cookie, so the week of inactivity a user is
// allowed counts from their last visit rather than from when they logged in.
func (h *Handlers) me(w http.ResponseWriter, r *http.Request) {
	id, ok := FromContext(r.Context())
	if !ok {
		httpx.Error(w, h.logger, http.StatusUnauthorized, "unauthenticated", "")
		return
	}

	h.mw.RefreshCookie(w, r, id)
	httpx.JSON(w, h.logger, http.StatusOK, sessionResponse{User: id.User, ExpiresAt: id.Session.ExpiresAt})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *Handlers) changePassword(w http.ResponseWriter, r *http.Request) {
	id, ok := FromContext(r.Context())
	if !ok {
		httpx.Error(w, h.logger, http.StatusUnauthorized, "unauthenticated", "")
		return
	}

	var req changePasswordRequest
	if err := httpx.DecodeJSON(w, r, maxBodyBytes, &req); err != nil {
		httpx.Error(w, h.logger, http.StatusBadRequest, "invalid_body", "expected a JSON object")
		return
	}

	// The caller's own session survives; every other one is revoked.
	err := h.svc.ChangePassword(r.Context(), id.User.ID, req.CurrentPassword, req.NewPassword, id.Token, AuthEvent{
		UserID:    id.User.ID,
		Email:     id.User.Email,
		IP:        h.mw.ClientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) wsTicket(w http.ResponseWriter, r *http.Request) {
	id, ok := FromContext(r.Context())
	if !ok {
		httpx.Error(w, h.logger, http.StatusUnauthorized, "unauthenticated", "")
		return
	}

	ticket, ttl, err := h.svc.sessions.IssueWSTicket(r.Context(), id.User.ID)
	if err != nil {
		h.logger.Error("issue websocket ticket failed", "error", err)
		httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	httpx.JSON(w, h.logger, http.StatusOK, map[string]any{
		"ticket":     ticket,
		"expires_in": int(ttl.Seconds()),
	})
}

func (h *Handlers) writeSession(w http.ResponseWriter, mode deliveryMode, user User, token string, sess Session, status int) {
	resp := sessionResponse{User: user, ExpiresAt: sess.ExpiresAt}

	if mode == modeBearer {
		resp.Token = token
		resp.TokenType = "Bearer"
	} else {
		h.mw.SetCookie(w, token, sess.ExpiresAt)
	}

	httpx.JSON(w, h.logger, status, resp)
}

// writeAuthError maps domain errors to responses without leaking which part of
// a credential was wrong.
func (h *Handlers) writeAuthError(w http.ResponseWriter, err error) {
	var rateErr *RateLimitError
	switch {
	case errors.As(err, &rateErr):
		w.Header().Set("Retry-After", strconv.Itoa(int(rateErr.RetryAfter.Seconds())+1))
		httpx.Error(w, h.logger, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again later")

	case errors.Is(err, ErrInvalidCredentials):
		httpx.Error(w, h.logger, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")

	case errors.Is(err, ErrEmailTaken):
		httpx.Error(w, h.logger, http.StatusConflict, "email_taken", "that email is already registered")

	case errors.Is(err, ErrInvalidEmail):
		httpx.Error(w, h.logger, http.StatusBadRequest, "invalid_email", "enter a valid email address")

	case errors.Is(err, ErrInvalidDisplayName):
		httpx.Error(w, h.logger, http.StatusBadRequest, "invalid_display_name", ErrInvalidDisplayName.Error())

	case errors.Is(err, ErrPasswordTooShort), errors.Is(err, ErrPasswordTooLong), errors.Is(err, ErrPasswordNotAllowed):
		httpx.Error(w, h.logger, http.StatusBadRequest, "weak_password", err.Error())

	default:
		h.logger.Error("auth request failed", "error", err)
		httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
	}
}
