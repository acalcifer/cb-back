// Package invites rings a user into a room.
//
// An invite is a push, not a record: it goes to whatever inbox connections the
// recipient has open at that moment and is not stored. A phone that is offline
// when it is rung simply misses the call, and the caller is told so through
// the delivered count.
package invites

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cb-back/internal/auth"
	"cb-back/internal/httpx"
	"cb-back/internal/inbox"
	"cb-back/internal/rooms"
)

const maxBodyBytes = 1 << 10

// PerSender bounds how often one account can ring, cancel or decline. A real
// call needs two or three of these; the limit is what stops a signed-in user
// from making someone's phone ring on a loop.
var PerSender = auth.Limit{Requests: 30, Window: time.Minute}

// Deliverer is the inbox hub as this package needs it.
type Deliverer interface {
	Deliver(userID string, data []byte) int
}

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// Matches the CHECK constraint on rooms.slug.
	slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
)

type Handlers struct {
	rooms   *rooms.Service
	users   *auth.UserStore
	limiter *auth.RateLimiter
	inbox   Deliverer
	logger  *slog.Logger
}

func NewHandlers(roomService *rooms.Service, users *auth.UserStore, limiter *auth.RateLimiter, inbox Deliverer, logger *slog.Logger) *Handlers {
	return &Handlers{rooms: roomService, users: users, limiter: limiter, inbox: inbox, logger: logger}
}

func (h *Handlers) Routes(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("POST /api/rooms/{slug}/invites", require(h.handle(inbox.TypeInvite)))
	mux.Handle("POST /api/rooms/{slug}/invites/cancel", require(h.handle(inbox.TypeInviteCancelled)))
	mux.Handle("POST /api/rooms/{slug}/invites/decline", require(h.handle(inbox.TypeInviteDeclined)))
}

type request struct {
	// UserID is the recipient: the person being rung for an invite or a
	// cancel, and the person who rang for a decline.
	UserID string `json:"user_id"`
}

type response struct {
	Delivered int `json:"delivered"`
}

// handle serves all three actions. They differ only in the event type and in
// whether the room must still exist: a caller who hangs up may delete the room
// before the cancel lands, and the recipient's phone must stop ringing anyway.
func (h *Handlers) handle(eventType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.FromContext(r.Context())
		if !ok {
			httpx.Error(w, h.logger, http.StatusUnauthorized, "unauthenticated", "")
			return
		}

		var req request
		if err := httpx.DecodeJSON(w, r, maxBodyBytes, &req); err != nil {
			httpx.Error(w, h.logger, http.StatusBadRequest, "invalid_body", "expected a JSON object")
			return
		}
		recipient := strings.ToLower(strings.TrimSpace(req.UserID))
		if !uuidPattern.MatchString(recipient) {
			httpx.Error(w, h.logger, http.StatusBadRequest, "invalid_user", "user_id must be a user id")
			return
		}
		if recipient == id.User.ID {
			httpx.Error(w, h.logger, http.StatusBadRequest, "invalid_user", "you cannot ring yourself")
			return
		}

		slug := strings.ToLower(strings.TrimSpace(r.PathValue("slug")))
		if !slugPattern.MatchString(slug) {
			httpx.Error(w, h.logger, http.StatusNotFound, "room_not_found", "no such room")
			return
		}

		allowed, retryAfter, err := h.limiter.Allow(r.Context(), "invite:user:"+id.User.ID, PerSender)
		if err != nil {
			h.logger.Error("invite rate limiter unavailable", "error", err)
			httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			httpx.Error(w, h.logger, http.StatusTooManyRequests, "rate_limited", "too many calls, try again later")
			return
		}

		event := inbox.Event{
			Type: eventType,
			Room: inbox.Room{Slug: slug},
			From: inbox.Sender{ID: id.User.ID, DisplayName: id.User.DisplayName},
		}

		room, err := h.rooms.BySlug(r.Context(), slug)
		switch {
		case err == nil:
			event.Room.Name = room.Name
		case errors.Is(err, rooms.ErrNotFound) && eventType != inbox.TypeInvite:
			// Cancels and declines outlive the room; see handle's comment.
		case errors.Is(err, rooms.ErrNotFound):
			httpx.Error(w, h.logger, http.StatusNotFound, "room_not_found", "no such room")
			return
		default:
			h.logger.Error("resolve room for invite failed", "error", err)
			httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
			return
		}

		if _, err := h.users.ByID(r.Context(), recipient); err != nil {
			if errors.Is(err, auth.ErrUserNotFound) || errors.Is(err, auth.ErrUserDisabled) {
				httpx.Error(w, h.logger, http.StatusNotFound, "user_not_found", "no such user")
				return
			}
			h.logger.Error("resolve invite recipient failed", "error", err)
			httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
			return
		}

		data, err := event.Encode()
		if err != nil {
			h.logger.Error("encode invite failed", "error", err)
			httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
			return
		}

		delivered := h.inbox.Deliver(recipient, data)
		h.logger.Info("invite sent", "type", eventType, "from", id.User.ID, "to", recipient, "room", slug, "delivered", delivered)

		httpx.JSON(w, h.logger, http.StatusOK, response{Delivered: delivered})
	})
}
