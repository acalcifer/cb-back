package rooms

import (
	"errors"
	"log/slog"
	"net/http"

	"cb-back/internal/auth"
	"cb-back/internal/httpx"
)

const maxBodyBytes = 2 << 10

type Handlers struct {
	svc    *Service
	logger *slog.Logger
}

func NewHandlers(svc *Service, logger *slog.Logger) *Handlers {
	return &Handlers{svc: svc, logger: logger}
}

// Routes registers the room surface. Every endpoint requires a session: a room
// list is personal, and an anonymous caller has no rooms.
func (h *Handlers) Routes(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("POST /api/rooms", require(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/rooms", require(http.HandlerFunc(h.list)))
	mux.Handle("GET /api/rooms/{slug}", require(http.HandlerFunc(h.bySlug)))
	mux.Handle("DELETE /api/rooms/{slug}", require(http.HandlerFunc(h.delete)))
}

type createRequest struct {
	Name string `json:"name,omitempty"`
}

func (h *Handlers) create(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.FromContext(r.Context())
	if !ok {
		httpx.Error(w, h.logger, http.StatusUnauthorized, "unauthenticated", "")
		return
	}

	var req createRequest
	// An empty body is fine: the room gets a default name.
	if r.ContentLength > 0 {
		if err := httpx.DecodeJSON(w, r, maxBodyBytes, &req); err != nil {
			httpx.Error(w, h.logger, http.StatusBadRequest, "invalid_body", "expected a JSON object")
			return
		}
	}

	room, err := h.svc.Create(r.Context(), id.User.ID, req.Name)
	if err != nil {
		if errors.Is(err, ErrInvalidName) {
			httpx.Error(w, h.logger, http.StatusBadRequest, "invalid_name", err.Error())
			return
		}
		h.logger.Error("create room failed", "error", err)
		httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	httpx.JSON(w, h.logger, http.StatusCreated, room)
}

// list is the public room directory: every signed-in user sees every room, so
// they have something to join. It still requires a session — an anonymous
// caller has no way to join a call anyway.
func (h *Handlers) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.FromContext(r.Context()); !ok {
		httpx.Error(w, h.logger, http.StatusUnauthorized, "unauthenticated", "")
		return
	}

	list, err := h.svc.List(r.Context())
	if err != nil {
		h.logger.Error("list rooms failed", "error", err)
		httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	httpx.JSON(w, h.logger, http.StatusOK, map[string]any{"rooms": list})
}

// delete removes a room. Any signed-in user may delete any room: the directory
// is shared, so tidying it is shared too. The trade-off is that someone can
// remove a room others are using — if that becomes a problem, restricting it to
// the creator is a one-line change to the query.
func (h *Handlers) delete(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.FromContext(r.Context()); !ok {
		httpx.Error(w, h.logger, http.StatusUnauthorized, "unauthenticated", "")
		return
	}

	if err := h.svc.Delete(r.Context(), r.PathValue("slug")); err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.Error(w, h.logger, http.StatusNotFound, "room_not_found", "no such room")
			return
		}
		h.logger.Error("delete room failed", "error", err)
		httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// bySlug resolves an invitation link. Any authenticated user may resolve any
// slug — that is the access model, and it is why slugs are generated rather
// than chosen.
func (h *Handlers) bySlug(w http.ResponseWriter, r *http.Request) {
	room, err := h.svc.BySlug(r.Context(), r.PathValue("slug"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.Error(w, h.logger, http.StatusNotFound, "room_not_found", "no such room")
			return
		}
		h.logger.Error("resolve room failed", "error", err)
		httpx.Error(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	httpx.JSON(w, h.logger, http.StatusOK, room)
}
