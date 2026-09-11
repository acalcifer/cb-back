// Package turn issues short-lived credentials for the coturn relay, using
// coturn's shared-secret scheme so the two share no credential store.
package turn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"cb-back/internal/auth"
	"cb-back/internal/httpx"
)

type Handlers struct {
	secret []byte
	urls   []string
	ttl    time.Duration
	now    func() time.Time
	logger *slog.Logger
}

func NewHandlers(secret string, urls []string, ttl time.Duration, logger *slog.Logger) *Handlers {
	return &Handlers{secret: []byte(secret), urls: urls, ttl: ttl, now: time.Now, logger: logger}
}

func (h *Handlers) Routes(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("GET /api/turn-credentials", require(http.HandlerFunc(h.credentials)))
}

// Credentials is shaped like an RTCIceServer so clients can pass it to
// iceServers unchanged.
type Credentials struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
	TTL        int      `json:"ttl"`
}

func (h *Handlers) credentials(w http.ResponseWriter, r *http.Request) {
	if len(h.secret) == 0 {
		httpx.Error(w, h.logger, http.StatusServiceUnavailable, "turn_disabled", "no TURN relay is configured")
		return
	}

	id, ok := auth.FromContext(r.Context())
	if !ok {
		httpx.Error(w, h.logger, http.StatusUnauthorized, "unauthenticated", "")
		return
	}

	httpx.JSON(w, h.logger, http.StatusOK, h.mint(id.User.ID))
}

// mint implements coturn's use-auth-secret: username "<expiry>:<user>",
// credential base64(HMAC-SHA1(secret, username)).
func (h *Handlers) mint(userID string) Credentials {
	username := strconv.FormatInt(h.now().Add(h.ttl).Unix(), 10) + ":" + userID

	mac := hmac.New(sha1.New, h.secret)
	mac.Write([]byte(username))

	return Credentials{
		URLs:       h.urls,
		Username:   username,
		Credential: base64.StdEncoding.EncodeToString(mac.Sum(nil)),
		TTL:        int(h.ttl.Seconds()),
	}
}
