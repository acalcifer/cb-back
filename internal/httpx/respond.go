package httpx

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// ErrorBody is the single error shape every endpoint returns, so clients never
// have to branch on which layer failed.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// JSON writes v as the response body. A marshalling failure is logged rather
// than retried: the status line is already on the wire by then.
func JSON(w http.ResponseWriter, logger *slog.Logger, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		logger.Error("marshal response failed", "error", err)
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		logger.Debug("write response failed", "error", err)
	}
}

// Error writes a machine-readable error code with an optional human message.
// Codes are stable; messages are not, and must never leak whether an account
// exists.
func Error(w http.ResponseWriter, logger *slog.Logger, status int, code, message string) {
	JSON(w, logger, status, ErrorBody{Error: code, Message: message})
}

// DecodeJSON reads a size-limited JSON body and rejects unknown fields, so a
// typo in a client payload fails loudly instead of silently defaulting.
func DecodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// Recover turns a handler panic into a 500 instead of a dropped connection,
// and keeps the stack in the logs where it belongs rather than in the response.
func Recover(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic in handler", "panic", rec, "path", r.URL.Path)
				Error(w, logger, http.StatusInternalServerError, "internal_error", "")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders sets the headers that matter for a JSON API. This is an API
// with no HTML surface, so the CSP simply forbids everything.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// ClientIP resolves the address used for rate limiting.
//
// X-Forwarded-For is only consulted when trustProxy is set. Honouring it
// unconditionally would let any caller spoof the header and walk straight past
// per-IP limits, so the default is the real socket address.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Left-most entry is the original client; the proxy appends.
			if first, _, found := strings.Cut(xff, ","); found || first != "" {
				if ip := strings.TrimSpace(first); ip != "" {
					return ip
				}
			}
		}
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			return real
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
