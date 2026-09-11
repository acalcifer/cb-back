package turn

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cb-back/internal/httpx"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestMintMatchesCoturnScheme(t *testing.T) {
	h := NewHandlers("s3cret", []string{"turn:turn.example.com:3478?transport=udp"}, time.Hour, testLogger())
	h.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	got := h.mint("user-1")

	// Reference value from: printf '1700003600:user-1' | openssl dgst -sha1 -hmac s3cret -binary | base64
	if want := "1700003600:user-1"; got.Username != want {
		t.Errorf("username = %q, want %q", got.Username, want)
	}
	if want := "D/3A4z6ImTw+jB+qL+7PTELkgCk="; got.Credential != want {
		t.Errorf("credential = %q, want %q", got.Credential, want)
	}
	if got.TTL != 3600 {
		t.Errorf("ttl = %d, want 3600", got.TTL)
	}
	if len(got.URLs) != 1 || got.URLs[0] != "turn:turn.example.com:3478?transport=udp" {
		t.Errorf("urls = %v", got.URLs)
	}
}

func TestCredentialsDisabledWithoutSecret(t *testing.T) {
	h := NewHandlers("", nil, time.Hour, testLogger())
	rec := httptest.NewRecorder()

	h.credentials(rec, httptest.NewRequest(http.MethodGet, "/api/turn-credentials", nil))

	assertError(t, rec, http.StatusServiceUnavailable, "turn_disabled")
}

func TestCredentialsWithoutIdentity(t *testing.T) {
	h := NewHandlers("s3cret", []string{"turn:x"}, time.Hour, testLogger())
	rec := httptest.NewRecorder()

	h.credentials(rec, httptest.NewRequest(http.MethodGet, "/api/turn-credentials", nil))

	assertError(t, rec, http.StatusUnauthorized, "unauthenticated")
}

func TestRouteIsWrappedInRequire(t *testing.T) {
	mux := http.NewServeMux()
	deny := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})
	}
	NewHandlers("s3cret", []string{"turn:x"}, time.Hour, testLogger()).Routes(mux, deny)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/turn-credentials", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want the require wrapper's %d", rec.Code, http.StatusTeapot)
	}
}

func assertError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d", rec.Code, status)
	}
	var body httpx.ErrorBody
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != code {
		t.Errorf("error = %q, want %q", body.Error, code)
	}
}
