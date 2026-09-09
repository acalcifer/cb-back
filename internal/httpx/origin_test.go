package httpx

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestOriginPolicy(t *testing.T) {
	tests := []struct {
		name    string
		allowed string
		origin  string
		host    string
		want    bool
	}{
		{"empty origin allowed", "", "", "example.com", true},
		{"same host allowed by default", "", "https://example.com", "example.com", true},
		{"cross host denied by default", "", "https://evil.com", "example.com", false},
		{"allowlisted origin", "https://app.example.com", "https://app.example.com", "api.example.com", true},
		{"allowlist is case insensitive", "https://App.Example.com", "https://app.example.com", "x", true},
		{"origin outside allowlist", "https://app.example.com", "https://evil.com", "app.example.com", false},
		{"allowlist overrides same host", "https://app.example.com", "https://api.example.com", "api.example.com", false},
		{"scheme must match", "https://app.example.com", "http://app.example.com", "x", false},
		{"multiple origins", "https://a.example.com, https://b.example.com", "https://b.example.com", "x", true},
		{"wildcard allows all", "*", "https://evil.com", "example.com", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := NewOriginPolicy(tc.allowed, testLogger())
			if err != nil {
				t.Fatalf("NewOriginPolicy: %v", err)
			}
			r := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/ws", nil)
			r.Host = tc.host
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := policy.Allow(r); got != tc.want {
				t.Fatalf("Allow(origin=%q, host=%q) = %v, want %v", tc.origin, tc.host, got, tc.want)
			}
		})
	}
}

func TestOriginPolicyRejectsBadConfig(t *testing.T) {
	for _, bad := range []string{"example.com", "https://", "://nope"} {
		if _, err := NewOriginPolicy(bad, testLogger()); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestCSRFGuard(t *testing.T) {
	policy, err := NewOriginPolicy("https://app.example.com", testLogger())
	if err != nil {
		t.Fatalf("NewOriginPolicy: %v", err)
	}

	denied := false
	guard := CSRF(policy,
		func(w http.ResponseWriter, r *http.Request, reason string) {
			denied = true
			w.WriteHeader(http.StatusForbidden)
		},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	tests := []struct {
		name       string
		method     string
		origin     string
		authHeader string
		wantStatus int
	}{
		{"safe method skips check", http.MethodGet, "https://evil.com", "", http.StatusOK},
		{"allowed origin passes", http.MethodPost, "https://app.example.com", "", http.StatusOK},
		{"cross-site post blocked", http.MethodPost, "https://evil.com", "", http.StatusForbidden},
		{"bearer token exempt", http.MethodPost, "https://evil.com", "Bearer abc", http.StatusOK},
		{"missing origin passes", http.MethodPost, "", "", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			denied = false
			r := httptest.NewRequest(tc.method, "https://api.example.com/api/auth/login", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.authHeader != "" {
				r.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			guard.ServeHTTP(w, r)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (denied=%v)", w.Code, tc.wantStatus, denied)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remote     string
		xff        string
		trustProxy bool
		want       string
	}{
		{"socket address by default", "203.0.113.9:5555", "", false, "203.0.113.9"},
		{"spoofed header ignored when untrusted", "203.0.113.9:5555", "1.2.3.4", false, "203.0.113.9"},
		{"header honoured when trusted", "10.0.0.1:5555", "1.2.3.4", true, "1.2.3.4"},
		{"leftmost entry wins", "10.0.0.1:5555", "1.2.3.4, 10.0.0.9", true, "1.2.3.4"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := ClientIP(r, tc.trustProxy); got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}
