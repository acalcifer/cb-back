package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"cb-back/internal/database"
	"cb-back/internal/httpx"

	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests run against the Postgres and Redis started by docker-compose.
// They are skipped unless both URLs are exported, so `go test ./...` still
// works on a machine with no containers:
//
//	TEST_DATABASE_URL=... TEST_REDIS_URL=... go test ./internal/auth/
var (
	testPool *pgxpool.Pool
	testRDB  *redis.Client
	testIPs  atomic.Uint32
)

func TestMain(m *testing.M) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbURL == "" || redisURL == "" {
		fmt.Fprintln(os.Stderr, "skipping auth integration tests: set TEST_DATABASE_URL and TEST_REDIS_URL")
		os.Exit(m.Run())
	}

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	pool, err := database.Connect(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect test database: %v\n", err)
		os.Exit(1)
	}
	if err := database.Migrate(ctx, pool, logger); err != nil {
		fmt.Fprintf(os.Stderr, "migrate test database: %v\n", err)
		os.Exit(1)
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse TEST_REDIS_URL: %v\n", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		fmt.Fprintf(os.Stderr, "ping test redis: %v\n", err)
		os.Exit(1)
	}

	testPool, testRDB = pool, rdb
	code := m.Run()

	_ = rdb.Close()
	pool.Close()
	os.Exit(code)
}

func requireContainers(t *testing.T) {
	t.Helper()
	if testPool == nil || testRDB == nil {
		t.Skip("set TEST_DATABASE_URL and TEST_REDIS_URL to run integration tests")
	}
}

type testServer struct {
	*httptest.Server
	svc *Service
	mw  *Middleware
	ip  string
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	requireContainers(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sessions := NewSessionStore(testRDB, time.Hour, 24*time.Hour, 30*time.Second)
	svc := NewService(NewUserStore(testPool), sessions, NewRateLimiter(testRDB), logger)
	mw := NewMiddleware(svc, logger, MiddlewareOptions{
		CookieName:   "cb_session",
		CookieSecure: false,
		IdleTTL:      time.Hour,
		AbsoluteTTL:  24 * time.Hour,
		// Each test presents its own X-Forwarded-For so per-IP rate limits
		// stay isolated between tests.
		TrustProxy: true,
	})

	policy, err := httpx.NewOriginPolicy("http://app.test", logger)
	if err != nil {
		t.Fatalf("NewOriginPolicy: %v", err)
	}

	mux := http.NewServeMux()
	NewHandlers(svc, mw, logger).Routes(mux, mw.Require)

	deny := func(w http.ResponseWriter, r *http.Request, reason string) {
		httpx.Error(w, logger, http.StatusForbidden, "forbidden_origin", reason)
	}

	srv := httptest.NewServer(httpx.Recover(logger, httpx.SecurityHeaders(httpx.CSRF(policy, deny, mux))))
	t.Cleanup(srv.Close)

	return &testServer{
		Server: srv,
		svc:    svc,
		mw:     mw,
		// A fresh address per test AND per run: rate-limit windows live in
		// Redis for up to an hour, so reusing addresses across runs would
		// leak one test's quota into the next.
		ip: fmt.Sprintf("10.%d.%d.%d", rand.IntN(256), rand.IntN(256), testIPs.Add(1)%256),
	}
}

// do issues a request carrying this test's isolated client IP.
func (ts *testServer) do(t *testing.T, method, path string, body any, opts ...func(*http.Request)) *http.Response {
	t.Helper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, ts.URL+path, payload)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ts.ip)
	for _, opt := range opts {
		opt(req)
	}

	// Redirects are never expected from this API.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func withCookie(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

func withBearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func withHeader(key, value string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(key, value) }
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func uniqueEmail() string {
	return fmt.Sprintf("user-%d-%d@example.com", time.Now().UnixNano(), testIPs.Load())
}

const testPassword = "a properly long passphrase"

func sessionCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == "cb_session" {
			return c
		}
	}
	t.Fatal("no session cookie in response")
	return nil
}

func TestRegisterIssuesHttpOnlyCookieAndNoTokenInBody(t *testing.T) {
	ts := newTestServer(t)

	resp := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{
		"email":        uniqueEmail(),
		"password":     testPassword,
		"display_name": "Test User",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	body := decode[sessionResponse](t, resp)
	if body.Token != "" {
		t.Fatal("cookie-mode response leaked the session token into the body, where JavaScript could read it")
	}
	if body.User.ID == "" {
		t.Fatal("response has no user id")
	}

	cookie := sessionCookie(t, resp)
	if !cookie.HttpOnly {
		t.Error("session cookie is not HttpOnly; XSS could steal it")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Value == "" {
		t.Error("session cookie is empty")
	}
}

func TestRegisterRejectsDuplicateEmailAndWeakPassword(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	if resp := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{
		"email": email, "password": testPassword,
	}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("first register: status = %d, want 201", resp.StatusCode)
	}

	resp := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{
		"email": email, "password": testPassword,
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate register: status = %d, want 409", resp.StatusCode)
	}

	weak := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{
		"email": uniqueEmail(), "password": "short",
	})
	if weak.StatusCode != http.StatusBadRequest {
		t.Fatalf("weak password: status = %d, want 400", weak.StatusCode)
	}
	if got := decode[httpx.ErrorBody](t, weak).Error; got != "weak_password" {
		t.Fatalf("error code = %q, want weak_password", got)
	}
}

func TestLoginCookieFlowAndMe(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})

	resp := ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": testPassword})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status = %d, want 200", resp.StatusCode)
	}
	cookie := sessionCookie(t, resp)

	me := ts.do(t, http.MethodGet, "/api/auth/me", nil, withCookie(cookie))
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me: status = %d, want 200", me.StatusCode)
	}
	if got := decode[sessionResponse](t, me).User.Email; got != email {
		t.Fatalf("me returned %q, want %q", got, email)
	}

	anon := ts.do(t, http.MethodGet, "/api/auth/me", nil)
	if anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated me: status = %d, want 401", anon.StatusCode)
	}
}

func TestLoginBearerModeForNativeClients(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})

	resp := ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email": email, "password": testPassword, "mode": "bearer",
	})
	body := decode[sessionResponse](t, resp)
	if body.Token == "" {
		t.Fatal("bearer mode did not return a token")
	}
	if body.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", body.TokenType)
	}
	if len(resp.Cookies()) != 0 {
		t.Fatal("bearer mode should not also set a cookie")
	}

	me := ts.do(t, http.MethodGet, "/api/auth/me", nil, withBearer(body.Token))
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me with bearer token: status = %d, want 200", me.StatusCode)
	}
}

func TestWrongPasswordAndUnknownEmailAreIndistinguishable(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})

	wrong := ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": "the wrong passphrase"})
	unknown := ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": uniqueEmail(), "password": testPassword})

	if wrong.StatusCode != http.StatusUnauthorized || unknown.StatusCode != http.StatusUnauthorized {
		t.Fatalf("statuses = %d and %d, want both 401", wrong.StatusCode, unknown.StatusCode)
	}

	wrongBody, unknownBody := decode[httpx.ErrorBody](t, wrong), decode[httpx.ErrorBody](t, unknown)
	if wrongBody != unknownBody {
		t.Fatalf("responses differ and leak whether an account exists: %+v vs %+v", wrongBody, unknownBody)
	}
}

func TestLoginRateLimitLocksAccount(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})

	for i := range LoginPerAccount.Requests {
		resp := ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": "wrong passphrase"})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, resp.StatusCode)
		}
	}

	blocked := ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": "wrong passphrase"})
	if blocked.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 after %d failures", blocked.StatusCode, LoginPerAccount.Requests)
	}
	if blocked.Header.Get("Retry-After") == "" {
		t.Error("429 response has no Retry-After header")
	}

	// The lockout must hold even for the correct password, or it is no defence.
	correct := ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": testPassword})
	if correct.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want the lockout to apply to correct credentials too", correct.StatusCode)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	reg := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})
	cookie := sessionCookie(t, reg)

	out := ts.do(t, http.MethodPost, "/api/auth/logout", nil, withCookie(cookie), withHeader("Origin", "http://app.test"))
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status = %d, want 204", out.StatusCode)
	}

	me := ts.do(t, http.MethodGet, "/api/auth/me", nil, withCookie(cookie))
	if me.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session still valid after logout: status = %d", me.StatusCode)
	}
}

func TestPasswordChangeRevokesOtherSessionsButKeepsCurrent(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})

	first := sessionCookie(t, ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": testPassword}))
	second := sessionCookie(t, ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": testPassword}))

	const newPassword = "an entirely different passphrase"
	change := ts.do(t, http.MethodPost, "/api/auth/password", map[string]string{
		"current_password": testPassword,
		"new_password":     newPassword,
	}, withCookie(second), withHeader("Origin", "http://app.test"))
	if change.StatusCode != http.StatusNoContent {
		t.Fatalf("change password: status = %d, want 204", change.StatusCode)
	}

	if me := ts.do(t, http.MethodGet, "/api/auth/me", nil, withCookie(second)); me.StatusCode != http.StatusOK {
		t.Fatalf("the session that changed the password was revoked: status = %d", me.StatusCode)
	}
	if me := ts.do(t, http.MethodGet, "/api/auth/me", nil, withCookie(first)); me.StatusCode != http.StatusUnauthorized {
		t.Fatalf("other session survived the password change: status = %d", me.StatusCode)
	}

	if resp := ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": newPassword}); resp.StatusCode != http.StatusOK {
		t.Fatalf("login with the new password: status = %d, want 200", resp.StatusCode)
	}
}

func TestLogoutAllRevokesEverySession(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})
	first := sessionCookie(t, ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": testPassword}))
	second := sessionCookie(t, ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": testPassword}))

	resp := ts.do(t, http.MethodPost, "/api/auth/logout-all", nil, withCookie(first), withHeader("Origin", "http://app.test"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout-all: status = %d, want 200", resp.StatusCode)
	}

	for name, cookie := range map[string]*http.Cookie{"first": first, "second": second} {
		if me := ts.do(t, http.MethodGet, "/api/auth/me", nil, withCookie(cookie)); me.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s session survived logout-all: status = %d", name, me.StatusCode)
		}
	}
}

func TestWebsocketTicketIsSingleUse(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	reg := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})
	cookie := sessionCookie(t, reg)

	resp := ts.do(t, http.MethodPost, "/api/auth/ws-ticket", nil, withCookie(cookie), withHeader("Origin", "http://app.test"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ws-ticket: status = %d, want 200", resp.StatusCode)
	}

	ticket := decode[struct {
		Ticket    string `json:"ticket"`
		ExpiresIn int    `json:"expires_in"`
	}](t, resp)
	if ticket.Ticket == "" {
		t.Fatal("no ticket returned")
	}
	if ticket.ExpiresIn <= 0 || ticket.ExpiresIn > 60 {
		t.Fatalf("expires_in = %d, want a short lifetime", ticket.ExpiresIn)
	}

	ctx := context.Background()
	if _, err := ts.svc.Sessions().RedeemWSTicket(ctx, ticket.Ticket); err != nil {
		t.Fatalf("first redemption failed: %v", err)
	}
	if _, err := ts.svc.Sessions().RedeemWSTicket(ctx, ticket.Ticket); err == nil {
		t.Fatal("ticket was redeemable twice; it must be single-use")
	}
}

func TestCSRFBlocksCrossSitePost(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	reg := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})
	cookie := sessionCookie(t, reg)

	resp := ts.do(t, http.MethodPost, "/api/auth/logout-all", nil, withCookie(cookie), withHeader("Origin", "https://evil.example"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site post: status = %d, want 403", resp.StatusCode)
	}

	if me := ts.do(t, http.MethodGet, "/api/auth/me", nil, withCookie(cookie)); me.StatusCode != http.StatusOK {
		t.Fatalf("blocked request still took effect: status = %d", me.StatusCode)
	}
}

func TestSessionTokenIsNotStoredInRedis(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	reg := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})
	cookie := sessionCookie(t, reg)

	ctx := context.Background()
	keys, err := testRDB.Keys(ctx, "sess:*").Result()
	if err != nil {
		t.Fatalf("list session keys: %v", err)
	}

	for _, key := range keys {
		if key == "sess:"+cookie.Value {
			t.Fatal("the raw session token is a Redis key; a snapshot leak would be directly replayable")
		}
		value, err := testRDB.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		if bytes.Contains([]byte(value), []byte(cookie.Value)) {
			t.Fatal("the raw session token appears in a Redis value")
		}
	}
}

func TestDisabledAccountCannotAuthenticate(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	reg := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})
	cookie := sessionCookie(t, reg)

	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE users SET disabled_at = now() WHERE email = $1`, email); err != nil {
		t.Fatalf("disable account: %v", err)
	}

	// An existing session must stop working immediately, not at expiry.
	if me := ts.do(t, http.MethodGet, "/api/auth/me", nil, withCookie(cookie)); me.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled account kept its session: status = %d", me.StatusCode)
	}

	login := ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": testPassword})
	if login.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled account could log in: status = %d", login.StatusCode)
	}
	if got := decode[httpx.ErrorBody](t, login).Error; got != "invalid_credentials" {
		t.Fatalf("error code = %q; a disabled account must be indistinguishable from a wrong password", got)
	}
}

func TestAuthEventsAreRecorded(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})
	ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": "wrong passphrase"})
	ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": testPassword})

	rows, err := testPool.Query(context.Background(),
		`SELECT event FROM auth_events WHERE email = $1 ORDER BY created_at`, email)
	if err != nil {
		t.Fatalf("query auth events: %v", err)
	}
	defer rows.Close()

	var events []string
	for rows.Next() {
		var event string
		if err := rows.Scan(&event); err != nil {
			t.Fatalf("scan: %v", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	want := []string{"register", "login_failed_bad_password", "login"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}

// The app calls /me on start-up to decide whether the user is still signed in.
// It must also slide the cookie, or the browser copy expires on the schedule
// set at login even though the server-side session kept renewing.
func TestSessionCheckRefreshesTheCookie(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	reg := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{
		"email": email, "password": testPassword,
	})
	original := sessionCookie(t, reg)

	me := ts.do(t, http.MethodGet, "/api/auth/me", nil, withCookie(original))
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me: status = %d, want 200", me.StatusCode)
	}

	refreshed := sessionCookie(t, me)
	if refreshed.Value != original.Value {
		t.Fatal("the session token changed; only its lifetime should slide")
	}
	if !refreshed.HttpOnly {
		t.Fatal("refreshed cookie lost HttpOnly")
	}
	if refreshed.MaxAge <= 0 {
		t.Fatalf("refreshed cookie has MaxAge %d, want a positive lifetime", refreshed.MaxAge)
	}
}

// A bearer client keeps its own token and has no cookie to update; sending it
// one would hand a browser-style credential to a client that never asked.
func TestBearerClientsGetNoCookie(t *testing.T) {
	ts := newTestServer(t)
	email := uniqueEmail()

	ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": testPassword})
	login := ts.do(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email": email, "password": testPassword, "mode": "bearer",
	})
	token := decode[sessionResponse](t, login).Token

	me := ts.do(t, http.MethodGet, "/api/auth/me", nil, withBearer(token))
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me: status = %d, want 200", me.StatusCode)
	}
	for _, c := range me.Cookies() {
		if c.Name == "cb_session" {
			t.Fatal("a bearer request was issued a session cookie")
		}
	}
}

// The address book is how a client finds someone to ring. It must list other
// people, omit the caller, and — like the room directory — never carry an
// email address.
func TestContactsListOthersWithoutEmails(t *testing.T) {
	ts := newTestServer(t)

	self := ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{
		"email": uniqueEmail(), "password": testPassword, "mode": "bearer",
	})
	me := decode[sessionResponse](t, self)

	other := decode[sessionResponse](t, ts.do(t, http.MethodPost, "/api/auth/register", map[string]string{
		"email": uniqueEmail(), "password": testPassword, "display_name": "Someone Else",
	}))

	resp := ts.do(t, http.MethodGet, "/api/users", nil, withBearer(me.Token))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if bytes.Contains(raw, []byte("@example.com")) {
		t.Fatalf("contacts response contains an email address: %s", raw)
	}

	var list struct {
		Users []Contact `json:"users"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var sawOther bool
	for _, c := range list.Users {
		if c.ID == me.User.ID {
			t.Fatal("contacts include the caller")
		}
		if c.ID == other.User.ID {
			sawOther = true
			if c.DisplayName != "Someone Else" {
				t.Fatalf("display name = %q", c.DisplayName)
			}
		}
	}
	if !sawOther {
		t.Fatal("contacts omitted another user")
	}

	if anon := ts.do(t, http.MethodGet, "/api/users", nil); anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous contacts: status = %d, want 401", anon.StatusCode)
	}
}
