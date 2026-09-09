package rooms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"cb-back/internal/auth"
	"cb-back/internal/database"
	"cb-back/internal/httpx"
)

// Runs against the compose Postgres and Redis; skipped when they are not
// configured, so `go test ./...` still works without containers.
var (
	testPool *pgxpool.Pool
	testRDB  *redis.Client
)

func TestMain(m *testing.M) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbURL == "" || redisURL == "" {
		fmt.Fprintln(os.Stderr, "skipping rooms integration tests: set TEST_DATABASE_URL and TEST_REDIS_URL")
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

type testServer struct {
	*httptest.Server
	svc *Service
}

// newTestServer wires rooms behind the real auth middleware, so the tests
// exercise the actual composition rather than a stubbed identity.
func newTestServer(t *testing.T) *testServer {
	t.Helper()
	if testPool == nil || testRDB == nil {
		t.Skip("set TEST_DATABASE_URL and TEST_REDIS_URL to run integration tests")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sessions := auth.NewSessionStore(testRDB, time.Hour, 24*time.Hour, 30*time.Second)
	authService := auth.NewService(auth.NewUserStore(testPool), sessions, auth.NewRateLimiter(testRDB), logger)
	mw := auth.NewMiddleware(authService, logger, auth.MiddlewareOptions{
		CookieName:  "cb_session",
		IdleTTL:     time.Hour,
		AbsoluteTTL: 24 * time.Hour,
		TrustProxy:  true,
	})

	svc := NewService(NewStore(testPool))

	mux := http.NewServeMux()
	auth.NewHandlers(authService, mw, logger).Routes(mux, mw.Require)
	NewHandlers(svc, logger).Routes(mux, mw.Require)

	srv := httptest.NewServer(httpx.Recover(logger, mux))
	t.Cleanup(srv.Close)

	return &testServer{Server: srv, svc: svc}
}

// signIn registers a fresh account and returns its session cookie.
func (ts *testServer) signIn(t *testing.T) *http.Cookie {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"email":    fmt.Sprintf("rooms-%d@example.com", time.Now().UnixNano()),
		"password": "a properly long passphrase",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/register", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// A unique address per test keeps the per-IP registration limit from
	// leaking one test's quota into the next.
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.1.%d.%d", time.Now().UnixNano()%256, time.Now().UnixNano()/256%256))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want 201", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "cb_session" {
			return c
		}
	}
	t.Fatal("no session cookie after register")
	return nil
}

func (ts *testServer) do(t *testing.T, method, path string, body any, cookie *http.Cookie) *http.Response {
	t.Helper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, ts.URL+path, payload)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decodeBody[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// Matches the CHECK constraint in the migration.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)

func TestCreateRoomGeneratesAValidSlug(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.signIn(t)

	resp := ts.do(t, http.MethodPost, "/api/rooms", map[string]string{"name": "Standup"}, cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	room := decodeBody[Room](t, resp)
	if room.Name != "Standup" {
		t.Fatalf("name = %q", room.Name)
	}
	if !slugPattern.MatchString(room.Slug) {
		t.Fatalf("slug %q does not satisfy the database constraint", room.Slug)
	}
	if room.ID == "" || room.CreatedBy == "" {
		t.Fatalf("room is missing identity fields: %+v", room)
	}
}

func TestSlugsAreUnpredictable(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.signIn(t)

	seen := make(map[string]struct{})
	for range 10 {
		resp := ts.do(t, http.MethodPost, "/api/rooms", nil, cookie)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d, want 201", resp.StatusCode)
		}
		room := decodeBody[Room](t, resp)
		if _, dup := seen[room.Slug]; dup {
			t.Fatalf("slug %q was issued twice", room.Slug)
		}
		seen[room.Slug] = struct{}{}
	}
}

func TestEmptyBodyGetsADefaultName(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.signIn(t)

	resp := ts.do(t, http.MethodPost, "/api/rooms", nil, cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if room := decodeBody[Room](t, resp); room.Name == "" {
		t.Fatal("room created with an empty name")
	}
}

// The directory is public: a user must be able to see rooms they did not
// create, or there is nothing to join.
func TestListIsAPublicDirectory(t *testing.T) {
	ts := newTestServer(t)

	mine := ts.signIn(t)
	theirs := ts.signIn(t)

	ownRoom := decodeBody[Room](t, ts.do(t, http.MethodPost, "/api/rooms", map[string]string{"name": "Mine"}, mine))
	otherRoom := decodeBody[Room](t, ts.do(t, http.MethodPost, "/api/rooms", map[string]string{"name": "Theirs"}, theirs))

	resp := ts.do(t, http.MethodGet, "/api/rooms", nil, mine)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	list := decodeBody[struct {
		Rooms []Room `json:"rooms"`
	}](t, resp)

	found := make(map[string]Room, len(list.Rooms))
	for _, r := range list.Rooms {
		found[r.ID] = r
	}

	if _, ok := found[ownRoom.ID]; !ok {
		t.Fatal("directory omitted the caller's own room")
	}
	other, ok := found[otherRoom.ID]
	if !ok {
		t.Fatal("directory omitted another user's room; it is supposed to be public")
	}
	if other.CreatedByName == "" {
		t.Fatal("directory row has no creator name to display")
	}
}

// The directory is readable, but it must not turn into a user-enumeration
// endpoint: display names are fine, email addresses are not.
func TestDirectoryDoesNotLeakEmailAddresses(t *testing.T) {
	ts := newTestServer(t)

	cookie := ts.signIn(t)
	ts.do(t, http.MethodPost, "/api/rooms", map[string]string{"name": "Public"}, cookie)

	resp := ts.do(t, http.MethodGet, "/api/rooms", nil, cookie)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if bytes.Contains(body, []byte("@example.com")) {
		t.Fatalf("directory response contains an email address: %s", body)
	}
}

// Knowing the slug is the invitation: any signed-in user can resolve it.
func TestAnySignedInUserCanResolveASlug(t *testing.T) {
	ts := newTestServer(t)

	owner := ts.signIn(t)
	guest := ts.signIn(t)

	created := decodeBody[Room](t, ts.do(t, http.MethodPost, "/api/rooms", nil, owner))

	resp := ts.do(t, http.MethodGet, "/api/rooms/"+created.Slug, nil, guest)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := decodeBody[Room](t, resp); got.ID != created.ID {
		t.Fatalf("resolved %q, want %q", got.ID, created.ID)
	}
}

func TestUnknownSlugIsNotFound(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.signIn(t)

	resp := ts.do(t, http.MethodGet, "/api/rooms/no-such-room", nil, cookie)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if got := decodeBody[httpx.ErrorBody](t, resp).Error; got != "room_not_found" {
		t.Fatalf("error = %q, want room_not_found", got)
	}
}

func TestRoomEndpointsRequireASession(t *testing.T) {
	ts := newTestServer(t)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/rooms"},
		{http.MethodGet, "/api/rooms"},
		{http.MethodGet, "/api/rooms/anything"},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if resp := ts.do(t, tc.method, tc.path, nil, nil); resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

func TestOverlongNameRejected(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.signIn(t)

	long := make([]byte, 101)
	for i := range long {
		long[i] = 'a'
	}

	resp := ts.do(t, http.MethodPost, "/api/rooms", map[string]string{"name": string(long)}, cookie)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
