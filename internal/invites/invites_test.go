package invites

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
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"cb-back/internal/auth"
	"cb-back/internal/database"
	"cb-back/internal/httpx"
	"cb-back/internal/inbox"
	"cb-back/internal/rooms"
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
		fmt.Fprintln(os.Stderr, "skipping invites integration tests: set TEST_DATABASE_URL and TEST_REDIS_URL")
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
	hub *inbox.Hub
	ip  string
}

type account struct {
	id    string
	token string
}

// newTestServer wires invites behind the real auth middleware and a real inbox
// hub, so a test can ring one account and read the event off the other's
// websocket.
func newTestServer(t *testing.T) *testServer {
	t.Helper()
	if testPool == nil || testRDB == nil {
		t.Skip("set TEST_DATABASE_URL and TEST_REDIS_URL to run integration tests")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	users := auth.NewUserStore(testPool)
	limiter := auth.NewRateLimiter(testRDB)
	sessions := auth.NewSessionStore(testRDB, time.Hour, 24*time.Hour, 30*time.Second)
	authService := auth.NewService(users, sessions, limiter, logger)
	mw := auth.NewMiddleware(authService, logger, auth.MiddlewareOptions{
		CookieName:  "cb_session",
		IdleTTL:     time.Hour,
		AbsoluteTTL: 24 * time.Hour,
		TrustProxy:  true,
	})

	roomService := rooms.NewService(rooms.NewStore(testPool))
	hub := inbox.NewHub(logger)

	mux := http.NewServeMux()
	auth.NewHandlers(authService, mw, logger).Routes(mux, mw.Require)
	rooms.NewHandlers(roomService, logger).Routes(mux, mw.Require)
	NewHandlers(roomService, users, limiter, hub, logger).Routes(mux, mw.Require)
	mux.Handle("GET /ws/inbox", inbox.NewHandler(hub, logger, func(*http.Request) bool { return true }, mw))

	srv := httptest.NewServer(httpx.Recover(logger, mux))
	t.Cleanup(func() {
		hub.Shutdown()
		srv.Close()
	})

	// A fresh address per test and per run keeps the per-IP registration
	// limit from leaking between tests.
	return &testServer{Server: srv, hub: hub, ip: fmt.Sprintf("10.%d.%d.%d", rand.IntN(256), rand.IntN(256), rand.IntN(256))}
}

func (ts *testServer) do(t *testing.T, method, path, token string, body any) *http.Response {
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
	req.Header.Set("X-Forwarded-For", ts.ip)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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

func (ts *testServer) register(t *testing.T, displayName string) account {
	t.Helper()
	resp := ts.do(t, http.MethodPost, "/api/auth/register", "", map[string]string{
		"email":        fmt.Sprintf("invites-%d-%d@example.com", time.Now().UnixNano(), rand.IntN(1_000_000)),
		"password":     "a properly long passphrase",
		"display_name": displayName,
		"mode":         "bearer",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want 201", resp.StatusCode)
	}
	body := decodeBody[struct {
		User  struct{ ID string } `json:"user"`
		Token string              `json:"token"`
	}](t, resp)
	return account{id: body.User.ID, token: body.Token}
}

func (ts *testServer) createRoom(t *testing.T, owner account, name string) rooms.Room {
	t.Helper()
	resp := ts.do(t, http.MethodPost, "/api/rooms", owner.token, map[string]string{"name": name})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create room: status = %d, want 201", resp.StatusCode)
	}
	return decodeBody[rooms.Room](t, resp)
}

// openInbox connects an account's inbox and waits until the hub has it, so a
// delivery made right after cannot race the registration.
func (ts *testServer) openInbox(t *testing.T, a account) *websocket.Conn {
	t.Helper()

	before := ts.hub.ConnectionCount()
	header := http.Header{"Authorization": []string{"Bearer " + a.token}}
	ws, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http")+"/ws/inbox", header)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial inbox: %v (status %s)", err, resp.Status)
		}
		t.Fatalf("dial inbox: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	deadline := time.Now().Add(time.Second)
	for ts.hub.ConnectionCount() == before {
		if time.Now().After(deadline) {
			t.Fatal("inbox connection never registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ws
}

func readEvent(t *testing.T, ws *websocket.Conn) inbox.Event {
	t.Helper()
	if err := ws.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	_, raw, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read inbox: %v", err)
	}
	var event inbox.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return event
}

func TestInviteRingsTheRecipientWithAServerStampedSender(t *testing.T) {
	ts := newTestServer(t)

	caller := ts.register(t, "Бабушка")
	callee := ts.register(t, "Мама")
	room := ts.createRoom(t, caller, "Звонок")
	ws := ts.openInbox(t, callee)

	resp := ts.do(t, http.MethodPost, "/api/rooms/"+room.Slug+"/invites", caller.token, map[string]string{"user_id": callee.id})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := decodeBody[response](t, resp).Delivered; got != 1 {
		t.Fatalf("delivered = %d, want 1", got)
	}

	event := readEvent(t, ws)
	if event.Type != inbox.TypeInvite {
		t.Fatalf("type = %q, want invite", event.Type)
	}
	if event.From.ID != caller.id || event.From.DisplayName != "Бабушка" {
		t.Fatalf("from = %+v, want the authenticated caller", event.From)
	}
	if event.Room.Slug != room.Slug || event.Room.Name != "Звонок" {
		t.Fatalf("room = %+v", event.Room)
	}
}

// A zero count is how the caller learns nobody will hear the ring.
func TestInviteToAnOfflineUserReportsNothingDelivered(t *testing.T) {
	ts := newTestServer(t)

	caller := ts.register(t, "Caller")
	callee := ts.register(t, "Offline")
	room := ts.createRoom(t, caller, "Call")

	resp := ts.do(t, http.MethodPost, "/api/rooms/"+room.Slug+"/invites", caller.token, map[string]string{"user_id": callee.id})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := decodeBody[response](t, resp).Delivered; got != 0 {
		t.Fatalf("delivered = %d, want 0", got)
	}
}

// The caller may delete the room on hang-up before the cancel is sent; the
// recipient's phone must still stop ringing.
func TestCancelIsDeliveredAfterTheRoomIsGone(t *testing.T) {
	ts := newTestServer(t)

	caller := ts.register(t, "Caller")
	callee := ts.register(t, "Callee")
	room := ts.createRoom(t, caller, "Call")
	ws := ts.openInbox(t, callee)

	if resp := ts.do(t, http.MethodDelete, "/api/rooms/"+room.Slug, caller.token, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status = %d", resp.StatusCode)
	}

	resp := ts.do(t, http.MethodPost, "/api/rooms/"+room.Slug+"/invites/cancel", caller.token, map[string]string{"user_id": callee.id})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if event := readEvent(t, ws); event.Type != inbox.TypeInviteCancelled || event.Room.Slug != room.Slug {
		t.Fatalf("event = %+v", event)
	}
}

func TestDeclineReachesTheCaller(t *testing.T) {
	ts := newTestServer(t)

	caller := ts.register(t, "Caller")
	callee := ts.register(t, "Callee")
	room := ts.createRoom(t, caller, "Call")
	callerInbox := ts.openInbox(t, caller)

	resp := ts.do(t, http.MethodPost, "/api/rooms/"+room.Slug+"/invites/decline", callee.token, map[string]string{"user_id": caller.id})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	event := readEvent(t, callerInbox)
	if event.Type != inbox.TypeInviteDeclined || event.From.ID != callee.id {
		t.Fatalf("event = %+v", event)
	}
}

func TestInviteRejectsBadTargets(t *testing.T) {
	ts := newTestServer(t)

	caller := ts.register(t, "Caller")
	callee := ts.register(t, "Callee")
	room := ts.createRoom(t, caller, "Call")

	tests := []struct {
		name       string
		slug       string
		userID     string
		wantStatus int
		wantCode   string
	}{
		{"unknown room", "no-such-room", callee.id, http.StatusNotFound, "room_not_found"},
		{"unknown user", room.Slug, "00000000-0000-0000-0000-000000000000", http.StatusNotFound, "user_not_found"},
		{"not a user id", room.Slug, "mama", http.StatusBadRequest, "invalid_user"},
		{"yourself", room.Slug, caller.id, http.StatusBadRequest, "invalid_user"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := ts.do(t, http.MethodPost, "/api/rooms/"+tc.slug+"/invites", caller.token, map[string]string{"user_id": tc.userID})
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if got := decodeBody[httpx.ErrorBody](t, resp).Error; got != tc.wantCode {
				t.Fatalf("error = %q, want %q", got, tc.wantCode)
			}
		})
	}
}

func TestInviteRequiresASession(t *testing.T) {
	ts := newTestServer(t)

	caller := ts.register(t, "Caller")
	callee := ts.register(t, "Callee")
	room := ts.createRoom(t, caller, "Call")

	resp := ts.do(t, http.MethodPost, "/api/rooms/"+room.Slug+"/invites", "", map[string]string{"user_id": callee.id})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
