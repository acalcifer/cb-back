package signaling

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"cb-back/internal/httpx"
)

// stubAuth stands in for the auth middleware: it accepts every request unless
// told to reject, so signaling tests exercise relaying rather than credentials.
type stubAuth struct {
	err  error
	user string
}

func (s stubAuth) AuthenticateWS(context.Context, *http.Request) (string, string, error) {
	if s.err != nil {
		return "", "", s.err
	}
	user := s.user
	if user == "" {
		user = "user-1"
	}
	return user, "Test User", nil
}

// stubRooms resolves the slugs the tests use and rejects everything else.
func stubRooms(ctx context.Context, slug string) (string, error) {
	switch slug {
	case "known-room", "other-room":
		return "id-" + slug, nil
	default:
		return "", ErrRoomNotFound
	}
}

func startServer(t *testing.T, allowedOrigins string) string {
	t.Helper()
	return startServerWithAuth(t, allowedOrigins, stubAuth{})
}

func startServerWithAuth(t *testing.T, allowedOrigins string, auth Authenticator) string {
	t.Helper()

	policy, err := httpx.NewOriginPolicy(allowedOrigins, testLogger())
	if err != nil {
		t.Fatalf("NewOriginPolicy: %v", err)
	}

	h, _ := startHub(t)
	srv := httptest.NewServer(NewHandler(h, testLogger(), policy.CheckOrigin, auth, stubRooms))
	t.Cleanup(srv.Close)

	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
}

func dial(t *testing.T, url string, header http.Header) *websocket.Conn {
	t.Helper()
	conn, resp, err := websocket.DefaultDialer.Dial(url, header)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial %s: %v (status %s)", url, err, resp.Status)
		}
		t.Fatalf("dial %s: %v", url, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readOutbound(t *testing.T, conn *websocket.Conn) Outbound {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out Outbound
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	return out
}

func readOutboundOfType(t *testing.T, conn *websocket.Conn, want string) Outbound {
	t.Helper()
	for range 5 {
		if out := readOutbound(t, conn); out.Type == want {
			return out
		}
	}
	t.Fatalf("never received a %q frame", want)
	return Outbound{}
}

func TestRelaysMessagesBetweenClients(t *testing.T) {
	url := startServer(t, "")

	sender := dial(t, url+"?room=known-room", nil)
	receiver := dial(t, url+"?room=known-room", nil)

	readOutboundOfType(t, sender, TypeWelcome)
	readOutboundOfType(t, receiver, TypeWelcome)

	if err := sender.WriteJSON(Inbound{Type: TypeOffer, Payload: json.RawMessage(`{"sdp":"offer"}`)}); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := readOutboundOfType(t, receiver, TypeOffer)
	if string(got.Payload) != `{"sdp":"offer"}` {
		t.Fatalf("payload = %s", got.Payload)
	}
	if got.From == "" {
		t.Fatal("relayed frame has no sender")
	}
}

// A client must not be able to name its own sender: doing so would let it
// inject an offer as another participant.
func TestClientCannotSpoofSender(t *testing.T) {
	url := startServer(t, "")

	sender := dial(t, url+"?room=known-room", nil)
	receiver := dial(t, url+"?room=known-room", nil)
	readOutboundOfType(t, sender, TypeWelcome)
	readOutboundOfType(t, receiver, TypeWelcome)

	raw := `{"type":"offer","from":"someone-else","payload":{"sdp":"x"}}`
	if err := sender.WriteMessage(websocket.TextMessage, []byte(raw)); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := readOutboundOfType(t, receiver, TypeOffer)
	if got.From == "someone-else" {
		t.Fatal("server relayed a client-supplied sender; impersonation is possible")
	}
	if got.From != "user-1" {
		t.Fatalf("from = %q, want the authenticated user", got.From)
	}
}

func TestUnknownMessageTypeIsNotRelayed(t *testing.T) {
	url := startServer(t, "")

	sender := dial(t, url+"?room=known-room", nil)
	receiver := dial(t, url+"?room=known-room", nil)
	readOutboundOfType(t, sender, TypeWelcome)
	readOutboundOfType(t, receiver, TypeWelcome)

	for _, bad := range []string{
		`{"type":"evil","payload":{}}`,
		`not json`,
		`{"payload":{}}`,
	} {
		if err := sender.WriteMessage(websocket.TextMessage, []byte(bad)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := sender.WriteJSON(Inbound{Type: TypeAnswer, Payload: json.RawMessage(`{"ok":true}`)}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The first frame through must be the valid one: everything before it was
	// rejected rather than relayed.
	got := readOutboundOfType(t, receiver, TypeAnswer)
	if string(got.Payload) != `{"ok":true}` {
		t.Fatalf("payload = %s", got.Payload)
	}
}

func TestPresenceOverTheWire(t *testing.T) {
	url := startServer(t, "")

	first := dial(t, url+"?room=known-room", nil)
	if welcome := readOutboundOfType(t, first, TypeWelcome); len(welcome.Peers) != 0 {
		t.Fatalf("first client should see an empty room, got %v", welcome.Peers)
	}

	second := dial(t, url+"?room=known-room", nil)
	readOutboundOfType(t, second, TypeWelcome)

	if joined := readOutboundOfType(t, first, TypePeerJoined); joined.From == "" {
		t.Fatal("peer-joined carried no identity")
	}

	if err := second.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if left := readOutboundOfType(t, first, TypePeerLeft); left.From == "" {
		t.Fatal("peer-left carried no identity")
	}
}

func TestRoomRequiredAndUnknownRoomRejected(t *testing.T) {
	url := startServer(t, "")

	tests := []struct {
		name       string
		query      string
		wantStatus int
	}{
		{"missing room", "", http.StatusBadRequest},
		{"unknown room", "?room=nope", http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, resp, err := websocket.DefaultDialer.Dial(url+tc.query, nil)
			if err == nil {
				_ = conn.Close()
				t.Fatal("expected the dial to be rejected")
			}
			if resp == nil || resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %v, want %d", resp, tc.wantStatus)
			}
		})
	}
}

func TestOversizedMessageClosesConnection(t *testing.T) {
	url := startServer(t, "")

	conn := dial(t, url+"?room=known-room", nil)
	readOutboundOfType(t, conn, TypeWelcome)

	oversized := append([]byte(`{"type":"offer","payload":"`), append([]byte(strings.Repeat("x", maxMessageSize+1)), []byte(`"}`)...)...)
	if err := conn.WriteMessage(websocket.TextMessage, oversized); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return // closed, as required
		}
	}
}

func TestUnauthenticatedUpgradeRejected(t *testing.T) {
	url := startServerWithAuth(t, "", stubAuth{err: errors.New("no session")})

	conn, resp, err := websocket.DefaultDialer.Dial(url+"?room=known-room", nil)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected unauthenticated dial to be rejected")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %v", resp)
	}
}

// Authentication is checked before the room, so an unauthenticated caller
// cannot use the 404 to learn which slugs exist.
func TestUnauthenticatedUnknownRoomStillReturns401(t *testing.T) {
	url := startServerWithAuth(t, "", stubAuth{err: errors.New("no session")})

	conn, resp, err := websocket.DefaultDialer.Dial(url+"?room=nope", nil)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected the dial to be rejected")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401 (not 404, which would leak room existence)", resp)
	}
}

func TestCrossOriginConnectionRejected(t *testing.T) {
	url := startServer(t, "https://app.example.com")

	header := http.Header{}
	header.Set("Origin", "https://evil.com")

	conn, resp, err := websocket.DefaultDialer.Dial(url+"?room=known-room", header)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected cross-origin dial to be rejected")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %v", resp)
	}
}
