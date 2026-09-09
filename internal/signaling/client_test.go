package signaling

import (
	"context"
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
	err error
}

func (s stubAuth) AuthenticateWS(context.Context, *http.Request) (string, string, error) {
	if s.err != nil {
		return "", "", s.err
	}
	return "user-1", "Test User", nil
}

func startServer(t *testing.T, allowedOrigins string) (string, context.CancelFunc) {
	t.Helper()
	return startServerWithAuth(t, allowedOrigins, stubAuth{})
}

func startServerWithAuth(t *testing.T, allowedOrigins string, auth Authenticator) (string, context.CancelFunc) {
	t.Helper()

	policy, err := httpx.NewOriginPolicy(allowedOrigins, testLogger())
	if err != nil {
		t.Fatalf("NewOriginPolicy: %v", err)
	}

	h, cancel := startHub(t)
	srv := httptest.NewServer(NewHandler(h, testLogger(), policy.CheckOrigin, auth))
	t.Cleanup(srv.Close)

	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws", cancel
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

func TestRelaysMessagesBetweenClients(t *testing.T) {
	url, _ := startServer(t, "")

	sender := dial(t, url, nil)
	receiver := dial(t, url, nil)

	if err := sender.WriteMessage(websocket.TextMessage, []byte(`{"sdp":"offer"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, data, err := receiver.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != `{"sdp":"offer"}` {
		t.Fatalf("got %q", data)
	}
}

func TestMalformedJSONIsNotRelayed(t *testing.T) {
	url, _ := startServer(t, "")

	sender := dial(t, url, nil)
	receiver := dial(t, url, nil)

	if err := sender.WriteMessage(websocket.TextMessage, []byte(`not json`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sender.WriteMessage(websocket.TextMessage, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, data, err := receiver.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Fatalf("malformed payload leaked through: %q", data)
	}
}

func TestOversizedMessageClosesConnection(t *testing.T) {
	url, _ := startServer(t, "")

	conn := dial(t, url, nil)
	oversized := append([]byte(`{"pad":"`), append([]byte(strings.Repeat("x", maxMessageSize+1)), []byte(`"}`)...)...)
	if err := conn.WriteMessage(websocket.TextMessage, oversized); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected connection to be closed for exceeding the read limit")
	}
}

func TestUnauthenticatedUpgradeRejected(t *testing.T) {
	url, _ := startServerWithAuth(t, "", stubAuth{err: errors.New("no session")})

	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected unauthenticated dial to be rejected")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %v", resp)
	}
}
