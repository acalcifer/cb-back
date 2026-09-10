package inbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func addConn(t *testing.T, h *Hub, userID string, buf int) *conn {
	t.Helper()
	c := &conn{id: userID, userID: userID, logger: testLogger(), send: make(chan []byte, buf)}
	if !h.add(c) {
		t.Fatalf("hub refused %s", userID)
	}
	return c
}

func TestDeliverReachesEveryConnectionOfThatUserOnly(t *testing.T) {
	h := NewHub(testLogger())

	phone := addConn(t, h, "mama", 4)
	tablet := addConn(t, h, "mama", 4)
	other := addConn(t, h, "babushka", 4)

	if n := h.Deliver("mama", []byte(`{"type":"invite"}`)); n != 2 {
		t.Fatalf("delivered = %d, want 2", n)
	}
	for _, c := range []*conn{phone, tablet} {
		select {
		case got := <-c.send:
			if string(got) != `{"type":"invite"}` {
				t.Fatalf("payload = %s", got)
			}
		default:
			t.Fatal("a connection of the addressed user got nothing")
		}
	}
	select {
	case got := <-other.send:
		t.Fatalf("another user received %s", got)
	default:
	}
}

func TestDeliverToAbsentUserReportsZero(t *testing.T) {
	h := NewHub(testLogger())
	if n := h.Deliver("nobody", []byte(`{}`)); n != 0 {
		t.Fatalf("delivered = %d, want 0", n)
	}
}

func TestStalledConnectionIsDropped(t *testing.T) {
	h := NewHub(testLogger())
	c := addConn(t, h, "mama", 1)

	if n := h.Deliver("mama", []byte(`1`)); n != 1 {
		t.Fatalf("first delivery = %d, want 1", n)
	}
	if n := h.Deliver("mama", []byte(`2`)); n != 0 {
		t.Fatalf("delivery to a full buffer = %d, want 0", n)
	}
	if h.ConnectionCount() != 0 {
		t.Fatalf("count = %d, want 0 after eviction", h.ConnectionCount())
	}

	<-c.send
	if _, open := <-c.send; open {
		t.Fatal("evicted connection's channel is still open")
	}
}

func TestRemoveIsIdempotentAndShutdownRefusesNewConnections(t *testing.T) {
	h := NewHub(testLogger())
	c := addConn(t, h, "mama", 1)

	h.remove(c)
	h.remove(c) // must not double-close

	live := addConn(t, h, "babushka", 1)
	h.Shutdown()
	if _, open := <-live.send; open {
		t.Fatal("shutdown left a connection open")
	}
	if h.add(&conn{userID: "late", send: make(chan []byte, 1)}) {
		t.Fatal("add succeeded after shutdown")
	}
}

type stubAuth struct {
	user string
	err  error
}

func (s stubAuth) AuthenticateWS(context.Context, *http.Request) (string, string, error) {
	return s.user, "Test", s.err
}

func startServer(t *testing.T, auth Authenticator) (*Hub, string) {
	t.Helper()
	h := NewHub(testLogger())
	srv := httptest.NewServer(NewHandler(h, testLogger(), func(*http.Request) bool { return true }, auth))
	t.Cleanup(func() {
		h.Shutdown()
		srv.Close()
	})
	return h, "ws" + strings.TrimPrefix(srv.URL, "http")
}

func TestEventArrivesOverTheWire(t *testing.T) {
	h, url := startServer(t, stubAuth{user: "mama"})

	ws, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	// Registration happens after the upgrade returns, so wait for it.
	deadline := time.Now().Add(time.Second)
	for h.ConnectionCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	data, err := Event{Type: TypeInvite, Room: Room{Slug: "abc-defg-hij"}, From: Sender{ID: "babushka", DisplayName: "Бабушка"}}.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if n := h.Deliver("mama", data); n != 1 {
		t.Fatalf("delivered = %d, want 1", n)
	}

	if err := ws.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	_, raw, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got Event
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Type != TypeInvite || got.From.ID != "babushka" || got.Room.Slug != "abc-defg-hij" {
		t.Fatalf("event = %+v", got)
	}
}

func TestUnauthenticatedInboxRejected(t *testing.T) {
	_, url := startServer(t, stubAuth{err: errors.New("no session")})

	ws, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err == nil {
		_ = ws.Close()
		t.Fatal("expected the dial to be rejected")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401", resp)
	}
}
