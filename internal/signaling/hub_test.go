package signaling

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startHub(t *testing.T) (*Hub, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := NewHub(testLogger())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("hub did not stop")
		}
	})
	return h, cancel
}

func newTestClient(h *Hub, buf int) *Client {
	return &Client{id: "test", userID: "user-test", hub: h, logger: testLogger(), send: make(chan []byte, buf)}
}

func TestBroadcastSkipsSender(t *testing.T) {
	h, _ := startHub(t)

	sender := newTestClient(h, 1)
	receiver := newTestClient(h, 1)
	if !h.add(sender) || !h.add(receiver) {
		t.Fatal("hub refused registration")
	}

	h.publish(message{data: []byte(`{"a":1}`), sender: sender})

	select {
	case got := <-receiver.send:
		if string(got) != `{"a":1}` {
			t.Fatalf("got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("receiver got nothing")
	}

	select {
	case got := <-sender.send:
		t.Fatalf("sender received its own message: %q", got)
	default:
	}
}

func TestSlowClientIsDropped(t *testing.T) {
	h, _ := startHub(t)

	sender := newTestClient(h, 1)
	// Zero-capacity send channel: the hub can never enqueue to it.
	slow := newTestClient(h, 0)
	if !h.add(sender) || !h.add(slow) {
		t.Fatal("hub refused registration")
	}

	h.publish(message{data: []byte(`{}`), sender: sender})

	// Wait for the drop first: receiving from slow.send here would make the
	// hub's send succeed and mask the behaviour under test.
	waitForCount(t, h, 1)

	select {
	case _, ok := <-slow.send:
		if ok {
			t.Fatal("expected send channel to be closed, not written to")
		}
	default:
		t.Fatal("send channel was not closed")
	}
}

func TestUnregisterIsIdempotent(t *testing.T) {
	h, _ := startHub(t)

	c := newTestClient(h, 1)
	if !h.add(c) {
		t.Fatal("hub refused registration")
	}

	// A second drop must not panic on a double close of send.
	h.drop(c)
	h.drop(c)

	waitForCount(t, h, 0)
}

func TestShutdownClosesClientsAndUnblocksCallers(t *testing.T) {
	h, cancel := startHub(t)

	c := newTestClient(h, 1)
	if !h.add(c) {
		t.Fatal("hub refused registration")
	}

	cancel()

	select {
	case _, ok := <-c.send:
		if ok {
			t.Fatal("expected send channel to be closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not close client")
	}

	// After shutdown these must return rather than block forever, which is
	// what would otherwise leak a goroutine per connected client.
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.drop(c)
		h.publish(message{data: []byte(`{}`), sender: c})
		if h.add(newTestClient(h, 1)) {
			t.Error("add succeeded after shutdown")
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("hub calls blocked after shutdown")
	}
}

func waitForCount(t *testing.T, h *Hub, want int64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if h.ClientCount() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("client count = %d, want %d", h.ClientCount(), want)
}
