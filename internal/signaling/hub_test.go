package signaling

import (
	"context"
	"encoding/json"
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

// addClient registers a client in a room. The buffer is generous by default so
// presence frames do not fill it; tests that exercise the stalled path pass a
// small one deliberately.
func addClient(t *testing.T, h *Hub, room, userID string, buf int) *Client {
	t.Helper()
	c := &Client{
		id:          userID,
		userID:      userID,
		displayName: userID,
		roomID:      room,
		hub:         h,
		logger:      testLogger(),
		send:        make(chan []byte, buf),
	}
	if !h.add(c) {
		t.Fatalf("hub refused registration of %s", userID)
	}
	return c
}

func readFrame(t *testing.T, c *Client, within time.Duration) Outbound {
	t.Helper()
	select {
	case raw, ok := <-c.send:
		if !ok {
			t.Fatalf("%s: send channel closed while waiting for a frame", c.userID)
		}
		var out Outbound
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s: decode frame: %v", c.userID, err)
		}
		return out
	case <-time.After(within):
		t.Fatalf("%s: no frame within %s", c.userID, within)
		return Outbound{}
	}
}

// readType reads until a frame of the wanted type arrives, skipping presence
// chatter the test is not asserting on.
func readType(t *testing.T, c *Client, want string) Outbound {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case raw, ok := <-c.send:
			if !ok {
				t.Fatalf("%s: send channel closed while waiting for %q", c.userID, want)
			}
			var out Outbound
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("%s: decode frame: %v", c.userID, err)
			}
			if out.Type == want {
				return out
			}
		case <-deadline:
			t.Fatalf("%s: never received a %q frame", c.userID, want)
		}
	}
}

func expectNoFrame(t *testing.T, c *Client, within time.Duration) {
	t.Helper()
	select {
	case raw, ok := <-c.send:
		if !ok {
			return // closed is not a delivered message
		}
		t.Fatalf("%s: unexpected frame %s", c.userID, raw)
	case <-time.After(within):
	}
}

func relay(t *testing.T, h *Hub, from *Client, to, msgType, payload string) {
	t.Helper()
	out, err := encode(Outbound{Type: msgType, From: from.userID, Payload: json.RawMessage(payload)})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	h.publish(message{room: from.roomID, sender: from, to: to, data: out})
}

// The assertion that matters most: one room's traffic must never reach another.
func TestRoomsAreIsolated(t *testing.T) {
	h, _ := startHub(t)

	alice := addClient(t, h, "room-a", "alice", 8)
	bob := addClient(t, h, "room-a", "bob", 8)
	carol := addClient(t, h, "room-b", "carol", 8)

	readType(t, alice, TypeWelcome)
	readType(t, bob, TypeWelcome)
	readType(t, carol, TypeWelcome)
	readType(t, alice, TypePeerJoined) // bob joined room-a

	relay(t, h, alice, "", TypeOffer, `{"sdp":"a"}`)

	got := readType(t, bob, TypeOffer)
	if got.From != "alice" {
		t.Fatalf("from = %q, want alice", got.From)
	}
	expectNoFrame(t, carol, 200*time.Millisecond)
}

func TestAddressedMessageReachesOnlyThatPeer(t *testing.T) {
	h, _ := startHub(t)

	alice := addClient(t, h, "room-a", "alice", 8)
	bob := addClient(t, h, "room-a", "bob", 8)
	carol := addClient(t, h, "room-a", "carol", 8)

	for _, c := range []*Client{alice, bob, carol} {
		readType(t, c, TypeWelcome)
	}
	// Drain the joins so only the offer remains outstanding.
	readType(t, alice, TypePeerJoined)
	readType(t, alice, TypePeerJoined)
	readType(t, bob, TypePeerJoined)

	relay(t, h, alice, "bob", TypeOffer, `{"sdp":"for-bob"}`)

	if got := readType(t, bob, TypeOffer); string(got.Payload) != `{"sdp":"for-bob"}` {
		t.Fatalf("payload = %s", got.Payload)
	}
	expectNoFrame(t, carol, 200*time.Millisecond)
}

func TestSenderNeverReceivesItsOwnMessage(t *testing.T) {
	h, _ := startHub(t)

	alice := addClient(t, h, "room-a", "alice", 8)
	bob := addClient(t, h, "room-a", "bob", 8)
	readType(t, alice, TypeWelcome)
	readType(t, bob, TypeWelcome)
	readType(t, alice, TypePeerJoined)

	relay(t, h, alice, "", TypeCandidate, `{"candidate":"x"}`)

	readType(t, bob, TypeCandidate)
	expectNoFrame(t, alice, 200*time.Millisecond)
}

func TestWelcomeListsExistingPeersAndJoinIsAnnounced(t *testing.T) {
	h, _ := startHub(t)

	alice := addClient(t, h, "room-a", "alice", 8)
	if welcome := readType(t, alice, TypeWelcome); len(welcome.Peers) != 0 {
		t.Fatalf("first peer should see an empty room, got %v", welcome.Peers)
	}

	bob := addClient(t, h, "room-a", "bob", 8)
	welcome := readType(t, bob, TypeWelcome)
	if len(welcome.Peers) != 1 || welcome.Peers[0].ID != "alice" {
		t.Fatalf("welcome peers = %v, want [alice]", welcome.Peers)
	}

	joined := readType(t, alice, TypePeerJoined)
	if joined.From != "bob" {
		t.Fatalf("peer-joined from = %q, want bob", joined.From)
	}
}

func TestLeaveIsAnnouncedToTheRoom(t *testing.T) {
	h, _ := startHub(t)

	alice := addClient(t, h, "room-a", "alice", 8)
	bob := addClient(t, h, "room-a", "bob", 8)
	readType(t, alice, TypeWelcome)
	readType(t, bob, TypeWelcome)
	readType(t, alice, TypePeerJoined)

	h.drop(bob)

	left := readType(t, alice, TypePeerLeft)
	if left.From != "bob" {
		t.Fatalf("peer-left from = %q, want bob", left.From)
	}
	waitForCount(t, h, 1)
}

func TestSlowClientIsDroppedAndAnnounced(t *testing.T) {
	h, _ := startHub(t)

	alice := addClient(t, h, "room-a", "alice", 8)
	readType(t, alice, TypeWelcome)

	// Buffer of one, never drained: the welcome fills it, so the next frame
	// cannot be enqueued and the client must be evicted.
	slow := addClient(t, h, "room-a", "slow", 1)
	readType(t, alice, TypePeerJoined)

	relay(t, h, alice, "", TypeOffer, `{"sdp":"a"}`)

	// Wait for the eviction before touching slow.send: draining it first would
	// free buffer space and un-stall the client, masking the behaviour here.
	waitForCount(t, h, 1)

	<-slow.send // the buffered welcome
	if _, stillOpen := <-slow.send; stillOpen {
		t.Fatal("stalled client was not evicted")
	}

	if left := readType(t, alice, TypePeerLeft); left.From != "slow" {
		t.Fatalf("peer-left from = %q, want slow", left.From)
	}
}

func TestUnregisterIsIdempotent(t *testing.T) {
	h, _ := startHub(t)

	c := addClient(t, h, "room-a", "alice", 8)
	readType(t, c, TypeWelcome)

	// A second drop must not panic on a double close of send.
	h.drop(c)
	h.drop(c)

	waitForCount(t, h, 0)
}

func TestEmptyRoomsAreReclaimed(t *testing.T) {
	h, _ := startHub(t)

	c := addClient(t, h, "room-a", "alice", 8)
	readType(t, c, TypeWelcome)
	h.drop(c)
	waitForCount(t, h, 0)

	// Publishing into a room nobody is in must be a no-op, not a panic.
	relay(t, h, c, "", TypeOffer, `{}`)
}

func TestShutdownClosesClientsAndUnblocksCallers(t *testing.T) {
	h, cancel := startHub(t)

	c := addClient(t, h, "room-a", "alice", 8)
	readType(t, c, TypeWelcome)

	cancel()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-c.send:
			if !ok {
				goto closed
			}
		case <-deadline:
			t.Fatal("shutdown did not close client")
		}
	}
closed:

	// After shutdown these must return rather than block forever, which is
	// what would otherwise leak a goroutine per connected client.
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.drop(c)
		h.publish(message{room: "room-a", sender: c, data: []byte(`{}`)})
		if h.add(&Client{userID: "late", roomID: "room-a", send: make(chan []byte, 1), logger: testLogger()}) {
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
