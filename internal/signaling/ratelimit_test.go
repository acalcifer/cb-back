package signaling

import (
	"testing"
	"time"
)

func TestTokenBucketAllowsABurstThenRefills(t *testing.T) {
	start := time.Now()
	b := newTokenBucket(10, 5, start)

	for i := range 10 {
		if !b.allow(start) {
			t.Fatalf("message %d rejected inside the burst allowance", i+1)
		}
	}
	if b.allow(start) {
		t.Fatal("burst allowance was not enforced")
	}

	// One second later, five more tokens should have accrued.
	later := start.Add(time.Second)
	for i := range 5 {
		if !b.allow(later) {
			t.Fatalf("refilled token %d was not granted", i+1)
		}
	}
	if b.allow(later) {
		t.Fatal("bucket refilled beyond the elapsed rate")
	}
}

func TestTokenBucketDoesNotExceedCapacity(t *testing.T) {
	start := time.Now()
	b := newTokenBucket(10, 5, start)

	// A long idle period must not bank unlimited credit.
	idle := start.Add(time.Hour)
	for i := range 10 {
		if !b.allow(idle) {
			t.Fatalf("token %d rejected after idling", i+1)
		}
	}
	if b.allow(idle) {
		t.Fatal("bucket accumulated more than its capacity while idle")
	}
}

func TestChatIsRelayed(t *testing.T) {
	h, _ := startHub(t)

	alice := addClient(t, h, "room-a", "alice", 8)
	bob := addClient(t, h, "room-a", "bob", 8)
	readType(t, alice, TypeWelcome)
	readType(t, bob, TypeWelcome)
	readType(t, alice, TypePeerJoined)

	relay(t, h, alice, "", TypeChat, `{"text":"привет"}`)

	got := readType(t, bob, TypeChat)
	if got.From != "alice" {
		t.Fatalf("from = %q, want alice", got.From)
	}
	if string(got.Payload) != `{"text":"привет"}` {
		t.Fatalf("payload = %s", got.Payload)
	}
}

func TestParseInboundAcceptsChatAndRejectsUnknown(t *testing.T) {
	if _, err := parseInbound([]byte(`{"type":"chat","payload":{"text":"hi"}}`)); err != nil {
		t.Fatalf("chat rejected: %v", err)
	}
	if _, err := parseInbound([]byte(`{"type":"welcome"}`)); err == nil {
		t.Fatal("a server-only type must not be accepted from a client")
	}
}
