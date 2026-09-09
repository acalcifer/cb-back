package signaling

import (
	"context"
	"log/slog"
	"sync/atomic"
)

// message is one frame to deliver, already encoded, plus the routing the hub
// needs to place it.
type message struct {
	room   string
	sender *Client
	// to addresses a single peer by user id; empty fans out to the whole room.
	to   string
	data []byte
}

// Hub keeps track of connected clients, grouped by room, and fans messages out
// within a room.
//
// The rooms map is owned exclusively by the Run goroutine; every other
// goroutine reaches it through the register/unregister/broadcast channels.
// That ownership is also what makes closing Client.send safe: the hub is the
// only closer, and it only closes a client it is removing from the map.
type Hub struct {
	logger *slog.Logger

	// rooms maps a room id to its members. A room exists only while it has at
	// least one member, so empty rooms cannot accumulate.
	rooms      map[string]map[*Client]struct{}
	register   chan *Client
	unregister chan *Client
	broadcast  chan message

	// done is closed when Run returns, so callers blocked on the channels
	// above can give up instead of leaking a goroutine at shutdown.
	done chan struct{}

	count atomic.Int64
}

func NewHub(logger *slog.Logger) *Hub {
	return &Hub{
		logger:     logger,
		rooms:      make(map[string]map[*Client]struct{}),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan message),
		done:       make(chan struct{}),
	}
}

func (h *Hub) Run(ctx context.Context) {
	defer close(h.done)
	defer h.closeAll()

	for {
		select {
		case <-ctx.Done():
			h.logger.Info("hub shutting down", "clients", h.count.Load())
			return

		case c := <-h.register:
			h.join(c)

		case c := <-h.unregister:
			h.leave(c)

		case m := <-h.broadcast:
			h.deliver(m)
		}
	}
}

// join adds a client to its room, tells it who is already there, and announces
// it to the others. A client cannot start a peer connection until it knows the
// room's membership, so the welcome is not optional.
func (h *Hub) join(c *Client) {
	members, ok := h.rooms[c.roomID]
	if !ok {
		members = make(map[*Client]struct{})
		h.rooms[c.roomID] = members
	}

	peers := make([]Peer, 0, len(members))
	for other := range members {
		peers = append(peers, Peer{ID: other.userID, DisplayName: other.displayName})
	}

	members[c] = struct{}{}
	h.count.Add(1)
	h.logger.Info("client joined room",
		"client", c.id, "user", c.userID, "room", c.roomID, "members", len(members))

	welcome, err := encode(Outbound{Type: TypeWelcome, From: c.userID, Peers: peers})
	if err != nil {
		h.logger.Error("encode welcome failed", "error", err)
		return
	}
	if !h.push(c, welcome) {
		// It could not accept its own welcome; it will never keep up.
		h.leave(c)
		return
	}

	joined, err := encode(Outbound{Type: TypePeerJoined, From: c.userID,
		Peers: []Peer{{ID: c.userID, DisplayName: c.displayName}}})
	if err != nil {
		h.logger.Error("encode peer-joined failed", "error", err)
		return
	}
	h.announce(c.roomID, joined, c)
}

// leave removes a client and tells the rest of its room. Safe to call more than
// once for the same client: membership is what guards the close of send.
func (h *Hub) leave(c *Client) bool {
	members, ok := h.rooms[c.roomID]
	if !ok {
		return false
	}
	if _, member := members[c]; !member {
		return false
	}

	delete(members, c)
	close(c.send)
	h.count.Add(-1)

	if len(members) == 0 {
		delete(h.rooms, c.roomID)
	}

	h.logger.Info("client left room",
		"client", c.id, "user", c.userID, "room", c.roomID, "members", len(members))

	left, err := encode(Outbound{Type: TypePeerLeft, From: c.userID,
		Peers: []Peer{{ID: c.userID, DisplayName: c.displayName}}})
	if err != nil {
		h.logger.Error("encode peer-left failed", "error", err)
		return true
	}
	h.announce(c.roomID, left, c)
	return true
}

// deliver routes one client message within its room.
func (h *Hub) deliver(m message) {
	var stalled []*Client

	for c := range h.rooms[m.room] {
		if c == m.sender {
			continue
		}
		// An addressed message goes to that peer only. A user with two
		// connections in the room gets it on both, which is what they'd
		// expect from two open tabs.
		if m.to != "" && c.userID != m.to {
			continue
		}
		if !h.push(c, m.data) {
			stalled = append(stalled, c)
		}
	}

	h.dropStalled(stalled)
}

// announce sends a server-generated frame to a room, skipping one client.
func (h *Hub) announce(room string, data []byte, except *Client) {
	var stalled []*Client

	for c := range h.rooms[room] {
		if c == except {
			continue
		}
		if !h.push(c, data) {
			stalled = append(stalled, c)
		}
	}

	h.dropStalled(stalled)
}

// push offers a frame without blocking. A full buffer means the client is not
// draining; blocking on it would stall the hub for everyone else.
func (h *Hub) push(c *Client, data []byte) bool {
	select {
	case c.send <- data:
		return true
	default:
		return false
	}
}

// dropStalled evicts clients that could not keep up. Each eviction announces a
// peer-left, which may itself find another stalled client — that recursion
// terminates because every level removes at least one client.
func (h *Hub) dropStalled(stalled []*Client) {
	for _, c := range stalled {
		h.logger.Warn("dropping unresponsive client", "client", c.id, "user", c.userID, "room", c.roomID)
		h.leave(c)
	}
}

func (h *Hub) closeAll() {
	for _, members := range h.rooms {
		for c := range members {
			close(c.send)
		}
	}
	h.rooms = make(map[string]map[*Client]struct{})
	h.count.Store(0)
}

// add registers a client, reporting false if the hub has already stopped.
func (h *Hub) add(c *Client) bool {
	select {
	case h.register <- c:
		return true
	case <-h.done:
		return false
	}
}

// drop unregisters a client, returning immediately if the hub has stopped.
func (h *Hub) drop(c *Client) {
	select {
	case h.unregister <- c:
	case <-h.done:
	}
}

// publish routes a message, returning immediately if the hub has stopped.
func (h *Hub) publish(m message) {
	select {
	case h.broadcast <- m:
	case <-h.done:
	}
}

// ClientCount is the number of connected clients across every room.
func (h *Hub) ClientCount() int64 { return h.count.Load() }
