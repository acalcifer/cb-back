package signaling

import (
	"context"
	"log/slog"
	"sync/atomic"
)

// message pairs a broadcast payload with the client that sent it, so the
// hub can skip echoing it back to the sender.
type message struct {
	data   []byte
	sender *Client
}

// Hub keeps track of connected clients and fans out messages between them.
//
// The clients map is owned exclusively by the run goroutine; every other
// goroutine reaches it through the register/unregister/broadcast channels.
// That ownership is also what makes closing Client.send safe: the hub is the
// only closer, and it only closes a client it is removing from the map.
type Hub struct {
	logger *slog.Logger

	clients    map[*Client]struct{}
	register   chan *Client
	unregister chan *Client
	broadcast  chan message

	// done is closed when run returns, so callers blocked on the channels
	// above can give up instead of leaking a goroutine at shutdown.
	done chan struct{}

	count atomic.Int64
}

func NewHub(logger *slog.Logger) *Hub {
	return &Hub{
		logger:     logger,
		clients:    make(map[*Client]struct{}),
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
			h.clients[c] = struct{}{}
			h.count.Store(int64(len(h.clients)))
			h.logger.Info("client registered", "client", c.id, "user", c.userID, "clients", len(h.clients))

		case c := <-h.unregister:
			if h.remove(c) {
				h.logger.Info("client unregistered", "client", c.id, "user", c.userID, "clients", len(h.clients))
			}

		case m := <-h.broadcast:
			for c := range h.clients {
				if c == m.sender {
					continue
				}
				select {
				case c.send <- m.data:
				default:
					// The client is not draining fast enough. Dropping it
					// beats blocking the hub for everyone else; closing send
					// makes its writePump tear the connection down.
					h.logger.Warn("dropping unresponsive client", "client", c.id, "user", c.userID)
					h.remove(c)
				}
			}
		}
	}
}

// remove drops a client and closes its send channel. Safe to call more than
// once for the same client: the map membership check is what prevents a
// double close. Must only be called from the run goroutine.
func (h *Hub) remove(c *Client) bool {
	if _, ok := h.clients[c]; !ok {
		return false
	}
	delete(h.clients, c)
	close(c.send)
	h.count.Store(int64(len(h.clients)))
	return true
}

func (h *Hub) closeAll() {
	for c := range h.clients {
		h.remove(c)
	}
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

// publish fans a message out, returning immediately if the hub has stopped.
func (h *Hub) publish(m message) {
	select {
	case h.broadcast <- m:
	case <-h.done:
	}
}

func (h *Hub) ClientCount() int64 { return h.count.Load() }
