// Package inbox delivers events addressed to a user rather than to a room.
//
// The room relay only reaches people who are already in a call. Ringing
// someone needs a channel they hold open while idle, so a phone can learn it is
// being called without polling. Each signed-in client keeps one inbox
// websocket; the server pushes to every connection a user has open.
package inbox

import (
	"log/slog"
	"sync"
	"sync/atomic"
)

// Hub tracks inbox connections by user id.
//
// Unlike the signaling hub there is no fan-out between clients and no
// ordering to preserve across them, so a mutex is simpler than an owning
// goroutine. The mutex also guards closing conn.send: only a caller holding it
// may close, and only while removing the connection from the map.
type Hub struct {
	logger *slog.Logger

	mu     sync.Mutex
	users  map[string]map[*conn]struct{}
	closed bool

	count atomic.Int64
}

func NewHub(logger *slog.Logger) *Hub {
	return &Hub{logger: logger, users: make(map[string]map[*conn]struct{})}
}

// Deliver queues an encoded event on every connection the user has open and
// reports how many accepted it. Zero means the user is not reachable right
// now, which a caller shows as "not online" instead of ringing into the void.
func (h *Hub) Deliver(userID string, data []byte) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	delivered := 0
	for c := range h.users[userID] {
		select {
		case c.send <- data:
			delivered++
		default:
			// A full buffer means the client stopped draining. Blocking here
			// would stall every other delivery behind one dead phone.
			h.logger.Warn("dropping unresponsive inbox connection", "user", userID, "conn", c.id)
			h.removeLocked(c)
		}
	}
	return delivered
}

// add registers a connection, reporting false once the hub has shut down.
func (h *Hub) add(c *conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return false
	}
	set, ok := h.users[c.userID]
	if !ok {
		set = make(map[*conn]struct{})
		h.users[c.userID] = set
	}
	set[c] = struct{}{}
	h.count.Add(1)
	return true
}

// remove unregisters a connection. Safe to call more than once.
func (h *Hub) remove(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removeLocked(c)
}

func (h *Hub) removeLocked(c *conn) {
	set, ok := h.users[c.userID]
	if !ok {
		return
	}
	if _, member := set[c]; !member {
		return
	}
	delete(set, c)
	close(c.send)
	h.count.Add(-1)
	if len(set) == 0 {
		delete(h.users, c.userID)
	}
}

// Shutdown closes every connection and refuses new ones. The server's
// Shutdown does not wait on hijacked websockets, so this is what drains them.
func (h *Hub) Shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed = true
	for _, set := range h.users {
		for c := range set {
			close(c.send)
		}
	}
	h.users = make(map[string]map[*conn]struct{})
	h.count.Store(0)
}

// ConnectionCount is the number of open inbox connections across all users.
func (h *Hub) ConnectionCount() int64 { return h.count.Load() }
