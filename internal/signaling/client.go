package signaling

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10

	// maxMessageSize caps a single inbound frame. Without it a client can
	// make the server allocate without bound from one connection.
	maxMessageSize = 64 << 10

	sendBufferSize = 64
)

var clientIDs atomic.Uint64

// Client wraps one websocket connection registered with the hub.
type Client struct {
	id          string
	userID      string
	displayName string
	roomID      string
	hub         *Hub
	conn        *websocket.Conn
	logger      *slog.Logger
	send        chan []byte
}

// Authenticator resolves the user behind an upgrade request. The signaling
// package declares what it needs rather than importing the auth package, which
// keeps the dependency pointing one way.
type Authenticator interface {
	AuthenticateWS(ctx context.Context, r *http.Request) (userID, displayName string, err error)
}

// ErrRoomNotFound tells the handler to answer 404. A resolver returns it for a
// slug that does not exist.
var ErrRoomNotFound = errors.New("signaling: room not found")

// RoomResolver turns the ?room= slug from the URL into the room id the hub
// keys on. It is a function rather than an interface so the rooms package and
// the signaling package need not know about each other.
type RoomResolver func(ctx context.Context, slug string) (roomID string, err error)

type Handler struct {
	hub         *Hub
	logger      *slog.Logger
	auth        Authenticator
	resolveRoom RoomResolver
	upgrader    websocket.Upgrader
}

func NewHandler(hub *Hub, logger *slog.Logger, checkOrigin func(*http.Request) bool, auth Authenticator, resolveRoom RoomResolver) *Handler {
	return &Handler{
		hub:         hub,
		logger:      logger,
		auth:        auth,
		resolveRoom: resolveRoom,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     checkOrigin,
		},
	}
}

// fail writes a JSON error before the upgrade. Once the connection is hijacked
// there is no way to send a status code, so every rejection happens here.
func (h *Handler) fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, err := fmt.Fprintf(w, `{"error":%q}`, code); err != nil {
		h.logger.Debug("write error response failed", "error", err)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authenticate before upgrading. After the hijack there is no way to send
	// a status code, so an unauthenticated caller would otherwise get an open
	// socket followed by a close frame instead of a plain 401.
	userID, displayName, err := h.auth.AuthenticateWS(r.Context(), r)
	if err != nil {
		h.logger.Debug("websocket authentication failed", "error", err, "remote", r.RemoteAddr)
		h.fail(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	slug := r.URL.Query().Get("room")
	if slug == "" {
		h.fail(w, http.StatusBadRequest, "room_required")
		return
	}

	roomID, err := h.resolveRoom(r.Context(), slug)
	if err != nil {
		if errors.Is(err, ErrRoomNotFound) {
			h.fail(w, http.StatusNotFound, "room_not_found")
			return
		}
		h.logger.Error("resolve room failed", "error", err, "room", slug)
		h.fail(w, http.StatusInternalServerError, "internal_error")
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has already written an error response to the client.
		h.logger.Warn("websocket upgrade failed", "error", err, "remote", r.RemoteAddr)
		return
	}

	id := strconv.FormatUint(clientIDs.Add(1), 10)
	c := &Client{
		id:          id,
		userID:      userID,
		displayName: displayName,
		roomID:      roomID,
		hub:         h.hub,
		conn:        conn,
		logger:      h.logger.With("client", id, "user", userID, "room", roomID, "remote", r.RemoteAddr),
		send:        make(chan []byte, sendBufferSize),
	}

	if !h.hub.add(c) {
		// Server is shutting down; refuse the connection politely.
		c.writeClose(websocket.CloseGoingAway, "server shutting down")
		c.close()
		return
	}

	go c.writePump()
	go c.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.drop(c)
		c.close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	if err := c.conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		c.logger.Warn("set read deadline", "error", err)
		return
	}
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	budget := newTokenBucket(messageBurst, messagesPerSecond, time.Now())

	for {
		msgType, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure, websocket.CloseAbnormalClosure) {
				c.logger.Warn("read failed", "error", err)
			} else {
				c.logger.Debug("connection closed", "error", err)
			}
			return
		}

		// The write side always emits text frames, so refuse anything else
		// rather than silently relabelling a binary payload as text.
		if msgType != websocket.TextMessage {
			c.logger.Debug("rejecting non-text frame", "type", msgType)
			c.writeClose(websocket.CloseUnsupportedData, "text frames only")
			return
		}

		// Closing beats silently dropping: a discarded ICE candidate breaks a
		// call in a way that is very hard to diagnose from the client.
		if !budget.allow(time.Now()) {
			c.logger.Warn("client exceeded the message rate")
			c.writeClose(websocket.ClosePolicyViolation, "message rate exceeded")
			return
		}

		in, err := parseInbound(data)
		if err != nil {
			c.logger.Debug("discarding invalid message", "error", err, "bytes", len(data))
			continue
		}

		// The sender is stamped here, from the authenticated connection. Any
		// "from" a client put in its own payload is irrelevant: it never
		// reaches a peer, so a client cannot pose as another participant.
		out, err := encode(Outbound{Type: in.Type, From: c.userID, Payload: in.Payload})
		if err != nil {
			c.logger.Warn("encode outbound failed", "error", err)
			continue
		}

		c.hub.publish(message{room: c.roomID, sender: c, to: in.To, data: out})
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.close()
	}()

	for {
		select {
		case data, ok := <-c.send:
			if !ok {
				// The hub closed the channel: send a close frame so the peer
				// sees a clean shutdown rather than a dropped socket.
				c.writeClose(websocket.CloseNormalClosure, "")
				return
			}
			if err := c.write(websocket.TextMessage, data); err != nil {
				c.logger.Debug("write failed", "error", err)
				return
			}

		case <-ticker.C:
			if err := c.write(websocket.PingMessage, nil); err != nil {
				c.logger.Debug("ping failed", "error", err)
				return
			}
		}
	}
}

func (c *Client) write(msgType int, data []byte) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	return c.conn.WriteMessage(msgType, data)
}

// writeClose makes a best-effort attempt at the closing handshake. Failures
// are expected when the peer has already vanished, so they are logged at
// debug level only.
func (c *Client) writeClose(code int, reason string) {
	err := c.write(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason))
	if err != nil {
		c.logger.Debug("close handshake failed", "error", err)
	}
}

// close is safe to call from both pumps; the second call reports
// net.ErrClosed, which is not worth reporting.
func (c *Client) close() {
	if err := c.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		c.logger.Debug("connection close failed", "error", err)
	}
}
