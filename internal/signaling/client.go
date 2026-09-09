package signaling

import (
	"context"
	"encoding/json"
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

type Handler struct {
	hub      *Hub
	logger   *slog.Logger
	auth     Authenticator
	upgrader websocket.Upgrader
}

func NewHandler(hub *Hub, logger *slog.Logger, checkOrigin func(*http.Request) bool, auth Authenticator) *Handler {
	return &Handler{
		hub:    hub,
		logger: logger,
		auth:   auth,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     checkOrigin,
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authenticate before upgrading. After the hijack there is no way to send
	// a status code, so an unauthenticated caller would otherwise get an open
	// socket followed by a close frame instead of a plain 401.
	userID, displayName, err := h.auth.AuthenticateWS(r.Context(), r)
	if err != nil {
		h.logger.Debug("websocket authentication failed", "error", err, "remote", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte(`{"error":"unauthenticated"}`)); err != nil {
			h.logger.Debug("write unauthorized response failed", "error", err)
		}
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
		hub:         h.hub,
		conn:        conn,
		logger:      h.logger.With("client", id, "user", userID, "remote", r.RemoteAddr),
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

		if !json.Valid(data) {
			c.logger.Debug("discarding malformed json", "bytes", len(data))
			continue
		}

		c.hub.publish(message{data: data, sender: c})
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
