package inbox

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

	// The inbox is server-to-client only; anything a client sends is read and
	// discarded, so the cap only needs to fit control frames.
	maxMessageSize = 512

	sendBufferSize = 16
)

// Event types the inbox carries.
const (
	// TypeInvite asks the recipient to join a room: their phone rings.
	TypeInvite = "invite"
	// TypeInviteCancelled tells the recipient the caller gave up, so ringing
	// stops.
	TypeInviteCancelled = "invite-cancelled"
	// TypeInviteDeclined tells the caller the recipient refused.
	TypeInviteDeclined = "invite-declined"
)

type Room struct {
	Slug string `json:"slug"`
	Name string `json:"name,omitempty"`
}

type Sender struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

// Event is what the server pushes down an inbox connection. From is always
// stamped by the server from the authenticated sender.
type Event struct {
	Type string `json:"type"`
	Room Room   `json:"room"`
	From Sender `json:"from"`
}

func (e Event) Encode() ([]byte, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", e.Type, err)
	}
	return data, nil
}

// Authenticator matches the signaling package's: cookie, bearer or single-use
// ticket, resolved before the upgrade.
type Authenticator interface {
	AuthenticateWS(ctx context.Context, r *http.Request) (userID, displayName string, err error)
}

var connIDs atomic.Uint64

type conn struct {
	id     string
	userID string
	ws     *websocket.Conn
	logger *slog.Logger
	send   chan []byte
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
			ReadBufferSize:  512,
			WriteBufferSize: 1024,
			CheckOrigin:     checkOrigin,
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authenticate before upgrading: after the hijack there is no status code
	// left to send.
	userID, _, err := h.auth.AuthenticateWS(r.Context(), r)
	if err != nil {
		h.logger.Debug("inbox authentication failed", "error", err, "remote", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte(`{"error":"unauthenticated"}`)); err != nil {
			h.logger.Debug("write error response failed", "error", err)
		}
		return
	}

	ws, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Warn("inbox upgrade failed", "error", err, "remote", r.RemoteAddr)
		return
	}

	id := strconv.FormatUint(connIDs.Add(1), 10)
	c := &conn{
		id:     id,
		userID: userID,
		ws:     ws,
		logger: h.logger.With("inbox_conn", id, "user", userID, "remote", r.RemoteAddr),
		send:   make(chan []byte, sendBufferSize),
	}

	if !h.hub.add(c) {
		c.writeClose(websocket.CloseGoingAway, "server shutting down")
		c.close()
		return
	}
	c.logger.Info("inbox connected")

	go c.writePump()
	go c.readPump(h.hub)
}

// readPump exists to process pongs and notice the peer going away. Clients
// have nothing to say on this channel, so data frames are discarded.
func (c *conn) readPump(hub *Hub) {
	defer func() {
		hub.remove(c)
		c.close()
		c.logger.Info("inbox disconnected")
	}()

	c.ws.SetReadLimit(maxMessageSize)
	if err := c.ws.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		return
	}
	c.ws.SetPongHandler(func(string) error {
		return c.ws.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		if _, _, err := c.ws.ReadMessage(); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure, websocket.CloseAbnormalClosure) {
				c.logger.Debug("inbox read failed", "error", err)
			}
			return
		}
	}
}

func (c *conn) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.close()
	}()

	for {
		select {
		case data, ok := <-c.send:
			if !ok {
				c.writeClose(websocket.CloseNormalClosure, "")
				return
			}
			if err := c.write(websocket.TextMessage, data); err != nil {
				c.logger.Debug("inbox write failed", "error", err)
				return
			}
		case <-ticker.C:
			if err := c.write(websocket.PingMessage, nil); err != nil {
				c.logger.Debug("inbox ping failed", "error", err)
				return
			}
		}
	}
}

func (c *conn) write(msgType int, data []byte) error {
	if err := c.ws.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	return c.ws.WriteMessage(msgType, data)
}

func (c *conn) writeClose(code int, reason string) {
	if err := c.write(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason)); err != nil {
		c.logger.Debug("inbox close handshake failed", "error", err)
	}
}

func (c *conn) close() {
	if err := c.ws.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		c.logger.Debug("inbox close failed", "error", err)
	}
}
