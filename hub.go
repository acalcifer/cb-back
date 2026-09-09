package main

// message pairs a broadcast payload with the client that sent it, so the
// hub can skip echoing it back to the sender.
type message struct {
	data   []byte
	sender *Client
}

// Hub keeps track of connected clients and fans out messages between them.
type Hub struct {
	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client
	broadcast  chan message
}

func newHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan message),
	}
}

func (h *Hub) run() {
	for {
		select {
		case c := <-h.register:
			h.clients[c] = true

		case c := <-h.unregister:
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.send)
			}

		case m := <-h.broadcast:
			for c := range h.clients {
				if c == m.sender {
					continue
				}
				select {
				case c.send <- m.data:
				default:
					close(c.send)
					delete(h.clients, c)
				}
			}
		}
	}
}
