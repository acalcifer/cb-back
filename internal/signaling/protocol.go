package signaling

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Message types a client may send.
const (
	TypeOffer     = "offer"
	TypeAnswer    = "answer"
	TypeCandidate = "candidate"
	TypeBye       = "bye"
	TypeChat      = "chat"
)

// Message types only the server emits.
const (
	TypeWelcome    = "welcome"
	TypePeerJoined = "peer-joined"
	TypePeerLeft   = "peer-left"
)

var errUnknownType = errors.New("unknown message type")

// Peer identifies a participant to the other members of a room.
type Peer struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

// Inbound is what a client sends.
//
// There is deliberately no "from" field: the server stamps the sender itself.
// A client that could name its own sender could inject an SDP offer — or a
// chat message — as someone else in the room.
type Inbound struct {
	Type string `json:"type"`
	// To addresses one peer by user id. Empty means the whole room, which is
	// what a client uses before it knows who is present.
	To      string          `json:"to,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Outbound is what the server sends.
type Outbound struct {
	Type    string          `json:"type"`
	From    string          `json:"from,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	// Peers is populated for TypeWelcome only.
	Peers []Peer `json:"peers,omitempty"`
}

// parseInbound decodes and validates a client frame. Unknown types are rejected
// rather than relayed, so the set of messages that can cross the hub stays
// exactly the set listed above.
func parseInbound(data []byte) (Inbound, error) {
	var in Inbound
	if err := json.Unmarshal(data, &in); err != nil {
		return Inbound{}, fmt.Errorf("decode message: %w", err)
	}

	switch in.Type {
	case TypeOffer, TypeAnswer, TypeCandidate, TypeBye, TypeChat:
	default:
		return Inbound{}, fmt.Errorf("%w: %q", errUnknownType, in.Type)
	}

	return in, nil
}

// encode marshals a server frame. Callers treat a failure as fatal for that
// message only: the payload came from a client, so a bad one must not take the
// hub down.
func encode(out Outbound) ([]byte, error) {
	data, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", out.Type, err)
	}
	return data, nil
}
