-- Rooms scope the signaling relay: a message reaches only the clients in the
-- same room, so two calls can run at once without hearing each other.
--
-- Access model: knowing the slug is the invitation, like a meeting link. There
-- is deliberately no per-room ACL yet; if one is added later it goes in a
-- room_members table alongside this one.

CREATE TABLE rooms (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       text NOT NULL UNIQUE,
    name       text NOT NULL,
    created_by uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT rooms_slug_format CHECK (slug ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
    CONSTRAINT rooms_name_length CHECK (char_length(name) BETWEEN 1 AND 100)
);

CREATE INDEX rooms_created_by_created_at_idx ON rooms (created_by, created_at DESC);
