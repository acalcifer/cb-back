-- Identity schema. Password credentials live in their own table alongside
-- webauthn_credentials so passkeys can be added later without touching users
-- and without a column-shuffling migration.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email          citext NOT NULL UNIQUE,
    display_name   text NOT NULL,
    email_verified boolean NOT NULL DEFAULT false,
    disabled_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_email_length CHECK (char_length(email) BETWEEN 3 AND 254),
    CONSTRAINT users_display_name_length CHECK (char_length(display_name) BETWEEN 1 AND 100)
);

-- password_hash is a full PHC string ($argon2id$v=19$m=...,t=...,p=...$salt$hash),
-- so the cost parameters travel with each hash and can be raised over time
-- without invalidating existing credentials.
CREATE TABLE password_credentials (
    user_id       uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Unused until passkeys ship; created now so the identity model does not have
-- to change when they do.
CREATE TABLE webauthn_credentials (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    public_key    bytea NOT NULL,
    sign_count    bigint NOT NULL DEFAULT 0,
    transports    text[] NOT NULL DEFAULT '{}',
    aaguid        bytea,
    label         text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);

CREATE INDEX webauthn_credentials_user_id_idx ON webauthn_credentials (user_id);

-- Audit trail for authentication. Kept in Postgres rather than Redis because
-- it must survive a cache flush: it is the record used to spot credential
-- stuffing and to answer "was this account accessed?" after an incident.
CREATE TABLE auth_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    uuid REFERENCES users(id) ON DELETE SET NULL,
    email      citext,
    event      text NOT NULL,
    ip         inet,
    user_agent text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX auth_events_user_id_created_at_idx ON auth_events (user_id, created_at DESC);
CREATE INDEX auth_events_email_created_at_idx ON auth_events (email, created_at DESC);
