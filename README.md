# cb-back

Authentication and WebRTC signaling backend for video and audio calls, in Go.

## Layout

```
cmd/server/          process entry point: config, wiring, graceful shutdown
internal/config/     environment parsing, validated once at startup
internal/database/   pgx pool + embedded SQL migrations
internal/auth/       Argon2id passwords, Redis sessions, rate limits, handlers
internal/signaling/  websocket hub; relays JSON between authenticated clients
internal/httpx/      origin policy, CSRF guard, JSON + panic-recovery helpers
```

## Running

```sh
cp .env.example .env      # then fill in real secrets: openssl rand -base64 32
docker compose up -d      # postgres + redis
go run ./cmd/server       # migrations run automatically at startup
```

To run the API in a container too:

```sh
docker compose --profile api up --build
```

Rancher Desktop on the dockerd (moby) backend runs these commands unchanged.
On the containerd backend, substitute `nerdctl compose`. Kubernetes is not
used by this project — disabling it in Rancher Desktop's preferences avoids the
"Waiting for Kubernetes API" startup wait.

## Data stores

**Postgres** holds identity and anything that must survive a restart: users,
credentials, and the authentication audit trail. It is also the right home for
what a calls product needs next — rooms, membership, invitations and call
history are relational, and per-call WebRTC statistics are time-series that the
TimescaleDB extension handles without moving to a second database. JSONB covers
the semi-structured parts (SDP metadata, device info) without a schema change
for every field.

**Redis** holds sessions, single-use websocket tickets and rate-limit counters.
These are short-lived, read on nearly every request, and need atomic
increments and native TTLs — all things Redis does in one round trip and
Postgres would make you build. Persistence is on (`appendonly yes`), so a
restart does not sign every user out.

Media never flows through this server: WebRTC sends audio and video peer to
peer, and this backend only relays the signaling messages that let two peers
find each other.

## Authentication

Email and password today, with the storage schema already shaped for passkeys.

- **Argon2id** password hashing (OWASP parameters: 19 MiB, t=2, p=1), each hash
  storing its own cost parameters in PHC format. Raising the cost later
  upgrades hashes silently on next login instead of invalidating them.
  Concurrent hashes are capped so a login flood cannot exhaust memory.
- **Opaque session tokens**, 256 bits from `crypto/rand`. Redis stores only
  their SHA-256, so a leaked Redis snapshot contains nothing replayable.
  Sessions have a sliding idle TTL inside a fixed absolute lifetime.
- **Browsers** receive the session in an `HttpOnly`, `Secure`, `SameSite=Lax`
  cookie — unreadable from JavaScript, so an XSS bug cannot steal it. The token
  is never placed in a response body for browser clients.
- **Native clients** pass `"mode":"bearer"` and receive the token to store in
  Keychain/Keystore, sending it as `Authorization: Bearer`.
- **CSRF** is blocked by `SameSite=Lax` plus an Origin check on every unsafe
  method. Bearer requests are exempt, having no ambient credential to abuse.
- **Rate limits** are per account and per IP. The per-account limit is what
  stops credential stuffing, since a botnet defeats per-IP limits alone.
- **Enumeration resistance**: a wrong password and an unknown address return
  an identical response, and the unknown-account path performs the same Argon2
  work so response time does not distinguish them either.
- **Passkeys** drop into `webauthn_credentials`, which already exists. Adding
  them needs no migration to `users` or to the session layer.

### Endpoints

| Method | Path                    | Auth      | Purpose                                  |
| ------ | ----------------------- | --------- | ---------------------------------------- |
| POST   | `/api/auth/register`    | –         | Create an account and sign in            |
| POST   | `/api/auth/login`       | –         | Sign in                                  |
| POST   | `/api/auth/logout`      | –         | Revoke the current session (idempotent)  |
| GET    | `/api/auth/me`          | session   | Current user                             |
| POST   | `/api/auth/logout-all`  | session   | Revoke every session for the account     |
| POST   | `/api/auth/password`    | session   | Change password; revokes other sessions  |
| POST   | `/api/auth/ws-ticket`   | session   | Mint a 30-second single-use ws ticket    |
| GET    | `/ws`                   | session   | Websocket upgrade                        |
| GET    | `/healthz`              | –         | Liveness plus connected client count     |
| GET    | `/readyz`               | –         | Checks Postgres and Redis                |

`/ws` accepts a cookie, a bearer token, or `?ticket=`. The ticket exists
because browsers cannot set headers on a websocket handshake: it keeps a
long-lived token out of a URL, where it would land in proxy and server logs.

```sh
curl -X POST localhost:8080/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"a@example.com","password":"a properly long passphrase"}'
```

## Configuration

| Variable               | Default   | Meaning                                                              |
| ---------------------- | --------- | -------------------------------------------------------------------- |
| `ADDR`                 | `:8080`   | Listen address                                                        |
| `DATABASE_URL`         | required  | Postgres connection string                                            |
| `REDIS_URL`            | required  | Redis connection string                                               |
| `ALLOWED_ORIGINS`      | unset     | Comma-separated browser origins; unset = same-host only; `*` disables |
| `COOKIE_SECURE`        | `true`    | Set false only for local http development                             |
| `SESSION_COOKIE_NAME`  | `cb_session` | Session cookie name                                                |
| `SESSION_IDLE_TTL`     | `24h`     | Sliding inactivity window                                             |
| `SESSION_ABSOLUTE_TTL` | `720h`    | Hard session lifetime, never extended                                 |
| `TRUST_PROXY`          | `false`   | Honour `X-Forwarded-For`; only behind a proxy that overwrites it      |
| `LOG_LEVEL`            | `info`    | `debug`, `info`, `warn`, `error`; JSON on stdout                      |

## Tests

```sh
go test -race ./...        # unit tests; integration tests skip

# with docker compose up:
set -a; . ./.env; set +a
TEST_DATABASE_URL="$DATABASE_URL" TEST_REDIS_URL="$REDIS_URL" go test -race ./...
```

The auth integration tests run against the compose Postgres and Redis and
cover the cookie and bearer flows, lockout, session revocation, CSRF, and the
enumeration and token-storage properties described above.

## Not built yet

- **Email verification and password reset.** Until verification exists,
  registration returns 409 on a duplicate address, which does reveal that the
  address is registered; per-IP registration limits are what currently keep
  that from being usable in bulk.
- **Rooms.** Every connected client is in one global room, so two concurrent
  calls would cross-talk. Room IDs are the next schema addition.
- **TURN.** Peers behind symmetric NAT need a relay; signaling alone is not
  enough for calls to connect reliably.
- **Breach-corpus password screening** via the Have I Been Pwned range API,
  which checks a password without transmitting it.
