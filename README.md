# cb-back

Authentication and WebRTC signaling backend for video and audio calls, in Go.

## Layout

```
cmd/server/          process entry point: config, wiring, graceful shutdown
internal/config/     environment parsing, validated once at startup
internal/database/   pgx pool + embedded SQL migrations
internal/auth/       Argon2id passwords, Redis sessions, rate limits, handlers
internal/signaling/  websocket hub; relays JSON between authenticated clients
internal/inbox/      per-user websocket that pushes invites to idle clients
internal/invites/    ring, cancel and decline endpoints
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
  their SHA-256, so a leaked Redis snapshot contains nothing replayable. The
  session itself lives server-side; the cookie is only a handle to it.
- **Staying signed in for a week.** The idle window slides on each
  authenticated request, and `GET /api/auth/me` re-issues the cookie, so the
  week counts from the user's last visit rather than from when they logged in.
  The absolute lifetime never slides, so a stolen session still expires.
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
| POST   | `/api/rooms`            | session   | Create a room (server generates the slug) |
| GET    | `/api/rooms`            | session   | Public room directory, newest first      |
| GET    | `/api/rooms/{slug}`     | session   | Resolve an invitation slug               |
| DELETE | `/api/rooms/{slug}`     | session   | Delete a room (any signed-in user)       |
| POST   | `/api/rooms/{slug}/invites`         | session | Ring a user into a room          |
| POST   | `/api/rooms/{slug}/invites/cancel`  | session | Stop ringing them                |
| POST   | `/api/rooms/{slug}/invites/decline` | session | Refuse an invite                 |
| GET    | `/api/users`            | session   | Address book: other users' display names |
| GET    | `/ws?room={slug}`       | session   | Websocket upgrade into a room            |
| GET    | `/ws/inbox`             | session   | Per-user websocket that carries invites  |
| GET    | `/healthz`              | –         | Liveness plus connected client count     |
| GET    | `/readyz`               | –         | Checks Postgres and Redis                |

`/ws` accepts a cookie, a bearer token, or `?ticket=`. The ticket exists
because browsers cannot set headers on a websocket handshake: it keeps a
long-lived token out of a URL, where it would land in proxy and server logs.

Authentication is checked before the room, so an unknown slug returns 401 to an
unauthenticated caller rather than 404 — a 404 there would let anyone probe for
which rooms exist.

## Rooms and the signaling protocol

A room scopes the relay: a message reaches only clients connected to the same
room, so two calls can run at once without hearing each other.

**Access model — rooms are public.** Every signed-in user sees every room in the
directory and may join any of them; the directory is how someone finds a call.
Slugs are still generated rather than chosen, so a link can be shared directly
without colliding with an existing room, and they avoid vowels and look-alike
characters so they survive being read aloud.

Each directory row carries the creator's display name, never their email
address, so the list is readable without becoming a user-enumeration endpoint.

Deletion is open to any signed-in user, matching the open directory: shared
housekeeping for a shared list. The trade-off is that someone can remove a room
others are using — restricting it to the creator is a one-line change to the
query if that becomes a problem. Deleting does not disconnect anyone already in
the room; their websockets stay up until they leave, and the room simply stops
appearing in the directory and can no longer be joined.
There is deliberately no private-room concept yet: if one is added, it belongs
in a `visibility` column plus a `room_members` table, and the directory query
becomes the place that enforces it.

Clients send:

```json
{ "type": "offer|answer|candidate|bye|chat", "to": "<peer user id>", "payload": { } }
```

`to` is optional; omitting it fans the message out to the whole room, which is
what a client does before it knows who is present. The server sends:

```json
{ "type": "...", "from": "<user id>", "payload": { }, "peers": [ ] }
```

**`from` is stamped by the server** from the authenticated connection, and any
`from` in a client's own frame is discarded. A client that could name its own
sender could inject an SDP offer — or a chat message — as another participant.
Unknown message types are rejected rather than relayed, so the set of frames
that can cross the hub is exactly the set above.

`chat` rides the same relay as the WebRTC frames. Chat is **not persisted**: it
lives for the duration of the connection, like the chat panel in a meeting. If
history is wanted later it needs its own table, and the relay becomes a write
plus a fan-out rather than a fan-out alone.

Each connection has an inbound message budget: a burst of 120 with sustained
refill at 60/second. ICE candidates arrive in bursts of tens during
negotiation, so a real call never approaches it. A connection that does is
closed rather than silently throttled, because a dropped ICE candidate breaks a
call in a way that is very hard to diagnose from the client.

On top of the relay the server emits presence, without which a client would not
know whom to call: `welcome` (sent on join, listing everyone already present),
`peer-joined`, and `peer-left`. `peer-left` also fires when a client is dropped
for failing to drain its queue, so peers tear down the dead connection instead
of waiting on it.

## Ringing: the inbox and invites

The room relay only reaches people already in a call. To ring someone, each
signed-in client also holds `GET /ws/inbox` open while idle — the Android app
keeps it in a foreground service. The server pushes to every inbox connection
the user has:

```json
{ "type": "invite|invite-cancelled|invite-declined",
  "room": { "slug": "...", "name": "..." },
  "from": { "id": "<user id>", "display_name": "..." } }
```

A direct call is a room with two people in it. The caller creates a room, joins
it, and posts `{"user_id": "..."}` to `/api/rooms/{slug}/invites`; the callee's
phone rings, and answering joins the same room. A cancel goes to the callee when
the caller gives up, a decline goes back to the caller. `from` is stamped by the
server, as on the room relay.

**Invites are pushes, not records.** Nothing is stored: a user with no inbox
open misses the call, and the response's `delivered` count (the number of their
connections that received it) is how the caller finds that out and shows "not
online" instead of ringing into the void. Waking a phone that the OS has frozen
needs a push service (FCM); that is the upgrade path if a held-open socket
proves unreliable on some devices.

Cancels and declines are accepted after the room is gone, because a caller who
hangs up may delete the room before the cancel lands. All three share a
per-sender limit of 30 a minute, so a signed-in user cannot make someone's phone
ring on a loop.

`GET /api/users` lists every other enabled user's id and display name — never
the email — so a client has someone to call. It follows the room directory's
model: visible to any signed-in user.

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
| `SESSION_IDLE_TTL`     | `168h`    | Sliding inactivity window (one week)                                  |
| `SESSION_ABSOLUTE_TTL` | `720h`    | Hard session lifetime, never extended                                 |
| `TRUST_PROXY`          | `false`   | Honour `X-Forwarded-For`; only behind a proxy that overwrites it      |
| `TURN_SECRET`          | unset     | Secret shared with coturn; set together with `TURN_URLS` or not at all |
| `TURN_URLS`            | unset     | Comma-separated ICE server URLs returned to clients                   |
| `TURN_CREDENTIAL_TTL`  | `24h`     | TURN credential lifetime; a relayed call drops when it runs out       |
| `TURN_REALM`           | `cb-back` | coturn only: authentication realm                                     |
| `TURN_PUBLIC_IP`       | required with coturn | coturn only: the VPS public IPv4 advertised to clients     |
| `LOG_LEVEL`            | `info`    | `debug`, `info`, `warn`, `error`; JSON on stdout                      |

## Tests

```sh
go test -race ./...        # unit tests; integration tests skip

# with docker compose up — .env already points TEST_* at isolated storage:
set -a; . ./.env; set +a
go test -race ./...
```

The integration tests create real users and rooms, so they run against a
separate `cbback_test` database and Redis index 1. Pointing them at the
development database instead fills the room directory with fixtures. The
database is created on first `docker compose up`; on an existing volume:

```sh
docker compose exec postgres createdb -U cbback cbback_test
```

The auth integration tests run against the compose Postgres and Redis and
cover the cookie and bearer flows, lockout, session revocation, CSRF, and the
enumeration and token-storage properties described above.

## TURN relay

Phones on mobile data sit behind carrier-grade NAT, which defeats a direct
peer-to-peer path, so calls fall back to relaying media through coturn.

`GET /api/turn-credentials` (authenticated) returns an `RTCIceServer`-shaped
object — `urls`, `username`, `credential`, `ttl` — that a client passes
straight into its peer connection's `iceServers`. Credentials use coturn's
shared-secret scheme: the username is `<expiry>:<user id>` and the credential
is `base64(HMAC-SHA1(TURN_SECRET, username))`, so coturn verifies them without
a shared credential store, and a credential lifted from a device expires on
its own. Fetch fresh credentials before each call. With `TURN_SECRET` and
`TURN_URLS` unset the endpoint answers 503 `turn_disabled`.

coturn runs under the `api` compose profile with host networking, because it
allocates relay ports per client and Docker port mapping cannot forward those.
Open `3478/tcp`, `3478/udp` and `49160-49200/udp` on the VPS firewall. It
refuses to relay to private and loopback ranges, so a signed-in user cannot
use it to reach Postgres, Redis or anything else on the host's network.

## Not built yet

- **Email verification and password reset.** Until verification exists,
  registration returns 409 on a duplicate address, which does reveal that the
  address is registered; per-IP registration limits are what currently keep
  that from being usable in bulk.
- **Breach-corpus password screening** via the Have I Been Pwned range API,
  which checks a password without transmitting it.
