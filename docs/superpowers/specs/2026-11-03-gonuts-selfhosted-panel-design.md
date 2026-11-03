# GoNuts self-hosted panel — design

Date: 2026-11-03
Status: approved direction (Go relay), spec awaiting review

## 1. Context

The public GoNuts service is retired. `https://gonuts.at/dashboard/` returns
HTTP 410, and the final released mod disables every hosted service:

- `ProjectStatus.publicServicesEnabled()` returns `false`.
- `DashboardProtocol` hard-codes `gonuts.at` for the page, pairing redeem,
  client check and WebSocket endpoint.
- `HostedDashboardClient.start()` and `tick()` return early when public
  services are disabled.

The repository still contains everything needed to revive the dashboard
locally:

- the full client panel HTML/CSS/JS (`Pages.APP`, source copy in
  `docs/media-source/panel-v2.html`),
- the panel relay operations (`DashboardPanel`),
- the telemetry/command shapes (`HostedDashboardClient`,
  `DashboardMetrics`, `DashboardActivityCounters`),
- the hosted dashboard protocol contract
  (`docs/HOSTED-DASHBOARD-CONTRACT.md`, protocol 1).

The hosted dashboard's own card-list HTML/CSS is not in the repository and has
no Wayback Machine snapshot. The card page therefore has to be reconstructed
from the provided screenshots and the documented telemetry fields. The full
panel itself is not reconstructed: it is the mod's own page, relayed.

### Constraints from the user

- Reproduce only the panel/dashboard; do not rebuild the rest of GoNuts.
- Add a link module to the mod; do not redesign the mod UI.
- Sign in with Discord.
- Test before production.
- Immediate runtime: run in a GitHub Codespace with a public forwarded HTTPS
  port. This gives Discord a valid HTTPS callback and the mod a WSS endpoint
  without a domain.
- Later target: the Synology NAS (512 MB RAM, ARM CPU) over LAN HTTP. Ask
  before deploying there.

## 2. Goals

1. A self-hosted web dashboard that shows one card per linked GoNuts client,
   matching the supplied screenshots closely.
2. “Open panel” loads the mod's own complete panel (every page and button)
   through the relay, not a reimplementation.
3. Discord OAuth sign-in. Each Discord user only sees and controls the
   installations they paired.
4. A config-only mod link module so the existing GoNuts Dashboard screen can
   pair with the self-hosted relay instead of gonuts.at.
5. A single static Linux ARM64 binary, small enough for a 512 MB NAS, with a
   Dockerfile and a native-binary path.
6. Automated tests for protocol, auth, panel proxying, and UI; a live
   one-client test before production.

## 3. Non-goals

- Swarm discovery, Swarm rankings, shared staff sightings, shared market data.
- The hosted bug tracker, automatic bug filing, diagnostic uploads, market API.
- The optional Discord control bot.
- Rebuilding the hosted dashboard's unrelated pages.
- Any visual redesign of the mod's in-game screens.
- Changing trading logic, safety limits, or the local database schema.

The per-card Swarm row remains in the UI but shows the real telemetry state
(likely “not sharing / guidance off / not eligible”). It is never faked green.

## 4. Architecture

```
Minecraft client (GoNuts mod, patched RelayLink)
  │  1. POST /dashboard/api/pair/redeem          (pairing code)
  │  2. POST /dashboard/api/client/check          (credential check)
  │  3. WSS  /dashboard/ws/client                  (telemetry, commands,
  │                                                 panel requests/results)
  ▼
NAS: gonuts-panel (single Go binary)
  │  HTTPS + SSE
  ▼
Browser (Discord OAuth session)
```

The relay is the only public component. It stores only what the protocol needs:
users, sessions, pairing codes, installations, the last telemetry frame, and a
bounded command audit. It never reads the mod's database and never proxies
trading commands except `pause`, `resume`, `snapshot`, and panel actions that
the mod itself authorises.

### Stack decision

- Go 1.27.3, standard library for HTTP, SSE, OAuth, crypto, JSON, and embedded
  assets.
- One external dependency: `github.com/gorilla/websocket` (pure Go, custom
  close codes, read deadlines).
- Static assets embedded with `embed.FS`; the binary is self-contained.
- Cross-compiled with `CGO_ENABLED=0 GOOS=linux GOARCH=arm64`.
- Expected RSS: roughly 15–35 MB plus small caches.

Rejected alternative: Node 24 + `ws` was initially considered and would also
fit 512 MB, but the user selected Go for the lower footprint and single-binary
deployment.

## 5. Repository layout

```
gonut/
  .tools/                       portable Go toolchain (not committed)
  upstream/                     reference clone of cody-raves/Gonuts (not committed)
  panel/                        Go relay and web app
    go.mod
    cmd/gonuts-panel/main.go
    internal/config/
    internal/store/
    internal/auth/
    internal/relay/
    internal/panel/
    internal/web/
    web/                        embedded dashboard HTML/CSS/JS/assets
    Dockerfile
    docker-compose.yml
    .env.example
  docs/superpowers/specs/
```

The mod change is applied to a working copy of the upstream source and
delivered as a patch plus a built JAR. The reference clone stays untouched.

## 6. Data model

One JSON state file (`$GONUTS_DATA_DIR/state.json`, 0600) written atomically
(write temp, fsync, rename, fsync directory). A process-level mutex serialises
mutations. The file is small; no database is needed for a handful of bots.

```jsonc
{
  "users": {
    "discordId": { "id": "...", "username": "...", "globalName": "...",
                   "avatar": "...", "createdAt": 0 }
  },
  "sessions": {
    "sha256(sessionToken)": { "discordId": "...", "csrf": "...",
                              "createdAt": 0, "expiresAt": 0 }
  },
  "codes": {
    "sha256(normalizedCode)": { "discordId": "...", "createdAt": 0,
                                "expiresAt": 0, "attempts": 0, "usedAt": 0 }
  },
  "installations": {
    "12": { "id": 12, "discordId": "...", "name": "...", "build": "...",
            "hive": "...", "capabilities": ["pause", "resume", "snapshot", "panel"],
            "credentialHash": "...", "createdAt": 0, "lastSeen": 0,
            "telemetry": { ...last frame... }, "online": false }
  },
  "commands": {
    "cmd_...": { "id": "...", "installationId": 12, "discordId": "...",
                 "command": "pause", "createdAt": 0, "expiresAt": 0,
                 "state": "accepted|delivered|received|completed|rejected|expired|unknown|offline",
                 "reason": "" }
  },
  "nextInstallationId": 13
}
```

Rules:

- Credentials are `gni1_` + 43 base64url characters. Only SHA-256 is stored.
- Pairing codes use an unambiguous 32-character alphabet
  (`ABCDEFGHJKLMNPQRSTUVWXYZ23456789`), 8 characters, displayed `ABCD-EFGH`,
  hashed at rest, valid 5 minutes, one live code per user, one use,
  5 attempts, then deleted.
- Sessions are opaque 32-byte tokens; only SHA-256 is stored. Cookie
  `gonuts_session`, HttpOnly, SameSite=Lax, Secure when the public origin is
  HTTPS. 30-day expiry.
- Commands are pruned after 7 days or when the ring reaches 1,000 entries.
- Telemetry is clamped exactly as the contract requires: strings ≤160 chars
  (names ≤48), counts 0..1,000,000, money ±1,000,000,000,000, state allowlist,
  no path/token-looking strings in `detail`, `lastAction`, or `account`.
- Unknown telemetry fields are ignored, not stored.

## 7. HTTP and auth

### Routes

| Route | Auth | Purpose |
|---|---|---|
| `GET /` | none | redirect to `/dashboard` |
| `GET /dashboard` | public | dashboard shell when signed in; sign-in page when signed out |
| `GET /auth/login` | none | build Discord authorize URL (state + PKCE), redirect |
| `GET /auth/callback` | OAuth state cookie | exchange code, create session, redirect `/dashboard` |
| `GET /auth/dev` | dev-only flag | create a local test session; disabled by default |
| `POST /auth/logout` | session | delete session, clear cookie, redirect |
| `GET /dashboard/api/state` | session | user, installations, hive grouping, last command |
| `POST /dashboard/api/pair/code` | session | create a pairing code |
| `POST /dashboard/api/installations/{id}/command` | session + CSRF | `pause`, `resume`, `snapshot` |
| `POST /dashboard/api/installations/{id}/rename` | session + CSRF | update display name |
| `DELETE /dashboard/api/installations/{id}` | session + CSRF | unlink/revoke |
| `GET /dashboard/events` | session | SSE updates |
| `POST /dashboard/api/pair/redeem` | none, rate-limited | mod redeems a code |
| `POST /dashboard/api/client/check` | bearer | mod checks its credential |
| `GET /dashboard/ws/client` | bearer | mod WebSocket |
| `GET /dashboard/panel/{id}/` | session + ownership | relayed panel page |
| `GET /dashboard/panel/{id}/state` and `/api/{name}` | session + ownership | relayed panel data |
| `GET /dashboard/panel/{id}/panel.png` | session + ownership | relayed panel image |
| `GET /dashboard/panel/{id}/item/{item}.png` | session + ownership | relayed item icon |
| `GET /dashboard/panel/{id}/logo.png` and `/font.ttf` | session + ownership | relayed panel assets |
| `POST /dashboard/panel/{id}/act` and `/api/{name}` | session + ownership + CSRF | relayed panel actions |
| `GET /healthz` | none | liveness |

Unknown routes return 404 without leaking file paths.

### Discord OAuth

- Scope: `identify` only.
- Authorize URL: `https://discord.com/oauth2/authorize` with
  `client_id`, `redirect_uri`, `response_type=code`, `scope=identify`,
  `state`, `code_challenge`, `code_challenge_method=S256`.
- `state` is random, stored server-side for 10 minutes with the PKCE verifier,
  and bound to an HttpOnly short-lived cookie.
- Token exchange: `POST https://discord.com/api/oauth2/token` with the client
  secret; never log the code, token, or response body.
- User fetch: `GET https://discord.com/api/users/@me`.
- `redirect_uri` is always `${PUBLIC_BASE_URL}/auth/callback`.
- Any Discord user may sign in. `GONUTS_ALLOWED_DISCORD_IDS` is an optional
  comma-separated allowlist; empty means allow any authenticated Discord user.
- Each installation is owned by the Discord user who generated the pairing
  code. Ownership is checked on every read, command, and panel route.

### CSRF and origin

- Every mutating browser request requires `X-Gonuts-Csrf` equal to the
  session's CSRF token. Dashboard JS sends it; the relayed panel gets an
  injected fetch wrapper that adds it.
- Mutating requests also require an `Origin` (or `Referer`) matching
  `PUBLIC_BASE_URL`. Requests without a valid origin are rejected.
- Panel POSTs additionally require `X-GoNuts: 1` (the panel already sends it).
- Cookies are HttpOnly and SameSite=Lax; no cross-site form can satisfy the
  custom-header requirement.

### Rate limits (in-memory token buckets)

| Action | Limit |
|---|---|
| Pairing code creation | 10/min per user |
| Redeem | 10/min per IP, 60/min global, 5 attempts per code |
| Commands | 60/min per user |
| Panel HTTP | 120/min per session |
| Dashboard HTTP | 120/min per IP |
| SSE connections | 5 per user |
| WS connections | 1 per installation; newest wins (older closed 4409) |

`X-Forwarded-For` is trusted only when `GONUTS_TRUST_PROXY=1`.

### Security headers

- Dashboard: CSP `default-src 'self'; img-src 'self' data:; style-src 'self'
  'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self';
  frame-ancestors 'none'; base-uri 'none'; form-action 'self'`.
- Relayed panel: same, but `script-src 'self' 'unsafe-inline'` because the
  panel's own inline script must run. No external origins are allowed.
- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy` minimal.

## 8. Client protocol (protocol 1)

Implemented from `docs/HOSTED-DASHBOARD-CONTRACT.md`.

### Pairing

`POST /dashboard/api/pair/redeem` accepts the documented JSON. Request
validation:

- `protocols` must include `1`.
- `code` is normalised (upper-case, remove dash/space, `0→O`, `1/I→L`).
- `name` ≤48 chars, `[A-Za-z0-9 _().-]`, no credential/path-looking text;
  fallback `GoNuts client`.
- `build` matches `[0-9A-Za-z.+_-]{0,60}`.
- `hive` matches `[0-9A-Za-z_-]{0,64}`.
- `capabilities` is a subset of the known set.

Success `201`:

```json
{
  "installationId": 12,
  "credential": "gni1_...",
  "name": "...",
  "protocol": 1,
  "wsUrl": "wss://HOST/dashboard/ws/client",
  "checkUrl": "https://HOST/dashboard/api/client/check",
  "heartbeatSeconds": 20,
  "telemetryMinIntervalMs": 1000,
  "maxMessageBytes": 32768
}
```

The credential is shown once and stored hashed. `wsUrl` uses `wss://` for an
HTTPS public origin and `ws://` only for a localhost HTTP test origin. Errors
follow the contract (400/404/409/410/429/503). The mod's existing
`DashboardProtocol.pairError` already maps these.

### Socket

- Upgrade path `/dashboard/ws/client`, `Authorization: Bearer gni1_…`.
- A request without a valid bearer credential is rejected before the upgrade
  (HTTP 401). A valid credential that nevertheless carries an `Origin` header
  (browser-style) is upgraded and immediately closed with 4403. The mod never
  sends `Origin`.
- Unknown/revoked credential: close 4401.
- First frame within 10 s must be `hello` with `protocols` containing 1.
- Reply `welcome` with protocol, installation id, heartbeat 20,
  telemetry interval 1000, max message 32768, and commands
  `["pause","resume","snapshot","panel"]`. No optional Swarm/diagnostic
  fields are advertised, so those client features stay off.
- JSON `ping` → JSON `pong`.
- Any frame refreshes `lastSeen`; 80 s silence closes 4408 and marks offline.
- Telemetry is forwarded to the browser store after validation/clamping.
  Faster than 1/s is coalesced.
- Newest socket for an installation wins; the older one is closed 4409.
- Frame size: 1 MiB read limit; telemetry frames are validated at 32 KiB;
  panel result frames up to 768 KiB.
- `command` frames: `{id, command, createdAt, expiresAt}`. Dedupe is the
  mod's job; the relay records `ack`, `result`, timeout, and disconnects.
- `panel` frames: `{id, op, ...}` with `expiresAt ≤ now+15s`; the mod answers
  with `panel_result`. The relay matches by id, one answer only.

### Commands

- `pause` → `STOP`, `resume` → `START`, `snapshot` → immediate telemetry.
- Command states: accepted → delivered → received → completed/rejected;
  or expired (30 s), unknown (socket lost), offline (not connected).
- Nothing is queued for an offline client.
- Browser POST returns `202` with the command id; the dashboard learns the
  final state through SSE/state refresh. A small per-card status line shows
  the last command result.

## 9. Panel relay

The mod advertises `panel` and already implements every operation in
`DashboardPanel`. The relay is a thin, bounded proxy.

### HTTP → panel frame mapping

| Browser route | Frame op |
|---|---|
| `GET /dashboard/panel/{id}/` | `page` |
| `GET …/state` | `state` |
| `GET …/api/{name}?query` | `data` with `{name, query}` |
| `POST …/api/{name}` (form) | `change` with `{name, form}` |
| `POST …/act` (form) | `act` with `{id, value?, text?}` |
| `GET …/panel.png` | `png` |
| `GET …/item/{item}.png` | `icon` |
| `GET …/logo.png` | `asset: logo` |
| `GET …/font.ttf` | `asset: font` |

### Bounds and lifetime

- At most 8 panel requests in flight per installation; the 9th returns 429.
- Each request gets a fresh `pr_` id, must answer within 15 s, and is removed
  after the answer or timeout.
- A socket close rejects all of that installation's pending requests.
- Page HTML cached 10 minutes per installation + build; assets/icons cached
  10 minutes with a 16 MiB total cap. State is never cached.
- Offline + page cache: serve the cached page; the panel's own refresh shows
  “The game is not answering.”
- Offline + no cache: 503 with a small styled page and a dashboard link.
- Missing `panel` capability: 501. Another user's installation: 404.

### Page rewrite (only these changes)

The relayed HTML is the mod's `Pages.APP`. Only URL/CSRF plumbing changes:

- `/state` → `state`
- `/api/` → `api/`
- `/act` → `act`
- `/panel.png` → `panel.png`
- `/item/` → `item/`
- `/logo.png` → `logo.png`
- `url(/font.ttf)` → `url(font.ttf)`
- `https://gonuts.at/dashboard/` → `/dashboard`
- `https://gonuts.at/dashboard/bugs` → `/dashboard`
- `fetch('https://gonuts.at/dashboard/api/public/bugs'` → `fetch('api/public/bugs'`
  (returns 404; the panel already handles an unavailable tracker)
- `<form class="out" method="post" action="/logout">` → a GET link to
  `/dashboard` (the hosted panel's “Lock” returns to the dashboard; it does
  not sign the user out)
- Inject `<meta name="gonuts-csrf" content="…">` and a small fetch wrapper
  that adds `X-Gonuts-Csrf` to same-origin requests.

No layout, style, text, or navigation changes to the panel.

## 10. Dashboard UI

Vanilla HTML/CSS/JS embedded in the binary. No framework, no external fonts.

### Visual language

Taken from the panel source so the dashboard and panel look related:

- Background `#0c121b`; card surfaces `#182230`/`#101823`; edge `#2c3b4c`.
- Gold `#f4cd7a`, teal `#56dccb`, good `#77deb0`, warn `#f3b576`, bad `#ff858c`.
- Font: bundled `Monocraft.ttf` as “GoNuts Pixel”; system UI for long prose.
- Mascot sprite: the mod's `mascot_v2.png` (8-cell sheet), cropped by
  `mascotFace` (IDLE, WATCH, WORK, SALE, PAUSED, SLEEP, ALERT).
- Buttons and pills use the panel's rounded, thin-edge style; the primary
  action is gold.

### Dashboard shell

- Header: “GoNuts dashboard” in gold pixel type; right side shows the signed-in
  Discord username and “Sign out”; a “Link client” button opens the pairing
  modal.
- The dead “Bug tracker” link is omitted. No fake feature links are added.
- Hive summary below the cards when more than one installation shares a hive:
  “You have N linked bots in this hive.” with Pause all / Resume all.
- Empty state: “No clients linked yet” plus a short pairing explanation and
  the same Link client button.

### Card

Two columns on desktop (max width ~1180 px), one column under 860 px. Each
card contains:

1. Header row: installation name (gold pixel) and status pill
   (`online` teal, `offline` grey).
2. Mascot + state line (`SCANNING`, `STOPPED`, …) and the human state
   description.
3. Two-column metric rows:
   - account / bank
   - profit 1h / profit 24h
   - sales 1h/24h / purchases 24h
   - listings 24h / reprices 24h
   - listed/slots / client trades (session)
4. Profit source line (`booked`/`recorded`/`session`/`hive`) and last action
   with relative age.
5. Swarm badge and real status: sharing/guidance/eligible flags.
6. Buttons: **Open panel** (gold), **Pause**, **Resume**, **Refresh**.
   Disabled according to `controls` and online state.
7. Footer: build string; “seen Xm ago”; “rename · unlink”.

Formatting:

- Money: `$128.00m`, `$19.9k`, `$21.20m`; negative values keep the sign.
- Missing values render `—`, never `0` or a fabricated figure.
- Times are relative (“46m ago”, “1m ago”) and tick client-side.
- All telemetry strings are inserted with `textContent`, never `innerHTML`.
- Offline cards keep the last telemetry, clearly labelled offline/stale.

### Live updates

- SSE `/dashboard/events` sends a small `update` event; the client debounces
  100 ms and refetches `/dashboard/api/state`.
- If SSE fails, fall back to 5-second polling.
- “Updated Xs ago” in the header and “seen Xm ago” per card tick every second.
- No page reload after pairing; the new card appears from SSE.

### Pairing modal

- Calls `POST /dashboard/api/pair/code`, shows the code with a 5:00 countdown,
  a copy button, and the instructions from the Swarm guide:
  GoNuts → Dashboard → paste code + client label → **Link with code**.
- The code is one-use and expires. The modal says so.
- The code is not placed in the URL or logs.

### Rename / unlink

- Rename: inline edit with Save/Cancel; server-side name validation; the mod
  sees the new name on its next check/reconnect.
- Unlink: confirmation; server closes the socket 4403 and deletes the
  installation; the mod's next check gets 401 and forgets its credential.

## 11. Mod link module

Applied to a working copy of the upstream source.

### `RelayLink` (new, `dev.doughbay.fabric.hosted`)

- Reads `config/gonuts-panel-link.json`:
  ```json
  { "baseUrl": "https://panel.example.com" }
  ```
- Also accepts `-Dgonuts.panel.baseUrl=` and `GONUTS_PANEL_BASE_URL` for
  tests/headless runs.
- Validates an `http(s)` origin with no path/query/fragment; `http` is allowed
  only for `localhost`/`127.0.0.1` testing. Trailing slash is stripped.
- `enabled()` is true only when a valid base URL is configured.
- Derives:
  - page `BASE/dashboard/`
  - redeem `BASE/dashboard/api/pair/redeem`
  - check `BASE/dashboard/api/client/check`
  - socket `wss://HOST/dashboard/ws/client` (or `ws://` for localhost)
- `hostLabel()` for the one host reference in the Dashboard screen.

### Patches

- `DashboardProtocol`: replace the four static `URI` constants with methods
  that delegate to `RelayLink`; keep `JSON`, `code`, `label`, `build`,
  `hello`, `pairing`, telemetry clamping, `parse`, `backoff`, `pairError`
  unchanged.
- `HostedDashboardClient.start()` and `tick()`: use
  `ProjectStatus.publicServicesEnabled() || RelayLink.enabled()` instead of
  the public-services check alone.
- `DashboardWebsiteAccess` and `DashboardScreen`: use
  `DashboardProtocol.page()`; replace the hard-coded `gonuts.at` host text
  with `RelayLink.hostLabel()`.
- Leave `enrollCommunity`, `CommunityClient`, diagnostics, bug reports,
  trading, local panel, and every layout/style untouched.
- The Dashboard screen's hard-coded host text and its “Linking joins Swarm”
  sentence are replaced with self-hosted wording (the relay does not join
  Swarm). No layout, spacing, or style changes.

### Build and install

- `./gradlew :trader-fabric:build` with JDK 25 (available on this machine).
- Deliver the built JAR, the source patch, and the config example.
- Install on one test client first, after backing up the existing JAR and
  database.
- Build version remains `0.1.2-swarm+26.2`; the new config is the only
  behavioural switch.

## 12. Testing

### Relay unit/integration (Go)

- Code normalisation, hashing, one-use/expiry/attempt limits.
- Credential generation/hash/constant-time lookup, revocation.
- Session cookie, CSRF, origin checks, allowlist.
- Telemetry clamping and refusal rules (path/credential-looking strings).
- Pairing success + 400/404/409/410/429 paths.
- WS hello/welcome, ping/pong, heartbeat timeout, duplicate socket 4409,
  command ack/result/expiry/disconnect.
- Panel broker: id matching, duplicate answer, timeout, in-flight limit,
  429/501/404/503, binary decoding, cache bounds.
- Page rewrite: relative URLs, CSRF injection, Lock behavior, no gonuts.at
  fetches, no layout changes.
- SSE event delivery, fallback polling endpoint.
- Rate-limit buckets.
- Store atomic write/load, corrupt-file refusal (fail closed, do not wipe).

### Mock client and browser

- A Go test mock implements the mod side: redeem, check, WSS hello,
  telemetry, command ack/result, panel page/results.
- Browser tests (manual via the browser tool, plus screenshots at desktop and
  mobile widths):
  - Discord/dev sign-in, card rendering, every metric, missing-value dashes.
  - Link client modal, rename, unlink, pause/resume/refresh feedback.
  - Open panel, navigate pages, press a control, observe the relayed result.
  - Offline behaviour and stale data.
- Visual comparison against the supplied screenshots; iterate on spacing and
  typography.

### Mod

- `./gradlew :trader-fabric:build` (compiles and runs JVM tests).
- New `RelayLinkTest` for URL derivation/validation and disabled default.
- Updated `DashboardProtocolTest` for derived endpoints.
- No in-game automated run is possible here; the user performs the one-client
  live pairing test before production.

### Production gate

1. Relay + mock client tests pass.
2. Browser UI passes desktop/mobile checks.
3. Mod builds; JVM tests pass.
4. One real client pairs, appears online, sends fresh telemetry, and responds
   to Pause/Resume/Refresh and panel actions.
5. ARM64 binary runs on the NAS behind HTTPS/WSS; memory measured.
6. Discord OAuth callback works with the production URL.
7. No secrets in logs; CSRF/origin/rate-limit checks exercised.

## 13. Deployment

### Immediate: GitHub Codespace

- Run the Go server directly in the Codespace on port `8080`.
- Make the forwarded port public. `PUBLIC_BASE_URL` is the forwarded HTTPS
  origin `https://${CODESPACE_NAME}-8080.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}`.
- Discord redirect URI is `${PUBLIC_BASE_URL}/auth/callback`.
- Set `GONUTS_COOKIE_SECURE=1` and `GONUTS_TRUST_PROXY=1`.
- Mod link base URL is the same HTTPS origin; it derives `wss://`.
- A `.devcontainer/devcontainer.json` and `scripts/codespace.sh` document the
  exact setup. The Codespace URL changes if the Codespace is recreated, so the
  Discord redirect URI must be updated then.

### Later: Synology NAS

Do not touch the NAS until the user approves. The NAS target may use plain
HTTP on the LAN (`http://<LAN-IP>:<port>`); the relay and mod link support
loopback and RFC1918 private HTTP origins for that case. Discord OAuth cannot
use a non-localhost HTTP callback, so the NAS needs either a local
password/PIN sign-in, an SSH tunnel to a localhost callback, or HTTPS.

Prepare:

- A static ARM64 binary and a minimal Docker image (`scratch`/distroless or
  `alpine`; no build tools).
- `docker-compose.yml` with a minimal runtime image (distroless/static or
  alpine), `memory: 256m`, restart policy, data volume, env file.
- Environment:
  - `GONUTS_PUBLIC_BASE_URL`
  - `GONUTS_DISCORD_CLIENT_ID`
  - `GONUTS_DISCORD_CLIENT_SECRET`
  - `GONUTS_DATA_DIR`
  - `GONUTS_ALLOWED_DISCORD_IDS` (optional)
  - `GONUTS_TRUST_PROXY=1`
  - `GONUTS_DEV_LOGIN` (never in production)
- Reachability options, to be chosen by the user:
  - Synology DDNS/domain + DSM reverse proxy + Let's Encrypt, WebSocket
    upgrade enabled.
  - Cloudflare Tunnel (`cloudflared` container), no port forwarding.
  - Tailscale/private VPN with a TLS hostname.
- Discord application setup instructions (client ID/secret, redirect URL
  `${PUBLIC_BASE_URL}/auth/callback`, identify scope; no bot token).
- Backups of `state.json`, and a note that the mod's own database/settings
  are untouched.
- Memory watch after start; cap panel/asset caches; no build on the NAS.

## 14. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Hosted dashboard card CSS is unavailable | Reconstruct from screenshots + telemetry contract; iterate with browser screenshots. The panel itself is exact. |
| Mod rebuild fails or is not installable | Build and test here; deliver source patch and fallback instructions. Live data requires the patched JAR. |
| Real Discord OAuth cannot be tested here | Implement to spec; local dev login for UI tests; user creates the Discord app; test callback on the NAS. |
| Public panel controls trading | Discord ownership, pairing codes, hashed credentials, CSRF, same-origin, rate limits, no offline command queue. |
| 512 MB NAS | Static Go binary, 256 MB container limit, small caches, no build on device, memory measurement during smoke test. |
| Panel relay complexity | Reuse the mod's existing `DashboardPanel`; bounded broker with tests; cache page/assets; clear offline errors. |
| Swarm row looks “off” | Show real telemetry state and explain in the UI; no fake eligibility. |
| Reverse proxy breaks WSS | Document upgrade headers; test with the chosen tunnel/proxy before production. |

## 15. Acceptance criteria

- A signed-in Discord user can create a code, pair one client, and see its
  card with live telemetry.
- Pause, Resume, Refresh, rename, and unlink work and show final outcomes.
- “Open panel” shows the mod's actual panel and its pages/buttons work through
  the relay.
- Offline clients show stale data and disabled controls, never blank cards.
- The page works at desktop and phone widths and matches the supplied visual
  direction.
- The patched mod builds, pairs with the self-hosted relay, and leaves trading
  and the local panel unaffected.
- The ARM64 binary runs on the NAS behind HTTPS/WSS with acceptable memory.
- No secrets appear in logs, URLs, or rendered HTML.

## 16. Open items for the user

- Discord application client ID/secret (not yet created).
- Public hostname for the NAS and the chosen reachability option.
- NAS runtime preference: Docker vs native static binary.
- Confirmation before any production deployment.
- One live client test after the mod JAR is built.
