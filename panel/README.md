# GoNuts self-hosted panel

`gonuts-panel` is the server behind the self-hosted GoNuts dashboard. It serves
the sign-in pages and dashboard, relays each client's panel page from the mod's
WebSocket connection, and stores installations, pairing codes, and sessions in
a single `state.json`. Sign-in is Discord OAuth, a local password/PIN, or the
loopback-only development link.

Everything is served from one origin. The browser only talks to this process:
no CDN, no analytics, no third-party requests; Monocraft is bundled under the
SIL Open Font License (`web/assets/Monocraft-OFL.txt`).

- `GET /healthz` — liveness probe.
- `/auth/*` — Discord OAuth, local password sign-in (`POST /auth/local`), or
  `GONUTS_DEV_LOGIN=1` local sign-in.
- `/dashboard` — signed-in panel; the sign-in page when signed out.
- `/dashboard/ws/client` — the mod's WebSocket.
- `/dashboard/api/*` — pairing, telemetry-check, and command endpoints.

## Requirements

- Go 1.27 (only for building/running natively; the container carries its own).
- A Discord application (see below), a local password, or `GONUTS_DEV_LOGIN=1`.
- No database: state lives in `GONUTS_DATA_DIR/state.json` (mode 0600).

## Run in a GitHub Codespace

The repository ships `.devcontainer/devcontainer.json`: a Codespace gets Go
1.27, runs `go mod download`, and forwards port 8080.

1. Open the repository in a Codespace and wait for the Go feature and
   `go mod download` to finish.
2. In the Discord developer portal (OAuth2 → Redirects) add

   ```
   https://${CODESPACE_NAME}-8080.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}/auth/callback
   ```

   That is the exact, publicly forwarded HTTPS origin of this Codespace.
3. Set `GONUTS_DISCORD_CLIENT_ID` and `GONUTS_DISCORD_CLIENT_SECRET` in the
   Codespace terminal, or as Codespaces secrets (never commit them).
4. Run the runbook script:

   ```bash
   ./scripts/codespace.sh
   ```

   It refuses to start without both Discord values, then sets

   ```
   GONUTS_PUBLIC_BASE_URL=https://${CODESPACE_NAME}-8080.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}
   GONUTS_COOKIE_SECURE=1
   GONUTS_TRUST_PROXY=1
   GONUTS_DATA_DIR=$PWD/panel/data
   ```

   runs `go test ./...`, and finally `go run ./cmd/gonuts-panel`. The Discord
   redirect is derived as `${PUBLIC_BASE_URL}/auth/callback`.
5. Run the suite once under the race detector as well. `-race` needs cgo and a
   C compiler, so the Codespace (or any Linux host with gcc) is the place for
   it, not the Windows development host:

   ```bash
   ./scripts/test-race.sh    # go test -race ./... -count=1
   ```
6. In the Ports tab confirm port **8080** is **Public**, then open the forwarded
   URL. The origin is `https://<codespace>-8080.<region>.app.github.dev`.
7. Point the mod at the same origin in `config/gonuts-panel-link.json`:

   ```json
   {"baseUrl":"https://<codespace>-8080.app.github.dev"}
   ```

   The string must match `GONUTS_PUBLIC_BASE_URL` exactly (scheme, host, port,
   no trailing slash); otherwise pairing succeeds but the link is rejected.
8. If the Codespace is recreated it gets a new URL: update the Discord redirect
   and the mod's `baseUrl`, and restart the client (the config is read once).

## Discord application

1. Create an application at
   <https://discord.com/developers/applications>.
2. OAuth2 → Redirects → add `https://YOUR_HOST/auth/callback`, where
   `YOUR_HOST` is the exact host in `GONUTS_PUBLIC_BASE_URL`. Codespaces use the
   forwarded origin from step 2 above; a NAS uses its reverse-proxy hostname.
   Discord only accepts `https://` redirects (plus `http://localhost`), so a
   NAS reached as `http://192.168.x.x:8080` cannot use Discord OAuth — use the
   local password there.
3. OAuth2 → copy the **Client ID** and **Client Secret** into `.env` for a
   Docker deployment (or export them as `GONUTS_DISCORD_CLIENT_ID` and
   `GONUTS_DISCORD_CLIENT_SECRET` for a native run). The panel only requests
   the `identify` scope — no bot token, no guild access.
4. Optional: set `GONUTS_ALLOWED_DISCORD_IDS` to a comma-separated list of
   Discord user IDs to restrict who may sign in. Leave it empty to let any
   Discord account that can reach the panel sign in.
5. Never commit `.env`; it is already in `.gitignore`.

## Docker on a Synology NAS

Copy `panel/` to the NAS (or clone the repository there), then:

```bash
cp .env.example .env    # fill in the Discord values and the public URL
mkdir -p data && chown -R 1000:1000 data   # once; the container runs as UID 1000
docker compose up -d --build
docker logs -f gonuts-panel
```

`docker-compose.yml` builds a static ARM64/x86-64 image (`golang:1.27-alpine`
build stage, `alpine:3.22` runtime), runs as `user: "1000:1000"`, mounts
`./data` at `/data`, exports port 8080, and runs read-only with a 256 MB memory
limit, a `/tmp` tmpfs, and `no-new-privileges`.

Docker vs native: the container is the simplest option on DSM 7, which ships
Container Manager. Use the native binary below if you prefer to avoid Docker.

### Reverse proxy and HTTPS

Synology DSM → **Login Portal → Advanced → Reverse Proxy**:

- Source: HTTPS, `panel.example.com`, port 443.
- Destination: HTTP, `127.0.0.1`, port 8080.
- Enable **WebSocket** in Custom Header (the mod and the dashboard SSE stream
  both need it).
- HSTS is optional; the panel already sends CSP, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`.

Set `GONUTS_PUBLIC_BASE_URL=https://panel.example.com` and keep
`GONUTS_TRUST_PROXY=1` so rate limits key on `X-Forwarded-For`.

Alternatives: Cloudflare Tunnel or Tailscale. Either way set
`GONUTS_PUBLIC_BASE_URL` to the exact HTTPS host the mod will dial and add
`<that host>/auth/callback` to the Discord redirects.

### LAN-only plain HTTP

The panel itself accepts an `http://` origin. For a LAN-only install set
`GONUTS_PUBLIC_BASE_URL=http://192.168.x.x:8080`, `GONUTS_COOKIE_SECURE=0`, and
`GONUTS_TRUST_PROXY=0`. The mod only accepts `http://` for loopback and RFC1918
addresses; every other origin must be HTTPS.

Discord OAuth cannot use a non-localhost `http://` callback, so a LAN-only
install signs in with a local password instead (next section). Discord and the
local password can also be enabled together.

## Local password on a NAS

The panel can sign in with a local password (a PIN works too) instead of
Discord. It is meant for a NAS on a trusted LAN or a host behind an HTTPS
reverse proxy.

1. Pick a password of at least four characters and generate its PBKDF2 hash.
   The hash generator runs before any configuration is read, prints only the
   hash, and exits:

   ```bash
   cd panel
   ../.tools/go/bin/go run ./cmd/gonuts-panel -hash-password 'your password'
   # pbkdf2-sha256$600000$...$...
   ```

   A built binary does the same:
   `./gonuts-panel -hash-password 'your password'`. Quote the password, and
   note that a command-line argument is visible in the shell history and the
   process table while it runs; generate the hash on a trusted machine.

2. Configure the panel. For a LAN-only native run on the NAS:

   ```bash
   GONUTS_PUBLIC_BASE_URL=http://<LAN-IP>:8080
   GONUTS_COOKIE_SECURE=0
   GONUTS_TRUST_PROXY=0
   GONUTS_LOCAL_PASSWORD_HASH='pbkdf2-sha256$600000$...$...'
   GONUTS_LOCAL_USER=owner
   GONUTS_DATA_DIR=/volume1/docker/gonuts-panel/data
   ```

   `GONUTS_LOCAL_PASSWORD` (plaintext) is a fallback for when generating a hash
   is inconvenient; it is compared in constant time but the deployment should
   prefer `GONUTS_LOCAL_PASSWORD_HASH`. `GONUTS_LOCAL_USER` names the account
   the panel creates on first sign-in and defaults to `local`.

3. Start the panel (see [Native binary](#native-binary-no-docker)) and open
   `http://<LAN-IP>:8080`. The sign-in page shows a password field; the ping,
   pairing, and dashboard flows are unchanged.

Notes:

- Sign-in attempts are limited to 10 per minute per client IP; a wrong password
  redirects back to the sign-in page with a generic "Incorrect password."
- A local sign-in creates a normal 30-day session in `state.json`, exactly like
  a Discord sign-in, so the dashboard, SSE stream, and panel relay all work.
- Plain HTTP sends the password unencrypted over the network. Use it only on a
  LAN you trust; otherwise terminate TLS in the DSM reverse proxy and keep
  `GONUTS_COOKIE_SECURE=1`.
- With neither Discord nor a local password (and no `GONUTS_DEV_LOGIN=1`), the
  panel refuses to start; with a local password and no Discord credentials, the
  `/auth/login` and `/auth/callback` Discord routes answer 404.

## Native binary (no Docker)

Cross-compile from the repository root:

```bash
cd panel
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 ../.tools/go/bin/go build -trimpath -ldflags="-s -w" -o dist/gonuts-panel-linux-arm64 ./cmd/gonuts-panel
```

`dist/gonuts-panel-linux-arm64` is a static ELF64 AArch64 executable (roughly
9 MB). Copy it to the NAS, make it executable, and export the variables from
`.env` before launching it (`set -a; . ./.env; set +a`). The binary reads only
its process environment and never parses `.env` itself; the systemd unit below
supplies the same variables with `EnvironmentFile=`. Launch it from a DSM
**Task Scheduler** boot task, or (on a systemd host) with a unit such as:

```ini
[Unit]
Description=GoNuts panel
After=network-online.target

[Service]
User=gonuts
EnvironmentFile=/volume1/docker/gonuts-panel/.env
ExecStart=/volume1/docker/gonuts-panel/gonuts-panel-linux-arm64
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/volume1/docker/gonuts-panel/data

[Install]
WantedBy=multi-user.target
```

## Operating it

- **State and backup.** `data/state.json` holds users, sessions, installations,
  pairing codes, and the last telemetry. Back it up before upgrades; it is
  written atomically with mode 0600. `dist/` and `data/` are ignored by git —
  never commit them either.
- **Memory.** The container is limited to 256 MB; watch `docker stats`. The
  relayed-page cache is bounded by `GONUTS_PANEL_CACHE_BYTES` (default 16 MiB)
  and per-installation buffers are fixed, so memory does not grow with use.
- **Logs.** `docker logs gonuts-panel` (or the DSM task log). The panel never
  logs request bodies, cookies, pairing codes, or Discord secrets.
- **Upgrades.** Rebuild the image (or replace the binary), restart, and keep the
  `data/` directory. Sessions in `state.json` survive a restart.
- **Tests.** From `panel/`: `../.tools/go/bin/go vet ./...` and
  `../.tools/go/bin/go test ./... -count=1`. The race detector needs cgo and a
  C toolchain, so run it on the Codespace or another Linux host from the
  repository root: `./scripts/test-race.sh` (that is
  `go test -race ./... -count=1` from `panel/`).

## Local development

```bash
cd panel
GONUTS_DEV_LOGIN=1 GONUTS_DATA_DIR=./data ../.tools/go/bin/go run ./cmd/gonuts-panel
```

Then open <http://localhost:8080> and use the dev sign-in link. `GONUTS_DEV_LOGIN`
mints a session without Discord, so it is refused unless explicitly set, it is
rejected unless `GONUTS_PUBLIC_BASE_URL` is loopback (`localhost`, `127.0.0.1`,
or `[::1]`), and the deployment `.env.example` pins it to `0`.

For a local test with no login page at all, set `GONUTS_AUTH_DISABLED=1`
**and** bind loopback explicitly:

```bash
GONUTS_AUTH_DISABLED=1 GONUTS_ADDR=127.0.0.1:8080 \
GONUTS_PUBLIC_BASE_URL=http://127.0.0.1:8080 \
GONUTS_DATA_DIR=./data ../.tools/go/bin/go run ./cmd/gonuts-panel
```

Every `/dashboard` request receives a loopback-only session for
`GONUTS_LOCAL_USER` (default `local`). The panel refuses to start if either the
listen address or the public origin is not loopback, so this cannot silently
expose bot controls to a LAN or the internet.

## Release packaging

See [panel/deploy/RELEASE-ARTIFACTS.md](deploy/RELEASE-ARTIFACTS.md) for the release asset list. The optional `gonuts-panel.jar`
requires Java 17+ on Linux and bundles the arm64 and amd64 panel binaries.
