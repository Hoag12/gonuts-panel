# Using the GoNuts panel and the doughbay mod

Three pieces:

| Piece | What it is |
| --- | --- |
| **Panel** (`panel/`) | One Go process. Serves the dashboard, the pairing API, the mod's WebSocket, and relays each client's panel page. State lives in `data/state.json` (mode 0600) — no database. |
| **Mod** (`doughbay-0.1.2-swarm+26.2.jar`) | Fabric client mod. Connects out to the panel over its own WebSocket, streams telemetry, accepts `pause`/`resume`/`snapshot`, and serves its own panel UI back through the panel. |
| **Dashboard** (`/dashboard`) | The browser UI served by the panel: clients, telemetry, per-client panel tab, commands. |

The mod is attached to the [release](https://github.com/Hoag12/gonuts-panel/releases); its checksum is in the release notes.

## 1. Run the panel

### Docker (recommended)

```bash
cd panel
cat > .env <<'EOF'
GONUTS_ADDR=0.0.0.0:8080
GONUTS_PUBLIC_BASE_URL=http://192.168.2.8:8080
GONUTS_DATA_DIR=/data
GONUTS_AUTH_DISABLED=1
GONUTS_ALLOW_UNAUTH_LAN=1
GONUTS_COOKIE_SECURE=0
GONUTS_TRUST_PROXY=0
EOF
mkdir -p data && sudo chown -R 1000:1000 data
docker compose up -d
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/healthz   # 200
```

### systemd on a NAS or Linux host

```bash
sudo install -m 0755 gonuts-panel /usr/local/bin/gonuts-panel
sudo mkdir -p /opt/gonuts-panel/data && sudo chown "$USER" /opt/gonuts-panel/data
sudo systemctl enable gonuts-panel && sudo systemctl start gonuts-panel
```

DSM 7.1.1 has no `systemctl enable --now`; run `enable` and `start` separately.

### Configuration

| Variable | Meaning |
| --- | --- |
| `GONUTS_ADDR` | listen address, e.g. `0.0.0.0:8080` |
| `GONUTS_PUBLIC_BASE_URL` | the origin clients and browsers use. It **must** match: it drives the CSRF `Origin`/`Referer` check and the WebSocket URL handed to the mod. |
| `GONUTS_DATA_DIR` | where `state.json` and the persistent `swarm.key` live |
| `GONUTS_AUTH_DISABLED=1` | no sign-in — loopback only unless `GONUTS_ALLOW_UNAUTH_LAN=1` is also set. Only for a trusted LAN. |
| `GONUTS_ALLOW_UNAUTH_LAN=1` | allow the above from the LAN |
| `GONUTS_COOKIE_SECURE` | `0` for plain `http://`, `1` behind HTTPS |
| `GONUTS_TRUST_PROXY` | `1` when a reverse proxy terminates TLS |
| `GONUTS_EXTRA_ORIGINS` | comma-separated extra origins that may send mutations, e.g. `http://100.95.121.78:8080` — without it the dashboard works over that address but every action returns 403 and the page reloads |
| `GONUTS_LOCAL_PASSWORD_HASH` | PBKDF2 hash; generate with `gonuts-panel -hash-password 'your-pin'` |
| `GONUTS_DEV_LOGIN=1` | loopback development sign-in |
| `GONUTS_DISCORD_CLIENT_ID` / `_SECRET` | Discord OAuth instead of a local password; redirect must be `${GONUTS_PUBLIC_BASE_URL}/auth/callback` |

Back up before an upgrade or configuration change. Copy the whole data
directory, not just `state.json`: `swarm.key` must be retained or credential
signing and stable account IDs change.

```bash
cd /opt/gonuts-panel
cp panel.env panel.env.bak-$(date +%Y%m%d-%H%M%S)
cp -a data data.bak-$(date +%Y%m%d-%H%M%S)
```

Keep the same `GONUTS_DATA_DIR` (or Docker `./data:/data` mount) across the
upgrade. Do not delete the data directory, recreate the container with an empty
mount, or run `docker compose down -v`. If using systemd, stop the service
before copying the backup.

## 2. Install the mod

Requirements: **Minecraft 26.2**, **Fabric loader 0.19.5**, **Fabric API**, **JDK 25**.

1. Download `doughbay-0.1.2-swarm+26.2.jar` from the release page and drop it into `<profile>/mods/`.
2. Write `<profile>/config/gonuts-panel-link.json`:

   ```json
   {"baseUrl":"http://192.168.2.8:8080"}
   ```

   `http://` is accepted **only** for `localhost`, `127.0.0.1`, `::1`, `10.x`, `192.168.x` and `172.16–31.x`. A Tailscale `100.x` address is rejected by the mod — use the LAN address, or run the panel-facing proxy described in §6.

The base URL may also come from `-Dgonuts.panel.baseUrl` or `GONUTS_PANEL_BASE_URL`; the
system property wins, then the environment variable, then the config file.

## 3. Link a client

### Through the dashboard

Open `/dashboard`, choose **Add client**, and copy the short pairing code. Start
Minecraft with the mod installed; the client redeems the code and appears in the list.

### Through the API (what the headless scripts do)

```bash
BASE=http://192.168.2.8:8080
curl -s -c /tmp/jar -o /dev/null "$BASE/dashboard"                 # session cookie
CSRF=$(curl -s -b /tmp/jar "$BASE/dashboard" | grep -o 'name="gonuts-csrf" content="[^"]*"' | sed 's/.*content="//;s/"//')
CODE=$(curl -s -b /tmp/jar -X POST -H "X-Gonuts-Csrf: $CSRF" -H "Origin: $BASE" "$BASE/dashboard/api/pair/code" | jq -r .code)
curl -s -b /tmp/jar -X POST -H "Content-Type: application/json" \
  -H "X-Gonuts-Csrf: $CSRF" -H "Origin: $BASE" -H "Referer: $BASE/dashboard" \
  -d "{\"build\":\"0.1.2-swarm+26.2\",\"name\":\"Thaohg\",\"hive\":\"\",\"protocols\":[1],
       \"capabilities\":[\"pause\",\"resume\",\"snapshot\",\"panel\",\"swarm_enable\",\"swarm_disable\",
                          \"swarm_rank\",\"swarm_staff\",\"read_savings\",\"data_use\",
                          \"settings_analysis\",\"diagnostic_history\"],
       \"code\":\"$CODE\"}" \
  "$BASE/dashboard/api/pair/redeem"
```

The reply carries `credential`, `installationId`, `wsUrl`, `checkUrl`; the mod stores
the credential in `<profile>/gonuts-dashboard/installation.json` (mode 0600).

**One link per Minecraft account.** If a client is re-paired under the same name,
delete the old installation instead of keeping both:

```bash
curl -s -b /tmp/jar -X DELETE -H "X-Gonuts-Csrf: $CSRF" -H "Origin: $BASE" \
  "$BASE/dashboard/api/installations/<id>"
```

## 4. Use the dashboard

- **Client list** — online state, scanner state, bank, trades, profit/revenue (1h, 24h), swarm status.
- **Panel tab** — `/dashboard/panel/<id>/` relays the mod's own UI. It only works if the
  stored capabilities include `panel`; a client linked by an older build shows
  *“the client does not support the panel”* — re-pair it with the capability list above.
- **Commands** — `pause`, `resume`, `snapshot` are capability-gated; a rejected resume
  usually means the client has not joined the server yet (it answers `rejected` and the
  reason lands in `lastCommand`).
- **Rename / delete** — `/dashboard/api/installations/<id>/rename` and `DELETE`, both
  needing the CSRF header and a matching `Origin`.

Mutating requests from any origin other than `GONUTS_PUBLIC_BASE_URL` are refused with
`403 invalid request origin or token`. Reach the panel through its public base URL, not
through a Tailscale address, or the dashboard will look read-only.

## 5. Files the mod writes

| Path | Purpose |
| --- | --- |
| `config/gonuts-panel-link.json` | panel base URL |
| `config/doughbay/hive.json`, `gonuts-hive.json` | hive identity; `directory` is an **absolute** path, so it must be rewritten after moving an instance |
| `config/doughbay/doughbay.db` | shared trading database — snapshot it with `sqlite3 doughbay.db ".backup out.db"`, never copy it while the game is running |
| `gonuts-dashboard/installation.json` | panel link credential (0600) |

## 6. Running headless

A Minecraft client needs a display even when nobody watches it: run Xvfb, then the
launcher. Everything below lives in the sibling repo `gonuts-cloud`.

- **GitHub Codespaces** — `.devcontainer` + `scripts/bootstrap.sh`, then
  `scripts/start-stack.sh` starts Xvfb, userspace Tailscale, the local panel proxy,
  `alive.py` and `watchdog.sh`; the watchdog relaunches the client from
  `~/.gonuts/autostart` if the JVM dies. Logs: `/tmp/game-<instance>.log`.
- **A real Linux host** — `scripts/vps-setup.sh` installs JDK 25, `cmd-launcher`,
  Tailscale and `gonuts-client@<instance>.service` units with `Restart=always`. Such a
  host has `/dev/net/tun`, so set `GONUTS_USE_PROXY=0` and the panel is reached directly.
- **Codespaces without TUN** — the mod cannot be given a `100.x` URL and Java does not
  honour `-DsocksProxyHost`, so `panelproxy.py` (HTTP proxy on `127.0.0.1:8099`, dialing
  through tailscaled's SOCKS5) plus `PanelProxyAgent.java` (a `-javaagent` installing a
  `ProxySelector` for `192.168.2.8` only) bridge the gap. `run-client.sh` wires both.
- **Hugging Face Space** — `hf-space/` builds a 2 vCPU / 16GB Docker Space with no
  payment method required: state is mirrored to a private dataset because the disk is
  ephemeral, and `/healthz` must be hit every few hours so the free tier does not sleep.

### Keeping a Codespace alive from the HF Space

GitHub stops a Codespace 240 minutes after the last activity. A call to
`POST /user/codespaces/<name>/start` **refreshes that clock even while the machine is
running** (verified 2026-11-05), so a loop inside a Space is enough:

```python
# every 2 hours, with a fine-grained PAT scoped to Codespaces read/write
requests.post(f"https://api.github.com/user/codespaces/{name}/start",
              headers={"Authorization": f"Bearer {token}",
                       "Accept": "application/vnd.github+json"})
```

Remember the other ceiling: GitHub Free includes 120 core-hours per month, so two
4-core Codespaces can only run ~15 hours a month no matter who pings them.

## 7. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `401 sign in required` from `/dashboard/api/state` | no session cookie | `GET /dashboard` first and reuse the cookie |
| `403 invalid request origin or token` | origin ≠ `GONUTS_PUBLIC_BASE_URL`, or missing CSRF header | call the panel through its public base URL and send `X-Gonuts-Csrf` |
| *the client does not support the panel* | linked build stored no `panel` capability | re-pair with the full capability list |
| Client listed but offline | stale jar loaded before replacing it, or wrong `baseUrl` | restart the client; the jar cannot hot-reload |
| `hive folder is unavailable` | `hive.json` `directory` points at another machine | run `scripts/fixhive.py <instance>` |
| `Shared trading database is missing` | no `doughbay.db` next to the instance | restore a `sqlite3 .backup` snapshot |
| Resume answered `rejected` | client not in the server yet, or no local panel on 8765 | wait for `SCANNING`, then retry |
| Panel tab 502 / blank | mod's WebSocket dropped | restart the client; check `wsUrl` in `installation.json` |

## 8. Rules

- Never expose the panel to the internet: no tunnel, no Funnel, no port-forward. LAN or
  Tailscale only.
- Never commit or copy `state.json`, `panel.env`, `account.json`, or
  `installation.json` anywhere.
- Back up `panel.env` and the whole data directory (including `state.json` and
  `swarm.key`) before editing or upgrading.
- Do not kill a running Minecraft client without the operator's approval, and never
  paste `jcmd -l` output — it contains access tokens.
