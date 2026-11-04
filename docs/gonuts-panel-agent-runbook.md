# GoNuts Self-Hosted Panel - Agent Operating Instructions

Runbook for an AI agent that operates the self-hosted GoNuts panel, keeps the
Fabric mod linked, and brings the game up on another device. Written from the
working deployment on 2026-11-04. Substitute the placeholders before use.

Placeholders:

| Placeholder | Meaning |
|---|---|
| `<NAS_IP>` | LAN address of the NAS running the panel (e.g. 192.168.x.x) |
| `<NAS_USER>` | SSH user on the NAS |
| `<PANEL_DIR>` | Install directory on the NAS (contains binary, `panel.env`, `panel.log`, `data/`) |
| `<PROFILE_DIR>` | Launcher profile directory on a game device |
| `<PANEL_URL>` | `http://<NAS_IP>:8080` while the panel is LAN-only |

Current deployment facts: panel runs on Synology DSM 7.1.1 (armv7), systemd unit
`gonuts-panel`, no public tunnel, dashboard auth disabled for the LAN, two linked
installations (`Actub` id 2, `Thaohg` id 3).

## 1. Topology

```
Minecraft client (Fabric 26.2 + doughbay jar)
  |  RelayLink reads <PROFILE_DIR>/config/gonuts-panel-link.json once per connect
  v
Go relay  http://<NAS_IP>:8080
  /healthz                     liveness
  /dashboard                   web dashboard (session cookie, CSRF)
  /dashboard/api/state         dashboard JSON (needs session cookie)
  /dashboard/api/client/check  mod check-in (Bearer installation credential)
  /dashboard/ws/client         mod WebSocket (Bearer installation credential)
  /dashboard/panel/<id>/       relayed mod panel page, rewritten per request
  |
  v
data/state.json                installations, credentials (hashed), telemetry, sessions
```

Rules the agent must follow:

1. Never expose the panel publicly (no Funnel, tunnel, or port-forward) without
   explicit operator approval.
2. Never print or upload credentials, Minecraft access tokens, session cookies,
   or `data/state.json` contents.
3. `http://` is only valid for localhost and private LAN addresses; the mod
   rejects public HTTP origins.
4. Back up `panel.env` and `data/state.json` before changing them.
5. Do not kill Minecraft clients without approval; prefer the hot reload in
   section 8.

## 2. Panel lifecycle (on the NAS)

```sh
# status
systemctl is-enabled gonuts-panel
systemctl is-active gonuts-panel

# restart and verify
systemctl restart gonuts-panel
sleep 2
curl -s -o /dev/null -w '%{http_code}\n' http://<NAS_IP>:8080/healthz   # expect 200
tail -n 50 <PANEL_DIR>/panel.log

# DSM 7.1.1 does not support `enable --now`; run enable and start separately
systemctl enable gonuts-panel
systemctl start gonuts-panel
```

`panel.env` used by the LAN-only deployment:

```sh
GONUTS_ADDR=0.0.0.0:8080
GONUTS_PUBLIC_BASE_URL=http://<NAS_IP>:8080
GONUTS_DATA_DIR=<PANEL_DIR>/data
GONUTS_AUTH_DISABLED=1
GONUTS_ALLOW_UNAUTH_LAN=1
GONUTS_COOKIE_SECURE=0
GONUTS_TRUST_PROXY=0
GONUTS_LOCAL_USER=local
```

Notes:

- `GONUTS_AUTH_DISABLED` is loopback-only unless `GONUTS_ALLOW_UNAUTH_LAN=1` is
  also set. Only use both on a trusted LAN.
- To require a password instead, drop both disabled flags and set
  `GONUTS_LOCAL_PASSWORD_HASH` (PBKDF2) or the Discord OAuth variables.
- `GONUTS_PUBLIC_BASE_URL` must match the origin clients use; it feeds CSRF
  origin checks and the mod's WebSocket URL.

Backups before edits:

```sh
cd <PANEL_DIR>
cp panel.env panel.env.bak-$(date +%Y%m%d-%H%M%S)
cp data/state.json data/state.json.bak-$(date +%Y%m%d-%H%M%S)
```

## 3. Build the mod

From the mod worktree:

```sh
# Windows: the short TEMP avoids two known 8.3-path test failures
TEMP=C:\tmp TMP=C:\tmp ./gradlew :trader-fabric:build
```

Artifact: `trader-fabric/build/libs/doughbay-0.1.2-swarm+26.2.jar`.

The build output is locked while Minecraft runs. Close the game before copying,
or let a watcher copy it after both `javaw` processes exit.

## 4. Install the mod

1. Launcher: Modrinth App, Minecraft 26.2, Fabric loader, Fabric API.
2. Copy `doughbay-0.1.2-swarm+26.2.jar` into `<PROFILE_DIR>/mods/`.
3. Write `<PROFILE_DIR>/config/gonuts-panel-link.json`:

```json
{"baseUrl":"http://<NAS_IP>:8080"}
```

`baseUrl` is a bare origin: no path, query, or fragment. HTTPS is allowed for any
host; HTTP only for `localhost`, `127.0.0.1`, `::1`, `10.x`, `192.168.x`, and
`172.16-31.x`.

The mod reads this file once per connection attempt. The current jar reloads it
before every attempt, so a config change is picked up on the next retry without
a restart. Older jars read it once at startup and need a restart.

## 5. Pair a client

1. Open `<PANEL_URL>/dashboard` in a browser (no sign-in needed while auth is
   disabled; otherwise sign in first).
2. Choose "Link client" and copy the pairing code (valid five minutes).
3. In game: DoughBay dashboard screen, enter the code and a client label, press
   "Link with code".
4. The installation appears in `/dashboard/api/state` with `online: true` once
   the WebSocket handshake completes.

Each launcher profile stores its credential in
`<PROFILE_DIR>/gonuts-dashboard/installation.json`. Do not copy that file between
profiles: two clients sharing one installation credential get WebSocket close
code 4409 and stop reconnecting.

## 6. Open the game on another device

Requirements: the device can reach `<NAS_IP>:8080` (same LAN, or a private VPN
such as WireGuard/Tailscale; never a public tunnel without approval).

1. Install Modrinth App and a Fabric 26.2 profile with Fabric API.
2. Add the mod jar and write `config/gonuts-panel-link.json` as in section 4.
3. Launch and join with a Minecraft account that is not already online; the
   server rejects duplicate logins, and each concurrent client needs its own
   account.
4. Pair it with a new code from the dashboard. It becomes a new installation id.
5. The new installation has its own dashboard card and its own panel URL
   `/dashboard/panel/<new-id>/`.

The mod's split-mode scoping keeps each panel page on that client's account; the
dashboard "Hive" view aggregates all linked installations.

## 7. Verify sync

```sh
# panel alive
curl -s -o /dev/null -w '%{http_code}\n' http://<NAS_IP>:8080/healthz

# dashboard JSON (session cookie is created by the dashboard page)
curl -s -c /tmp/gonuts.jar -o /dev/null http://<NAS_IP>:8080/dashboard
curl -s -b /tmp/gonuts.jar http://<NAS_IP>:8080/dashboard/api/state
```

Healthy signs: each installation has `online: true`, fresh `lastSeen`, and
telemetry fields such as `bank`, `listed`, `slots`. The relayed panel page should
return 200 and contain `gonuts-csrf`:

```sh
curl -s -b /tmp/gonuts.jar -o /tmp/panel.html -w '%{http_code}\n' \
  http://<NAS_IP>:8080/dashboard/panel/<id>/
grep -c gonuts-csrf /tmp/panel.html    # expect 1
```

## 8. Recover a client that points at an old URL (no restart)

Symptom: the game is running and farming, but the dashboard shows it offline and
the device has no TCP connection to port 8080. The mod is still dialing a URL it
loaded earlier. This happens when the link config was changed while the game was
open (for example during a tunnel experiment).

Fastest fix: fully quit and relaunch the game.

No-restart fix for a live JVM that accepts the Attach API (JDK 9+):

```java
// LinkFix.java - load with: java -cp . Attach <pid> C:\tmp\gonuts-hotfix\linkfix.jar
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.nio.file.*;

public final class LinkFix {
    public static void agentmain(String args, Instrumentation inst) {
        try {
            Class<?> relay = null, client = null;
            for (Class<?> c : inst.getAllLoadedClasses()) {
                if (c.getName().equals("dev.doughbay.fabric.hosted.RelayLink")) relay = c;
                if (c.getName().equals("dev.doughbay.fabric.hosted.HostedDashboardClient")) client = c;
            }
            relay.getMethod("reload").invoke(null);
            Object instance = client.getField("INSTANCE").get(null);
            client.getMethod("reconnect").invoke(instance);
        } catch (Throwable t) {
            try { Files.writeString(Path.of("C:\\tmp\\gonuts-hotfix.log"), t.toString()); }
            catch (Throwable ignored) {}
        }
    }
}
```

```java
// Attach.java
import com.sun.tools.attach.VirtualMachine;
public final class Attach {
    public static void main(String[] a) throws Exception {
        VirtualMachine vm = VirtualMachine.attach(a[0]);
        try { vm.loadAgent(a[1]); } finally { vm.detach(); }
    }
}
```

Build the agent jar with `Agent-Class: LinkFix` in the manifest, then attach to
each Minecraft PID. Verify with `Get-NetTCPConnection -OwningProcess <pid>` on
Windows (expect an established connection to `<NAS_IP>:8080`).

Warning: `jcmd -l` prints full Java command lines, including Minecraft access
tokens. Never paste that output into logs, chats, or uploads.

## 9. Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| Dashboard `401 sign in required` on `/dashboard/api/state` | API needs a session cookie | Open `/dashboard` first and reuse the cookie |
| Mod offline, no TCP to 8080 | In-memory URL is stale | Restart, or hot reload from section 8 |
| Mod reports 401 / unlinks itself | Credential revoked or state rolled back | Pair a new code |
| WebSocket closes 4409 | Two clients share one installation credential | Remove the copied `installation.json`, pair one client again |
| Dashboard mutation returns 403 | Stale page/CSRF token after relay restart | Reload the dashboard page |
| Mod can't link over `http://` | Public host over plain HTTP is rejected | Use HTTPS, or a private LAN address |
| Panel health 200 but page blank | Assets requested from the wrong base URL | Check `GONUTS_PUBLIC_BASE_URL` matches the browser origin |
| Port 8080 bind error in `panel.log` | Old process still bound | Stop the duplicate, then restart the unit |

## 10. Security checklist

- Panel is LAN-only; Funnel and tunnels stay off unless the operator asks.
- No credentials, installation tokens, or Minecraft access tokens in logs or
  shared documents.
- Keep `data/state.json` (contains credential hashes and sessions) private.
- Back up `panel.env` and `data/state.json` before deployments.
- If the panel ever leaves the LAN, put it behind HTTPS and re-enable
  authentication first.
