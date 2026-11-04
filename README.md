# GoNuts panel

Self-hosted dashboard for the doughbay trading clients: pairing, telemetry, a relay
of each client's own panel page, and pause/resume/snapshot commands.

- `panel/` — the Go service (single binary, state in `data/state.json`)
- `patches/` — the client-mod patches that add the panel link
- `docs/TUTORIAL.md` — install and operate guide
- releases — panel binaries (linux amd64/arm64, macOS arm64) and the mod jar

Runs on a LAN or a tailnet; never expose it to the internet.
