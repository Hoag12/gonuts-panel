
## Release artifacts

The GitHub release contains:

- `doughbay-0.1.2-swarm+26.2.jar` — the patched mod (install one client first).
- `gonuts-panel-linux-arm64` — the panel for the ARM64 NAS (recommended).
- `gonuts-panel-linux-amd64` — the panel for x86_64 Linux.
- `gonuts-panel.jar` — optional executable launcher (Java 17+, Linux only) that
  extracts and runs the bundled arm64/amd64 panel binary. The native binary is
  smaller and preferred on the NAS.
- `gonuts-panel-source.tar.gz` — this repository's source at the release tag.
- `doughbay-source-0.1.2-selfhost.tar.gz` — the patched mod source tree.
- `relay-link.patch` — the mod changes as a patch against the public upstream.
- `SHA256SUMS.txt` — checksums for every asset.

Build them locally with `./scripts/build-release.sh` (set `GO`, `JAVAC`, and
`JAR` if they are not on `PATH`).
