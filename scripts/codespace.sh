#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GONUTS_DISCORD_CLIENT_ID:?set GONUTS_DISCORD_CLIENT_ID}"
: "${GONUTS_DISCORD_CLIENT_SECRET:?set GONUTS_DISCORD_CLIENT_SECRET}"
export GONUTS_PUBLIC_BASE_URL="https://${CODESPACE_NAME}-8080.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"
export GONUTS_COOKIE_SECURE=1
export GONUTS_TRUST_PROXY=1
export GONUTS_DATA_DIR="${GONUTS_DATA_DIR:-$PWD/panel/data}"
cd panel
go test ./...
exec go run ./cmd/gonuts-panel
