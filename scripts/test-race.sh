#!/usr/bin/env sh
# Run the panel tests with the race detector.
#
# -race requires cgo and a C toolchain (gcc or clang), so run this on the
# Codespace or another Linux/macOS host. It is not available in the Windows
# development environment this repository is edited in.
#
#   ./scripts/test-race.sh
#   GO=../.tools/go/bin/go ./scripts/test-race.sh
set -eu
cd "$(dirname "$0")/../panel"
exec "${GO:-go}" test -race ./... -count=1
