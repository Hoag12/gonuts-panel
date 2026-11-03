#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GO="${GO:-go}"
JAVAC="${JAVAC:-javac}"
JAR="${JAR:-jar}"
if ! command -v "$JAR" >/dev/null 2>&1 && [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/jar" ]; then
  JAR="$JAVA_HOME/bin/jar"
fi
if ! command -v "$JAR" >/dev/null 2>&1; then
  JAR="$(dirname "$(command -v "$JAVAC")")/jar.exe"
fi

mkdir -p panel/dist dist
rm -rf panel/dist/launcher-classes panel/dist/jar
mkdir -p panel/dist/launcher-classes panel/dist/jar/bin

echo "Building panel binaries..."
(cd panel && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$GO" build -trimpath -ldflags="-s -w" -o dist/gonuts-panel-linux-arm64 ./cmd/gonuts-panel)
(cd panel && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" build -trimpath -ldflags="-s -w" -o dist/gonuts-panel-linux-amd64 ./cmd/gonuts-panel)

echo "Building optional executable panel JAR..."
"$JAVAC" --release 17 -d panel/dist/launcher-classes panel/deploy/launcher/Launcher.java
cp panel/dist/gonuts-panel-linux-arm64 panel/dist/jar/bin/
cp panel/dist/gonuts-panel-linux-amd64 panel/dist/jar/bin/
cp panel/deploy/launcher/README.txt panel/dist/jar/README.txt
"$JAR" --create --file panel/dist/gonuts-panel.jar --main-class Launcher \
  -C panel/dist/launcher-classes . -C panel/dist/jar .

echo "Building source archives..."
git archive --format=tar.gz --prefix=gonuts-panel-source/ -o dist/gonuts-panel-source.tar.gz HEAD
if [ -d mod ]; then
  tar -czf dist/doughbay-source-0.1.2-selfhost.tar.gz \
    --exclude=.git --exclude=build --exclude=.gradle --exclude=run --exclude=release --exclude=docs/assets \
    -C mod .
fi

if [ -f dist/doughbay-0.1.2-swarm+26.2.jar ]; then
  :
fi
cp patches/relay-link.patch dist/

echo "Writing checksums..."
rm -f dist/SHA256SUMS.txt
(cd dist && sha256sum * > SHA256SUMS.txt)

echo "Release artifacts:"
ls -lh dist panel/dist/gonuts-panel.jar
