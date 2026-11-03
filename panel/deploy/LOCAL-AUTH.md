# Local password sign-in: deployment notes

The panel accepts a local password (or PIN) in addition to Discord OAuth. The
operator-facing quickstart lives in [../README.md](../README.md#local-password-on-a-nas);
this file records what the mode does and how it is verified.

## Usage

```bash
# 1. Generate a hash (prints pbkdf2-sha256$<iterations>$<salt>$<key>, then exits)
./gonuts-panel -hash-password 'your password'
# or, from a checkout:
cd panel && ../.tools/go/bin/go run ./cmd/gonuts-panel -hash-password 'your password'

# 2. Configure and start
export GONUTS_PUBLIC_BASE_URL=http://192.168.1.20:8080
export GONUTS_COOKIE_SECURE=0
export GONUTS_LOCAL_PASSWORD_HASH='pbkdf2-sha256$600000$...$...'
export GONUTS_LOCAL_USER=owner
./gonuts-panel
```

- `GONUTS_LOCAL_PASSWORD_HASH` is preferred; `GONUTS_LOCAL_PASSWORD` is a
  plaintext fallback compared in constant time.
- `GONUTS_LOCAL_USER` defaults to `local` and names the account created on the
  first local sign-in.
- Discord credentials are optional when a local password is set, and the two
  modes can be enabled together. Startup fails if neither Discord nor a local
  password is configured and `GONUTS_DEV_LOGIN` is not `1`; the dev-login
  loopback guard is unchanged.
- `POST /auth/local` requires a same-origin request, is limited to 10 attempts
  per minute per client IP (429 JSON beyond that), and on success creates a
  normal 30-day session and redirects to `/dashboard`. A wrong password
  redirects (303) to `/dashboard?error=local`, which renders
  "Incorrect password."; the submitted password is never logged.
- `GET /auth/login` and `GET /auth/callback` answer 404 when Discord is not
  configured.

Plain HTTP protects nothing on the wire: use this mode on a trusted LAN or
behind an HTTPS reverse proxy.

## Tests

From `panel/`:

```bash
../.tools/go/bin/go test ./... -count=1
../.tools/go/bin/go vet ./...
../.tools/go/bin/gofmt -l .
```

Coverage added with the mode:

- `internal/auth/password_test.go`: round trip (fresh 16-byte salt, 32-byte
  key), wrong/empty password, tampered salt and key, default and bounded
  iteration counts, minimum password length, and a table of malformed
  encodings (unknown scheme, non-numeric/zero/negative/oversized iteration
  counts, wrong salt/key sizes, padded or invalid base64) that must all fail
  closed.
- `internal/config/config_test.go`: hash-only startup with no Discord, no
  Discord/no local/no dev login rejected, Discord-only still accepted, both
  configured accepted, plaintext fallback preserved byte-for-byte, custom
  local user, and the dev-login loopback guard.
- `internal/web/web_test.go`: local sign-in success (session, user row,
  dashboard shell), wrong and empty password redirect, cross-origin rejection,
  the 10/min limiter (429 JSON, per-IP buckets), plaintext fallback with
  hash precedence, 404 when unconfigured, and the sign-in page in all four
  modes (local only, Discord only, both, neither) plus the `?error=local`
  message.
