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
  plaintext fallback compared in constant time. Both require at least four
  characters, and a hash that does not parse as
  `pbkdf2-sha256$<iterations>$<salt>$<key>` stops startup with a generic error
  (the value is never logged).
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
  iteration counts, minimum password length, `ValidPasswordHash` on a real hash
  and on every malformed encoding, and a table of malformed
  encodings (unknown scheme, non-numeric/zero/negative/oversized iteration
  counts, wrong salt/key sizes, padded or invalid base64) that must all fail
  closed.
- `internal/config/config_test.go`: hash-only startup with no Discord, no
  Discord/no local/no dev login rejected, Discord-only still accepted, both
  configured accepted, plaintext fallback preserved byte-for-byte, plaintext
  shorter than four characters rejected with four accepted, custom local user,
  and the dev-login loopback guard.
- `internal/web/web_test.go`: local sign-in success (session, user row,
  dashboard shell), wrong and empty password redirect, cross-origin rejection,
  the 10/min limiter (429 JSON, per-IP buckets), plaintext fallback with
  hash precedence, 404 when unconfigured, and the sign-in page in all four
  modes (local only, Discord only, both, neither) plus the `?error=local`
  message.

## Fix report: local-auth review findings (2026-11-03)

Two Important findings from the local password/PIN review, both fixed on
`selfhost-panel`.

1. **Short plaintext fallback accepted.** `GONUTS_LOCAL_PASSWORD` was accepted
   at any non-whitespace length, so a one-character password started the panel
   and signed in, even though the quickstart documents a four-character minimum
   (and `HashPassword` already enforced it). `internal/config/config.go` now
   rejects a non-whitespace plaintext value shorter than four bytes, matching
   `auth.MinPasswordLength` (the constant is duplicated as
   `minLocalPasswordLength` because `auth` already imports `config`). The value
   is still not trimmed: the length check and the fallback comparison both use
   the exact bytes. `TestLoadEnforcesPlaintextMinimumLength` asserts that
   `"abc"` fails while `"abcd"` loads with no Discord credentials.
2. **Malformed hash failed every login silently.** A typo in
   `GONUTS_LOCAL_PASSWORD_HASH` was only discovered when a login returned
   "Incorrect password." `auth.ValidPasswordHash` was added next to
   `VerifyPassword`; both now share `parsePasswordHash`, so validation is
   identical (scheme, iteration range, strict unpadded base64, 16-byte salt,
   32-byte key) but `ValidPasswordHash` derives no key. `cmd/gonuts-panel`
   checks it right after `config.Load` when a hash is configured and exits with
   `gonuts-panel: GONUTS_LOCAL_PASSWORD_HASH is malformed; regenerate it with
   -hash-password` (the value is not logged). `TestValidPasswordHash` covers a
   generated hash and every malformed encoding in the shared table.
3. **Shell-expandable README example.** The README assignment is now
   `GONUTS_LOCAL_PASSWORD_HASH='pbkdf2-sha256$600000$...$...'` so `$600000` and
   the `$` field separators cannot be expanded. `deploy/LOCAL-AUTH.md` already
   used single quotes and is unchanged there.

Verification from `panel/`:

```text
$ ../.tools/go/bin/go test ./... -count=1
?   	gonutspanel/cmd/gonuts-panel	[no test files]
?   	gonutspanel/cmd/mockclient	[no test files]
ok  	gonutspanel/internal/auth	1.839s
ok  	gonutspanel/internal/config	0.148s
ok  	gonutspanel/internal/panel	0.186s
ok  	gonutspanel/internal/relay	2.322s
ok  	gonutspanel/internal/store	0.980s
ok  	gonutspanel/internal/web	1.202s
ok  	gonutspanel/web	0.035s

$ ../.tools/go/bin/go vet ./...
(no output)

$ ../.tools/go/bin/gofmt -l .
(no output)
```

Manual startup checks: `GONUTS_LOCAL_PASSWORD=abc` exits with
`GONUTS_LOCAL_PASSWORD must be at least 4 characters`; a malformed
`GONUTS_LOCAL_PASSWORD_HASH` exits with the generic malformed-hash message
before the listener opens.
