# GoNuts Self-Hosted Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-hosted Go relay + dashboard that revives only the GoNuts bot panel, signs users in with Discord, and links the patched mod to it over the documented protocol.

**Architecture:** A single Go binary serves the dashboard, Discord OAuth, pairing/check endpoints, and a WebSocket relay. The patched mod connects outbound, sends telemetry, answers commands, and serves its own panel HTML through relayed panel operations. The browser receives cards over SSE and loads the mod's real panel under `/dashboard/panel/<id>/`.

**Tech Stack:** Go 1.27.3, `net/http`, `embed`, `crypto/*`, `encoding/json`, `github.com/gorilla/websocket v1.5.3`; static Linux ARM64 binary; Docker/alpine for Synology.

**Spec:** `docs/superpowers/specs/2026-11-03-gonuts-selfhosted-panel-design.md`

## Global Constraints

- Go toolchain lives at `.tools/go` (portable, not committed); invoke it as `../.tools/go/bin/go` from `panel/`.
- Exactly one external Go dependency: `github.com/gorilla/websocket v1.5.3`.
- `CGO_ENABLED=0`; the production target is `linux/arm64`.
- Protocol 1 from `upstream/docs/HOSTED-DASHBOARD-CONTRACT.md` is authoritative. Do not invent wire fields.
- Never log request bodies, pairing codes, credentials, cookies, OAuth codes, or tokens.
- All relay state is under `$GONUTS_DATA_DIR`; the state file is written atomically with mode `0600`.
- Browser mutations require a session, `X-Gonuts-Csrf`, and a matching `Origin`/`Referer`.
- The relayed panel HTML is the mod's `Pages.APP`; only URL/CSRF plumbing may change.
- The mod's `0.1.2-swarm+26.2` version, layout, and styles do not change. Only the link module, endpoint derivation, and the two host/Swarm text strings change.
- Do not touch the NAS until the user approves deployment.
- Every task ends with `go test ./...` passing, a focused test for the new behavior, and a commit.

## File Structure

```
gonut/
  panel/
    go.mod, go.sum
    cmd/gonuts-panel/main.go
    cmd/mockclient/main.go
    internal/config/config.go, config_test.go
    internal/store/store.go, store_test.go
    internal/auth/auth.go, discord.go, auth_test.go
    internal/relay/protocol.go, hub.go, relay_test.go
    internal/panel/rewrite.go, rewrite_test.go
    internal/web/server.go, auth.go, api.go, panel.go, sse.go, web_test.go
    web/dashboard.html, login.html, dashboard.css, dashboard.js
    web/assets/mascot_v2.png, Monocraft.ttf, logo.png
    Dockerfile, docker-compose.yml, .env.example, README.md
  docs/superpowers/plans/2026-11-03-gonuts-selfhosted-panel.md
```

The mod patch is applied in a temporary Git worktree at `mod/` created from `upstream/`; the patch is exported to `mod/relay-link.patch` and the JAR to `dist/`.

---

### Task 1: Go scaffold, config, health endpoint

**Files:**
- Create: `panel/go.mod`
- Create: `panel/cmd/gonuts-panel/main.go`
- Create: `panel/internal/config/config.go`
- Test: `panel/internal/config/config_test.go`

**Interfaces:**
- Produces: `config.Config` and `config.Load() (Config, error)`, used by `main`, `web`, `relay`, `auth`.
- Produces: `GET /healthz` returning `{"ok":true}`.

- [ ] **Step 1: Write the failing config test**

```go
package config

import "testing"

func TestLoadDefaultsAndNormalizes(t *testing.T) {
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "https://panel.example.com/")
	t.Setenv("GONUTS_DEV_LOGIN", "1")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicBaseURL != "https://panel.example.com" {
		t.Fatalf("base=%q", cfg.PublicBaseURL)
	}
	if !cfg.DevLogin || cfg.Addr != ":8080" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadRejectsBadBaseURL(t *testing.T) {
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "https://panel.example.com/path")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for path in base URL")
	}
}
```

- [ ] **Step 2: Run it and verify failure**

Run: `cd panel && ../.tools/go/bin/go test ./internal/config -run TestLoad -v`
Expected: FAIL because package/function does not exist.

- [ ] **Step 3: Implement config**

```go
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr                string
	PublicBaseURL       string
	DataDir             string
	DiscordClientID     string
	DiscordClientSecret string
	AllowedDiscordIDs   map[string]bool
	TrustProxy          bool
	DevLogin            bool
	CookieSecure        bool
	PanelCacheBytes     int64
	OAuthAuthorizeURL   string
	DiscordAPIBase      string
}

func Load() (Config, error) {
	base := strings.TrimRight(env("GONUTS_PUBLIC_BASE_URL", "http://localhost:8080"), "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Config{}, fmt.Errorf("GONUTS_PUBLIC_BASE_URL must be an absolute http(s) URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Config{}, fmt.Errorf("GONUTS_PUBLIC_BASE_URL must use http or https")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return Config{}, fmt.Errorf("GONUTS_PUBLIC_BASE_URL must be an origin without a path")
	}
	cfg := Config{
		Addr:                env("GONUTS_ADDR", ":8080"),
		PublicBaseURL:       base,
		DataDir:             env("GONUTS_DATA_DIR", "./data"),
		DiscordClientID:     os.Getenv("GONUTS_DISCORD_CLIENT_ID"),
		DiscordClientSecret: os.Getenv("GONUTS_DISCORD_CLIENT_SECRET"),
		AllowedDiscordIDs:   map[string]bool{},
		TrustProxy:          boolEnv("GONUTS_TRUST_PROXY", false),
		DevLogin:            boolEnv("GONUTS_DEV_LOGIN", false),
		PanelCacheBytes:     16 << 20,
		OAuthAuthorizeURL:   env("GONUTS_OAUTH_AUTHORIZE_URL", "https://discord.com/oauth2/authorize"),
		DiscordAPIBase:      env("GONUTS_DISCORD_API_BASE", "https://discord.com/api"),
	}
	for _, id := range strings.Split(os.Getenv("GONUTS_ALLOWED_DISCORD_IDS"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			cfg.AllowedDiscordIDs[id] = true
		}
	}
	if n, err := strconv.ParseInt(os.Getenv("GONUTS_PANEL_CACHE_BYTES"), 10, 64); err == nil && n > 0 {
		cfg.PanelCacheBytes = n
	}
	cfg.CookieSecure = boolEnv("GONUTS_COOKIE_SECURE", strings.HasPrefix(base, "https://"))
	if !cfg.DevLogin && (cfg.DiscordClientID == "" || cfg.DiscordClientSecret == "") {
		return Config{}, fmt.Errorf("Discord client id/secret are required unless GONUTS_DEV_LOGIN=1")
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func boolEnv(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
```

- [ ] **Step 4: Create module and main with health**

Run: `cd panel && ../.tools/go/bin/go mod init gonutspanel && ../.tools/go/bin/go get github.com/gorilla/websocket@v1.5.3`

```go
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"gonutspanel/internal/config"
)

func main() {
	flag.Parse()
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	srv := &http.Server{Addr: cfg.Addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("gonuts-panel listening on %s", cfg.Addr)
	log.Fatal(srv.ListenAndServe())
}
```

- [ ] **Step 5: Run tests and smoke the health route**

Run: `cd panel && ../.tools/go/bin/go test ./... && GONUTS_DEV_LOGIN=1 ../.tools/go/bin/go run ./cmd/gonuts-panel &`
Then: `curl -sS http://localhost:8080/healthz`
Expected: `{"ok":true}`; stop the server.

- [ ] **Step 6: Commit**

```bash
git add panel/go.mod panel/go.sum panel/cmd/gonuts-panel panel/internal/config
git commit -m "feat(panel): scaffold Go server and config"
```

---

### Task 2: Persistent store and pairing-code lifecycle

**Files:**
- Create: `panel/internal/store/store.go`
- Test: `panel/internal/store/store_test.go`

**Interfaces:**
- Produces: `store.User`, `store.Session`, `store.Code`, `store.Installation`,
  `store.Telemetry`, `store.Command`, `store.State`, `store.Store`.
- Produces: `store.Open(dir)`, `CreateSession`, `Session`, `DeleteSession`,
  `UpsertUser`, `User`, `CreateCode`,
  `RedeemCode(code, name, build, hive string, caps []string, now time.Time) (*Installation, string, error)`,
  `Installation`, `InstallationByCredential`, `InstallationsFor`, `SetOnline`,
  `SetTelemetry`, `RenameInstallation`, `DeleteInstallation`, `AddCommand`,
  `UpdateCommand`, `LastCommand`, `State`, `SaveNow`, `Close`.
- Produces errors: `ErrNotFound`, `ErrUsed`, `ErrExpired`, `ErrAttempts`.
- Produces: `NormalizeCode`, `HashToken`, `RandomToken`, `CloneTelemetry`.

**Data shapes** (JSON on disk and API):

```go
type User struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	GlobalName string `json:"globalName,omitempty"`
	Avatar     string `json:"avatar,omitempty"`
	CreatedAt  int64  `json:"createdAt"`
}
type Session struct {
	DiscordID string `json:"discordId"`
	CSRF      string `json:"csrf"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
}
type Code struct {
	DiscordID string `json:"discordId"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
	Attempts  int    `json:"attempts"`
	UsedAt    int64  `json:"usedAt,omitempty"`
}
type Interval struct {
	H1     *int64 `json:"h1,omitempty"`
	H24    *int64 `json:"h24,omitempty"`
	Source string `json:"source,omitempty"`
}
type Swarm struct {
	Enabled        bool `json:"enabled"`
	GuidanceEnabled bool `json:"guidanceEnabled"`
	Eligible       bool `json:"eligible"`
}
type Controls struct {
	Pause    bool `json:"pause"`
	Resume   bool `json:"resume"`
	Snapshot bool `json:"snapshot"`
}
type Telemetry struct {
	At           int64     `json:"at"`
	State        string    `json:"state"`
	Detail       string    `json:"detail"`
	Account      string    `json:"account"`
	Listed       int64     `json:"listed"`
	Slots        int64     `json:"slots"`
	Bank         *int64    `json:"bank,omitempty"`
	Trades       int64     `json:"trades"`
	Profit       *Interval `json:"profit,omitempty"`
	Sales        *Interval `json:"sales,omitempty"`
	Purchases    *Interval `json:"purchases,omitempty"`
	Listings     *Interval `json:"listings,omitempty"`
	Reprices     *Interval `json:"reprices,omitempty"`
	Build        string    `json:"build"`
	LastAction   string    `json:"lastAction"`
	LastActionAt int64     `json:"lastActionAt"`
	MascotFace   string    `json:"mascotFace"`
	Swarm        *Swarm    `json:"swarm,omitempty"`
	Controls     *Controls `json:"controls,omitempty"`
}
type Installation struct {
	ID             int64    `json:"id"`
	DiscordID      string   `json:"discordId"`
	Name           string   `json:"name"`
	Build          string   `json:"build"`
	Hive           string   `json:"hive"`
	Capabilities   []string `json:"capabilities"`
	CredentialHash string   `json:"credentialHash"`
	CreatedAt      int64    `json:"createdAt"`
	LastSeen       int64    `json:"lastSeen"`
	Telemetry      *Telemetry `json:"telemetry,omitempty"`
	Online         bool     `json:"online"`
}
type Command struct {
	ID             string `json:"id"`
	InstallationID int64  `json:"installationId"`
	DiscordID      string `json:"discordId"`
	Command        string `json:"command"`
	CreatedAt      int64  `json:"createdAt"`
	ExpiresAt      int64  `json:"expiresAt"`
	State          string `json:"state"`
	Reason         string `json:"reason,omitempty"`
}
type State struct {
	Users              map[string]*User         `json:"users"`
	Sessions           map[string]*Session      `json:"sessions"`
	Codes              map[string]*Code         `json:"codes"`
	Installations      map[string]*Installation `json:"installations"`
	Commands           map[string]*Command      `json:"commands"`
	NextInstallationID int64                    `json:"nextInstallationId"`
}
```

- [ ] **Step 1: Write failing store tests**

```go
package store

import (
	"testing"
	"time"
)

func TestPairingCodeIsOneUseAndHashed(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	defer s.Close()
	now := time.Now()
	code, exp, err := s.CreateCode("u1", now)
	if err != nil { t.Fatal(err) }
	if exp <= now.UnixMilli() { t.Fatal("code should expire in the future") }
	inst, cred, err := s.RedeemCode(code, "Bot", "0.1.2-swarm+26.2", "hive", []string{"pause"}, now)
	if err != nil { t.Fatal(err) }
	if inst.ID == 0 || len(cred) < 10 || inst.CredentialHash == cred { t.Fatalf("bad install/credential: %+v %q", inst, cred) }
	if _, _, err := s.RedeemCode(code, "Bot", "b", "", nil, now); err != ErrUsed {
		t.Fatalf("second redeem err=%v", err)
	}
}

func TestStateSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	now := time.Now()
	if _, _, err := s.CreateSession("u1", now); err != nil { t.Fatal(err) }
	if err := s.SaveNow(); err != nil { t.Fatal(err) }
	s.Close()
	s2, err := Open(dir)
	if err != nil { t.Fatal(err) }
	defer s2.Close()
	if len(s2.State().Sessions) != 1 { t.Fatal("session lost") }
}

func TestCorruptStateIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{"), 0600); err != nil { t.Fatal(err) }
	if _, err := Open(dir); err == nil { t.Fatal("expected corrupt state error") }
}
```

- [ ] **Step 2: Run and verify failure**

Run: `cd panel && ../.tools/go/bin/go test ./internal/store -v`
Expected: FAIL (package missing).

- [ ] **Step 3: Implement store**

Implement exactly the interfaces above. Key rules:

```go
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil { return nil, err }
	path := filepath.Join(dir, "state.json")
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.data = newState()
		return s, s.saveLocked()
	}
	if err != nil { return nil, err }
	if err := json.Unmarshal(b, &s.data); err != nil { return nil, fmt.Errorf("state.json is corrupt: %w", err) }
	s.data.ensure()
	return s, nil
}
```

- `saveLocked`: `json.MarshalIndent`, write temp with `os.CreateTemp(dir, ".state-*.tmp")`, `Chmod(0600)`, `Write`, `Sync`, `Close`, `os.Rename`, and best-effort directory sync.
- `CreateCode`: delete the user's previous code, generate 8 chars from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, store `hashToken(normalized)` with `expiresAt=now+5m`, return `ABCD-EFGH`.
- `RedeemCode(code, name, build, hive string, caps []string, now time.Time)`: normalize, hash, look up; return `ErrNotFound`; if `UsedAt>0` return `ErrUsed`; if expired delete+`ErrExpired`; increment attempts, if `>5` delete+`ErrAttempts`; mark used; generate credential `gni1_`+base64url(32 bytes); create installation with sequential ID; save; return copy and credential.
- `InstallationByCredential(hash string) (*Installation, bool)` looks up the hashed credential.
- `LastCommand(id int64) *Command` returns a copy of the newest command for an installation.
- `State() State` returns a copy for tests and diagnostics (never used in request paths).
- `NormalizeCode`: upper-case, remove `-` and spaces, map `0→O`, `1/I→L`; require 8 chars from `[A-Z2-9]`.
- `RandomToken(n)`: crypto/rand, base64.RawURLEncoding.
- `HashToken`: hex sha256.
- `CloneTelemetry`: deep copy nested intervals/swarm/controls.
- All read methods return copies; never expose internal pointers.
- `SetTelemetry` marks dirty; `SaveNow` persists. `SetOnline` persists immediately.
- `Open` prunes expired sessions, codes, commands older than 7 days.

- [ ] **Step 4: Run tests**

Run: `cd panel && ../.tools/go/bin/go test ./internal/store -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add panel/internal/store
git commit -m "feat(panel): persistent state and pairing codes"
```

---

### Task 3: Sessions, CSRF, origin checks, Discord OAuth, dev login

**Files:**
- Create: `panel/internal/auth/auth.go`
- Create: `panel/internal/auth/discord.go`
- Test: `panel/internal/auth/auth_test.go`

**Interfaces:**
- Produces: `auth.RandomToken`, `auth.HashToken`, `auth.Equal`,
  `auth.NewVerifier`, `auth.Challenge`, `auth.VerifyPKCE`.
- Produces: `auth.CookieName`, `auth.SetSessionCookie`, `auth.ClearSessionCookie`,
  `auth.CookieToken`, `auth.OriginAllowed`, `auth.CSRFHeader`.
- Produces: `auth.Discord`, `auth.DiscordUser`, `auth.NewDiscord(cfg)`.
- Produces: `Discord.AuthorizeURLFor(state, challenge)`, `Exchange(ctx, code, verifier)`,
  `Me(ctx, accessToken)`.

- [ ] **Step 1: Write failing auth tests**

```go
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPKCE(t *testing.T) {
	v, err := NewVerifier()
	if err != nil { t.Fatal(err) }
	if len(v) < 43 || !VerifyPKCE(v, Challenge(v)) { t.Fatal("bad pkce") }
	if VerifyPKCE(v+"x", Challenge(v)) { t.Fatal("verifier mismatch accepted") }
}

func TestOriginAllowed(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/dashboard", nil)
	r.Header.Set("Origin", "https://panel.example.com")
	if !OriginAllowed(r, "https://panel.example.com") { t.Fatal("same origin rejected") }
	r.Header.Set("Origin", "https://evil.example")
	if OriginAllowed(r, "https://panel.example.com") { t.Fatal("cross origin accepted") }
}

func TestDiscordExchangeAndMe(t *testing.T) {
	var tokenBody map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			_ = json.NewDecoder(r.Body).Decode(&tokenBody)
			json.NewEncoder(w).Encode(map[string]any{"access_token": "tok"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" { t.Errorf("bad auth header") }
		json.NewEncoder(w).Encode(map[string]any{"id": "42", "username": "tester", "global_name": "Test"})
	}))
	defer ts.Close()
	d := &Discord{ClientID: "id", ClientSecret: "sec", RedirectURI: "http://localhost/auth/callback",
		AuthorizeURL: ts.URL + "/oauth2/authorize", TokenURL: ts.URL + "/oauth2/token",
		UserURL: ts.URL + "/users/@me", HTTP: ts.Client()}
	u, err := d.Exchange(context.Background(), "code", "verifier")
	if err != nil { t.Fatal(err) }
	if u.ID != "42" || u.Username != "tester" { t.Fatalf("user=%+v", u) }
	if tokenBody["code"] != "code" || tokenBody["code_verifier"] != "verifier" { t.Fatalf("token body=%v", tokenBody) }
}
```

- [ ] **Step 2: Run and verify failure**

Run: `cd panel && ../.tools/go/bin/go test ./internal/auth -v`
Expected: FAIL (package missing).

- [ ] **Step 3: Implement auth.go and discord.go**

`auth.go`:

```go
const (
	CookieName  = "gonuts_session"
	CSRFHeader  = "X-Gonuts-Csrf"
	OAuthCookie = "gonuts_oauth"
)

func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil { return "", err }
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func NewVerifier() (string, error) { return RandomToken(32) }
func Challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func VerifyPKCE(v, c string) bool { return Equal(Challenge(v), c) }

func CookieToken(r *http.Request) string {
	c, err := r.Cookie(CookieName); if err != nil { return "" }
	return c.Value
}
func SetSessionCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 30 * 24 * 60 * 60})
}
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
func SetOAuthCookie(w http.ResponseWriter, state string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: OAuthCookie, Value: state, Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 600})
}
func ClearOAuthCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: OAuthCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
func OriginAllowed(r *http.Request, base string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" { return false }
	u, err := url.Parse(origin); if err != nil || u.Scheme == "" || u.Host == "" { return false }
	b, err := url.Parse(base); if err != nil { return false }
	return strings.EqualFold(u.Scheme, b.Scheme) && strings.EqualFold(u.Host, b.Host)
}
```

`discord.go`:

```go
type DiscordUser struct {
	ID, Username, GlobalName, Avatar string
}
type Discord struct {
	ClientID, ClientSecret, RedirectURI string
	AuthorizeURL, TokenURL, UserURL     string
	HTTP                                *http.Client
}
func (d *Discord) AuthorizeURLFor(state, challenge string) string {
	q := url.Values{
		"client_id": {d.ClientID}, "redirect_uri": {d.RedirectURI},
		"response_type": {"code"}, "scope": {"identify"},
		"state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	return d.AuthorizeURL + "?" + q.Encode()
}
func (d *Discord) Exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{"client_id": {d.ClientID}, "client_secret": {d.ClientSecret},
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {d.RedirectURI}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(ctx, "POST", d.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := d.HTTP.Do(req); if err != nil { return "", err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return "", fmt.Errorf("discord token exchange: %s", resp.Status) }
	var out struct{ AccessToken string `json:"access_token"` }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil { return "", err }
	if out.AccessToken == "" { return "", fmt.Errorf("empty access token") }
	return out.AccessToken, nil
}
func (d *Discord) Me(ctx context.Context, token string) (DiscordUser, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", d.UserURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := d.HTTP.Do(req); if err != nil { return DiscordUser{}, err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return DiscordUser{}, fmt.Errorf("discord user: %s", resp.Status) }
	var raw struct{ ID, Username, GlobalName, Avatar string }
	// JSON keys are id, username, global_name, avatar.
	var m map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil { return DiscordUser{}, err }
	raw.ID, _ = m["id"].(string); raw.Username, _ = m["username"].(string)
	raw.GlobalName, _ = m["global_name"].(string); raw.Avatar, _ = m["avatar"].(string)
	if raw.ID == "" { return DiscordUser{}, fmt.Errorf("discord user id missing") }
	return DiscordUser{...}, nil
}
```

- [ ] **Step 4: Run tests**

Run: `cd panel && ../.tools/go/bin/go test ./internal/auth -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add panel/internal/auth
git commit -m "feat(panel): sessions, csrf, and Discord OAuth"
```

---

### Task 4: Telemetry parsing, pairing and check endpoints

**Files:**
- Create: `panel/internal/relay/protocol.go`
- Create: `panel/internal/web/server.go`
- Create: `panel/internal/web/auth.go`
- Create: `panel/internal/web/api.go`
- Test: `panel/internal/relay/relay_test.go` (protocol part), `panel/internal/web/web_test.go` (pairing part)

**Interfaces:**
- Produces: `relay.ParseTelemetry(raw []byte) (*store.Telemetry, error)`.
- Produces: `relay.ValidName`, `relay.ValidBuild`, `relay.ValidHive`, `relay.ValidCaps`.
- Produces: `relay.PairResponse(base string, id int64, credential, name string) map[string]any`.
- Produces: `web.Server` with `Handler() http.Handler`.

- [ ] **Step 1: Write failing protocol tests**

```go
func TestParseTelemetryClampsAndRefusesSecrets(t *testing.T) {
	j := []byte(`{"type":"telemetry","at":1,"state":"SCANNING","account":"Acc","bank":99999999999999999,
	  "listed":-5,"slots":18,"trades":3,"profit":{"h1":10,"h24":20,"source":"booked"},
	  "mascotFace":"WATCH","swarm":{"enabled":false},"detail":"ok"}`)
	tel, err := ParseTelemetry(j)
	if err != nil { t.Fatal(err) }
	if tel.Listed != 0 || tel.Bank == nil || *tel.Bank != 1000000000000 || tel.State != "SCANNING" { t.Fatalf("%+v", tel) }
	bad := []byte(`{"type":"telemetry","detail":"token gni1_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"}`)
	if _, err := ParseTelemetry(bad); err == nil { t.Fatal("credential-looking detail accepted") }
}

func TestPairResponseUsesConfiguredOrigin(t *testing.T) {
	m := PairResponse("https://panel.example.com", 12, "gni1_x", "Laptop")
	if m["wsUrl"] != "wss://panel.example.com/dashboard/ws/client" ||
		m["checkUrl"] != "https://panel.example.com/dashboard/api/client/check" {
		t.Fatalf("%+v", m)
	}
	local := PairResponse("http://localhost:8080", 13, "gni1_y", "Local")
	if local["wsUrl"] != "ws://localhost:8080/dashboard/ws/client" {
		t.Fatalf("local wsUrl=%v", local["wsUrl"])
	}
}
```

- [ ] **Step 2: Implement protocol parsing**

Parse into `map[string]json.RawMessage`, then:

- Reject frames > 32768 bytes.
- `state` must be one of `SCANNING BID_DESK PREPARING_LIST LISTING MONITORING COOLDOWN PAUSED STOPPED IDLE BUYING REPRICING RECOVERING EVADING`; else `UNKNOWN`.
- Strings: `account` ≤48, `detail`/`lastAction` ≤160, `build` ≤60, `mascotFace` ≤16.
- Reject `detail`/`lastAction`/`account` containing `C:\`, `/home/`, `/Users/`, `gni1_`, `dbay_`, `Bearer `, or a 40+ base64 run.
- `listed`, `slots`, `trades` clamp 0..1e6.
- `bank` clamp ±1e12; omit if missing or absent.
- `profit`/`sales`/`purchases`/`listings`/`reprices`: each object with optional `h1`, `h24` clamped to ±1e12 for money and 0..1e6 for counts; `profit.source` ≤16.
- `swarm` and `controls` booleans.
- Unknown fields ignored.

Also implement `NormalizeCode` in `store` and `PairResponse` as above.

- [ ] **Step 3: Implement web server shell, session middleware, redeem and check**

`web.Server`:

```go
// Relay is implemented by *relay.Hub and by test fakes.
type Relay interface {
	Online(id int64) bool
	SendCommand(id int64, command string) (string, error)
	PanelRequest(ctx context.Context, id int64, frame map[string]any) (*relay.PanelResult, error)
	CloseInstallation(id int64, code int, reason string)
	Updates() <-chan struct{}
	ServeWS(w http.ResponseWriter, r *http.Request)
}
type Server struct {
	Cfg     config.Config
	Store   *store.Store
	Hub     Relay
	Discord    *auth.Discord
	States     *oauthStates
	Limiter    *limiter
	SSE        *sseHub
	PanelCache *panelCache
}
func New(cfg config.Config, st *store.Store, hub Relay, d *auth.Discord) *Server {
	if hub == nil { hub = noopRelay{} }
	return &Server{Cfg: cfg, Store: st, Hub: hub, Discord: d,
		States: &oauthStates{m: map[string]oauthState{}},
		Limiter: newLimiter(120, 120), SSE: newSSEHub(5),
		PanelCache: newPanelCache(cfg.PanelCacheBytes)}
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", pageRedirect("/dashboard"))
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /dashboard", s.dashboardPage)
	mux.HandleFunc("GET /auth/login", s.authLogin)
	mux.HandleFunc("GET /auth/callback", s.authCallback)
	mux.HandleFunc("POST /auth/logout", s.authLogout)
	mux.HandleFunc("GET /auth/dev", s.authDev)
	mux.HandleFunc("GET /dashboard/api/state", s.apiState)
	mux.HandleFunc("POST /dashboard/api/pair/code", s.apiPairCode)
	mux.HandleFunc("POST /dashboard/api/installations/{id}/command", s.apiCommand)
	mux.HandleFunc("POST /dashboard/api/installations/{id}/rename", s.apiRename)
	mux.HandleFunc("DELETE /dashboard/api/installations/{id}", s.apiUnlink)
	mux.HandleFunc("GET /dashboard/events", s.sse)
	mux.HandleFunc("POST /dashboard/api/pair/redeem", s.apiRedeem)
	mux.HandleFunc("POST /dashboard/api/client/check", s.apiCheck)
	mux.HandleFunc("GET /dashboard/ws/client", s.Hub.ServeWS)
	mux.HandleFunc("GET /dashboard/panel/{id}/{$}", s.panelPage)
	mux.HandleFunc("GET /dashboard/panel/{id}/{path...}", s.panelGet)
	mux.HandleFunc("POST /dashboard/panel/{id}/{path...}", s.panelPost)
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(webassets.Assets))))
	return s.middleware(mux)
}
```

`middleware` sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, a default dashboard CSP, and recovers panics.
The panel handlers override CSP with the panel CSP. Rate-limit checks live in
each handler (Task 8, Step 0).

`New` replaces a nil `Relay` with an offline no-op so auth/pairing tests can
omit the hub:

```go
type noopRelay struct{}
func (noopRelay) Online(int64) bool { return false }
func (noopRelay) SendCommand(int64, string) (string, error) { return "", relay.ErrOffline }
func (noopRelay) PanelRequest(context.Context, int64, map[string]any) (*relay.PanelResult, error) {
	return nil, relay.ErrOffline
}
func (noopRelay) CloseInstallation(int64, int, string) {}
func (noopRelay) Updates() <-chan struct{} {
	ch := make(chan struct{}); close(ch); return ch
}
func (noopRelay) ServeWS(http.ResponseWriter, *http.Request) {}
```

Task 4 also creates the small skeleton types used by `New`: `oauthStates`
(`map[string]oauthState` guarded by a mutex), `limiter` (Task 8 Step 0 defines
the algorithm), `sseHub` (Task 8 Step 2 defines the methods), and `panelCache`
(Task 7 Step 3 defines the methods). Create the files with the structs in this
task so every intermediate `go test ./...` compiles; later tasks add the
handlers and tests that exercise them.

Session helper:

```go
func (s *Server) session(r *http.Request) (*store.Session, *store.User, bool) {
	tok := auth.CookieToken(r)
	sess, ok := s.Store.Session(tok, time.Now())
	if !ok { return nil, nil, false }
	user, ok := s.Store.User(sess.DiscordID)
	if !ok { return nil, nil, false }
	return sess, user, true
}
func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) (*store.Session, *store.User, bool) {
	sess, user, ok := s.session(r)
	if !ok { writeJSON(w, 401, map[string]any{"message": "sign in required", "status": 401}); return nil, nil, false }
	return sess, user, true
}
func (s *Server) requireMutation(w http.ResponseWriter, r *http.Request) (*store.Session, *store.User, bool) {
	sess, user, ok := s.requireSession(w, r); if !ok { return nil, nil, false }
	if !auth.Equal(r.Header.Get(auth.CSRFHeader), sess.CSRF) || !auth.OriginAllowed(r, s.Cfg.PublicBaseURL) {
		writeJSON(w, 403, map[string]any{"message": "invalid request origin or token", "status": 403})
		return nil, nil, false
	}
	return sess, user, true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func pageRedirect(to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, to, http.StatusFound) }
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) }
func (s *Server) clientIP(r *http.Request) string {
	if s.Cfg.TrustProxy {
		if x := r.Header.Get("X-Forwarded-For"); x != "" {
			return strings.TrimSpace(strings.Split(x, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil { return r.RemoteAddr }
	return host
}
```

`apiRedeem`:

- `http.MaxBytesReader(w, r.Body, 32768)`.
- Decode JSON with fields `code, protocols []int, name, build, hive, capabilities []string`.
- Require protocols contains 1; validate name/build/hive/caps; call `Store.RedeemCode`.
- On success `writeJSON(w, 201, relay.PairResponse(...))`.
- Map `ErrNotFound` 404, `ErrUsed` 409, `ErrExpired` 410, `ErrAttempts` 429.
- Never log body/code.

`apiCheck`:

- Bearer parse; hash; `Store.InstallationByCredential(hash)`.
- 200 `{"ok":true,"installationId":id,"name":name,"protocol":1}` or 401.

- [ ] **Step 4: Write pairing test**

```go
func TestPairingRedeemAndCheck(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	defer st.Close()
	token, csrf, _ := st.CreateSession("u1", time.Now())
	s := New(config.Config{PublicBaseURL: "https://panel.example.com"}, st, nil, nil)

	mutate := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		req.Header.Set("X-Gonuts-Csrf", csrf)
		req.Header.Set("Origin", "https://panel.example.com")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	rec := mutate("/dashboard/api/pair/code", "")
	if rec.Code != 200 { t.Fatalf("code status=%d body=%s", rec.Code, rec.Body) }
	var pc struct{ Code string `json:"code"` }
	if err := json.Unmarshal(rec.Body.Bytes(), &pc); err != nil || pc.Code == "" { t.Fatalf("code=%+v err=%v", pc, err) }

	redeemBody := `{"code":"` + pc.Code + `","protocols":[1],"name":"Bot","build":"b","hive":"","capabilities":["panel"]}`
	req := httptest.NewRequest("POST", "/dashboard/api/pair/redeem", strings.NewReader(redeemBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 201 { t.Fatalf("redeem status=%d body=%s", rec.Code, rec.Body) }
	var pair struct {
		InstallationID int64  `json:"installationId"`
		Credential     string `json:"credential"`
		WSURL          string `json:"wsUrl"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pair); err != nil { t.Fatal(err) }
	if pair.InstallationID == 0 || pair.Credential == "" || pair.WSURL != "wss://panel.example.com/dashboard/ws/client" {
		t.Fatalf("pair=%+v", pair)
	}

	req = httptest.NewRequest("POST", "/dashboard/api/pair/redeem", strings.NewReader(redeemBody))
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 409 { t.Fatalf("second redeem status=%d", rec.Code) }

	req = httptest.NewRequest("POST", "/dashboard/api/client/check", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+pair.Credential)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("check status=%d body=%s", rec.Code, rec.Body)
	}
}
```

- [ ] **Step 5: Run tests**

Run: `cd panel && ../.tools/go/bin/go test ./internal/relay ./internal/web -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add panel/internal/relay/protocol.go panel/internal/web
git commit -m "feat(panel): pairing, check, and telemetry parsing"
```

---

### Task 5: WebSocket hub — handshake, heartbeat, telemetry, presence

**Files:**
- Create: `panel/internal/relay/hub.go`
- Test: `panel/internal/relay/relay_test.go` (extend)

**Interfaces:**
- Produces: `relay.Hub`, `relay.NewHub(st, opts)`, `Hub.ServeWS`,
  `Hub.Online`, `Hub.CloseInstallation`, `Hub.Updates`, `Hub.Start`, `Hub.Stop`.
- Produces: `relay.ErrOffline`, `ErrBusy`, `ErrTimeout`, `ErrNoPanel`.
- Produces: `relay.Welcome(id)`.
- `Options{HeartbeatSeconds int; TelemetryMinInterval time.Duration; MaxMessageBytes int; PanelTimeout time.Duration; MaxPanelInFlight int}`.
- `relay.NewHub` fills zero `Options` with: heartbeat 20s, telemetry
  interval 1s, max message 32768, panel timeout 15s, max panel in-flight 8.

- [ ] **Step 1: Write failing handshake test**

```go
func TestWSHandshakeTelemetryAndPresence(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	h := NewHub(st, Options{HeartbeatSeconds: 20, MaxMessageBytes: 32768, MaxPanelInFlight: 8})
	go h.Start(context.Background()); defer h.Stop()
	ts := httptest.NewServer(http.HandlerFunc(h.ServeWS)); defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	// Pair a credential directly through store.
	code, _, _ := st.CreateCode("u1", time.Now())
	inst, cred, _ := st.RedeemCode(code, "Bot", "0.1.2", "", []string{"panel"}, time.Now())
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?x=1", http.Header{"Authorization": {"Bearer " + cred}})
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	conn.WriteJSON(map[string]any{"type":"hello","protocols":[]int{1},"name":"Bot","build":"0.1.2","hive":"","capabilities":[]string{"panel"}})
	var welcome map[string]any
	conn.ReadJSON(&welcome)
	if welcome["type"] != "welcome" { t.Fatalf("welcome=%v", welcome) }
	conn.WriteJSON(map[string]any{"type":"telemetry","at":time.Now().UnixMilli(),"state":"SCANNING","account":"Acc","listed":1,"slots":18})
	time.Sleep(100 * time.Millisecond)
	if !h.Online(inst.ID) { t.Fatal("not online") }
	got, _ := st.Installation(inst.ID)
	if got.Telemetry == nil || got.Telemetry.Account != "Acc" { t.Fatalf("telemetry=%+v", got.Telemetry) }
}
```

- [ ] **Step 2: Implement Hub**

Key requirements:

- `client` has `conn *websocket.Conn`, `send chan []byte`, `installationID`, `lastSeen atomic.Int64`, `closed chan struct{}`, `once sync.Once`.
- `ServeWS`:
  - Parse bearer; hash; lookup; return HTTP 401 if unknown (pre-upgrade).
  - Upgrade with `CheckOrigin` returning `true` (we enforce the origin after the
    credential check); then, if `Origin != ""`, upgrade and immediately close
    with code 4403, then return. The mod never sends `Origin`, so this only
    rejects browser-style attempts.
  - Set `SetReadLimit(max)`.
  - Replace old client: close old 4409.
  - Mark online in store; `notify()`.
  - Start `writePump`; read first frame with 10s deadline.
  - hello: require protocols contains 1; send welcome.
  - Loop `ReadMessage` with 80s deadline; update `lastSeen`; handle frames.
  - On exit: if this client is still current, delete, mark offline, reject pending, notify.
- `writePump`: range send; `SetWriteDeadline(10s)`; `WriteMessage(TextMessage,b)`; close on error.
- `handleFrame`:
  - `ping` -> pong.
  - `telemetry` -> `ParseTelemetry`; reject sensitive with error frame; `Store.SetTelemetry`; notify.
  - `ack` -> command state received; notify.
  - `result` -> command state completed/rejected with reason; notify.
  - `panel_result` -> resolve pending.
  - `pong`/`error` -> ignore.
  - unknown -> send error frame; keep open.
- Heartbeat sweep every 5s: for each client, if `now-lastSeen > 80s`, close 4408.
- `Updates()` returns a `<-chan struct{}` buffered 1; `notify()` nonblocking.
- `PanelRequest` and `SendCommand` are added in Task 6; stub them in this task with `ErrOffline`? Better implement fully in Task 6. For Task 5, only handshake/telemetry/presence.

- [ ] **Step 3: Run tests**

Run: `cd panel && ../.tools/go/bin/go test ./internal/relay -run TestWS -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add panel/internal/relay
git commit -m "feat(panel): websocket handshake, heartbeat, and telemetry"
```

---

### Task 6: Commands and panel broker

**Files:**
- Modify: `panel/internal/relay/hub.go`
- Test: `panel/internal/relay/relay_test.go` (extend)

**Interfaces:**
- Produces: `Hub.SendCommand(id int64, command string) (string, error)`.
- Produces: `Hub.PanelRequest(ctx, id, frame map[string]any) (*PanelResult, error)`.
- Produces: `Hub.CloseInstallation(id int64, code int, reason string)`.
- Produces: `PanelResult{Status int, ContentType string, Body []byte, Encoding string}`.
- `Options` must include `PanelTimeout time.Duration` (default 15s; tests set 100ms).
- Command state values: `accepted`, `delivered`, `received`, `completed`,
  `rejected`, `expired`, `unknown`, `offline`.

- [ ] **Step 1: Write failing command/panel tests**

```go
func startWS(t *testing.T, panelTimeout time.Duration) (*store.Store, *Hub, *store.Installation, *websocket.Conn, func()) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	h := NewHub(st, Options{HeartbeatSeconds: 20, MaxMessageBytes: 32768,
		MaxPanelInFlight: 8, PanelTimeout: panelTimeout})
	ctx, cancel := context.WithCancel(context.Background())
	go h.Start(ctx)
	ts := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	code, _, err := st.CreateCode("u1", time.Now())
	if err != nil { t.Fatal(err) }
	inst, cred, err := st.RedeemCode(code, "Bot", "0.1.2", "", []string{"panel"}, time.Now())
	if err != nil { t.Fatal(err) }
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http"),
		http.Header{"Authorization": {"Bearer " + cred}})
	if err != nil { t.Fatal(err) }
	if err := conn.WriteJSON(map[string]any{"type": "hello", "protocols": []int{1},
		"build": "0.1.2", "name": "Bot", "hive": "", "capabilities": []string{"panel"}}); err != nil { t.Fatal(err) }
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil { t.Fatal(err) }
	cleanup := func() { conn.Close(); ts.Close(); cancel(); h.Stop(); st.Close() }
	return st, h, inst, conn, cleanup
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() { return }
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestCommandAckResult(t *testing.T) {
	st, h, inst, conn, cleanup := startWS(t, time.Second)
	defer cleanup()
	go func() {
		for {
			var f map[string]any
			if conn.ReadJSON(&f) != nil { return }
			if f["type"] == "command" {
				id, _ := f["id"].(string)
				conn.WriteJSON(map[string]any{"type": "ack", "id": id})
				conn.WriteJSON(map[string]any{"type": "result", "id": id,
					"status": "completed", "reason": "trading paused"})
			}
		}
	}()
	id, err := h.SendCommand(inst.ID, "pause")
	if err != nil || id == "" { t.Fatalf("send: %v %q", err, id) }
	waitFor(t, "completed command", func() bool {
		c := st.LastCommand(inst.ID)
		return c != nil && c.ID == id && c.State == "completed" && c.Reason == "trading paused"
	})
}

func TestPanelRequestMatchesID(t *testing.T) {
	_, h, inst, conn, cleanup := startWS(t, time.Second)
	defer cleanup()
	go func() {
		var f map[string]any
		if conn.ReadJSON(&f) != nil { return }
		id, _ := f["id"].(string)
		conn.WriteJSON(map[string]any{"type": "panel_result", "id": id, "status": 200,
			"contentType": "text/html; charset=utf-8", "body": "<html>ok</html>"})
	}()
	res, err := h.PanelRequest(context.Background(), inst.ID, map[string]any{"op": "page"})
	if err != nil { t.Fatal(err) }
	if res.Status != 200 || !strings.Contains(string(res.Body), "ok") {
		t.Fatalf("result=%+v", res)
	}
}

func TestPanelTimeoutAndOffline(t *testing.T) {
	_, h, inst, conn, cleanup := startWS(t, 100*time.Millisecond)
	defer cleanup()
	// Leave the panel frame unanswered so the broker times out.
	go func() { var f map[string]any; _ = conn.ReadJSON(&f) }()
	if _, err := h.PanelRequest(context.Background(), inst.ID, map[string]any{"op": "page"}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
	h.CloseInstallation(inst.ID, 4403, "revoked")
	waitFor(t, "offline", func() bool { return !h.Online(inst.ID) })
	if _, err := h.PanelRequest(context.Background(), inst.ID, map[string]any{"op": "page"}); !errors.Is(err, ErrOffline) {
		t.Fatalf("expected ErrOffline, got %v", err)
	}
}
```

- [ ] **Step 2: Implement commands**

`SendCommand`:
- Generate `cmd_` + 16 base64url chars.
- Check online; if not, return `ErrOffline` (store an `offline` command? No; return error).
- Create `store.Command{State:"accepted"}`; send `{"type":"command","id","command","createdAt","expiresAt": +30s}` via client send channel.
- Set state `delivered`.
- Start `time.AfterFunc(30*time.Second, ...)`: if state not final, set `expired`, notify.
- Return id.

Handlers:
- `ack`: if known and not final, state `received`; notify.
- `result`: if known and not final, state `completed`/`rejected`; reason ≤160; notify.
- On disconnect: commands in `delivered`/`received` -> `unknown`; notify.

`PanelRequest`:
- Check client online; capability `panel`; in-flight <8; else `ErrOffline`/`ErrNoPanel`/`ErrBusy`.
- Generate `pr_` id; frame includes type/id/op/expiresAt = now+14s.
- Register pending with channel; enqueue frame; wait on channel/15s/ctx.
- On result: decode base64 if `encoding=="base64"`; return.
- Cleanup inflight and pending.
- On duplicate result: first wins; second ignored.
- On disconnect: close pending with `ErrOffline`.

`CloseInstallation`: if client exists, close with code/reason and remove; mark offline.

- [ ] **Step 3: Run tests**

Run: `cd panel && ../.tools/go/bin/go test ./internal/relay -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add panel/internal/relay
git commit -m "feat(panel): commands and panel request broker"
```

---

### Task 7: Panel rewrite and HTTP proxy

**Files:**
- Create: `panel/internal/panel/rewrite.go`
- Test: `panel/internal/panel/rewrite_test.go`
- Create: `panel/internal/web/panel.go`
- Test: `panel/internal/web/web_test.go` (extend)

**Interfaces:**
- Produces: `panel.Rewrite(html, csrf string) string`.
- Produces: `Server.panelPage`, `panelGet`, `panelPost`.
- Produces: panel cache; in-flight limit handled by hub.

- [ ] **Step 1: Write failing rewrite test**

```go
func TestRewriteMakesPanelRelativeAndInjectsCSRF(t *testing.T) {
	in := `<head></head><img src="/logo.png"><form class="out" method="post" action="/logout"><button>Lock</button></form>
	<script>fetch('/state');fetch('/api/bots');fetch('/act');img.src='/item/minecraft:stone.png';n.src='/panel.png';all.href='https://gonuts.at/dashboard/bugs';website.href='https://gonuts.at/dashboard/'</script>`
	out := Rewrite(in, "csrf123")
	for _, bad := range []string{`src="/logo.png"`, `action="/logout"`, `fetch('/state')`, `fetch('/api/`, `fetch('/act')`, `src='/item/`, `src='/panel.png`, "gonuts.at"} {
		if strings.Contains(out, bad) { t.Fatalf("still contains %q:\n%s", bad, out) }
	}
	for _, want := range []string{`name="gonuts-csrf" content="csrf123"`, `src="logo.png"`, `action="/dashboard"`, `fetch('state')`, `fetch('api/bots')`, `fetch('act')`, `item/minecraft:stone.png`, `n.src='panel.png'`, `X-Gonuts-Csrf`} {
		if !strings.Contains(out, want) { t.Fatalf("missing %q:\n%s", want, out) }
	}
}
```

- [ ] **Step 2: Implement Rewrite**

```go
func Rewrite(html, csrf string) string {
	r := strings.NewReplacer(
		`src="/logo.png"`, `src="logo.png"`,
		`src='/panel.png`, `src='panel.png`,
		`src='/item/`, `src='item/`,
		`src = '/item/'`, `src = 'item/'`,
		`fetch('/state'`, `fetch('state'`,
		`fetch('/api/`, `fetch('api/`,
		`fetch('/act'`, `fetch('act'`,
		`fetch('https://gonuts.at/dashboard/api/public/bugs'`, `fetch('api/public/bugs'`,
		`https://gonuts.at/dashboard/bugs`, `/dashboard`,
		`https://gonuts.at/dashboard/`, `/dashboard`,
		`url(/font.ttf)`, `url(font.ttf)`,
		`<form class="out" method="post" action="/logout">`, `<form class="out" method="get" action="/dashboard">`,
	)
	html = r.Replace(html)
	inject := `<meta name="gonuts-csrf" content="` + csrf + `">` +
		`<script>(function(){var t=document.querySelector('meta[name="gonuts-csrf"]').content;` +
		`var f=window.fetch.bind(window);window.fetch=function(u,o){o=o||{};var s=typeof u==='string'?u:u.url;` +
		`if(!/^[a-z]+:/i.test(s)){var h=new Headers(o.headers||{});h.set('X-Gonuts-Csrf',t);o.headers=h;}return f(u,o);};})();</script>`
	if i := strings.Index(strings.ToLower(html), "<head>"); i >= 0 {
		html = html[:i+6] + inject + html[i+6:]
	} else {
		html = inject + html
	}
	return html
}
```

- [ ] **Step 3: Implement panel HTTP handlers**

- `panelPage`: session + ownership; if no owner -> 404. Get raw page from cache (`id|build`) or `Hub.PanelRequest` with `op:"page"`. On offline + cache -> cached; offline no cache -> styled 503. Rewrite with `sess.CSRF`; set `Content-Type: text/html; charset=utf-8`; no-store.
- `panelGet`: map path:
  - `state` -> `op:"state"`.
  - `api/<name>` -> `op:"data", name, query` (parse query).
  - `panel.png` -> `op:"png"`.
  - `item/<item>.png` -> `op:"icon", item`.
  - `logo.png` -> `op:"asset", asset:"logo"`.
  - `font.ttf` -> `op:"asset", asset:"font"`.
  - Else 404.
  - Cache binary/asset results with byte cap; state never cached.
- `panelPost`: require mutation (CSRF + origin) and `X-GoNuts: 1`; only `act` or `api/<name>`.
  - Parse form ≤64KiB.
  - `act`: `{id, value?, text?}` -> `op:"act"`; return 204.
  - `api/<name>`: `op:"change", name, form`; return JSON body.
- Ownership: `inst.DiscordID == user.ID`; else 404.
- Offline: 503; timeout: 504; busy: 429; no panel: 501.
- Page cache key includes build. Asset cache key includes installation id + path.
- Cache max from config; if adding exceeds, clear asset cache (simple).

Cache type (in `internal/web/panel.go`):

```go
type cachedPage struct { body string; expires time.Time }
type cachedAsset struct { body []byte; contentType string; expires time.Time }
type panelCache struct {
	mu     sync.Mutex
	pages  map[string]cachedPage
	assets map[string]cachedAsset
	bytes  int64
	max    int64
}
func (c *panelCache) page(key string) (string, bool) {
	c.mu.Lock(); defer c.mu.Unlock()
	p, ok := c.pages[key]
	if !ok || time.Now().After(p.expires) { if ok { delete(c.pages, key) }; return "", false }
	return p.body, true
}
func (c *panelCache) putPage(key, body string, ttl time.Duration) {
	c.mu.Lock(); defer c.mu.Unlock()
	c.pages[key] = cachedPage{body: body, expires: time.Now().Add(ttl)}
}
```

Core page handler:

```go
func (s *Server) panelPage(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := s.session(r)
	if !ok {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil { http.NotFound(w, r); return }
	inst, ok := s.Store.Installation(id)
	if !ok || inst.DiscordID != user.ID { http.NotFound(w, r); return }

	key := fmt.Sprintf("%d|%s", inst.ID, inst.Build)
	raw, cached := s.PanelCache.page(key)
	if !cached {
		res, err := s.Hub.PanelRequest(r.Context(), inst.ID, map[string]any{"op": "page"})
		if err != nil {
			if cached, ok := s.PanelCache.page(key); ok {
				raw = cached
			} else {
				http.Error(w, "the client is not connected", http.StatusServiceUnavailable)
				return
			}
		} else if res.Status != 200 {
			http.Error(w, "the client refused the page", res.Status)
			return
		} else {
			raw = string(res.Body)
			s.PanelCache.putPage(key, raw, 10*time.Minute)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Write([]byte(panel.Rewrite(raw, sess.CSRF)))
}
```

- [ ] **Step 4: Write web test for panel rewrite/proxy**

```go
type fakeRelay struct {
	online   bool
	frames   []map[string]any
	commands []string
	updates  chan struct{}
	panel    func(context.Context, int64, map[string]any) (*relay.PanelResult, error)
}
func (f *fakeRelay) Online(int64) bool { return f.online }
func (f *fakeRelay) SendCommand(_ int64, c string) (string, error) { f.commands = append(f.commands, c); return "cmd_test", nil }
func (f *fakeRelay) PanelRequest(ctx context.Context, id int64, frame map[string]any) (*relay.PanelResult, error) {
	if !f.online { return nil, relay.ErrOffline }
	f.frames = append(f.frames, frame)
	return f.panel(ctx, id, frame)
}
func (f *fakeRelay) CloseInstallation(int64, int, string) {}
func (f *fakeRelay) Updates() <-chan struct{}            { return f.updates }
func (f *fakeRelay) ServeWS(http.ResponseWriter, *http.Request) {}

func TestPanelPageRewritesAndProxies(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	defer st.Close()
	token, csrf, _ := st.CreateSession("u1", time.Now())
	code, _, _ := st.CreateCode("u1", time.Now())
	inst, _, _ := st.RedeemCode(code, "Bot", "b", "", []string{"panel"}, time.Now())
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1), panel: func(context.Context, int64, map[string]any) (*relay.PanelResult, error) {
		return &relay.PanelResult{Status: 200, ContentType: "text/html; charset=utf-8",
			Body: []byte(`<head></head><img src="/logo.png"><form class="out" method="post" action="/logout"></form>`)}, nil
	}}
	s := New(config.Config{PublicBaseURL: "https://panel.example.com", PanelCacheBytes: 1 << 20}, st, fr, nil)
	base := "/dashboard/panel/" + strconv.FormatInt(inst.ID, 10) + "/"

	req := httptest.NewRequest("GET", base, nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 { t.Fatalf("page status=%d body=%s", rec.Code, rec.Body) }
	body := rec.Body.String()
	if !strings.Contains(body, `src="logo.png"`) || strings.Contains(body, "gonuts.at") || !strings.Contains(body, `gonuts-csrf`) {
		t.Fatalf("bad page:\n%s", body)
	}

	req = httptest.NewRequest("POST", base+"act", strings.NewReader("id=ctl:start"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-GoNuts", "1")
	req.Header.Set("X-Gonuts-Csrf", csrf)
	req.Header.Set("Origin", "https://panel.example.com")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 204 { t.Fatalf("act status=%d body=%s", rec.Code, rec.Body) }
	if len(fr.frames) < 2 || fr.frames[len(fr.frames)-1]["op"] != "act" || fr.frames[len(fr.frames)-1]["act"].(map[string]any)["id"] != "ctl:start" {
		t.Fatalf("frames=%+v", fr.frames)
	}

	// A different user gets 404, not another user's panel.
	token2, _, _ := st.CreateSession("u2", time.Now())
	req = httptest.NewRequest("GET", base, nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token2})
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 404 { t.Fatalf("ownership status=%d", rec.Code) }

	// Offline with no cache is a styled 503.
	fr.online = false
	st.DeleteInstallation(inst.ID, "u1")
	// Recreate an installation with no cached page to keep the id stable.
	code2, _, _ := st.CreateCode("u1", time.Now())
	inst2, _, _ := st.RedeemCode(code2, "Bot2", "b", "", []string{"panel"}, time.Now())
	req = httptest.NewRequest("GET", "/dashboard/panel/"+strconv.FormatInt(inst2.ID, 10)+"/", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 503 { t.Fatalf("offline status=%d", rec.Code) }
}
```

- [ ] **Step 5: Run tests**

Run: `cd panel && ../.tools/go/bin/go test ./internal/panel ./internal/web -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add panel/internal/panel panel/internal/web/panel.go panel/internal/web/web_test.go
git commit -m "feat(panel): relayed full panel with rewrite and cache"
```

---

### Task 8: Dashboard state API, SSE, auth pages, rate limits, and command endpoints

**Files:**
- Create: `panel/internal/web/sse.go`
- Create: `panel/internal/web/auth.go`
- Create: `panel/internal/web/limiter.go`
- Create: `panel/internal/web/limiter_test.go`
- Modify: `panel/internal/web/api.go`
- Modify: `panel/internal/web/server.go`
- Test: `panel/internal/web/web_test.go` (extend)

**Interfaces:**
- Produces: `GET /dashboard/api/state` shape:
  ```json
  {"csrf":"...","user":{...},"now":123,"installations":[{"id":1,"name":"...","online":true,"telemetry":{...},"lastCommand":{"state":"completed","reason":"","createdAt":0}}],"hives":[{"name":"...","count":2}]}
  ```
- Produces: SSE event `update`.
- Produces: OAuth login/callback, dev login, logout.
- Produces: `newLimiter(perMinute, burst float64)` and `(*limiter).allow(key, now)`.

- [ ] **Step 0: Write the failing limiter test and implement it**

```go
func TestLimiterBurstAndRefill(t *testing.T) {
	l := newLimiter(60, 2) // one token per second, burst 2
	now := time.Unix(0, 0)
	if !l.allow("ip", now) || !l.allow("ip", now) { t.Fatal("burst should allow two") }
	if l.allow("ip", now) { t.Fatal("third immediate request should fail") }
	if !l.allow("ip", now.Add(time.Second)) { t.Fatal("should refill one token after a second") }
	if !l.allow("other", now) { t.Fatal("keys must be independent") }
}
```

```go
type bucket struct { tokens float64; last time.Time }
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
}
func newLimiter(perMinute, burst float64) *limiter {
	return &limiter{rate: perMinute / 60, burst: burst, buckets: map[string]*bucket{}}
}
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock(); defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil { b = &bucket{tokens: l.burst, last: now}; l.buckets[key] = b }
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 { return false }
	b.tokens--
	return true
}
```

Use these keys: `redeem:<ip>` (10/min, burst 10), `redeem:global`
(60/min, burst 60), `command:<discordID>` (60/min, burst 60),
`panel:<sessionHash>` (120/min, burst 120), `dashboard:<ip>` (120/min,
burst 120). An empty/disabled limiter is not allowed in production; tests may
set generous values.

- [ ] **Step 1: Write failing state test**

```go
func TestStateIsScopedToUser(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	defer st.Close()
	now := time.Now()
	token1, csrf1, _ := st.CreateSession("u1", now)
	token2, _, _ := st.CreateSession("u2", now)
	code, _, _ := st.CreateCode("u1", now)
	inst, _, _ := st.RedeemCode(code, "Bot", "b", "", nil, now)
	st.SetTelemetry(inst.ID, &store.Telemetry{Account: "Acc", State: "SCANNING"}, now)
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1)}
	s := New(config.Config{PublicBaseURL: "https://panel.example.com"}, st, fr, nil)

	get := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/dashboard/api/state", nil)
		if token != "" { req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token}) }
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	rec := get(token1)
	if rec.Code != 200 { t.Fatalf("status=%d body=%s", rec.Code, rec.Body) }
	var body struct {
		CSRF string `json:"csrf"`
		Installations []struct {
			ID int64 `json:"id"`
			Name string `json:"name"`
			Online bool `json:"online"`
			Telemetry *store.Telemetry `json:"telemetry"`
		} `json:"installations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil { t.Fatal(err) }
	if body.CSRF != csrf1 || len(body.Installations) != 1 || body.Installations[0].Name != "Bot" ||
		!body.Installations[0].Online || body.Installations[0].Telemetry.Account != "Acc" {
		t.Fatalf("body=%s", rec.Body)
	}
	if rec := get(token2); strings.Contains(rec.Body.String(), `"Bot"`) { t.Fatalf("user2 saw user1's bot: %s", rec.Body) }
	if rec := get(""); rec.Code != 401 { t.Fatalf("anonymous status=%d", rec.Code) }
}
```

- [ ] **Step 2: Implement state API**

- `apiState`: `requireSession`; build installations for user; set `online` from `Hub.Online`; clone telemetry; attach last command (latest by CreatedAt); hives map; return `csrf`.
- `apiPairCode`: `requireMutation`; `Store.CreateCode`; return `{code, expiresAt}`.
- `apiCommand`: `requireMutation`; decode `{command}`; allow `pause|resume|snapshot`; `Hub.SendCommand`; if `ErrOffline` -> 409 `{"message":"client is offline"}`; return 202 `{id}`.
- `apiRename`: `requireMutation`; decode `{name}`; validate; `Store.RenameInstallation`; return 200.
- `apiUnlink`: `requireMutation`; `Store.DeleteInstallation`; `Hub.CloseInstallation(4403)`; return 200.
- `authLogin`: state+verifier; store in `States` map; set OAuth cookie; redirect.
- `authCallback`: validate state/cookie; exchange; Me; allowlist; upsert; create session; set cookie; clear OAuth; redirect.
- `authDev`: if `!Cfg.DevLogin` -> 404; user id `dev` or `dev-<query>`; create user/session; redirect `/dashboard`.
- `authLogout`: delete session; clear; redirect `/dashboard`.
- `dashboardPage`: session -> `renderDashboard(csrf)`; else `login.html` with no CSRF.
- `sse`: require session; headers; subscribe; initial update; keepalive 25s; max 5 per user.

Auth handlers (core):

```go
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	state, _ := auth.RandomToken(24)
	verifier, err := auth.NewVerifier()
	if err != nil { http.Error(w, "sign-in unavailable", 500); return }
	s.States.put(state, verifier, 10*time.Minute)
	auth.SetOAuthCookie(w, state, s.Cfg.CookieSecure)
	http.Redirect(w, r, s.Discord.AuthorizeURLFor(state, auth.Challenge(verifier)), http.StatusFound)
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(auth.OAuthCookie)
	if err != nil || c.Value == "" || c.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid sign-in state", 400); return
	}
	verifier, ok := s.States.take(c.Value)
	if !ok { http.Error(w, "sign-in expired", 400); return }
	auth.ClearOAuthCookie(w, s.Cfg.CookieSecure)
	if errText := r.URL.Query().Get("error"); errText != "" {
		http.Error(w, "Discord sign-in was cancelled", 400); return
	}
	token, err := s.Discord.Exchange(r.Context(), r.URL.Query().Get("code"), verifier)
	if err != nil { log.Printf("oauth exchange failed"); http.Error(w, "sign-in failed", 502); return }
	du, err := s.Discord.Me(r.Context(), token)
	if err != nil { log.Printf("oauth user failed"); http.Error(w, "sign-in failed", 502); return }
	if len(s.Cfg.AllowedDiscordIDs) > 0 && !s.Cfg.AllowedDiscordIDs[du.ID] {
		http.Error(w, "this Discord account is not allowed", 403); return
	}
	s.Store.UpsertUser(store.User{ID: du.ID, Username: du.Username, GlobalName: du.GlobalName, Avatar: du.Avatar, CreatedAt: time.Now().UnixMilli()})
	sessToken, _, err := s.Store.CreateSession(du.ID, time.Now())
	if err != nil { http.Error(w, "sign-in failed", 500); return }
	auth.SetSessionCookie(w, sessToken, s.Cfg.CookieSecure)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) authDev(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.DevLogin { http.NotFound(w, r); return }
	id := "dev"
	if q := strings.TrimSpace(r.URL.Query().Get("user")); q != "" {
		id = "dev-" + strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' { return r }
			return -1
		}, strings.ToLower(q))
	}
	s.Store.UpsertUser(store.User{ID: id, Username: id, GlobalName: id, CreatedAt: time.Now().UnixMilli()})
	token, _, err := s.Store.CreateSession(id, time.Now())
	if err != nil { http.Error(w, "dev sign-in failed", 500); return }
	auth.SetSessionCookie(w, token, s.Cfg.CookieSecure)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

OAuth state store (in `internal/web/auth.go`):

```go
type oauthState struct { verifier string; expires time.Time }
type oauthStates struct { mu sync.Mutex; m map[string]oauthState }
func (o *oauthStates) put(state, verifier string, ttl time.Duration) {
	o.mu.Lock(); defer o.mu.Unlock()
	o.m[state] = oauthState{verifier: verifier, expires: time.Now().Add(ttl)}
}
func (o *oauthStates) take(state string) (string, bool) {
	o.mu.Lock(); defer o.mu.Unlock()
	v, ok := o.m[state]; delete(o.m, state)
	if !ok || time.Now().After(v.expires) { return "", false }
	return v.verifier, true
}
```

SSE subscriber limit (in `internal/web/sse.go`):

```go
type sseHub struct { mu sync.Mutex; users map[string]int; max int }
func newSSEHub(max int) *sseHub { return &sseHub{users: map[string]int{}, max: max} }
func (h *sseHub) add(user string) bool {
	h.mu.Lock(); defer h.mu.Unlock()
	if h.users[user] >= h.max { return false }
	h.users[user]++; return true
}
func (h *sseHub) remove(user string) {
	h.mu.Lock(); defer h.mu.Unlock()
	h.users[user]--; if h.users[user] <= 0 { delete(h.users, user) }
}
```

```go
func (s *Server) apiState(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := s.requireSession(w, r)
	if !ok { return }
	installs := s.Store.InstallationsFor(user.ID)
	out := make([]map[string]any, 0, len(installs))
	hives := map[string]int{}
	for _, inst := range installs {
		if inst.Hive != "" { hives[inst.Hive]++ }
		out = append(out, map[string]any{
			"id": inst.ID, "name": inst.Name, "build": inst.Build, "hive": inst.Hive,
			"online": s.Hub.Online(inst.ID), "lastSeen": inst.LastSeen,
			"telemetry": inst.Telemetry, "lastCommand": s.Store.LastCommand(inst.ID),
		})
	}
	hiveList := make([]map[string]any, 0, len(hives))
	for name, count := range hives {
		hiveList = append(hiveList, map[string]any{"name": name, "count": count})
	}
	writeJSON(w, 200, map[string]any{
		"csrf": sess.CSRF, "user": user, "now": time.Now().UnixMilli(),
		"installations": out, "hives": hiveList,
	})
}

func (s *Server) apiCommand(w http.ResponseWriter, r *http.Request) {
	_, user, ok := s.requireMutation(w, r)
	if !ok { return }
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil { writeJSON(w, 404, map[string]any{"message": "not found", "status": 404}); return }
	inst, ok := s.Store.Installation(id)
	if !ok || inst.DiscordID != user.ID { writeJSON(w, 404, map[string]any{"message": "not found", "status": 404}); return }
	if !s.Limiter.allow("command:"+user.ID, time.Now()) {
		writeJSON(w, 429, map[string]any{"message": "too many commands", "status": 429}); return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var body struct{ Command string `json:"command"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil { writeJSON(w, 400, map[string]any{"message": "invalid body", "status": 400}); return }
	switch body.Command {
	case "pause", "resume", "snapshot":
	default:
		writeJSON(w, 400, map[string]any{"message": "unsupported command", "status": 400}); return
	}
	cmdID, err := s.Hub.SendCommand(id, body.Command)
	if errors.Is(err, relay.ErrOffline) {
		writeJSON(w, 409, map[string]any{"message": "client is offline", "status": 409}); return
	}
	if err != nil {
		writeJSON(w, 502, map[string]any{"message": "command failed", "status": 502}); return
	}
	writeJSON(w, 202, map[string]any{"id": cmdID})
}

func (s *Server) dashboardPage(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.session(r)
	if !ok {
		b, _ := webassets.FS.ReadFile("login.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
		return
	}
	b, err := dashboardHTML(sess.CSRF)
	if err != nil { http.Error(w, "dashboard unavailable", 500); return }
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func (s *Server) sse(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.requireSession(w, r)
	if !ok { return }
	if !s.SSE.add(sess.DiscordID) { writeJSON(w, 429, map[string]any{"message": "too many tabs", "status": 429}); return }
	defer s.SSE.remove(sess.DiscordID)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok { http.Error(w, "stream unsupported", 500); return }
	fmt.Fprint(w, "event: update\ndata: {}\n\n"); flusher.Flush()
	ticker := time.NewTicker(25 * time.Second); defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done(): return
		case <-s.Hub.Updates():
			fmt.Fprint(w, "event: update\ndata: {}\n\n"); flusher.Flush()
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n"); flusher.Flush()
		}
	}
}
```

- `requireSession` writes the 401 JSON; `sse` still tries to set headers after writing 401; guard by checking `ok` before headers. The snippet does that.
- `apiState` uses `s.Limiter` for dashboard GET? Add at the top: `if !s.Limiter.allow("dashboard:"+clientIP(r), time.Now()) { ... }`. Include in implementation.
- `apiPairCode` similar with `pair:<user>`.
- `apiRename`/`apiUnlink` mirror `apiCommand` ownership checks.

- [ ] **Step 3: Implement renderDashboard**

Read `web/dashboard.html`, replace `{{CSRF}}` with `csrf`, write. Login page is static.

- [ ] **Step 4: Wire the application in main.go**

```go
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"gonutspanel/internal/auth"
	"gonutspanel/internal/config"
	"gonutspanel/internal/relay"
	"gonutspanel/internal/store"
	"gonutspanel/internal/web"
)

func main() {
	cfg, err := config.Load()
	if err != nil { log.Fatal(err) }
	st, err := store.Open(cfg.DataDir)
	if err != nil { log.Fatal(err) }
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hub := relay.NewHub(st, relay.Options{
		HeartbeatSeconds: 20, TelemetryMinInterval: time.Second,
		MaxMessageBytes: 32768, PanelTimeout: 15 * time.Second, MaxPanelInFlight: 8,
	})
	go hub.Start(ctx)
	defer hub.Stop()

	d := &auth.Discord{
		ClientID: cfg.DiscordClientID, ClientSecret: cfg.DiscordClientSecret,
		RedirectURI: cfg.PublicBaseURL + "/auth/callback",
		AuthorizeURL: cfg.OAuthAuthorizeURL,
		TokenURL: cfg.DiscordAPIBase + "/oauth2/token",
		UserURL: cfg.DiscordAPIBase + "/users/@me",
		HTTP: &http.Client{Timeout: 15 * time.Second},
	}
	srv := &http.Server{Addr: cfg.Addr, Handler: web.New(cfg, st, hub, d).Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	log.Printf("gonuts-panel listening on %s", cfg.Addr)
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	_ = st.SaveNow()
}
```

- [ ] **Step 5: Run tests**

Run: `cd panel && ../.tools/go/bin/go test ./internal/web -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add panel/internal/web panel/cmd/gonuts-panel/main.go
git commit -m "feat(panel): dashboard state, SSE, auth routes, and app wiring"
```

---

### Task 9: Dashboard UI and assets

**Files:**
- Create: `panel/web/dashboard.html`
- Create: `panel/web/login.html`
- Create: `panel/web/assets/dashboard.css`
- Create: `panel/web/assets/dashboard.js`
- Create: `panel/web/assets/mascot_v2.png` (copy)
- Create: `panel/web/assets/Monocraft.ttf` (copy)
- Create: `panel/web/assets/logo.png` (copy)
- Modify: `panel/internal/web/server.go` (`webFS`)

**Interfaces:**
- Consumes: `GET /dashboard/api/state`, `POST /dashboard/api/pair/code`,
  `POST /dashboard/api/installations/{id}/command`, rename, delete, SSE.
- Produces: the user-visible dashboard.

- [ ] **Step 1: Copy assets**

```bash
mkdir -p panel/web/assets
cp upstream/trader-fabric/src/main/resources/assets/doughbay/textures/gui/mascot_v2.png panel/web/assets/mascot_v2.png
cp upstream/trader-fabric/src/main/resources/doughbay/web/Monocraft.ttf panel/web/assets/Monocraft.ttf
cp upstream/docs/assets/logo.png panel/web/assets/logo.png
```

- [ ] **Step 2: Create dashboard.html**

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="gonuts-csrf" content="{{CSRF}}">
<title>GoNuts dashboard</title>
<link rel="icon" href="/assets/logo.png">
<link rel="stylesheet" href="/assets/dashboard.css">
</head>
<body>
<header class="top">
  <h1>GoNuts <span>dashboard</span></h1>
  <div class="top-right">
    <button class="btn gold" id="linkClient">Link client</button>
    <span id="who" class="who"></span>
    <form method="post" action="/auth/logout"><button class="btn ghost">Sign out</button></form>
  </div>
</header>
<main>
  <section id="empty" class="empty panel" hidden>
    <h2>No clients linked yet</h2>
    <p>Choose <strong>Link client</strong>, then enter the code in GoNuts → Dashboard → Link with code.</p>
  </section>
  <section id="cards" class="cards" aria-live="polite"></section>
  <section id="hive" class="hive panel" hidden></section>
</main>
<div id="modal" class="modal" hidden>
  <div class="modal-card panel">
    <h2>Link a client</h2>
    <p>Enter this one-use code in the intended bot within five minutes.</p>
    <div class="code" id="code">…</div>
    <p class="muted" id="codeExpiry"></p>
    <div class="modal-actions">
      <button class="btn" id="copyCode">Copy code</button>
      <button class="btn ghost" id="closeModal">Close</button>
    </div>
  </div>
</div>
<div id="toast" class="toast" hidden></div>
<script src="/assets/dashboard.js"></script>
</body>
</html>
```

`login.html`:

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>GoNuts dashboard</title><link rel="icon" href="/assets/logo.png"><link rel="stylesheet" href="/assets/dashboard.css"></head>
<body class="login-body">
<main class="login panel">
  <img src="/assets/logo.png" alt="GoNuts" class="logo">
  <h1>GoNuts dashboard</h1>
  <p>Sign in with Discord to see and control the bots you link.</p>
  <a class="btn gold wide" href="/auth/login">Sign in with Discord</a>
</main>
</body>
</html>
```

- [ ] **Step 3: Create dashboard.css**

Use the panel palette and Monocraft. Include at minimum:

```css
@font-face { font-family:"GoNuts Pixel"; src:url(/assets/Monocraft.ttf) format("truetype"); font-display:swap; }
:root { --bg:#0b1118; --surface:#111a24; --inset:#0d141c; --edge:#263442; --text:#f0eee7;
  --secondary:#b6c2cd; --muted:#8799aa; --gold:#f4cd7a; --teal:#56dccb; --good:#77deb0;
  --warn:#f3b576; --bad:#ff858c; --pixel:"GoNuts Pixel", "Courier New", monospace; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.45 var(--pixel); }
.top { display:flex; align-items:center; gap:14px; padding:14px 20px; flex-wrap:wrap; }
.top h1 { margin:0; font-size:20px; color:var(--gold); font-weight:400; letter-spacing:.03em; }
.top h1 span { color:var(--text); }
.top-right { margin-left:auto; display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.who { color:var(--secondary); }
.panel { background:var(--surface); border:1px solid var(--edge); border-radius:7px; box-shadow:2px 3px 0 rgba(0,0,0,.35); }
main { max-width:1180px; margin:0 auto; padding:6px 20px 40px; }
.cards { display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:18px; }
@media (max-width:860px){ .cards { grid-template-columns:1fr; } }
.card { background:linear-gradient(180deg,#121b26,#0f1620); border:1px solid var(--edge);
  border-radius:8px; padding:14px 16px 12px; display:flex; flex-direction:column; gap:10px; }
.card-head { display:flex; align-items:center; gap:10px; }
.card-head h2 { margin:0; font-size:16px; color:var(--gold); font-weight:400; overflow-wrap:anywhere; }
.pill { margin-left:auto; border:1px solid var(--teal); color:var(--teal); border-radius:999px;
  padding:2px 10px; font-size:11px; text-transform:lowercase; white-space:nowrap; }
.pill.offline { border-color:var(--muted); color:var(--muted); }
.state-row { display:flex; align-items:center; gap:12px; }
.mascot { width:58px; height:58px; flex:none; image-rendering:pixelated;
  background:url(/assets/mascot_v2.png) 0 0/400% 200% no-repeat; }
.face-IDLE{background-position:0 0}.face-WATCH{background-position:33.333% 0}
.face-WORK{background-position:66.666% 0}.face-SALE{background-position:100% 0}
.face-PAUSED{background-position:0 100%}.face-SLEEP{background-position:33.333% 100%}
.face-ALERT{background-position:66.666% 100%}
.state { color:var(--gold); letter-spacing:.05em; text-transform:uppercase; font-size:12px; }
.state.bad { color:var(--bad); } .state.paused { color:var(--warn); }
.state-detail { color:var(--secondary); font-size:12px; margin-top:2px; }
.rows { display:grid; grid-template-columns:1fr 1fr; gap:2px 16px; border-top:1px solid var(--edge); padding-top:8px; }
.kv { display:flex; justify-content:space-between; gap:8px; min-width:0; }
.kv dt { color:var(--muted); font-size:12px; white-space:nowrap; }
.kv dd { margin:0; text-align:right; overflow-wrap:anywhere; font-size:13px; }
.rows .full { grid-column:1/-1; }
.swarm { display:flex; align-items:center; gap:8px; flex-wrap:wrap; font-size:12px; color:var(--secondary); }
.swarm .tag { border:1px solid var(--edge); color:var(--teal); border-radius:4px; padding:0 6px; }
.swarm .on { color:var(--good); } .swarm .off { color:var(--warn); }
.actions { display:flex; gap:6px; flex-wrap:wrap; }
.btn { font:inherit; font-size:12px; padding:8px 12px; min-height:36px; border-radius:5px;
  border:1px solid var(--edge); background:var(--inset); color:var(--text); cursor:pointer; }
.btn:hover:not(:disabled){ background:#1b2a3a; }
.btn:disabled { color:var(--muted); cursor:default; }
.btn.gold { color:#1a1205; background:var(--gold); border-color:var(--gold); font-weight:700; }
.btn.ghost { background:none; }
.btn.wide { display:block; text-align:center; text-decoration:none; }
.actions .btn { flex:1 1 90px; }
.card-foot { display:flex; justify-content:space-between; gap:10px; color:var(--muted);
  font-size:11px; border-top:1px solid var(--edge); padding-top:8px; flex-wrap:wrap; }
.links { display:flex; gap:10px; }
.link { background:none; border:0; color:var(--secondary); font:inherit; font-size:11px;
  text-decoration:underline; text-underline-offset:3px; cursor:pointer; padding:0; }
.link:hover { color:var(--gold); }
.hive { margin-top:18px; padding:12px 16px; display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
.hive .spacer { flex:1; }
.empty { padding:28px; text-align:center; margin-top:20px; }
.empty h2 { color:var(--gold); font-weight:400; }
.muted { color:var(--muted); }
.modal { position:fixed; inset:0; background:rgba(0,0,0,.6); display:grid; place-items:center; padding:20px; z-index:10; }
.modal-card { width:min(420px,100%); padding:20px; }
.modal-card h2 { margin:0 0 8px; color:var(--gold); font-weight:400; }
.code { font-size:30px; letter-spacing:.18em; text-align:center; color:var(--gold);
  background:var(--inset); border:1px solid var(--edge); border-radius:6px; padding:14px; margin:12px 0; }
.modal-actions { display:flex; gap:8px; }
.modal-actions .btn { flex:1; }
.toast { position:fixed; left:50%; bottom:18px; transform:translateX(-50%); background:var(--inset);
  border:1px solid var(--gold); border-radius:5px; padding:9px 14px; z-index:20; max-width:90vw; }
.toast.bad { border-color:var(--bad); color:var(--bad); }
.login-body { display:grid; place-items:center; min-height:100vh; padding:20px; }
.login { width:min(420px,100%); padding:26px; text-align:center; }
.login .logo { width:220px; max-width:80%; image-rendering:pixelated; }
.login h1 { color:var(--gold); font-weight:400; font-size:20px; }
.login p { color:var(--secondary); }
```

- [ ] **Step 4: Create dashboard.js**

```js
const $ = (id) => document.getElementById(id);
const CSRF = document.querySelector('meta[name="gonuts-csrf"]').content;
let current = null, toastTimer = 0, countdown = 0;

async function api(path, opts = {}) {
  const headers = new Headers(opts.headers || {});
  headers.set('X-Gonuts-Csrf', CSRF);
  if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const r = await fetch(path, { ...opts, headers, credentials: 'same-origin' });
  if (r.status === 401) { location.href = '/dashboard'; throw new Error('signed out'); }
  let data = null;
  try { data = await r.json(); } catch (e) {}
  if (!r.ok) throw new Error((data && data.message) || ('HTTP ' + r.status));
  return data;
}
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
function money(v) {
  if (v == null || !Number.isFinite(Number(v))) return '—';
  const n = Number(v), a = Math.abs(n), sign = n < 0 ? '-' : '';
  if (a >= 1e9) return sign + '$' + (a / 1e9).toFixed(2) + 'b';
  if (a >= 1e6) return sign + '$' + (a / 1e6).toFixed(2) + 'm';
  if (a >= 1e3) return sign + '$' + (a / 1e3).toFixed(1) + 'k';
  return sign + '$' + Math.round(a);
}
function compact(v) { if (v == null) return '—'; const a = Math.abs(Number(v)); return a >= 1e6 ? (Number(v)/1e6).toFixed(1)+'m' : a >= 1e3 ? (Number(v)/1e3).toFixed(1)+'k' : String(v); }
function ago(ms) {
  if (!ms) return 'never';
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
function interval(v) { return v && v.h24 != null ? v.h24 : null; }
function source(v) { return v && v.source ? v.source : 'booked'; }
function stateClass(state) { return state === 'STOPPED' ? 'bad' : state === 'PAUSED' ? 'paused' : ''; }
function row(label, value, full) {
  const d = el('div', 'kv' + (full ? ' full' : ''));
  d.append(el('dt', '', label), el('dd', '', value == null ? '—' : String(value)));
  return d;
}
function card(inst) {
  const t = inst.telemetry || {};
  const article = el('article', 'card');
  const head = el('div', 'card-head');
  head.append(el('h2', '', inst.name || 'GoNuts client'));
  head.append(el('span', 'pill' + (inst.online ? '' : ' offline'), inst.online ? 'online' : 'offline'));
  article.append(head);

  const stateRow = el('div', 'state-row');
  stateRow.append(el('div', 'mascot face-' + (t.mascotFace || 'IDLE')));
  const stateBox = el('div');
  const state = t.state || (inst.online ? 'UNKNOWN' : 'OFFLINE');
  stateBox.append(el('div', 'state ' + stateClass(state), state + (t.detail ? ' · ' + t.detail : '')));
  stateBox.append(el('div', 'state-detail', t.lastAction ? 'last: ' + t.lastAction + ' · ' + ago(t.lastActionAt) : 'Waiting for activity'));
  stateRow.append(stateBox);
  article.append(stateRow);

  const rows = el('section', 'rows');
  rows.append(row('account', t.account || '—'));
  rows.append(row('bank', t.bank == null ? '—' : money(t.bank)));
  rows.append(row('profit 1h', t.profit && t.profit.h1 != null ? money(t.profit.h1) : '—'));
  rows.append(row('profit 24h', t.profit && t.profit.h24 != null ? money(t.profit.h24) : '—'));
  rows.append(row('sales 1h / 24h', (t.sales && t.sales.h1 != null ? compact(t.sales.h1) : '—') + ' / ' + (t.sales && t.sales.h24 != null ? compact(t.sales.h24) : '—')));
  rows.append(row('purchases 24h', t.purchases && t.purchases.h24 != null ? compact(t.purchases.h24) : '—'));
  rows.append(row('listings 24h', t.listings && t.listings.h24 != null ? compact(t.listings.h24) : '—'));
  rows.append(row('reprices 24h', t.reprices && t.reprices.h24 != null ? compact(t.reprices.h24) : '—'));
  rows.append(row('listed / slots', (t.listed == null ? '—' : t.listed) + ' / ' + (t.slots == null ? '—' : t.slots), true));
  rows.append(row('trades (session)', t.trades == null ? '—' : t.trades, true));
  rows.append(row('profit source', source(t.profit), true));
  article.append(rows);

  const swarm = el('div', 'swarm');
  swarm.append(el('span', 'tag', 'Swarm'));
  const enabled = t.swarm && t.swarm.enabled;
  swarm.append(el('span', enabled ? 'on' : 'off', enabled ? 'sharing market observations' : 'not sharing'));
  swarm.append(el('span', '', '· guidance ' + (t.swarm && t.swarm.guidanceEnabled ? 'on' : 'off')));
  swarm.append(el('span', '', '· ' + (t.swarm && t.swarm.eligible ? 'eligible' : 'not eligible')));
  article.append(swarm);

  const actions = el('div', 'actions');
  const open = el('button', 'btn gold', 'Open panel');
  open.onclick = () => { location.href = '/dashboard/panel/' + inst.id + '/'; };
  const pause = el('button', 'btn', 'Pause');
  pause.disabled = !inst.online || !(t.controls ? t.controls.pause : false);
  pause.onclick = () => command(inst.id, 'pause');
  const resume = el('button', 'btn', 'Resume');
  resume.disabled = !inst.online || !(t.controls ? t.controls.resume : false);
  resume.onclick = () => command(inst.id, 'resume');
  const refresh = el('button', 'btn', 'Refresh');
  refresh.disabled = !inst.online;
  refresh.onclick = () => command(inst.id, 'snapshot');
  actions.append(open, pause, resume, refresh);
  article.append(actions);

  const foot = el('div', 'card-foot');
  foot.append(el('span', '', t.build || inst.build || 'unknown build'));
  foot.append(el('span', '', 'seen ' + ago(inst.lastSeen)));
  const links = el('div', 'links');
  const rename = el('button', 'link', 'rename');
  rename.onclick = () => renameInst(inst);
  const unlink = el('button', 'link', 'unlink');
  unlink.onclick = () => unlinkInst(inst);
  links.append(rename, unlink);
  foot.append(links);
  article.append(foot);

  if (inst.lastCommand && inst.lastCommand.state && !['completed'].includes(inst.lastCommand.state)) {
    article.append(el('div', 'muted', 'Last command: ' + inst.lastCommand.command + ' · ' + inst.lastCommand.state + (inst.lastCommand.reason ? ' · ' + inst.lastCommand.reason : '')));
  }
  return article;
}
function render(data) {
  current = data;
  $('who').textContent = data.user.globalName || data.user.username || '';
  const cards = $('cards');
  cards.replaceChildren(...data.installations.map(card));
  $('empty').hidden = data.installations.length > 0;
  const hive = $('hive');
  hive.replaceChildren();
  if (data.hives && data.hives.length) {
    const count = data.hives.reduce((n, h) => n + h.count, 0);
    hive.hidden = false;
    hive.append(el('span', '', 'You have ' + count + ' linked bot' + (count === 1 ? '' : 's') + '.'));
    hive.append(el('span', 'spacer'));
    const pauseAll = el('button', 'btn', 'Pause all');
    pauseAll.onclick = () => data.installations.filter(i => i.online).forEach(i => command(i.id, 'pause'));
    const resumeAll = el('button', 'btn', 'Resume all');
    resumeAll.onclick = () => data.installations.filter(i => i.online).forEach(i => command(i.id, 'resume'));
    hive.append(pauseAll, resumeAll);
  } else hive.hidden = true;
}
async function load() {
  try { render(await api('/dashboard/api/state', { cache: 'no-store' })); }
  catch (e) { toast(e.message, true); }
}
async function command(id, cmd) {
  try { await api('/dashboard/api/installations/' + id + '/command', { method: 'POST', body: JSON.stringify({ command: cmd }) }); toast(cmd + ' sent'); setTimeout(load, 400); }
  catch (e) { toast(e.message, true); }
}
async function renameInst(inst) {
  const name = prompt('Client label', inst.name || '');
  if (name == null || !name.trim()) return;
  try { await api('/dashboard/api/installations/' + inst.id + '/rename', { method: 'POST', body: JSON.stringify({ name: name.trim() }) }); toast('Renamed'); load(); }
  catch (e) { toast(e.message, true); }
}
async function unlinkInst(inst) {
  if (!confirm('Unlink ' + (inst.name || 'this client') + '? The bot will stop connecting.')) return;
  try { await api('/dashboard/api/installations/' + inst.id, { method: 'DELETE' }); toast('Unlinked'); load(); }
  catch (e) { toast(e.message, true); }
}
function toast(text, bad) {
  const t = $('toast'); t.textContent = text; t.className = 'toast' + (bad ? ' bad' : ''); t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.hidden = true, 4000);
}
async function linkClient() {
  try {
    const p = await api('/dashboard/api/pair/code', { method: 'POST' });
    $('code').textContent = p.code;
    $('modal').hidden = false;
    countdown = Math.max(0, Math.floor((p.expiresAt - Date.now()) / 1000));
    const tick = () => {
      if ($('modal').hidden) return;
      $('codeExpiry').textContent = countdown > 0 ? 'Expires in ' + Math.floor(countdown / 60) + ':' + String(countdown % 60).padStart(2, '0') : 'Code expired — create a new one';
      countdown--; setTimeout(tick, 1000);
    };
    tick();
  } catch (e) { toast(e.message, true); }
}
$('linkClient').onclick = linkClient;
$('closeModal').onclick = () => { $('modal').hidden = true; load(); };
$('copyCode').onclick = async () => { try { await navigator.clipboard.writeText($('code').textContent); toast('Copied'); } catch (e) { toast('Copy failed', true); } };

let sse = null;
function connect() {
  sse = new EventSource('/dashboard/events');
  sse.addEventListener('update', () => load());
  sse.onerror = () => { sse.close(); setTimeout(connect, 5000); };
}
load(); connect(); setInterval(() => { if (current) render(current); }, 10000);
```

- [ ] **Step 5: Wire the embedded assets and test UI**

Create `panel/web/web.go` (the `panel/web` directory is the embed root, so
`internal/web` cannot embed it directly):

```go
package webassets

import (
	"embed"
	"io/fs"
)

//go:embed dashboard.html login.html assets
var FS embed.FS
var Assets, _ = fs.Sub(FS, "assets")
```

In `internal/web/server.go`, import `webassets "gonutspanel/web"`, serve
`/assets/` with `http.FileServer(http.FS(webassets.Assets))`, and render:

```go
func dashboardHTML(csrf string) ([]byte, error) {
	b, err := webassets.FS.ReadFile("dashboard.html")
	if err != nil { return nil, err }
	return []byte(strings.ReplaceAll(string(b), "{{CSRF}}", csrf)), nil
}
```

- [ ] **Step 6: Browser test**

Run server:

```bash
cd panel
GONUTS_DEV_LOGIN=1 GONUTS_PUBLIC_BASE_URL=http://localhost:8080 ../.tools/go/bin/go run ./cmd/gonuts-panel
```

Use the browser tool:
1. Open `http://localhost:8080/dashboard`; sign in via `/auth/dev` or click through.
2. Click Link client; copy code.
3. Run the mock client (Task 10) with the code.
4. Verify the card, values, buttons, Open panel.
5. Screenshot desktop (1280×800) and mobile (390×844); compare with the supplied screenshots.

- [ ] **Step 7: Commit**

```bash
git add panel/web panel/internal/web/server.go
git commit -m "feat(panel): dashboard cards, pairing modal, and actions"
```

---

### Task 10: Mock client and end-to-end tests

**Files:**
- Create: `panel/cmd/mockclient/main.go`
- Test: `panel/internal/web/web_test.go` (extend)

**Interfaces:**
- Produces: a runnable mock mod for manual browser tests.
- Produces: an in-process mock helper (`startInProcessMock`) for tests.

- [ ] **Step 1: Implement mock client**

```go
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type pairResponse struct {
	InstallationID int64  `json:"installationId"`
	Credential     string `json:"credential"`
	WSURL          string `json:"wsUrl"`
}

type mock struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (m *mock) write(v any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conn.WriteJSON(v)
}

func telemetry() map[string]any {
	return map[string]any{
		"type": "telemetry", "at": time.Now().UnixMilli(),
		"state": "SCANNING", "detail": "Evaluating configured trades", "account": "MockAccount",
		"listed": 1, "slots": 18, "bank": 128000000, "trades": 23,
		"profit": map[string]any{"h1": 19000, "h24": 45000, "source": "booked"},
		"sales": map[string]any{"h1": 2, "h24": 22},
		"purchases": map[string]any{"h24": 24},
		"listings": map[string]any{"h24": 8},
		"reprices": map[string]any{"h24": 0},
		"build": "mock-1", "lastAction": "Evaluating configured trades", "lastActionAt": time.Now().UnixMilli(),
		"mascotFace": "WATCH", "swarm": map[string]any{"enabled": false},
		"controls": map[string]any{"pause": true, "resume": false, "snapshot": true},
	}
}

func main() {
	base := flag.String("base", "http://localhost:8080", "relay base URL")
	code := flag.String("code", "", "pairing code")
	name := flag.String("name", "Mock bot", "client label")
	flag.Parse()
	if *code == "" { log.Fatal("-code is required") }
	body, _ := json.Marshal(map[string]any{"code": *code, "protocols": []int{1}, "name": *name,
		"build": "mock-1", "hive": "mock", "capabilities": []string{"pause", "resume", "snapshot", "panel"}})
	resp, err := http.Post(*base+"/dashboard/api/pair/redeem", "application/json", bytes.NewReader(body))
	if err != nil { log.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != 201 { log.Fatalf("redeem: %s", resp.Status) }
	var pr pairResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil { log.Fatal(err) }
	log.Printf("paired installation %d", pr.InstallationID)
	url := pr.WSURL
	if strings.HasPrefix(url, "https") { url = "wss" + strings.TrimPrefix(url, "http") }
	if strings.HasPrefix(url, "http") { url = "ws" + strings.TrimPrefix(url, "http") }
	conn, _, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer " + pr.Credential}})
	if err != nil { log.Fatal(err) }
	defer conn.Close()
	m := &mock{conn: conn}
	if err := m.write(map[string]any{"type": "hello", "protocols": []int{1}, "build": "mock-1",
		"name": *name, "hive": "mock", "capabilities": []string{"pause", "resume", "snapshot", "panel"}}); err != nil { log.Fatal(err) }
	if err := m.write(telemetry()); err != nil { log.Fatal(err) }
	go func() {
		t := time.NewTicker(10 * time.Second); defer t.Stop()
		for range t.C { _ = m.write(telemetry()) }
	}()
	for {
		_, data, err := conn.ReadMessage()
		if err != nil { log.Fatal(err) }
		var frame map[string]any
		if json.Unmarshal(data, &frame) != nil { continue }
		switch frame["type"] {
		case "welcome":
			log.Printf("welcome: %v", frame)
		case "ping":
			_ = m.write(map[string]any{"type": "pong", "at": frame["at"]})
		case "command":
			id, _ := frame["id"].(string)
			_ = m.write(map[string]any{"type": "ack", "id": id})
			_ = m.write(map[string]any{"type": "result", "id": id, "status": "completed", "reason": ""})
			_ = m.write(telemetry())
		case "panel":
			handlePanel(m, frame)
		}
	}
}

func handlePanel(m *mock, frame map[string]any) {
	id, _ := frame["id"].(string)
	op, _ := frame["op"].(string)
	reply := map[string]any{"type": "panel_result", "id": id, "status": 200}
	switch op {
	case "page":
		reply["contentType"] = "text/html; charset=utf-8"
		reply["body"] = `<!doctype html><html><head><title>Mock panel</title></head><body style="background:#0c121b;color:#f0eee7;font-family:monospace"><h1 style="color:#f4cd7a">Mock panel</h1><p>This is the mod's panel placeholder.</p><button onclick="fetch('/act',{method:'POST',headers:{'X-GoNuts':'1','Content-Type':'application/x-www-form-urlencoded'},body:'id=ctl:start'})">Start</button></body></html>`
	case "state":
		reply["contentType"] = "application/json"; reply["body"] = `{"pageId":"MONEY","pages":[]}`
	case "data", "change":
		reply["contentType"] = "application/json"; reply["body"] = `{"ok":true}`
	case "act":
		reply["status"] = 204; reply["contentType"] = "text/plain"; reply["body"] = ""
	case "png", "icon", "asset":
		reply["status"] = 404; reply["contentType"] = "text/plain"; reply["body"] = "Not found"
	default:
		reply["status"] = 400; reply["contentType"] = "text/plain"; reply["body"] = "Bad op"
	}
	_ = m.write(reply)
}
```

- [ ] **Step 2: In-process mock helper**

Add to `panel/internal/web/web_test.go`:

```go
type inProcessMock struct {
	conn           *websocket.Conn
	mu             sync.Mutex
	installationID int64
	panelFrames    chan map[string]any
}

func (m *inProcessMock) write(v any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conn.WriteJSON(v)
}

func (m *inProcessMock) telemetry(account string) error {
	return m.write(map[string]any{"type": "telemetry", "at": time.Now().UnixMilli(),
		"state": "SCANNING", "detail": "Evaluating configured trades", "account": account,
		"listed": 1, "slots": 18, "bank": 128000000, "trades": 23,
		"profit": map[string]any{"h1": 19000, "h24": 45000, "source": "booked"},
		"sales": map[string]any{"h1": 2, "h24": 22}, "purchases": map[string]any{"h24": 24},
		"listings": map[string]any{"h24": 8}, "reprices": map[string]any{"h24": 0},
		"build": "mock-1", "lastAction": "Evaluating configured trades", "lastActionAt": time.Now().UnixMilli(),
		"mascotFace": "WATCH", "swarm": map[string]any{"enabled": false},
		"controls": map[string]any{"pause": true, "resume": false, "snapshot": true}})
}

func startInProcessMock(t *testing.T, baseURL, code string) *inProcessMock {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"code": code, "protocols": []int{1}, "name": "Mock bot",
		"build": "mock-1", "hive": "mock", "capabilities": []string{"pause", "resume", "snapshot", "panel"}})
	resp, err := http.Post(baseURL+"/dashboard/api/pair/redeem", "application/json", bytes.NewReader(body))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != 201 { t.Fatalf("redeem status=%d", resp.StatusCode) }
	var pr struct {
		InstallationID int64  `json:"installationId"`
		Credential     string `json:"credential"`
		WSURL          string `json:"wsUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil { t.Fatal(err) }
	url := pr.WSURL
	if strings.HasPrefix(url, "https") { url = "wss" + strings.TrimPrefix(url, "http") }
	if strings.HasPrefix(url, "http") { url = "ws" + strings.TrimPrefix(url, "http") }
	conn, _, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer " + pr.Credential}})
	if err != nil { t.Fatal(err) }
	m := &inProcessMock{conn: conn, installationID: pr.InstallationID, panelFrames: make(chan map[string]any, 8)}
	if err := m.write(map[string]any{"type": "hello", "protocols": []int{1}, "build": "mock-1",
		"name": "Mock bot", "hive": "mock", "capabilities": []string{"pause", "resume", "snapshot", "panel"}}); err != nil { t.Fatal(err) }
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil || welcome["type"] != "welcome" { t.Fatalf("welcome=%v err=%v", welcome, err) }
	go func() {
		for {
			var f map[string]any
			if conn.ReadJSON(&f) != nil { return }
			switch f["type"] {
			case "ping":
				_ = m.write(map[string]any{"type": "pong", "at": f["at"]})
			case "command":
				id, _ := f["id"].(string)
				_ = m.write(map[string]any{"type": "ack", "id": id})
				_ = m.write(map[string]any{"type": "result", "id": id, "status": "completed", "reason": "trading paused"})
				_ = m.telemetry("MockAccount")
			case "panel":
				m.panelFrames <- f
				reply := map[string]any{"type": "panel_result", "id": f["id"], "status": 200}
				switch f["op"] {
				case "page":
					reply["contentType"] = "text/html; charset=utf-8"
					reply["body"] = `<head></head><body><h1>Mock panel</h1><img src="/logo.png"><form class="out" method="post" action="/logout"></form><a href="https://gonuts.at/dashboard/bugs">bugs</a><script>fetch('/state');fetch('/act')</script></body>`
				case "state", "data", "change":
					reply["contentType"] = "application/json"; reply["body"] = `{"ok":true}`
				case "act":
					reply["status"] = 204; reply["contentType"] = "text/plain"; reply["body"] = ""
				default:
					reply["status"] = 404; reply["contentType"] = "text/plain"; reply["body"] = "Not found"
				}
				_ = m.write(reply)
			}
		}
	}()
	return m
}

func (m *inProcessMock) close() { m.conn.Close() }
```

- [ ] **Step 3: Write the end-to-end web test**

```go
func TestEndToEndPairTelemetryCommandPanel(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	defer st.Close()
	hub := relay.NewHub(st, relay.Options{HeartbeatSeconds: 20, MaxMessageBytes: 32768,
		MaxPanelInFlight: 8, PanelTimeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	go hub.Start(ctx)
	defer hub.Stop()
	defer cancel()

	ts := httptest.NewUnstartedServer(nil)
	cfg := config.Config{PublicBaseURL: "http://" + ts.Listener.Addr().String(),
		DevLogin: true, PanelCacheBytes: 1 << 20}
	s := New(cfg, st, hub, nil)
	ts.Config.Handler = s.Handler()
	ts.Start()
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(ts.URL + "/auth/dev")
	if err != nil { t.Fatal(err) }
	resp.Body.Close()
	resp, err = client.Get(ts.URL + "/dashboard")
	if err != nil { t.Fatal(err) }
	page, _ := io.ReadAll(resp.Body); resp.Body.Close()
	m := regexp.MustCompile(`name="gonuts-csrf" content="([^"]+)"`).FindSubmatch(page)
	if len(m) != 2 { t.Fatalf("no csrf in dashboard: %s", page) }
	csrf := string(m[1])

	req, _ := http.NewRequest("POST", ts.URL+"/dashboard/api/pair/code", nil)
	req.Header.Set("X-Gonuts-Csrf", csrf)
	req.Header.Set("Origin", ts.URL)
	resp, err = client.Do(req)
	if err != nil { t.Fatal(err) }
	var pairCode struct{ Code string `json:"code"` }
	json.NewDecoder(resp.Body).Decode(&pairCode); resp.Body.Close()
	if pairCode.Code == "" { t.Fatal("no pairing code") }

	mock := startInProcessMock(t, ts.URL, pairCode.Code)
	defer mock.close()
	waitWeb(t, "online", func() bool { return hub.Online(mock.installationID) })
	if err := mock.telemetry("MockAccount"); err != nil { t.Fatal(err) }

	state := func() map[string]any {
		req, _ := http.NewRequest("GET", ts.URL+"/dashboard/api/state", nil)
		resp, err := client.Do(req)
		if err != nil { t.Fatal(err) }
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil { t.Fatal(err) }
		return body
	}
	waitWeb(t, "telemetry", func() bool {
		b := state()
		list, _ := b["installations"].([]any)
		if len(list) != 1 { return false }
		inst := list[0].(map[string]any)
		tel, _ := inst["telemetry"].(map[string]any)
		return tel != nil && tel["account"] == "MockAccount"
	})

	req, _ = http.NewRequest("POST", ts.URL+"/dashboard/api/installations/"+
		strconv.FormatInt(mock.installationID, 10)+"/command", strings.NewReader(`{"command":"pause"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gonuts-Csrf", csrf)
	req.Header.Set("Origin", ts.URL)
	resp, err = client.Do(req)
	if err != nil { t.Fatal(err) }
	resp.Body.Close()
	if resp.StatusCode != 202 { t.Fatalf("command status=%d", resp.StatusCode) }
	waitWeb(t, "command result", func() bool {
		b := state()
		list, _ := b["installations"].([]any)
		if len(list) != 1 { return false }
		last, _ := list[0].(map[string]any)["lastCommand"].(map[string]any)
		return last != nil && last["state"] == "completed"
	})

	panelURL := ts.URL + "/dashboard/panel/" + strconv.FormatInt(mock.installationID, 10) + "/"
	resp, err = client.Get(panelURL)
	if err != nil { t.Fatal(err) }
	panel, _ := io.ReadAll(resp.Body); resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(panel), "Mock panel") ||
		!strings.Contains(string(panel), `src="logo.png"`) || strings.Contains(string(panel), "gonuts.at") {
		t.Fatalf("panel status=%d body=%s", resp.StatusCode, panel)
	}

	req, _ = http.NewRequest("POST", panelURL+"act", strings.NewReader("id=ctl:start"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-GoNuts", "1")
	req.Header.Set("X-Gonuts-Csrf", csrf)
	req.Header.Set("Origin", ts.URL)
	resp, err = client.Do(req)
	if err != nil { t.Fatal(err) }
	resp.Body.Close()
	if resp.StatusCode != 204 { t.Fatalf("act status=%d", resp.StatusCode) }
	select {
	case f := <-mock.panelFrames:
		if f["op"] != "page" { t.Fatalf("first panel frame=%v", f) }
	case <-time.After(time.Second):
		t.Fatal("mock did not receive page request")
	}
	select {
	case f := <-mock.panelFrames:
		if f["op"] != "act" { t.Fatalf("act frame=%v", f) }
	case <-time.After(time.Second):
		t.Fatal("mock did not receive act")
	}
}

func waitWeb(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok() { return }
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}
```

Update Task 10's file list to remove `panel/internal/relay/mock_test.go` and
`panel/internal/mockclient`; the in-process mock lives in `web_test.go`.

- [ ] **Step 4: Run all tests**

Run: `cd panel && ../.tools/go/bin/go test ./... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add panel/cmd/mockclient panel/internal/web/web_test.go
git commit -m "test(panel): mock client and end-to-end relay flow"
```

---

### Task 11: Mod link module, endpoint patch, and JAR build

**Files:**
- Create: `mod/trader-fabric/src/main/java/dev/doughbay/fabric/hosted/RelayLink.java`
- Modify: `mod/trader-fabric/src/main/java/dev/doughbay/fabric/hosted/DashboardProtocol.java`
- Modify: `mod/trader-fabric/src/main/java/dev/doughbay/fabric/hosted/HostedDashboardClient.java`
- Modify: `mod/trader-fabric/src/main/java/dev/doughbay/fabric/DashboardWebsiteAccess.java`
- Modify: `mod/trader-fabric/src/main/java/dev/doughbay/fabric/DashboardScreen.java`
- Test: `mod/trader-fabric/src/test/java/dev/doughbay/fabric/hosted/RelayLinkTest.java`
- Test: `mod/trader-fabric/src/test/java/dev/doughbay/fabric/hosted/DashboardProtocolTest.java` (update)
- Output: `patches/relay-link.patch`, `dist/doughbay-0.1.2-swarm+26.2.jar`

**Interfaces:**
- Produces: `RelayLink.enabled()`, `RelayLink.page()`, `RelayLink.redeem()`,
  `RelayLink.check()`, `RelayLink.socket()`, `RelayLink.hostLabel()`,
  `RelayLink.setForTest(String)`.
- `DashboardProtocol` keeps all existing helpers but derives the four URIs from `RelayLink`.

- [ ] **Step 1: Create the mod worktree**

```bash
mkdir -p patches
git -C upstream worktree add ../mod -b selfhost
```

Add `mod/`, `dist/`, `panel/dist/` to `.gitignore`.

- [ ] **Step 2: Write failing RelayLinkTest**

```java
package dev.doughbay.fabric.hosted;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RelayLinkTest {
    @Test void derivesEndpoints() {
        RelayLink.setForTest("https://panel.example.com");
        assertTrue(RelayLink.enabled());
        assertEquals("https://panel.example.com/dashboard/", RelayLink.page().toString());
        assertEquals("https://panel.example.com/dashboard/api/pair/redeem", RelayLink.redeem().toString());
        assertEquals("https://panel.example.com/dashboard/api/client/check", RelayLink.check().toString());
        assertEquals("wss://panel.example.com/dashboard/ws/client", RelayLink.socket().toString());
        assertEquals("panel.example.com", RelayLink.hostLabel());
    }
    @Test void rejectsPathAndInsecureRemote() {
        assertThrows(IllegalArgumentException.class, () -> RelayLink.setForTest("https://panel.example.com/x"));
        assertThrows(IllegalArgumentException.class, () -> RelayLink.setForTest("http://example.com"));
        assertEquals("http://localhost:8080", RelayLink.normalize("http://localhost:8080/"));
    }
    @Test void disabledByDefault() {
        RelayLink.setForTest("");
        assertFalse(RelayLink.enabled());
    }
}
```

- [ ] **Step 3: Implement RelayLink**

Use `FabricLoader.getInstance().getConfigDir().resolve("gonuts-panel-link.json")` in `load()`; catch `Throwable` so tests can run without Fabric. Validate with `URI`:

```java
public final class RelayLink {
    private static final String PROPERTY="gonuts.panel.baseUrl", ENV="GONUTS_PANEL_BASE_URL";
    private static final String LEGACY="https://gonuts.at";
    private static volatile String base=load();
    private RelayLink(){}
    public static boolean enabled(){return base!=null;}
    private static String effective(){return base!=null?base:LEGACY;}
    public static URI page(){return URI.create(effective()+"/dashboard/");}
    public static URI redeem(){return URI.create(effective()+"/dashboard/api/pair/redeem");}
    public static URI check(){return URI.create(effective()+"/dashboard/api/client/check");}
    public static URI socket(){return URI.create(effective().replaceFirst("^http","ws")+"/dashboard/ws/client");}
    public static String hostLabel(){URI u=URI.create(effective());return u.getPort()>0?u.getHost()+":"+u.getPort():u.getHost();}
    public static synchronized void setForTest(String value){base=normalize(value);}
    public static synchronized void reload(){base=load();}
    private static String load(){
        String v=System.getProperty(PROPERTY);
        if(v==null||v.isBlank())v=System.getenv(ENV);
        if(v==null||v.isBlank()){
            try{var p=net.fabricmc.loader.api.FabricLoader.getInstance().getConfigDir().resolve("gonuts-panel-link.json");
                if(java.nio.file.Files.isRegularFile(p))v=DashboardProtocol.JSON.readTree(java.nio.file.Files.readString(p)).path("baseUrl").asText("");
            }catch(Throwable ignored){}
        }
        try{return normalize(v);}catch(IllegalArgumentException e){return null;}
    }
    static String normalize(String value){
        if(value==null||value.isBlank())return null;
        URI u=URI.create(value.strip());
        if(u.getScheme()==null||!(u.getScheme().equals("https")||u.getScheme().equals("http")))throw new IllegalArgumentException("base URL must be http(s)");
        if(u.getHost()==null||u.getHost().isBlank())throw new IllegalArgumentException("base URL needs a host");
        if(u.getRawPath()!=null&&!u.getRawPath().isEmpty()&&!u.getRawPath().equals("/"))throw new IllegalArgumentException("base URL must not have a path");
        if(u.getRawQuery()!=null||u.getRawFragment()!=null||u.getUserInfo()!=null)throw new IllegalArgumentException("base URL must be an origin");
        if(u.getScheme().equals("http")&&!java.util.Set.of("localhost","127.0.0.1","::1").contains(u.getHost().toLowerCase(java.util.Locale.ROOT)))throw new IllegalArgumentException("http is only allowed for localhost");
        return u.getScheme()+"://"+u.getHost()+(u.getPort()>0?":"+u.getPort():"");
    }
}
```

- [ ] **Step 4: Patch DashboardProtocol**

Replace the four static URIs with methods:

```java
public static URI page(){return RelayLink.page();}
public static URI redeem(){return RelayLink.redeem();}
public static URI check(){return RelayLink.check();}
public static URI socket(){return RelayLink.socket();}
```

Update every use. In `HostedDashboardClient`:
- `start`: `if(!ProjectStatus.publicServicesEnabled()&&!RelayLink.enabled()){...RETIRED...}`
- `tick`: same.
- `pair`: `DashboardProtocol.redeem()`, `DashboardProtocol.socket()`, `DashboardProtocol.check()`.
- `connect`: same.
- `HostedDashboardClient.start` may call `CommunityClient` which is retired; unchanged.
- `DashboardWebsiteAccess.address()`: `DashboardProtocol.page().toASCIIString()`.
- `DashboardScreen`: `DashboardProtocol.page()`; text `"Sign in on "+RelayLink.hostLabel()+", choose Link client, then enter its code."`; replace the Swarm sentence with `"Linking connects this bot to your self-hosted dashboard."`.

- [ ] **Step 5: Update DashboardProtocolTest**

Change hard-coded gonuts.at expectations to `RelayLink.setForTest("https://panel.example.com")` and assert derived hosts. Keep the label/code tests unchanged.

- [ ] **Step 6: Run the mod tests and build**

```bash
cd mod
./gradlew :trader-fabric:test --tests 'dev.doughbay.fabric.hosted.*'
./gradlew :trader-fabric:build
ls -l trader-fabric/build/libs/
```

Expected: tests pass; JAR built. Copy it:

```bash
mkdir -p ../dist
cp trader-fabric/build/libs/doughbay-0.1.2-swarm+26.2.jar ../dist/
```

- [ ] **Step 7: Export the patch**

```bash
git -C mod add -A
git -C mod diff --cached > ../patches/relay-link.patch
```

- [ ] **Step 8: Commit plan repo bookkeeping**

```bash
git add .gitignore patches/relay-link.patch
git commit -m "feat(mod): configurable self-hosted dashboard link"
```

- [ ] **Step 9: Live test checklist (user)**

1. Back up the existing mod JAR and `config/doughbay` / world DB.
2. Create `config/gonuts-panel-link.json` with `{"baseUrl":"https://YOUR_PANEL_HOST"}`.
3. Replace the mod JAR with `dist/doughbay-0.1.2-swarm+26.2.jar`.
4. Launch one client; open GoNuts → Dashboard; generate a code on the panel; pair.
5. Verify the card shows online and fresh telemetry; test Pause, Resume, Refresh, Open panel.
6. Confirm trading and the local panel are unaffected.
7. Only then roll the JAR to the other two clients.

---

### Task 12: Deployment artifacts, ARM64 build, and final verification

**Files:**
- Create: `panel/Dockerfile`
- Create: `panel/docker-compose.yml`
- Create: `panel/.env.example`
- Create: `panel/README.md`
- Output: `panel/dist/gonuts-panel-linux-arm64`
- Modify: `.gitignore`

- [ ] **Step 1: Write Dockerfile**

```dockerfile
# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=arm64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/gonuts-panel ./cmd/gonuts-panel

FROM alpine:3.22
RUN adduser -D -u 1000 gonuts \
 && apk add --no-cache ca-certificates tzdata \
 && mkdir -p /data && chown gonuts:gonuts /data
COPY --from=build /out/gonuts-panel /usr/local/bin/gonuts-panel
USER gonuts
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["gonuts-panel"]
```

- [ ] **Step 2: Write compose and env example**

```yaml
services:
  gonuts-panel:
    build: .
    image: gonuts-panel:local
    container_name: gonuts-panel
    restart: unless-stopped
    env_file: .env
    ports:
      - "8080:8080"
    volumes:
      - ./data:/data
    user: "1000:1000"
    # Run `chown -R 1000:1000 ./data` once on the NAS, or use a named volume.
    read_only: true
    tmpfs:
      - /tmp
    mem_limit: 256m
    security_opt:
      - no-new-privileges:true
```

```dotenv
GONUTS_ADDR=:8080
GONUTS_PUBLIC_BASE_URL=https://panel.example.com
GONUTS_DATA_DIR=/data
GONUTS_DISCORD_CLIENT_ID=
GONUTS_DISCORD_CLIENT_SECRET=
GONUTS_ALLOWED_DISCORD_IDS=
GONUTS_TRUST_PROXY=1
GONUTS_DEV_LOGIN=0
GONUTS_COOKIE_SECURE=1
```

- [ ] **Step 3: Write README with Discord app and NAS steps**

Include:

1. Create the Discord application at `https://discord.com/developers/applications`.
2. OAuth2 → Redirects → add `https://YOUR_HOST/auth/callback`.
3. Copy Client ID/Secret into `.env`; scope is `identify`; no bot token.
4. Reverse proxy: Synology DSM → Login Portal → Advanced → Reverse Proxy; source HTTPS `panel.example.com:443`, destination `http://127.0.0.1:8080`; enable WebSocket; HSTS optional.
5. Alternative: Cloudflare Tunnel or Tailscale; set `PUBLIC_BASE_URL` to the exact HTTPS host.
6. Start: `docker compose up -d --build`; logs: `docker logs gonuts-panel`.
7. Native binary: `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 ../.tools/go/bin/go build -o dist/gonuts-panel-linux-arm64 ./cmd/gonuts-panel`; copy to NAS; run with env; use DSM Task Scheduler or a systemd unit.
8. Backup `data/state.json`; permissions 0600; never commit `.env`.
9. Memory: container limit 256 MB; check `docker stats`.

- [ ] **Step 4: Cross-compile ARM64 and verify**

```bash
cd panel
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 ../.tools/go/bin/go build -trimpath -ldflags="-s -w" -o dist/gonuts-panel-linux-arm64 ./cmd/gonuts-panel
node -e "const b=require('fs').readFileSync('dist/gonuts-panel-linux-arm64');console.log('ELF'+(b[4]===2?'64':'32')+' '+(b[18]===183?'AArch64':'other'))"
```

Expected: `ELF64 AArch64`; `ls -lh` shows a single binary under ~20 MB.

- [ ] **Step 5: Final verification**

Run:

```bash
cd panel
../.tools/go/bin/go vet ./...
../.tools/go/bin/go test ./... -count=1
```

Browser checks:
- Desktop 1280×800 and mobile 390×844 screenshots.
- Signed-out login, dev/Discord sign-in, Link client modal, card fields, pause/resume/refresh, rename/unlink, Open panel, offline state.
- No console errors; no external requests.

Security checks:
- POST without CSRF → 403.
- Cross-origin POST → 403.
- Another user cannot see or command the installation.
- `gni1_`/cookie/secret strings absent from logs.
- WS with an `Origin` header is rejected with 4403.

- [ ] **Step 6: Ask before deployment**

Present the ARM64 binary, Docker/compose, `.env.example`, the Discord app guide, and the live-test checklist. Ask the user for:
- NAS runtime (Docker vs native),
- public hostname/tunnel choice,
- Discord client ID/secret (entered by the user, never committed),
- approval before touching the NAS.

- [ ] **Step 7: Commit**

```bash
git add panel/Dockerfile panel/docker-compose.yml panel/.env.example panel/README.md .gitignore
git commit -m "chore(panel): ARM64 deployment artifacts and docs"
```

---

## Self-Review

**Spec coverage:** Tasks 1–10 implement relay, auth, pairing, WS, commands, panel proxy, cards, SSE, UI, tests. Task 11 implements the mod link module and JAR. Task 12 implements deployment and final verification. Every spec section maps to a task.

**Placeholder scan:** No `TBD`/`TODO` remain. Tasks 4, 6, 7, 8, and 10 contain concrete tests; the standalone and in-process mocks are fully written. The only deferred item is the user-run live test in Task 11, which cannot be automated without a Minecraft client.

**Type consistency:** `store.Telemetry`, `store.Installation`, `store.Command`, `relay.PanelResult`, and `auth` signatures are introduced once and reused consistently. `Hub.SendCommand` returns `(string, error)`; `Hub.PanelRequest` returns `(*PanelResult, error)`. `PanelResult.Body` is decoded bytes, so the web layer sets content type and writes it.

**Known execution risk:** the Fabric Loom build downloads Minecraft 26.2 and may take a while. It is isolated in Task 11 and does not block Tasks 1–10.
