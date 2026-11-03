package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// minLocalPasswordLength matches auth.MinPasswordLength. config cannot import
// auth (auth imports config for the Discord settings), so the bound is
// duplicated here and enforced again by HashPassword.
const minLocalPasswordLength = 4

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
	// DiscordEnabled is true when both the client id and secret are set. The
	// Discord routes answer 404 otherwise.
	DiscordEnabled bool
	// LocalPasswordHash is the preferred PBKDF2 hash for local sign-in.
	LocalPasswordHash string
	// LocalPassword is a plaintext fallback for local sign-in. It is compared
	// in constant time, but operators should prefer LocalPasswordHash.
	LocalPassword string
	// LocalUser is the account id and display name local sign-in creates.
	LocalUser string
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
		LocalPasswordHash:   strings.TrimSpace(os.Getenv("GONUTS_LOCAL_PASSWORD_HASH")),
		// Not trimmed: a password may legitimately end in a space, and the
		// hash generator uses the exact bytes the operator typed.
		LocalPassword: os.Getenv("GONUTS_LOCAL_PASSWORD"),
		LocalUser:     env("GONUTS_LOCAL_USER", "local"),
	}
	cfg.DiscordEnabled = cfg.DiscordClientID != "" && cfg.DiscordClientSecret != ""
	for _, id := range strings.Split(os.Getenv("GONUTS_ALLOWED_DISCORD_IDS"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			cfg.AllowedDiscordIDs[id] = true
		}
	}
	if n, err := strconv.ParseInt(os.Getenv("GONUTS_PANEL_CACHE_BYTES"), 10, 64); err == nil && n > 0 {
		cfg.PanelCacheBytes = n
	}
	cfg.CookieSecure = boolEnv("GONUTS_COOKIE_SECURE", strings.HasPrefix(base, "https://"))
	if cfg.DevLogin && !IsLoopbackBaseURL(base) {
		return Config{}, fmt.Errorf("GONUTS_DEV_LOGIN requires a loopback GONUTS_PUBLIC_BASE_URL (localhost, 127.0.0.1, or [::1])")
	}
	// Mirror auth.HashPassword's minimum so the plaintext fallback cannot be a
	// password the hash generator would refuse. The raw value is measured, not
	// a trimmed copy, because the comparison and the generator both use the
	// exact bytes.
	if strings.TrimSpace(cfg.LocalPassword) != "" && len(cfg.LocalPassword) < minLocalPasswordLength {
		return Config{}, fmt.Errorf("GONUTS_LOCAL_PASSWORD must be at least %d characters", minLocalPasswordLength)
	}
	if !cfg.DevLogin && !cfg.DiscordEnabled && !cfg.LocalAuthEnabled() {
		return Config{}, fmt.Errorf("Discord client id/secret or GONUTS_LOCAL_PASSWORD_HASH/GONUTS_LOCAL_PASSWORD are required unless GONUTS_DEV_LOGIN=1")
	}
	return cfg, nil
}

// LocalAuthEnabled reports whether a local password or hash can sign a browser
// in. A whitespace-only plaintext value counts as unset, but spaces inside a
// real password are preserved. LocalUser always has a value (default "local").
func (c Config) LocalAuthEnabled() bool {
	return c.LocalPasswordHash != "" || strings.TrimSpace(c.LocalPassword) != ""
}

// IsLoopbackBaseURL reports whether base is an http(s) origin whose host is
// loopback. Dev login mints a session without any Discord proof, so it is only
// safe to expose on a loopback origin; a public Codespace or NAS host would let
// anyone who can reach the port sign in.
func IsLoopbackBaseURL(base string) bool {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
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
