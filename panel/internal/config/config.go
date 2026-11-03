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
	if cfg.DevLogin && !IsLoopbackBaseURL(base) {
		return Config{}, fmt.Errorf("GONUTS_DEV_LOGIN requires a loopback GONUTS_PUBLIC_BASE_URL (localhost, 127.0.0.1, or [::1])")
	}
	if !cfg.DevLogin && (cfg.DiscordClientID == "" || cfg.DiscordClientSecret == "") {
		return Config{}, fmt.Errorf("Discord client id/secret are required unless GONUTS_DEV_LOGIN=1")
	}
	return cfg, nil
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
