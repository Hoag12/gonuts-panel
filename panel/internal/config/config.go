package config

import (
	"crypto/sha256"
	"fmt"
	"net"
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
	Addr          string
	PublicBaseURL string
	// ExtraOrigins are additional origins (for example a tailnet address) that
	// mutations may come from; PublicBaseURL is always accepted as well.
	ExtraOrigins        []string
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
	// RemoteStateURL is a PostgreSQL URL used to mirror panel state so
	// accounts and sessions survive a redeploy on ephemeral hosting.
	RemoteStateURL string
	// SwarmSecret signs stateless community credentials so enrollments
	// survive restarts without storage.
	SwarmSecret []byte
	// HideLocalLogin keeps the local password endpoint available for
	// automation (the bridge signs in with it) while the login page offers
	// only Discord.
	HideLocalLogin bool
	// AuthDisabled auto-creates a loopback-only session for the dashboard.
	// It is refused unless both GONUTS_ADDR and GONUTS_PUBLIC_BASE_URL are
	// loopback, so a LAN/public panel can never expose unauthenticated controls
	// by accident. AllowUnauthLAN is the explicit opt-out of that guard.
	AuthDisabled bool
	// AllowUnauthLAN permits GONUTS_AUTH_DISABLED with a non-loopback bind.
	// Off by default: anyone who can reach the panel gets full bot control, so
	// this must be a deliberate operator choice (GONUTS_ALLOW_UNAUTH_LAN=1).
	AllowUnauthLAN bool
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
		LocalPassword:  os.Getenv("GONUTS_LOCAL_PASSWORD"),
		LocalUser:      env("GONUTS_LOCAL_USER", "local"),
		RemoteStateURL: strings.TrimSpace(os.Getenv("GONUTS_REMOTE_STATE_URL")),
		AuthDisabled:   boolEnv("GONUTS_AUTH_DISABLED", false),
		AllowUnauthLAN: boolEnv("GONUTS_ALLOW_UNAUTH_LAN", false),
	}
	extraOrigins, err := parseExtraOrigins(os.Getenv("GONUTS_EXTRA_ORIGINS"))
	if err != nil {
		return Config{}, err
	}
	cfg.ExtraOrigins = extraOrigins
	cfg.DiscordEnabled = cfg.DiscordClientID != "" && cfg.DiscordClientSecret != ""
	for _, id := range strings.Split(os.Getenv("GONUTS_ALLOWED_DISCORD_IDS"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			cfg.AllowedDiscordIDs[id] = true
		}
	}
	if n, err := strconv.ParseInt(os.Getenv("GONUTS_PANEL_CACHE_BYTES"), 10, 64); err == nil && n > 0 {
		cfg.PanelCacheBytes = n
	}
	sum := sha256.Sum256([]byte("gonuts-swarm|" + base + "|" + cfg.LocalPassword + "|" + cfg.LocalPasswordHash))
	cfg.SwarmSecret = sum[:]
	cfg.CookieSecure = boolEnv("GONUTS_COOKIE_SECURE", strings.HasPrefix(base, "https://"))
	cfg.HideLocalLogin = boolEnv("GONUTS_HIDE_LOCAL_LOGIN", false)
	if cfg.DevLogin && !IsLoopbackBaseURL(base) {
		return Config{}, fmt.Errorf("GONUTS_DEV_LOGIN requires a loopback GONUTS_PUBLIC_BASE_URL (localhost, 127.0.0.1, or [::1])")
	}
	if cfg.AuthDisabled && !cfg.AllowUnauthLAN {
		if !IsLoopbackBaseURL(base) {
			return Config{}, fmt.Errorf("GONUTS_AUTH_DISABLED requires a loopback GONUTS_PUBLIC_BASE_URL (or set GONUTS_ALLOW_UNAUTH_LAN=1)")
		}
		if !IsLoopbackAddr(cfg.Addr) {
			return Config{}, fmt.Errorf("GONUTS_AUTH_DISABLED requires GONUTS_ADDR to bind loopback, e.g. 127.0.0.1:8080 (or set GONUTS_ALLOW_UNAUTH_LAN=1)")
		}
	}
	// Mirror auth.HashPassword's minimum so the plaintext fallback cannot be a
	// password the hash generator would refuse. The raw value is measured, not
	// a trimmed copy, because the comparison and the generator both use the
	// exact bytes.
	if strings.TrimSpace(cfg.LocalPassword) != "" && len(cfg.LocalPassword) < minLocalPasswordLength {
		return Config{}, fmt.Errorf("GONUTS_LOCAL_PASSWORD must be at least %d characters", minLocalPasswordLength)
	}
	if !cfg.DevLogin && !cfg.DiscordEnabled && !cfg.LocalAuthEnabled() && !cfg.AuthDisabled {
		return Config{}, fmt.Errorf("Discord client id/secret or GONUTS_LOCAL_PASSWORD_HASH/GONUTS_LOCAL_PASSWORD are required unless GONUTS_DEV_LOGIN=1 or GONUTS_AUTH_DISABLED=1")
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

// IsLoopbackAddr reports whether a listen address binds only a loopback
// interface. An address with an empty host (":8080") binds every interface and
// is deliberately refused for unauthenticated mode.
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch strings.ToLower(host) {
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

// parseExtraOrigins accepts a comma separated list of additional origins the
// dashboard may be reached on (for example a tailnet address). Each entry must
// be a bare http(s) origin so the CSRF comparison stays exact.
func parseExtraOrigins(raw string) ([]string, error) {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		u, err := url.Parse(item)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("GONUTS_EXTRA_ORIGINS entry %q must be an absolute http(s) origin", item)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("GONUTS_EXTRA_ORIGINS entry %q must use http or https", item)
		}
		if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return nil, fmt.Errorf("GONUTS_EXTRA_ORIGINS entry %q must be an origin without a path", item)
		}
		out = append(out, u.Scheme+"://"+u.Host)
	}
	return out, nil
}
