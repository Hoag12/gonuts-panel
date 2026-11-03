package config

import "testing"

// clearAuthEnv removes every sign-in variable from the test environment so a
// case only sees what it sets. t.Setenv("") reads as unset for os.Getenv.
func clearAuthEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"GONUTS_PUBLIC_BASE_URL",
		"GONUTS_DISCORD_CLIENT_ID",
		"GONUTS_DISCORD_CLIENT_SECRET",
		"GONUTS_ALLOWED_DISCORD_IDS",
		"GONUTS_DEV_LOGIN",
		"GONUTS_LOCAL_PASSWORD_HASH",
		"GONUTS_LOCAL_PASSWORD",
		"GONUTS_LOCAL_USER",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadDefaultsAndNormalizes(t *testing.T) {
	clearAuthEnv(t)
	// Dev login is only allowed on a loopback origin, so this test uses one.
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "http://localhost:8080/")
	t.Setenv("GONUTS_DEV_LOGIN", "1")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicBaseURL != "http://localhost:8080" {
		t.Fatalf("base=%q", cfg.PublicBaseURL)
	}
	if !cfg.DevLogin || cfg.Addr != ":8080" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadRejectsDevLoginOnPublicOrigin(t *testing.T) {
	clearAuthEnv(t)
	// A public HTTPS base (a Codespace or NAS) must never mint dev sessions.
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "https://gonuts-panel-8080.app.github.dev")
	t.Setenv("GONUTS_DEV_LOGIN", "1")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for dev login on a public origin")
	}

	// The other loopback spellings remain valid.
	for _, base := range []string{"http://127.0.0.1:8080", "http://[::1]:8080", "https://localhost"} {
		t.Setenv("GONUTS_PUBLIC_BASE_URL", base)
		if cfg, err := Load(); err != nil || !cfg.DevLogin {
			t.Fatalf("base %q: cfg=%+v err=%v", base, cfg, err)
		}
	}
}

func TestLoadRejectsBadBaseURL(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "https://panel.example.com/path")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for path in base URL")
	}
}

func TestLoadLocalHashWithoutDiscord(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "http://192.168.1.20:8080")
	t.Setenv("GONUTS_LOCAL_PASSWORD_HASH", "pbkdf2-sha256$600000$c2FsdA$a2V5")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("local-hash-only startup rejected: %v", err)
	}
	if cfg.DiscordEnabled {
		t.Fatal("Discord marked enabled without credentials")
	}
	if !cfg.LocalAuthEnabled() || cfg.LocalUser != "local" {
		t.Fatalf("local auth=%v user=%q", cfg.LocalAuthEnabled(), cfg.LocalUser)
	}
	if cfg.CookieSecure {
		t.Fatal("plain http base should default to an insecure cookie")
	}
}

func TestLoadLocalPlaintextFallback(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "https://panel.example.com")
	t.Setenv("GONUTS_LOCAL_PASSWORD", "correct horse ")
	t.Setenv("GONUTS_LOCAL_USER", "owner")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LocalAuthEnabled() || cfg.LocalPassword != "correct horse " {
		t.Fatalf("local password=%q enabled=%v", cfg.LocalPassword, cfg.LocalAuthEnabled())
	}
	if cfg.LocalUser != "owner" {
		t.Fatalf("local user=%q", cfg.LocalUser)
	}
}

func TestLoadRejectsNoSignInMethod(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "https://panel.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("startup without Discord, local password, or dev login was accepted")
	}
}

func TestLoadIgnoresWhitespaceOnlyPlaintext(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "https://panel.example.com")
	t.Setenv("GONUTS_LOCAL_PASSWORD", "   ")
	if _, err := Load(); err == nil {
		t.Fatal("a whitespace-only local password counted as a sign-in method")
	}
}

func TestLoadDiscordOnlyStillWorks(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "https://panel.example.com")
	t.Setenv("GONUTS_DISCORD_CLIENT_ID", "id")
	t.Setenv("GONUTS_DISCORD_CLIENT_SECRET", "secret")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DiscordEnabled || cfg.LocalAuthEnabled() {
		t.Fatalf("discord=%v local=%v", cfg.DiscordEnabled, cfg.LocalAuthEnabled())
	}
}

func TestLoadAllowsDiscordAndLocalTogether(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "https://panel.example.com")
	t.Setenv("GONUTS_DISCORD_CLIENT_ID", "id")
	t.Setenv("GONUTS_DISCORD_CLIENT_SECRET", "secret")
	t.Setenv("GONUTS_LOCAL_PASSWORD_HASH", "pbkdf2-sha256$600000$c2FsdA$a2V5")
	t.Setenv("GONUTS_LOCAL_USER", "owner")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DiscordEnabled || !cfg.LocalAuthEnabled() || cfg.LocalUser != "owner" {
		t.Fatalf("cfg=%+v", cfg)
	}
}

func TestLoadDevLoginStillRequiresLoopback(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "http://192.168.1.20:8080")
	t.Setenv("GONUTS_DEV_LOGIN", "1")
	t.Setenv("GONUTS_LOCAL_PASSWORD_HASH", "pbkdf2-sha256$1000$c2FsdA$a2V5")
	if _, err := Load(); err == nil {
		t.Fatal("dev login on a LAN origin was accepted")
	}
}
