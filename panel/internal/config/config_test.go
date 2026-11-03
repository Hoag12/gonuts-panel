package config

import "testing"

func TestLoadDefaultsAndNormalizes(t *testing.T) {
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
	t.Setenv("GONUTS_PUBLIC_BASE_URL", "https://panel.example.com/path")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for path in base URL")
	}
}
