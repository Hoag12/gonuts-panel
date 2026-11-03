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
