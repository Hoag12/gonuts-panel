package webassets

import (
	"regexp"
	"testing"
)

// TestHiddenAttributeIsHonored is a static guard for the dashboard's
// hidden-toggled nodes. .modal sets display:grid and .hive-overview sets display:flex,
// both of which outrank the UA [hidden] rule, so without an explicit [hidden]
// override the pairing overlay renders on load, covers the page, and ignores
// every hidden toggle. Browser rendering is verified separately.
func TestHiddenAttributeIsHonored(t *testing.T) {
	css, err := FS.ReadFile("assets/dashboard.css")
	if err != nil {
		t.Fatalf("read embedded dashboard.css: %v", err)
	}
	override := regexp.MustCompile(`(?s)\[hidden\]\s*\{\s*display\s*:\s*none\s*!important\s*;?\s*\}`)
	if !override.Match(css) {
		t.Fatal("dashboard.css lacks a `[hidden] { display:none !important; }` override")
	}

	page, err := FS.ReadFile("dashboard.html")
	if err != nil {
		t.Fatalf("read embedded dashboard.html: %v", err)
	}
	for _, id := range []string{"modal", "hiveOverview", "empty", "toast"} {
		hidden := regexp.MustCompile(`(?s)<[a-z]+[^>]*\sid="` + id + `"[^>]*\shidden\b`)
		if !hidden.Match(page) {
			t.Errorf("dashboard.html node id=%q is not hidden by default", id)
		}
	}
}
