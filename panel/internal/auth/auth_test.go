package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gonutspanel/internal/config"
)

func TestPKCE(t *testing.T) {
	v, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) < 43 || !VerifyPKCE(v, Challenge(v)) {
		t.Fatal("bad pkce")
	}
	if VerifyPKCE(v+"x", Challenge(v)) {
		t.Fatal("verifier mismatch accepted")
	}
}

func TestRandomTokenAndHash(t *testing.T) {
	a, err := RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 43 || a == b {
		t.Fatalf("tokens a=%q b=%q", a, b)
	}
	if _, err := RandomToken(0); err == nil {
		t.Fatal("zero-size token accepted")
	}
	if HashToken("x") != HashToken("x") || HashToken("x") == HashToken("y") {
		t.Fatal("hash is not deterministic or distinct")
	}
	if !Equal("secret", "secret") || Equal("secret", "secreu") {
		t.Fatal("constant-time compare is wrong")
	}
}

func TestOriginAllowed(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/dashboard", nil)
	r.Header.Set("Origin", "https://panel.example.com")
	if !OriginAllowed(r, "https://panel.example.com") {
		t.Fatal("same origin rejected")
	}
	r.Header.Set("Origin", "https://evil.example")
	if OriginAllowed(r, "https://panel.example.com") {
		t.Fatal("cross origin accepted")
	}

	cases := []struct {
		name, origin, referer, base string
		want                        bool
	}{
		{"case-insensitive host", "https://PANEL.example.com", "", "https://panel.example.com", true},
		{"scheme mismatch", "http://panel.example.com", "", "https://panel.example.com", false},
		{"referer fallback keeps path", "", "https://panel.example.com/dashboard?x=1", "https://panel.example.com", true},
		{"referer fallback cross origin", "", "https://evil.example/x", "https://panel.example.com", false},
		{"missing both", "", "", "https://panel.example.com", false},
		{"opaque origin", "null", "", "https://panel.example.com", false},
		{"userinfo trick", "https://panel.example.com@evil.example", "", "https://panel.example.com", false},
		{"port mismatch", "https://panel.example.com:8443", "", "https://panel.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://localhost/dashboard", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				r.Header.Set("Referer", tc.referer)
			}
			if got := OriginAllowed(r, tc.base); got != tc.want {
				t.Fatalf("OriginAllowed(%q, %q) = %v, want %v", tc.origin, tc.base, got, tc.want)
			}
		})
	}
}

func TestSessionCookies(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "tok", true)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%v", cookies)
	}
	c := cookies[0]
	if c.Name != CookieName || c.Value != "tok" || c.Path != "/" || !c.HttpOnly ||
		!c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 30*24*60*60 {
		t.Fatalf("session cookie=%+v", c)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	if got := CookieToken(r); got != "tok" {
		t.Fatalf("CookieToken=%q", got)
	}
	if got := CookieToken(httptest.NewRequest("GET", "/", nil)); got != "" {
		t.Fatalf("CookieToken without cookie=%q", got)
	}

	rec = httptest.NewRecorder()
	SetSessionCookie(rec, "tok", false)
	if rec.Result().Cookies()[0].Secure {
		t.Fatal("insecure session cookie marked Secure")
	}

	rec = httptest.NewRecorder()
	ClearSessionCookie(rec, true)
	c = rec.Result().Cookies()[0]
	if c.Name != CookieName || c.Value != "" || c.MaxAge >= 0 || !c.HttpOnly || !c.Secure {
		t.Fatalf("cleared session cookie=%+v", c)
	}
}

func TestOAuthCookies(t *testing.T) {
	rec := httptest.NewRecorder()
	SetOAuthCookie(rec, "state", true)
	c := rec.Result().Cookies()[0]
	if c.Name != OAuthCookie || c.Value != "state" || c.Path != "/" || !c.HttpOnly ||
		!c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 600 {
		t.Fatalf("oauth cookie=%+v", c)
	}

	rec = httptest.NewRecorder()
	ClearOAuthCookie(rec, false)
	c = rec.Result().Cookies()[0]
	if c.Name != OAuthCookie || c.Value != "" || c.MaxAge >= 0 || c.Secure {
		t.Fatalf("cleared oauth cookie=%+v", c)
	}
}

func TestAuthorizeURLFor(t *testing.T) {
	d := &Discord{
		ClientID:     "id",
		RedirectURI:  "http://localhost/auth/callback",
		AuthorizeURL: "https://discord.com/oauth2/authorize",
	}
	u, err := url.Parse(d.AuthorizeURLFor("state123", "challenge123"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "discord.com" || u.Path != "/oauth2/authorize" {
		t.Fatalf("url=%s", u)
	}
	q := u.Query()
	want := map[string]string{
		"client_id":             "id",
		"redirect_uri":          "http://localhost/auth/callback",
		"response_type":         "code",
		"scope":                 "identify",
		"state":                 "state123",
		"code_challenge":        "challenge123",
		"code_challenge_method": "S256",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Fatalf("%s=%q, want %q", k, q.Get(k), v)
		}
	}
}

func TestNewDiscordFromConfig(t *testing.T) {
	d := NewDiscord(config.Config{
		DiscordClientID:     "id",
		DiscordClientSecret: "sec",
		OAuthAuthorizeURL:   "https://discord.com/oauth2/authorize",
		DiscordAPIBase:      "https://discord.com/api/",
	})
	if d.ClientID != "id" || d.ClientSecret != "sec" {
		t.Fatalf("discord=%+v", d)
	}
	if d.AuthorizeURL != "https://discord.com/oauth2/authorize" ||
		d.TokenURL != "https://discord.com/api/oauth2/token" ||
		d.UserURL != "https://discord.com/api/users/@me" {
		t.Fatalf("endpoints=%+v", d)
	}
	// The web layer owns the callback path, so NewDiscord leaves it unset.
	if d.RedirectURI != "" {
		t.Fatalf("RedirectURI=%q", d.RedirectURI)
	}
	if d.HTTP == nil {
		t.Fatal("no HTTP client")
	}
}

func TestDiscordExchangeAndMe(t *testing.T) {
	var tokenBody map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
				t.Errorf("content type=%q", ct)
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form: %v", err)
			}
			tokenBody = map[string]string{}
			for k := range r.PostForm {
				tokenBody[k] = r.PostForm.Get(k)
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "tok"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("bad auth header")
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "42", "username": "tester", "global_name": "Test"})
	}))
	defer ts.Close()
	d := &Discord{ClientID: "id", ClientSecret: "sec", RedirectURI: "http://localhost/auth/callback",
		AuthorizeURL: ts.URL + "/oauth2/authorize", TokenURL: ts.URL + "/oauth2/token",
		UserURL: ts.URL + "/users/@me", HTTP: ts.Client()}
	accessToken, err := d.Exchange(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	if accessToken != "tok" {
		t.Fatalf("token=%q", accessToken)
	}
	u, err := d.Me(context.Background(), accessToken)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "42" || u.Username != "tester" {
		t.Fatalf("user=%+v", u)
	}
	if u.GlobalName != "Test" {
		t.Fatalf("global name=%q", u.GlobalName)
	}
	if tokenBody["code"] != "code" || tokenBody["code_verifier"] != "verifier" {
		t.Fatalf("token body=%v", tokenBody)
	}
	if tokenBody["grant_type"] != "authorization_code" || tokenBody["redirect_uri"] != d.RedirectURI ||
		tokenBody["client_id"] != "id" || tokenBody["client_secret"] != "sec" {
		t.Fatalf("token body=%v", tokenBody)
	}
}

func TestDiscordErrorsDoNotLeakBodies(t *testing.T) {
	const body = "upstream-secret-detail"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, body)
	}))
	defer ts.Close()
	d := &Discord{TokenURL: ts.URL, UserURL: ts.URL, HTTP: ts.Client()}

	if _, err := d.Exchange(context.Background(), "code", "verifier"); err == nil || strings.Contains(err.Error(), body) {
		t.Fatalf("exchange error=%v", err)
	}
	if _, err := d.Me(context.Background(), "tok"); err == nil || strings.Contains(err.Error(), body) {
		t.Fatalf("me error=%v", err)
	}
}

func TestDiscordEmptyResponses(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{}")
	}))
	defer ts.Close()
	d := &Discord{TokenURL: ts.URL, UserURL: ts.URL, HTTP: ts.Client()}

	if _, err := d.Exchange(context.Background(), "code", "verifier"); err == nil {
		t.Fatal("empty access token accepted")
	}
	if _, err := d.Me(context.Background(), "tok"); err == nil {
		t.Fatal("missing user id accepted")
	}
}

func TestOriginAllowedAny(t *testing.T) {
	r, _ := http.NewRequest("POST", "http://192.168.2.8:8080/dashboard/api/x", nil)
	r.Header.Set("Origin", "http://100.95.121.78:8080")
	if OriginAllowed(r, "http://192.168.2.8:8080") {
		t.Fatal("plain base URL should not match a different origin")
	}
	if !OriginAllowedAny(r, []string{"http://192.168.2.8:8080", "http://100.95.121.78:8080"}) {
		t.Fatal("allowlisted tailnet origin should match")
	}
	if OriginAllowedAny(r, []string{"http://192.168.2.8:8080", ""}) {
		t.Fatal("empty entries must not match")
	}
}
