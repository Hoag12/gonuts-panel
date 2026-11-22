package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"gonutspanel/internal/auth"
	"gonutspanel/internal/config"
	"gonutspanel/internal/relay"
	"gonutspanel/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(config.Config{PublicBaseURL: "https://panel.example.com"}, st, nil, nil), st
}

func TestPairingRedeemAndCheck(t *testing.T) {
	s, st := newTestServer(t)
	if err := st.UpsertUser(store.User{ID: "u1", Username: "u1"}); err != nil {
		t.Fatal(err)
	}
	token, csrf, err := st.CreateSession("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	mutate := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		req.Header.Set(auth.CSRFHeader, csrf)
		req.Header.Set("Origin", "https://panel.example.com")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	// Pair-code creation is a dashboard mutation now.
	rec := mutate("/dashboard/api/pair/code", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("pair code status=%d body=%s", rec.Code, rec.Body)
	}
	var created struct {
		Code      string `json:"code"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Code == "" || created.ExpiresAt <= time.Now().UnixMilli() {
		t.Fatalf("pair code=%+v", created)
	}

	redeemBody := `{"code":"` + created.Code + `","protocols":[1],"name":"Bot","build":"b","hive":"","capabilities":["panel"]}`
	req := httptest.NewRequest("POST", "/dashboard/api/pair/redeem", strings.NewReader(redeemBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("redeem status=%d body=%s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("redeem cache-control=%q", rec.Header().Get("Cache-Control"))
	}
	var pair struct {
		InstallationID int64  `json:"installationId"`
		Credential     string `json:"credential"`
		WSURL          string `json:"wsUrl"`
		CheckURL       string `json:"checkUrl"`
		Protocol       int    `json:"protocol"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	if pair.InstallationID == 0 || pair.Credential == "" ||
		pair.WSURL != "wss://panel.example.com/dashboard/ws/client" ||
		pair.CheckURL != "https://panel.example.com/dashboard/api/client/check" ||
		pair.Protocol != 1 {
		t.Fatalf("pair=%+v", pair)
	}
	redeemResponse := rec.Body.String()

	req = httptest.NewRequest("POST", "/dashboard/api/pair/redeem", strings.NewReader(redeemBody))
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second redeem status=%d", rec.Code)
	}

	req = httptest.NewRequest("POST", "/dashboard/api/client/check", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+pair.Credential)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) ||
		!strings.Contains(rec.Body.String(), `"installationId":1`) {
		t.Fatalf("check status=%d body=%s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("check cache-control=%q", rec.Header().Get("Cache-Control"))
	}
	checkResponse := rec.Body.String()

	for name, body := range map[string]string{"redeem": redeemResponse, "check": checkResponse} {
		if strings.Contains(body, "credentialHash") {
			t.Fatalf("%s leaked credentialHash: %s", name, body)
		}
	}
}

func TestPairingRedeemErrors(t *testing.T) {
	s, st := newTestServer(t)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/dashboard/api/pair/redeem", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	if rec := post(`not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid json status=%d", rec.Code)
	}
	if rec := post(`{"code":"ABC","protocols":[2]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("protocol status=%d", rec.Code)
	}
	if rec := post(`{"code":"ABC","protocols":[1],"name":"bad/name"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("name status=%d", rec.Code)
	}
	// Unknown capability names are tolerated, but the shape and count are not.
	if rec := post(`{"code":"ABC","protocols":[1],"capabilities":["Panel"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("capability shape status=%d", rec.Code)
	}
	if rec := post(`{"code":"ABC","protocols":[1],"capabilities":["` +
		strings.Repeat("a", 33) + `"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("capability length status=%d", rec.Code)
	}
	if rec := post(`{"code":"AAAAAAAA","protocols":[1]}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown code status=%d body=%s", rec.Code, rec.Body)
	}

	expired, _, err := st.CreateCode("u1", time.Now().Add(-6*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"code":"` + expired + `","protocols":[1]}`
	if rec := post(body); rec.Code != http.StatusGone {
		t.Fatalf("expired status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestPairingRedeemTrimsPaddedDetails(t *testing.T) {
	s, st := newTestServer(t)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/dashboard/api/pair/redeem", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	// Validation and the stored installation must agree on the trimmed value.
	code, _, err := st.CreateCode("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := post(`{"code":"` + code + `","protocols":[1],"name":"  Padded Bot  ","build":"  b1.2  ","hive":"  hive1  "}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("padded redeem status=%d body=%s", rec.Code, rec.Body)
	}
	var pair struct {
		InstallationID int64  `json:"installationId"`
		Name           string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	if pair.Name != "Padded Bot" {
		t.Fatalf("response name=%q", pair.Name)
	}
	inst, ok := st.Installation(pair.InstallationID)
	if !ok {
		t.Fatalf("installation %d missing", pair.InstallationID)
	}
	if inst.Name != "Padded Bot" || inst.Build != "b1.2" || inst.Hive != "hive1" {
		t.Fatalf("stored name=%q build=%q hive=%q", inst.Name, inst.Build, inst.Hive)
	}

	// Padding must not smuggle an overlong value past the 48/60/64 limits.
	overlong := []struct{ field, value string }{
		{"name", strings.Repeat("n", 49)},
		{"build", strings.Repeat("b", 61)},
		{"hive", strings.Repeat("h", 65)},
	}
	for _, c := range overlong {
		code, _, err := st.CreateCode("u1", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		body := `{"code":"` + code + `","protocols":[1],"` + c.field + `":"  ` + c.value + `  "}`
		if rec := post(body); rec.Code != http.StatusBadRequest {
			t.Fatalf("padded overlong %s=%d body=%s", c.field, rec.Code, rec.Body)
		}
	}
}

// modCapabilities mirrors DashboardProtocol.CAPABILITIES in the real mod.
var modCapabilities = []string{
	"pause", "resume", "snapshot", "panel", "swarm_enable", "swarm_disable",
	"swarm_rank", "swarm_staff", "read_savings", "data_use", "settings_analysis",
	"diagnostic_history",
}

// TestPairingAcceptsRealModCapabilities is the C1 regression: the exact pairing
// body the mod sends (twelve capabilities) must be accepted, not answered 400.
func TestPairingAcceptsRealModCapabilities(t *testing.T) {
	s, st := newTestServer(t)
	code, _, err := st.CreateCode("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body := `{"build":"0.1.1","name":"Laptop","hive":"hive_123","protocols":[1],` +
		`"capabilities":["pause","resume","snapshot","panel","swarm_enable","swarm_disable",` +
		`"swarm_rank","swarm_staff","read_savings","data_use","settings_analysis","diagnostic_history"],` +
		`"code":"` + code + `"}`
	req := httptest.NewRequest("POST", "/dashboard/api/pair/redeem", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("redeem status=%d body=%s", rec.Code, rec.Body)
	}
	var pair struct {
		InstallationID int64  `json:"installationId"`
		Credential     string `json:"credential"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	inst, ok := st.Installation(pair.InstallationID)
	if !ok || len(inst.Capabilities) != len(modCapabilities) {
		t.Fatalf("stored capabilities=%v want %d", inst.Capabilities, len(modCapabilities))
	}
	for i, want := range modCapabilities {
		if inst.Capabilities[i] != want {
			t.Fatalf("stored capabilities=%v", inst.Capabilities)
		}
	}
}

func TestClientCheckRejectsMissingOrUnknownCredential(t *testing.T) {
	s, _ := newTestServer(t)
	for _, header := range []string{"", "Basic abc", "Bearer ", "Bearer gni1_unknown"} {
		req := httptest.NewRequest("POST", "/dashboard/api/client/check", strings.NewReader("{}"))
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("header %q status=%d body=%s", header, rec.Code, rec.Body)
		}
	}
}

func TestHandlersNoLongerAnswer501(t *testing.T) {
	s, _ := newTestServer(t)
	cases := []struct{ method, path string }{
		{"GET", "/dashboard"},
		{"GET", "/auth/login"},
		{"GET", "/auth/callback"},
		{"POST", "/auth/local"},
		{"POST", "/auth/logout"},
		{"GET", "/auth/dev"},
		{"GET", "/dashboard/api/state"},
		{"POST", "/dashboard/api/pair/code"},
		{"POST", "/dashboard/api/installations/1/command"},
		{"POST", "/dashboard/api/installations/1/rename"},
		{"DELETE", "/dashboard/api/installations/1"},
		{"GET", "/dashboard/events"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code == http.StatusNotImplemented {
			t.Fatalf("%s %s is still stubbed", c.method, c.path)
		}
		if strings.Contains(strings.ToLower(rec.Body.String()), "credentialhash") {
			t.Fatalf("%s %s leaked credentialHash", c.method, c.path)
		}
	}
}

func TestHealthHeadersAndRootRedirect(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("health status=%d body=%s", rec.Code, rec.Body)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
		rec.Header().Get("X-Frame-Options") != "DENY" ||
		rec.Header().Get("Referrer-Policy") != "no-referrer" ||
		rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("security headers missing: %v", rec.Header())
	}

	req = httptest.NewRequest("GET", "/", nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("root status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDashboardShellCarriesSessionCSRF(t *testing.T) {
	s, st := newTestServer(t)
	s.Cfg.DiscordEnabled = true // the signed-out page then links Discord
	if err := st.UpsertUser(store.User{ID: "u1", Username: "u1"}); err != nil {
		t.Fatal(err)
	}
	token, csrf, err := st.CreateSession("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Signed out: the login page, never a shell with a CSRF placeholder.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/dashboard", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("signed-out dashboard status=%d", rec.Code)
	}
	if page := rec.Body.String(); !strings.Contains(page, "/auth/login") ||
		strings.Contains(page, "gonuts-csrf") || strings.Contains(page, "dashboard.js") {
		t.Fatalf("signed-out page is not the login page: %s", page)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login cache-control=%q", rec.Header().Get("Cache-Control"))
	}

	// Signed in: the shell must carry this session's CSRF token and link the
	// same-origin assets.
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status=%d", rec.Code)
	}
	page := rec.Body.String()
	if !strings.Contains(page, `<meta name="gonuts-csrf" content="`+csrf+`">`) {
		t.Fatalf("dashboard does not carry the session CSRF: %s", page)
	}
	if !strings.Contains(page, `action="/auth/logout"`) {
		t.Fatal("dashboard does not offer a sign-out form")
	}
	if !strings.Contains(page, `<input type="hidden" name="csrf" value="`+csrf+`">`) {
		t.Fatal("sign-out form does not carry the session CSRF")
	}
	if !strings.Contains(page, `<a class="brand" href="/dashboard"`) {
		t.Fatal("dashboard logo does not link back to the dashboard")
	}
	for _, placeholder := range []string{"{{CSRF}}", "{{CSS}}", "{{JSV}}", "{{STATE}}"} {
		if strings.Contains(page, placeholder) {
			t.Fatalf("dashboard still contains %s", placeholder)
		}
	}
	// The stylesheet is inlined, the state is embedded, and the script URL is
	// content-hashed so repeat loads can come from the cache.
	for _, want := range []string{"<style>", "/assets/monocraft-subset.woff2", "/assets/dashboard.js?v=", "/assets/logo.png"} {
		if !strings.Contains(page, want) {
			t.Fatalf("dashboard does not contain %s", want)
		}
	}
	if strings.Contains(page, `<link rel="stylesheet"`) {
		t.Fatal("dashboard still blocks on an external stylesheet")
	}
	if strings.Contains(page, "Bug tracker") {
		t.Fatal("dashboard still links the removed bug tracker")
	}
	if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("dashboard headers: %v", rec.Header())
	}
}

func TestEmbeddedAssetsAreServed(t *testing.T) {
	s, _ := newTestServer(t)
	assets := []struct {
		path string
		typ  string
	}{
		{"/assets/dashboard.css", "text/css"},
		{"/assets/dashboard.js", "javascript"},
		{"/assets/mascot_v2.png", "image/png"},
		{"/assets/logo.png", "image/png"},
		// The font is served with nosniff, so the type has to be exact rather
		// than host-dependent.
		{"/assets/Monocraft.ttf", "font/ttf"},
		// The bundled font's license must ship with the binary.
		{"/assets/Monocraft-OFL.txt", "text/plain"},
	}
	for _, a := range assets {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", a.path, nil))
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Fatalf("%s status=%d len=%d", a.path, rec.Code, rec.Body.Len())
		}
		if a.typ != "" && !strings.Contains(rec.Header().Get("Content-Type"), a.typ) {
			t.Fatalf("%s content-type=%q", a.path, rec.Header().Get("Content-Type"))
		}
	}

	// The assets root cannot be used to read the shells or the repository.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/assets/../dashboard.html", nil))
	if strings.Contains(rec.Body.String(), "gonuts-csrf") {
		t.Fatal("assets route escaped its subtree")
	}
}

func TestNoopRelayWhenHubOmitted(t *testing.T) {
	s, _ := newTestServer(t)
	if s.Hub.Online(1) {
		t.Fatal("noop hub reported an installation online")
	}
	if _, err := s.Hub.SendCommand(1, "pause"); !errors.Is(err, relay.ErrOffline) {
		t.Fatalf("SendCommand err=%v", err)
	}
	if _, err := s.Hub.PanelRequest(nil, 1, nil); !errors.Is(err, relay.ErrOffline) {
		t.Fatalf("PanelRequest err=%v", err)
	}
	select {
	case <-s.Hub.Updates():
	default:
		t.Fatal("noop updates channel is not closed")
	}
}

func TestSessionHelpers(t *testing.T) {
	s, st := newTestServer(t)
	if err := st.UpsertUser(store.User{ID: "u1"}); err != nil {
		t.Fatal(err)
	}
	token, csrf, err := st.CreateSession("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	anonymous := httptest.NewRequest("POST", "/dashboard/api/pair/code", nil)
	rec := httptest.NewRecorder()
	if _, _, ok := s.requireMutation(rec, anonymous); ok || rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous ok=%v status=%d", ok, rec.Code)
	}

	req := httptest.NewRequest("POST", "/dashboard/api/pair/code", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec = httptest.NewRecorder()
	if _, _, ok := s.requireMutation(rec, req); ok || rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf ok=%v status=%d", ok, rec.Code)
	}

	req.Header.Set(auth.CSRFHeader, csrf)
	rec = httptest.NewRecorder()
	if _, _, ok := s.requireMutation(rec, req); ok || rec.Code != http.StatusForbidden {
		t.Fatalf("missing origin ok=%v status=%d", ok, rec.Code)
	}

	req.Header.Set("Origin", "https://panel.example.com")
	rec = httptest.NewRecorder()
	sess, user, ok := s.requireMutation(rec, req)
	if !ok || sess == nil || user == nil || sess.CSRF != csrf || user.ID != "u1" {
		t.Fatalf("valid mutation ok=%v sess=%+v user=%+v", ok, sess, user)
	}
}

func TestClientIPTrustProxy(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	if got := s.clientIP(req); got != "203.0.113.9" {
		t.Fatalf("untrusted proxy ip=%q", got)
	}
	s.Cfg.TrustProxy = true
	if got := s.clientIP(req); got != "198.51.100.7" {
		t.Fatalf("trusted proxy ip=%q", got)
	}
}

func TestLimiterBucketsStayBounded(t *testing.T) {
	l := newLimiter(60, 4) // one token per second, burst of four
	base := time.Unix(1700000000, 0)

	// Attacker-controlled keys must not grow the map without limit.
	for i := 0; i < 5000; i++ {
		l.allow(fmt.Sprintf("attacker-%d", i), base)
		if n := len(l.buckets); n > limiterMaxBuckets {
			t.Fatalf("after %d keys buckets=%d, want <= %d", i+1, n, limiterMaxBuckets)
		}
	}

	// Eviction must not reset buckets: a key that spent its burst stays
	// depleted even while unrelated keys push the map over the bound. hot is
	// newer than every filler, so cleanup never picks it as the oldest.
	spent := base.Add(time.Second)
	for i := 0; i < 4; i++ {
		if !l.allow("hot", spent) {
			t.Fatalf("hot request %d denied from a full bucket", i+1)
		}
	}
	if l.allow("hot", spent) {
		t.Fatal("hot exceeded its burst")
	}
	for i := 0; i < limiterMaxBuckets-1; i++ {
		l.allow(fmt.Sprintf("filler-%d", i), spent)
		if n := len(l.buckets); n > limiterMaxBuckets {
			t.Fatalf("after %d fillers buckets=%d, want <= %d", i+1, n, limiterMaxBuckets)
		}
	}

	// One second of refill is all hot has earned; a reset bucket would allow
	// a whole extra burst here.
	check := spent.Add(time.Second)
	allowed := 0
	for i := 0; i < 5; i++ {
		if l.allow("hot", check) {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("hot allowed %d more requests, want 1 (one refilled token, state preserved)", allowed)
	}

	// A brand-new key still starts full.
	for i := 0; i < 4; i++ {
		if !l.allow("fresh", check) {
			t.Fatalf("fresh key request %d denied", i+1)
		}
	}
	if l.allow("fresh", check) {
		t.Fatal("fresh key exceeded its burst")
	}
}

func TestLimiterDropsIdleBuckets(t *testing.T) {
	l := newLimiter(60, 4)
	base := time.Unix(1700000000, 0)
	for i := 0; i < limiterMaxBuckets; i++ {
		l.allow(fmt.Sprintf("idle-%d", i), base)
	}
	// Past the sweep age the stale buckets go away, leaving room for new keys.
	after := base.Add(limiterBucketTTL + time.Minute)
	l.allow("new", after)
	if n := len(l.buckets); n != 1 {
		t.Fatalf("buckets=%d after idle sweep, want 1", n)
	}
	if _, ok := l.buckets["new"]; !ok {
		t.Fatal("newly inserted bucket missing after sweep")
	}
}

// fakeRelay is a controllable Relay for panel proxy tests.
type fakeRelay struct {
	online   bool
	frames   []map[string]any
	commands []string
	closed   []int64
	updates  chan struct{}
	panel    func(context.Context, int64, map[string]any) (*relay.PanelResult, error)
}

func (f *fakeRelay) Online(int64) bool { return f.online }

func (f *fakeRelay) SendCommand(_ int64, c string) (string, error) {
	if !f.online {
		return "", relay.ErrOffline
	}
	f.commands = append(f.commands, c)
	return "cmd_test", nil
}

func (f *fakeRelay) PanelRequest(ctx context.Context, id int64, frame map[string]any) (*relay.PanelResult, error) {
	if !f.online {
		return nil, relay.ErrOffline
	}
	f.frames = append(f.frames, frame)
	return f.panel(ctx, id, frame)
}

func (f *fakeRelay) CloseInstallation(id int64, _ int, _ string) { f.closed = append(f.closed, id) }
func (f *fakeRelay) Updates() <-chan struct{}                    { return f.updates }
func (f *fakeRelay) ServeWS(http.ResponseWriter, *http.Request)  {}

// panelFixture is one signed-in user with one paired installation.
type panelFixture struct {
	srv   *Server
	store *store.Store
	inst  *store.Installation
	token string
	csrf  string
	base  string
}

func newPanelFixture(t *testing.T, fr *fakeRelay) *panelFixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	token, csrf, err := st.CreateSession("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := st.CreateCode("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inst, _, err := st.RedeemCode(code, "Bot", "b", "", []string{"panel"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(config.Config{PublicBaseURL: "https://panel.example.com", PanelCacheBytes: 1 << 20}, st, fr, nil)
	return &panelFixture{
		srv:   srv,
		store: st,
		inst:  inst,
		token: token,
		csrf:  csrf,
		base:  "/dashboard/panel/" + strconv.FormatInt(inst.ID, 10) + "/",
	}
}

func (f *panelFixture) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (f *panelFixture) get(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.token})
	return f.do(req)
}

func (f *panelFixture) post(path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-GoNuts", "1")
	req.Header.Set(auth.CSRFHeader, f.csrf)
	req.Header.Set("Origin", "https://panel.example.com")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.token})
	return f.do(req)
}

func pageRelay() func(context.Context, int64, map[string]any) (*relay.PanelResult, error) {
	return func(context.Context, int64, map[string]any) (*relay.PanelResult, error) {
		return &relay.PanelResult{Status: 200, ContentType: "text/html; charset=utf-8",
			Body: []byte(`<head></head><img src="/logo.png"><form class="out" method="post" action="/logout"><button>Lock</button></form>`)}, nil
	}
}

func TestPanelPageRewritesAndProxies(t *testing.T) {
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1), panel: pageRelay()}
	f := newPanelFixture(t, fr)

	rec := f.get(f.base)
	if rec.Code != 200 {
		t.Fatalf("page status=%d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `src="logo.png"`) || strings.Contains(body, "gonuts.at") || !strings.Contains(body, `gonuts-csrf`) {
		t.Fatalf("bad page:\n%s", body)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("panel csp=%q", rec.Header().Get("Content-Security-Policy"))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("page cache-control=%q", rec.Header().Get("Cache-Control"))
	}

	rec = f.post(f.base+"act", "id=ctl:start")
	if rec.Code != 204 {
		t.Fatalf("act status=%d body=%s", rec.Code, rec.Body)
	}
	if len(fr.frames) < 2 || fr.frames[len(fr.frames)-1]["op"] != "act" ||
		fr.frames[len(fr.frames)-1]["act"].(map[string]any)["id"] != "ctl:start" {
		t.Fatalf("frames=%+v", fr.frames)
	}

	// A different user gets 404, not another user's panel.
	token2, _, err := f.store.CreateSession("u2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", f.base, nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token2})
	if rec := f.do(req); rec.Code != 404 {
		t.Fatalf("ownership status=%d", rec.Code)
	}

	// Offline with no cache is a styled 503.
	fr.online = false
	if err := f.store.DeleteInstallation(f.inst.ID, "u1"); err != nil {
		t.Fatal(err)
	}
	code2, _, err := f.store.CreateCode("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inst2, _, err := f.store.RedeemCode(code2, "Bot2", "b", "", []string{"panel"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec = f.get("/dashboard/panel/" + strconv.FormatInt(inst2.ID, 10) + "/")
	if rec.Code != 503 {
		t.Fatalf("offline status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("offline content-type=%q", ct)
	}
	if !strings.Contains(rec.Body.String(), `href="/dashboard"`) {
		t.Fatalf("offline page has no dashboard link:\n%s", rec.Body)
	}
}

func TestPanelPageCachesRawHTMLAndInjectsSessionCSRF(t *testing.T) {
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1), panel: pageRelay()}
	f := newPanelFixture(t, fr)

	if rec := f.get(f.base); rec.Code != 200 {
		t.Fatalf("first page status=%d", rec.Code)
	}
	// A second session for the same owner must get its own token even though
	// the page body comes from the cache.
	token2, csrf2, err := f.store.CreateSession("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", f.base, nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token2})
	rec := f.do(req)
	if rec.Code != 200 {
		t.Fatalf("second page status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `content="`+csrf2+`"`) {
		t.Fatalf("second session token missing:\n%s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), `content="`+f.csrf+`"`) {
		t.Fatal("cached page carried the first session's token")
	}
	if len(fr.frames) != 1 {
		t.Fatalf("page frames=%d, want 1 (cached)", len(fr.frames))
	}
}

func TestPanelPageOfflineServesCachedPage(t *testing.T) {
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1), panel: pageRelay()}
	f := newPanelFixture(t, fr)
	if rec := f.get(f.base); rec.Code != 200 {
		t.Fatalf("page status=%d", rec.Code)
	}
	fr.online = false
	rec := f.get(f.base)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `gonuts-csrf`) {
		t.Fatalf("cached offline page status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestPanelGetMapsPathsAndCachesAssets(t *testing.T) {
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1)}
	fr.panel = func(_ context.Context, _ int64, frame map[string]any) (*relay.PanelResult, error) {
		switch frame["op"] {
		case "state":
			return &relay.PanelResult{Status: 200, ContentType: "application/json; charset=utf-8", Body: []byte(`{"ok":true}`)}, nil
		case "data":
			name := frame["name"].(string)
			return &relay.PanelResult{Status: 200, ContentType: "application/json; charset=utf-8", Body: []byte(`{"name":"` + name + `"}`)}, nil
		case "png":
			return &relay.PanelResult{Status: 200, ContentType: "image/png", Body: []byte{0x89, 'P', 'N', 'G'}}, nil
		case "icon":
			return &relay.PanelResult{Status: 200, ContentType: "image/png", Body: []byte{1, 2, 3}}, nil
		case "asset":
			if frame["asset"] == "font" {
				return &relay.PanelResult{Status: 200, ContentType: "font/ttf", Body: []byte{4, 5}}, nil
			}
			return &relay.PanelResult{Status: 200, ContentType: "image/png", Body: []byte{6, 7}}, nil
		}
		return &relay.PanelResult{Status: 404, ContentType: "text/plain; charset=utf-8"}, nil
	}
	f := newPanelFixture(t, fr)

	// State is relayed on every request and never cached.
	for i := 0; i < 2; i++ {
		rec := f.get(f.base + "state")
		if rec.Code != 200 || rec.Body.String() != `{"ok":true}` {
			t.Fatalf("state %d status=%d body=%s", i, rec.Code, rec.Body)
		}
		if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatalf("state content-type=%q", rec.Header().Get("Content-Type"))
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("state cache-control=%q", rec.Header().Get("Cache-Control"))
		}
	}
	if len(fr.frames) != 2 || fr.frames[0]["op"] != "state" {
		t.Fatalf("state frames=%+v", fr.frames)
	}

	// api/<name> keeps the parsed query.
	rec := f.get(f.base + "api/bots?hive=h1&q=a&q=b")
	if rec.Code != 200 || rec.Body.String() != `{"name":"bots"}` {
		t.Fatalf("data status=%d body=%s", rec.Code, rec.Body)
	}
	last := fr.frames[len(fr.frames)-1]
	query, ok := last["query"].(map[string]string)
	if last["op"] != "data" || last["name"] != "bots" || !ok || query["hive"] != "h1" || query["q"] != "a" {
		t.Fatalf("data frame=%+v", last)
	}

	// panel.png is a live view, so both requests relay a fresh png frame.
	for i := 0; i < 2; i++ {
		rec := f.get(f.base + "panel.png")
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" ||
			!bytes.Equal(rec.Body.Bytes(), []byte{0x89, 'P', 'N', 'G'}) {
			t.Fatalf("png %d status=%d type=%q body=%v", i, rec.Code, rec.Header().Get("Content-Type"), rec.Body.Bytes())
		}
		if png := fr.frames[len(fr.frames)-1]; png["op"] != "png" {
			t.Fatalf("png %d frame=%+v", i, png)
		}
	}
	pngOps := 0
	for _, frame := range fr.frames {
		if frame["op"] == "png" {
			pngOps++
		}
	}
	if pngOps != 2 {
		t.Fatalf("png frames=%d, want 2 fresh relays", pngOps)
	}

	if rec := f.get(f.base + "item/minecraft:stone.png"); rec.Code != 200 {
		t.Fatalf("icon status=%d", rec.Code)
	}
	icon := fr.frames[len(fr.frames)-1]
	if icon["op"] != "icon" || icon["item"] != "minecraft:stone" {
		t.Fatalf("icon frame=%+v", icon)
	}
	// Icons stay cached, so a repeat costs no frame.
	iconFrames := len(fr.frames)
	if rec := f.get(f.base + "item/minecraft:stone.png"); rec.Code != 200 || len(fr.frames) != iconFrames {
		t.Fatalf("icon not cached: status=%d frames=%d want %d", rec.Code, len(fr.frames), iconFrames)
	}

	// The logo and font come from the embedded copy, never the game socket.
	before := len(fr.frames)
	logoRec := f.get(f.base + "logo.png")
	if logoRec.Code != 200 || logoRec.Header().Get("Content-Type") != "image/png" || logoRec.Body.Len() == 0 {
		t.Fatalf("logo status=%d type=%q len=%d", logoRec.Code, logoRec.Header().Get("Content-Type"), logoRec.Body.Len())
	}
	fontRec := f.get(f.base + "font.ttf")
	if fontRec.Code != 200 || fontRec.Header().Get("Content-Type") != "font/ttf" || fontRec.Body.Len() == 0 {
		t.Fatalf("font status=%d type=%q len=%d", fontRec.Code, fontRec.Header().Get("Content-Type"), fontRec.Body.Len())
	}
	if len(fr.frames) != before {
		t.Fatalf("logo/font used the relay: frames=%d want %d", len(fr.frames), before)
	}

	for _, path := range []string{"nope", "api/Bots", "api/a/b", "api/", "item/bad%20item.png", "item/x.gif", "panel.png/"} {
		if rec := f.get(f.base + path); rec.Code != 404 {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body)
		}
	}
}

func TestPanelImageIsNeverCached(t *testing.T) {
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1)}
	pngs := 0
	fr.panel = func(_ context.Context, _ int64, frame map[string]any) (*relay.PanelResult, error) {
		switch frame["op"] {
		case "png":
			pngs++
			return &relay.PanelResult{Status: 200, ContentType: "image/png",
				Body: []byte{0x89, 'P', 'N', 'G', byte(pngs)}}, nil
		case "asset":
			return &relay.PanelResult{Status: 200, ContentType: "font/ttf", Body: []byte{9}}, nil
		}
		return &relay.PanelResult{Status: 404, ContentType: "text/plain; charset=utf-8"}, nil
	}
	f := newPanelFixture(t, fr)

	// The mod appends ?t= to panel.png. The query is not part of the route, and
	// every request must relay its own png op instead of a cached body.
	first := f.get(f.base + "panel.png?t=1000")
	second := f.get(f.base + "panel.png?t=2000")
	for i, rec := range []*httptest.ResponseRecorder{first, second} {
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" {
			t.Fatalf("png %d status=%d type=%q", i, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	if pngs != 2 || len(fr.frames) != 2 {
		t.Fatalf("png relays=%d frames=%d, want 2 fresh frames", pngs, len(fr.frames))
	}
	if !bytes.Equal(first.Body.Bytes(), []byte{0x89, 'P', 'N', 'G', 1}) ||
		!bytes.Equal(second.Body.Bytes(), []byte{0x89, 'P', 'N', 'G', 2}) {
		t.Fatalf("png bodies=%v / %v, want two distinct fresh frames", first.Body.Bytes(), second.Body.Bytes())
	}

	// The font is embedded, so it costs no relay frame at all.
	for i := 0; i < 2; i++ {
		if rec := f.get(f.base + "font.ttf"); rec.Code != 200 {
			t.Fatalf("font %d status=%d", i, rec.Code)
		}
	}
	if len(fr.frames) != 2 {
		t.Fatalf("font frames=%d, want no extra relay frames", len(fr.frames))
	}
}

func TestPanelContentTypeIsClamped(t *testing.T) {
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1)}
	fr.panel = func(_ context.Context, _ int64, frame map[string]any) (*relay.PanelResult, error) {
		ct := `text/html; onerror=alert(1)`
		switch frame["name"] {
		case "json":
			ct = "application/json; charset=utf-8"
		case "svg":
			ct = "image/svg+xml"
		case "quoted":
			ct = `text/plain; charset="UTF-8"`
		}
		return &relay.PanelResult{Status: 200, ContentType: ct, Body: []byte("{}")}, nil
	}
	f := newPanelFixture(t, fr)

	cases := map[string]string{
		"api/injected": "application/octet-stream",
		"api/json":     "application/json; charset=utf-8",
		"api/svg":      "application/octet-stream",
		"api/quoted":   "text/plain; charset=utf-8",
	}
	for path, want := range cases {
		rec := f.get(f.base + path)
		if rec.Code != 200 {
			t.Fatalf("%s status=%d", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != want {
			t.Fatalf("%s content-type=%q want %q", path, got, want)
		}
		if strings.Contains(rec.Header().Get("Content-Type"), "onerror") {
			t.Fatalf("%s leaked a raw content type", path)
		}
	}
}

func TestPanelPostValidation(t *testing.T) {
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1), panel: pageRelay()}
	f := newPanelFixture(t, fr)

	// Missing X-GoNuts.
	req := httptest.NewRequest("POST", f.base+"act", strings.NewReader("id=ctl:start"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(auth.CSRFHeader, f.csrf)
	req.Header.Set("Origin", "https://panel.example.com")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.token})
	if rec := f.do(req); rec.Code != http.StatusForbidden {
		t.Fatalf("missing X-GoNuts status=%d", rec.Code)
	}

	// Anonymous.
	req = httptest.NewRequest("POST", f.base+"act", strings.NewReader("id=ctl:start"))
	req.Header.Set("X-GoNuts", "1")
	if rec := f.do(req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d", rec.Code)
	}

	// Missing CSRF.
	req = httptest.NewRequest("POST", f.base+"act", strings.NewReader("id=ctl:start"))
	req.Header.Set("X-GoNuts", "1")
	req.Header.Set("Origin", "https://panel.example.com")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.token})
	if rec := f.do(req); rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status=%d", rec.Code)
	}

	// Another user's installation.
	token2, csrf2, err := f.store.CreateSession("u2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", f.base+"act", strings.NewReader("id=ctl:start"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-GoNuts", "1")
	req.Header.Set(auth.CSRFHeader, csrf2)
	req.Header.Set("Origin", "https://panel.example.com")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token2})
	if rec := f.do(req); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign installation status=%d", rec.Code)
	}

	// Bad action id and oversized form.
	if rec := f.post(f.base+"act", "id="+strings.Repeat("x", 20)); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad act id status=%d", rec.Code)
	}
	if rec := f.post(f.base+"act", "id=ctl:start&text="+strings.Repeat("a", 70<<10)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized form status=%d", rec.Code)
	}

	// Unsupported mutation routes.
	if rec := f.post(f.base+"panel.png", "x=1"); rec.Code != http.StatusNotFound {
		t.Fatalf("png post status=%d", rec.Code)
	}
	if rec := f.post(f.base+"api/Bots", "x=1"); rec.Code != http.StatusNotFound {
		t.Fatalf("bad api name status=%d", rec.Code)
	}
}

func TestPanelPostRelaysChangeAndAct(t *testing.T) {
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1)}
	fr.panel = func(_ context.Context, _ int64, frame map[string]any) (*relay.PanelResult, error) {
		if frame["op"] == "change" {
			return &relay.PanelResult{Status: 200, ContentType: "application/json; charset=utf-8", Body: []byte(`{"ok":true,"note":"saved"}`)}, nil
		}
		return &relay.PanelResult{Status: 204, ContentType: "text/plain; charset=utf-8"}, nil
	}
	f := newPanelFixture(t, fr)

	rec := f.post(f.base+"api/bots", "enabled=true&count=3")
	if rec.Code != 200 || rec.Body.String() != `{"ok":true,"note":"saved"}` {
		t.Fatalf("change status=%d body=%s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("change content-type=%q", rec.Header().Get("Content-Type"))
	}
	last := fr.frames[len(fr.frames)-1]
	form, ok := last["form"].(map[string]string)
	if last["op"] != "change" || last["name"] != "bots" || !ok || form["enabled"] != "true" || form["count"] != "3" {
		t.Fatalf("change frame=%+v", last)
	}

	if rec := f.post(f.base+"act", "id=tune:set&text=hello"); rec.Code != 204 {
		t.Fatalf("text act status=%d body=%s", rec.Code, rec.Body)
	}
	act := fr.frames[len(fr.frames)-1]["act"].(map[string]any)
	if act["id"] != "tune:set" || act["text"] != "hello" {
		t.Fatalf("text act=%+v", act)
	}
	if _, has := act["value"]; has {
		t.Fatalf("text act also carried a value: %+v", act)
	}

	if rec := f.post(f.base+"act", "id=ctl:start&value=run"); rec.Code != 204 {
		t.Fatalf("value act status=%d", rec.Code)
	}
	act = fr.frames[len(fr.frames)-1]["act"].(map[string]any)
	if act["id"] != "ctl:start" || act["value"] != "run" {
		t.Fatalf("value act=%+v", act)
	}
	if _, has := act["text"]; has {
		t.Fatalf("value act also carried text: %+v", act)
	}
}

func TestPanelErrorsMapToStatuses(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{relay.ErrOffline, http.StatusServiceUnavailable},
		{relay.ErrTimeout, http.StatusGatewayTimeout},
		{relay.ErrBusy, http.StatusTooManyRequests},
		{relay.ErrNoPanel, http.StatusNotImplemented},
		{errors.New("boom"), http.StatusBadGateway},
	}
	for _, c := range cases {
		fr := &fakeRelay{online: true, updates: make(chan struct{}, 1)}
		fr.panel = func(context.Context, int64, map[string]any) (*relay.PanelResult, error) {
			return nil, c.err
		}
		f := newPanelFixture(t, fr)
		if rec := f.get(f.base + "state"); rec.Code != c.want {
			t.Fatalf("%v status=%d want %d", c.err, rec.Code, c.want)
		}
	}

	// A refused status is relayed, not invented.
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1)}
	fr.panel = func(context.Context, int64, map[string]any) (*relay.PanelResult, error) {
		return &relay.PanelResult{Status: 404, ContentType: "text/plain; charset=utf-8"}, nil
	}
	f := newPanelFixture(t, fr)
	if rec := f.get(f.base + "api/missing"); rec.Code != 404 {
		t.Fatalf("refused status=%d", rec.Code)
	}
}

func TestPanelAnonymousAndBadIDs(t *testing.T) {
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1), panel: pageRelay()}
	f := newPanelFixture(t, fr)

	// Anonymous page requests go to the sign-in dashboard.
	rec := f.do(httptest.NewRequest("GET", f.base, nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("anonymous page status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	// Anonymous data requests are not found.
	if rec := f.do(httptest.NewRequest("GET", f.base+"state", nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("anonymous state status=%d", rec.Code)
	}
	// Unknown and malformed ids are not found.
	for _, path := range []string{"/dashboard/panel/abc/", "/dashboard/panel/9999/", "/dashboard/panel/0/"} {
		if rec := f.get(path); rec.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d", path, rec.Code)
		}
	}
}

func TestPanelCacheBoundsAndExpiry(t *testing.T) {
	c := newPanelCache(8)
	c.putAsset("a", []byte("12345"), "image/png", time.Minute)
	if a, ok := c.asset("a"); !ok || string(a.body) != "12345" || a.contentType != "image/png" {
		t.Fatalf("asset=%+v ok=%v", a, ok)
	}

	// Adding past the cap clears the asset cache rather than growing forever.
	c.putAsset("b", []byte("12345678"), "image/png", time.Minute)
	if _, ok := c.asset("a"); ok {
		t.Fatal("asset cache was not cleared when it exceeded max")
	}
	if c.bytes > c.max {
		t.Fatalf("cache bytes=%d max=%d", c.bytes, c.max)
	}

	// Expired entries are misses, and a stored body is not aliased.
	c.putAsset("c", []byte("x"), "image/png", -time.Second)
	if _, ok := c.asset("c"); ok {
		t.Fatal("expired asset served")
	}
	c.putPage("p|b", "<html></html>", -time.Second)
	if _, ok := c.page("p|b"); ok {
		t.Fatal("expired page served")
	}
	c.putPage("live|b", "<html></html>", time.Minute)
	if body, ok := c.page("live|b"); !ok || body != "<html></html>" {
		t.Fatalf("page=%q ok=%v", body, ok)
	}
	body := []byte("abc")
	c.putAsset("d", body, "image/png", time.Minute)
	body[0] = 'x'
	if a, ok := c.asset("d"); !ok || string(a.body) != "abc" {
		t.Fatalf("cached asset aliases the caller's slice: %+v", a)
	}
}

// dashboardFixture is a signed-in user with one paired installation.
type dashboardFixture struct {
	srv   *Server
	store *store.Store
	relay *fakeRelay
	inst  *store.Installation
	token string
	csrf  string
}

func newDashboardFixture(t *testing.T, online bool) *dashboardFixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.UpsertUser(store.User{ID: "u1", Username: "user one", GlobalName: "User One"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, csrf, err := st.CreateSession("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := st.CreateCode("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	inst, _, err := st.RedeemCode(code, "Bot", "b1.2", "hive1", []string{"panel", "pause"}, now)
	if err != nil {
		t.Fatal(err)
	}
	fr := &fakeRelay{online: online, updates: make(chan struct{}, 1)}
	srv := New(config.Config{PublicBaseURL: "https://panel.example.com", PanelCacheBytes: 1 << 20}, st, fr, nil)
	return &dashboardFixture{srv: srv, store: st, relay: fr, inst: inst, token: token, csrf: csrf}
}

func (f *dashboardFixture) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (f *dashboardFixture) get(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.token})
	return f.do(req)
}

func (f *dashboardFixture) mutate(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(auth.CSRFHeader, f.csrf)
	req.Header.Set("Origin", "https://panel.example.com")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.token})
	return f.do(req)
}

func (f *dashboardFixture) installPath(suffix string) string {
	return "/dashboard/api/installations/" + strconv.FormatInt(f.inst.ID, 10) + suffix
}

func TestStateIsScopedToUser(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	token1, csrf1, err := st.CreateSession("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	token2, _, err := st.CreateSession("u2", now)
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := st.CreateCode("u1", now)
	if err != nil {
		t.Fatal(err)
	}
	inst, _, err := st.RedeemCode(code, "Bot", "b", "", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTelemetry(inst.ID, &store.Telemetry{Account: "Acc", State: "SCANNING"}, now); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1)}
	s := New(config.Config{PublicBaseURL: "https://panel.example.com"}, st, fr, nil)

	get := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/dashboard/api/state", nil)
		if token != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	rec := get(token1)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	stateBody := rec.Body.String()
	var body struct {
		CSRF          string `json:"csrf"`
		Installations []struct {
			ID        int64            `json:"id"`
			Name      string           `json:"name"`
			Online    bool             `json:"online"`
			Telemetry *store.Telemetry `json:"telemetry"`
		} `json:"installations"`
		Hives []struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		} `json:"hives"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.CSRF != csrf1 || len(body.Installations) != 1 || body.Installations[0].Name != "Bot" ||
		body.Installations[0].ID != inst.ID || !body.Installations[0].Online ||
		body.Installations[0].Telemetry == nil || body.Installations[0].Telemetry.Account != "Acc" {
		t.Fatalf("body=%s", rec.Body)
	}
	if len(body.Hives) != 0 {
		t.Fatalf("empty hive should not be grouped: %s", rec.Body)
	}

	// Nothing in the state may carry the stored credential hash.
	for _, stored := range st.State().Installations {
		if strings.Contains(stateBody, stored.CredentialHash) {
			t.Fatalf("state leaked a credential hash: %s", stateBody)
		}
	}
	if strings.Contains(strings.ToLower(stateBody), "credentialhash") {
		t.Fatalf("state leaked a credentialHash field: %s", stateBody)
	}

	if rec := get(token2); rec.Code != 200 || strings.Contains(rec.Body.String(), `"Bot"`) {
		t.Fatalf("user2 saw user1's bot: status=%d body=%s", rec.Code, rec.Body)
	}
	if rec := get(""); rec.Code != 401 {
		t.Fatalf("anonymous status=%d", rec.Code)
	}
}

func TestStateGroupsHivesAndLastCommand(t *testing.T) {
	f := newDashboardFixture(t, true)
	now := time.Now()
	if err := f.store.AddCommand(store.Command{
		ID: "cmd_1", InstallationID: f.inst.ID, DiscordID: "u1", Command: "pause",
		CreatedAt: now.UnixMilli(), State: "completed",
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AddCommand(store.Command{
		ID: "cmd_2", InstallationID: f.inst.ID, DiscordID: "u1", Command: "resume",
		CreatedAt: now.Add(time.Second).UnixMilli(), State: "rejected", Reason: "paused",
	}); err != nil {
		t.Fatal(err)
	}

	rec := f.get("/dashboard/api/state")
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("state cache-control=%q", rec.Header().Get("Cache-Control"))
	}
	var body struct {
		Installations []struct {
			Build       string `json:"build"`
			Hive        string `json:"hive"`
			LastCommand *struct {
				Command   string `json:"command"`
				State     string `json:"state"`
				Reason    string `json:"reason"`
				CreatedAt int64  `json:"createdAt"`
			} `json:"lastCommand"`
		} `json:"installations"`
		Hives []struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		} `json:"hives"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Installations) != 1 || body.Installations[0].Build != "b1.2" {
		t.Fatalf("installations=%+v", body.Installations)
	}
	last := body.Installations[0].LastCommand
	if last == nil || last.Command != "resume" || last.State != "rejected" || last.Reason != "paused" {
		t.Fatalf("lastCommand=%+v", last)
	}
	if len(body.Hives) != 1 || body.Hives[0].Name != "hive1" || body.Hives[0].Count != 1 {
		t.Fatalf("hives=%+v", body.Hives)
	}
}

func TestDashboardResponsesNeverCarryCredentialHash(t *testing.T) {
	f := newDashboardFixture(t, true)
	hash := f.inst.CredentialHash
	if hash == "" {
		t.Fatal("fixture installation has no credential hash")
	}
	check := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if strings.Contains(strings.ToLower(rec.Body.String()), "credentialhash") {
			t.Fatalf("%s leaked a credentialHash field: %s", name, rec.Body)
		}
		if strings.Contains(rec.Body.String(), hash) {
			t.Fatalf("%s leaked the credential hash: %s", name, rec.Body)
		}
	}
	check("state", f.get("/dashboard/api/state"))
	check("pair code", f.mutate("POST", "/dashboard/api/pair/code", ""))
	check("command", f.mutate("POST", f.installPath("/command"), `{"command":"pause"}`))
	check("rename", f.mutate("POST", f.installPath("/rename"), `{"name":"Renamed"}`))
	check("unlink", f.mutate("DELETE", f.installPath(""), ""))
}

func TestDashboardCommandRenameUnlink(t *testing.T) {
	f := newDashboardFixture(t, true)

	rec := f.mutate("POST", f.installPath("/command"), `{"command":"pause"}`)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"id":"cmd_test"`) {
		t.Fatalf("command status=%d body=%s", rec.Code, rec.Body)
	}
	if len(f.relay.commands) != 1 || f.relay.commands[0] != "pause" {
		t.Fatalf("commands=%v", f.relay.commands)
	}

	if rec := f.mutate("POST", f.installPath("/command"), `{"command":"explode"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported command status=%d body=%s", rec.Code, rec.Body)
	}
	if rec := f.mutate("POST", f.installPath("/command"), `not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid body status=%d", rec.Code)
	}
	if rec := f.mutate("POST", "/dashboard/api/installations/9999/command", `{"command":"pause"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown installation status=%d", rec.Code)
	}

	// An offline client answers 409, never a queued command.
	f.relay.online = false
	if rec := f.mutate("POST", f.installPath("/command"), `{"command":"resume"}`); rec.Code != http.StatusConflict {
		t.Fatalf("offline command status=%d body=%s", rec.Code, rec.Body)
	}
	f.relay.online = true

	if rec := f.mutate("POST", f.installPath("/rename"), `{"name":"  New Bot  "}`); rec.Code != http.StatusOK {
		t.Fatalf("rename status=%d body=%s", rec.Code, rec.Body)
	}
	if inst, ok := f.store.Installation(f.inst.ID); !ok || inst.Name != "New Bot" {
		t.Fatalf("renamed installation=%+v ok=%v", inst, ok)
	}
	if rec := f.mutate("POST", f.installPath("/rename"), `{"name":"   "}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty rename status=%d", rec.Code)
	}
	if rec := f.mutate("POST", f.installPath("/rename"), `{"name":"bad/name"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid rename status=%d", rec.Code)
	}

	if rec := f.mutate("DELETE", f.installPath(""), ""); rec.Code != http.StatusOK {
		t.Fatalf("unlink status=%d body=%s", rec.Code, rec.Body)
	}
	if _, ok := f.store.Installation(f.inst.ID); ok {
		t.Fatal("installation still stored after unlink")
	}
	if len(f.relay.closed) != 1 || f.relay.closed[0] != f.inst.ID {
		t.Fatalf("closed=%v", f.relay.closed)
	}
	if rec := f.mutate("DELETE", f.installPath(""), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("second unlink status=%d", rec.Code)
	}
}

func TestDashboardMutatingRoutesRequireCSRFAndOwnership(t *testing.T) {
	f := newDashboardFixture(t, true)

	// No CSRF header.
	req := httptest.NewRequest("POST", f.installPath("/command"), strings.NewReader(`{"command":"pause"}`))
	req.Header.Set("Origin", "https://panel.example.com")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.token})
	if rec := f.do(req); rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status=%d", rec.Code)
	}
	// No origin.
	req = httptest.NewRequest("POST", f.installPath("/rename"), strings.NewReader(`{"name":"x"}`))
	req.Header.Set(auth.CSRFHeader, f.csrf)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.token})
	if rec := f.do(req); rec.Code != http.StatusForbidden {
		t.Fatalf("missing origin status=%d", rec.Code)
	}

	// Another user's installation is always 404.
	token2, csrf2, err := f.store.CreateSession("u2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path, body string }{
		{"POST", f.installPath("/command"), `{"command":"pause"}`},
		{"POST", f.installPath("/rename"), `{"name":"stolen"}`},
		{"DELETE", f.installPath(""), ""},
	} {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(auth.CSRFHeader, csrf2)
		req.Header.Set("Origin", "https://panel.example.com")
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token2})
		if rec := f.do(req); rec.Code != http.StatusNotFound {
			t.Fatalf("foreign %s %s status=%d body=%s", c.method, c.path, rec.Code, rec.Body)
		}
	}
}

func TestDashboardRateLimits(t *testing.T) {
	f := newDashboardFixture(t, true)
	f.srv.Limiter = newLimiter(1, 1)

	if rec := f.get("/dashboard/api/state"); rec.Code != http.StatusOK {
		t.Fatalf("first state status=%d body=%s", rec.Code, rec.Body)
	}
	rec := f.get("/dashboard/api/state")
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"status":429`) {
		t.Fatalf("second state status=%d body=%s", rec.Code, rec.Body)
	}

	f.srv.PairLimiter = newLimiter(1, 1)
	if rec := f.mutate("POST", "/dashboard/api/pair/code", ""); rec.Code != http.StatusOK {
		t.Fatalf("first pair code status=%d body=%s", rec.Code, rec.Body)
	}
	rec = f.mutate("POST", "/dashboard/api/pair/code", "")
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"status":429`) {
		t.Fatalf("second pair code status=%d body=%s", rec.Code, rec.Body)
	}

	f.srv.CommandLimiter = newLimiter(1, 1)
	if rec := f.mutate("POST", f.installPath("/command"), `{"command":"pause"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("first command status=%d body=%s", rec.Code, rec.Body)
	}
	rec = f.mutate("POST", f.installPath("/command"), `{"command":"pause"}`)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"status":429`) {
		t.Fatalf("second command status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestRedeemRateLimitsPerIPAndGlobal(t *testing.T) {
	post := func(s *Server, ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/dashboard/api/pair/redeem", strings.NewReader(`{"code":"AAAAAAAA","protocols":[1]}`))
		req.RemoteAddr = ip + ":1234"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	s, _ := newTestServer(t)
	s.PairLimiter = newLimiter(1, 1)
	if rec := post(s, "192.0.2.1"); rec.Code != http.StatusNotFound {
		t.Fatalf("first redeem status=%d body=%s", rec.Code, rec.Body)
	}
	if rec := post(s, "192.0.2.1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second redeem from one IP status=%d body=%s", rec.Code, rec.Body)
	}
	// A different IP has its own bucket.
	if rec := post(s, "192.0.2.2"); rec.Code != http.StatusNotFound {
		t.Fatalf("other IP status=%d body=%s", rec.Code, rec.Body)
	}

	s2, _ := newTestServer(t)
	s2.CommandLimiter = newLimiter(1, 1)
	if rec := post(s2, "192.0.2.1"); rec.Code != http.StatusNotFound {
		t.Fatalf("first global redeem status=%d", rec.Code)
	}
	if rec := post(s2, "192.0.2.2"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("global redeem limit status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestPanelRateLimitPerSession(t *testing.T) {
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1), panel: pageRelay()}
	f := newPanelFixture(t, fr)
	f.srv.Limiter = newLimiter(1, 1)

	if rec := f.get(f.base); rec.Code != http.StatusOK {
		t.Fatalf("first panel status=%d body=%s", rec.Code, rec.Body)
	}
	rec := f.get(f.base)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"status":429`) {
		t.Fatalf("second panel status=%d body=%s", rec.Code, rec.Body)
	}
}

// scanEvents reads SSE lines into a channel until the stream ends.
func scanEvents(body io.Reader) <-chan string {
	out := make(chan string, 32)
	go func() {
		defer close(out)
		scanner := bufio.NewScanner(body)
		for scanner.Scan() {
			out <- scanner.Text()
		}
	}()
	return out
}

// waitEvent waits for one complete event containing want.
func waitEvent(t *testing.T, lines <-chan string, want string) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	seen := make([]string, 0, 4)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("stream closed while waiting for %q (seen %v)", want, seen)
			}
			if line == "" {
				if strings.Contains(strings.Join(seen, "\n"), want) {
					return
				}
				seen = seen[:0]
				continue
			}
			seen = append(seen, line)
		case <-timeout:
			t.Fatalf("timed out waiting for %q (seen %v)", want, seen)
		}
	}
}

func TestSSEStreamAndTabLimit(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.UpsertUser(store.User{ID: "u1", Username: "u1"}); err != nil {
		t.Fatal(err)
	}
	token, _, err := st.CreateSession("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1)}
	s := New(config.Config{PublicBaseURL: "https://panel.example.com"}, st, fr, nil)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	type stream struct {
		resp   *http.Response
		cancel context.CancelFunc
		lines  <-chan string
	}
	open := func() *stream {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		req, err := http.NewRequestWithContext(ctx, "GET", ts.URL+"/dashboard/events", nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		resp, err := ts.Client().Do(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		return &stream{resp: resp, cancel: cancel, lines: scanEvents(resp.Body)}
	}

	first := open()
	defer first.cancel()
	if ct := first.resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type=%q", ct)
	}
	if cc := first.resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache-control=%q", cc)
	}
	waitEvent(t, first.lines, "event: update")

	// A hub notification reaches the stream.
	fr.updates <- struct{}{}
	waitEvent(t, first.lines, "event: update")

	// Five tabs are allowed; the sixth is refused.
	others := make([]*stream, 0, 4)
	defer func() {
		for _, o := range others {
			o.cancel()
			o.resp.Body.Close()
		}
	}()
	for i := 0; i < 4; i++ {
		others = append(others, open())
		waitEvent(t, others[i].lines, "event: update")
	}

	req, err := http.NewRequest("GET", ts.URL+"/dashboard/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(body), `"status":429`) {
		t.Fatalf("sixth tab status=%d body=%s", resp.StatusCode, body)
	}

	// Anonymous streams are refused before the tab budget is touched.
	anon, err := http.Get(ts.URL + "/dashboard/events")
	if err != nil {
		t.Fatal(err)
	}
	anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous stream status=%d", anon.StatusCode)
	}
}

// TestSSEExitsWhenBaseContextCanceled proves a dashboard stream ends when the
// server's base context is canceled. main cancels that context before
// http.Server.Shutdown, which never closes active connections; without it a
// single open dashboard tab makes shutdown wait out the whole deadline and
// then cut the stream off at process exit.
func TestSSEExitsWhenBaseContextCanceled(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.UpsertUser(store.User{ID: "u1", Username: "u1"}); err != nil {
		t.Fatal(err)
	}
	token, _, err := st.CreateSession("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fr := &fakeRelay{online: true, updates: make(chan struct{}, 1)}
	s := New(config.Config{PublicBaseURL: "https://panel.example.com"}, st, fr, nil)

	openStreams := func() int {
		s.SSE.mu.Lock()
		defer s.SSE.mu.Unlock()
		return s.SSE.users["u1"]
	}

	base, cancelBase := context.WithCancel(context.Background())
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.Config.BaseContext = func(net.Listener) context.Context { return base }
	ts.Start()
	t.Cleanup(func() {
		cancelBase()
		ts.Close()
	})

	req, err := http.NewRequest("GET", ts.URL+"/dashboard/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status=%d", resp.StatusCode)
	}
	lines := scanEvents(resp.Body)
	waitEvent(t, lines, "event: update")
	if n := openStreams(); n != 1 {
		t.Fatalf("open streams before cancel=%d", n)
	}

	// The handler must return on its own: the response ends and the line
	// channel closes.
	cancelBase()
	timeout := time.After(5 * time.Second)
	for closed := false; !closed; {
		select {
		case _, ok := <-lines:
			closed = !ok
		case <-timeout:
			t.Fatal("stream did not end after the base context was canceled")
		}
	}
	if n := openStreams(); n != 0 {
		t.Fatalf("stream slot not released after cancel: %d", n)
	}

	// With the stream gone, graceful shutdown has nothing left to wait on.
	shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ts.Config.Shutdown(shutdown); err != nil {
		t.Fatalf("shutdown after the stream ended: %v", err)
	}
}

// fakeDiscordUser starts a stand-in Discord API and returns a client for it.
func fakeDiscordUser(t *testing.T, id, username, globalName string) *auth.Discord {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "authcode" ||
				len(r.Form.Get("code_verifier")) < 43 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token-1"})
		case "/users/@me":
			if r.Header.Get("Authorization") != "Bearer token-1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": id, "username": username, "global_name": globalName,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &auth.Discord{
		ClientID:     "cid",
		ClientSecret: "secret",
		RedirectURI:  "https://panel.example.com/auth/callback",
		AuthorizeURL: "https://discord.example.com/oauth2/authorize",
		TokenURL:     srv.URL + "/oauth2/token",
		UserURL:      srv.URL + "/users/@me",
		HTTP:         srv.Client(),
	}
}

// startOAuth performs /auth/login and returns the state value.
func startOAuth(t *testing.T, s *Server) (state, verifier string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/auth/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login status=%d body=%s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state = loc.Query().Get("state")
	if state == "" {
		t.Fatalf("no state in %q", loc)
	}
	return state, s.States.m[state].verifier
}

func oauthCallback(s *Server, state, code string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET",
		"/auth/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape(code), nil)
	req.AddCookie(&http.Cookie{Name: auth.OAuthCookie, Value: state})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// oauthCookieCleared reports whether the response expires the OAuth cookie.
func oauthCookieCleared(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.OAuthCookie && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestOAuthLoginAndCallback(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d := fakeDiscordUser(t, "42", "alice", "Alice")
	s := New(config.Config{PublicBaseURL: "https://panel.example.com", DiscordEnabled: true}, st, nil, d)

	login := httptest.NewRecorder()
	s.Handler().ServeHTTP(login, httptest.NewRequest("GET", "/auth/login", nil))
	if login.Code != http.StatusFound {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body)
	}
	loc, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	state, challenge := q.Get("state"), q.Get("code_challenge")
	if state == "" || challenge == "" || q.Get("code_challenge_method") != "S256" ||
		q.Get("redirect_uri") != "https://panel.example.com/auth/callback" ||
		q.Get("client_id") != "cid" || q.Get("scope") != "identify" {
		t.Fatalf("authorize url=%q", loc)
	}
	entry, _ := st.PeekOAuthState(state)
	verifier := entry.Verifier
	if verifier == "" || !auth.VerifyPKCE(verifier, challenge) {
		t.Fatal("server-side verifier does not match the challenge")
	}

	var oauthCookie *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == auth.OAuthCookie {
			oauthCookie = c
		}
	}
	if oauthCookie == nil || oauthCookie.Value != state || !oauthCookie.HttpOnly ||
		oauthCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("oauth cookie=%+v", oauthCookie)
	}

	rec := oauthCallback(s, state, "authcode")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("callback status=%d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if !oauthCookieCleared(rec) {
		t.Fatal("callback did not clear the OAuth cookie")
	}
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			session = c
		}
	}
	if session == nil || session.Value == "" || !session.HttpOnly ||
		session.SameSite != http.SameSiteLaxMode || session.MaxAge != 30*24*60*60 {
		t.Fatalf("session cookie=%+v", session)
	}
	sess, ok := st.Session(session.Value, time.Now())
	if !ok || sess.DiscordID != "42" || sess.CSRF == "" {
		t.Fatalf("session=%+v ok=%v", sess, ok)
	}
	user, ok := st.User("42")
	if !ok || user.Username != "alice" || user.GlobalName != "Alice" {
		t.Fatalf("user=%+v ok=%v", user, ok)
	}
}

func TestOAuthCallbackRejectsBadState(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(config.Config{PublicBaseURL: "https://panel.example.com", DiscordEnabled: true}, st, nil, nil)

	cases := []struct {
		name   string
		cookie string
		value  string
	}{
		{"missing cookie", "", ""},
		{"empty state", "", ""},
		{"cookie without state", "abcdef", ""},
		{"state mismatch", "abcdef", "fedcba"},
		{"unknown state", "abcdef", "abcdef"},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/auth/callback?state="+url.QueryEscape(c.value)+"&code=x", nil)
		if c.cookie != "" {
			req.AddCookie(&http.Cookie{Name: auth.OAuthCookie, Value: c.cookie})
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", c.name, rec.Code, rec.Body)
		}
		if !oauthCookieCleared(rec) {
			t.Fatalf("%s did not clear the OAuth cookie", c.name)
		}
	}

	// A cancelled sign-in is reported after the state is validated.
	state, _ := auth.RandomToken(24)
	st.PutOAuthState(state, "verifier", time.Now().Add(time.Minute).UnixMilli())
	req := httptest.NewRequest("GET", "/auth/callback?state="+url.QueryEscape(state)+"&error=access_denied", nil)
	req.AddCookie(&http.Cookie{Name: auth.OAuthCookie, Value: state})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "cancelled") {
		t.Fatalf("cancelled status=%d body=%s", rec.Code, rec.Body)
	}
	if _, ok := st.PeekOAuthState(state); ok {
		t.Fatal("state was not consumed by the callback")
	}
}

func TestOAuthCallbackRejectsDisallowedUser(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d := fakeDiscordUser(t, "42", "alice", "Alice")
	s := New(config.Config{
		PublicBaseURL:     "https://panel.example.com",
		DiscordEnabled:    true,
		AllowedDiscordIDs: map[string]bool{"99": true},
	}, st, nil, d)

	state, _ := startOAuth(t, s)
	rec := oauthCallback(s, state, "authcode")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed status=%d body=%s", rec.Code, rec.Body)
	}
	if !oauthCookieCleared(rec) {
		t.Fatal("disallowed sign-in did not clear the OAuth cookie")
	}
	if len(st.State().Sessions) != 0 {
		t.Fatal("disallowed sign-in created a session")
	}
}

func TestDevLoginAndLogout(t *testing.T) {
	s, st := newTestServer(t)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/auth/dev", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("dev login disabled status=%d", rec.Code)
	}

	s.Cfg.PublicBaseURL = "http://localhost:8080"
	s.Cfg.DevLogin = true
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/auth/dev?user=Alice%20B!", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("dev login status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			session = c
		}
	}
	if session == nil || session.Value == "" {
		t.Fatal("dev login set no session cookie")
	}
	sess, ok := st.Session(session.Value, time.Now())
	if !ok || sess.DiscordID != "dev-aliceb" {
		t.Fatalf("dev session=%+v ok=%v", sess, ok)
	}
	if _, ok := st.User("dev-aliceb"); !ok {
		t.Fatal("dev user was not stored")
	}

	// Logout drops the session and clears the cookie; it carries the CSRF
	// header and origin like any other mutation.
	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session.Value})
	req.Header.Set(auth.CSRFHeader, sess.CSRF)
	req.Header.Set("Origin", "http://localhost:8080")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("logout status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear the session cookie")
	}
	if _, ok := st.Session(session.Value, time.Now()); ok {
		t.Fatal("logout left the session valid")
	}
}

func TestLogoutRequiresCSRFAndOrigin(t *testing.T) {
	s, st := newTestServer(t)
	if err := st.UpsertUser(store.User{ID: "u1", Username: "u1"}); err != nil {
		t.Fatal(err)
	}
	newSession := func() (string, string) {
		t.Helper()
		token, csrf, err := st.CreateSession("u1", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return token, csrf
	}
	logout := func(token, header, form, origin string) *httptest.ResponseRecorder {
		var body io.Reader
		if form != "" {
			body = strings.NewReader(url.Values{"csrf": {form}}.Encode())
		}
		req := httptest.NewRequest("POST", "/auth/logout", body)
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		if form != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if header != "" {
			req.Header.Set(auth.CSRFHeader, header)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	token, csrf := newSession()
	if rec := logout(token, "", "", "https://panel.example.com"); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("missing token status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	if _, ok := st.Session(token, time.Now()); ok {
		t.Fatal("stale-token logout left the session valid")
	}
	token, csrf = newSession()
	if rec := logout(token, "wrong", "", "https://panel.example.com"); rec.Code != http.StatusSeeOther {
		t.Fatalf("mismatched token status=%d", rec.Code)
	}
	if _, ok := st.Session(token, time.Now()); ok {
		t.Fatal("mismatched-token logout left the session valid")
	}
	token, csrf = newSession()
	if rec := logout(token, csrf, "", ""); rec.Code != http.StatusSeeOther {
		t.Fatalf("missing origin status=%d", rec.Code)
	}
	if _, ok := st.Session(token, time.Now()); !ok {
		t.Fatal("a foreign-origin logout revoked the session")
	}

	rec := logout(token, csrf, "", "https://panel.example.com")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("header logout status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear the session cookie")
	}
	if _, ok := st.Session(token, time.Now()); ok {
		t.Fatal("header logout left the session valid")
	}

	// The dashboard form sends the token in the body instead of a header.
	token, csrf = newSession()
	rec = logout(token, "", csrf, "https://panel.example.com")
	if rec.Code != http.StatusFound {
		t.Fatalf("form logout status=%d body=%s", rec.Code, rec.Body)
	}
	if _, ok := st.Session(token, time.Now()); ok {
		t.Fatal("form logout left the session valid")
	}
}

func TestAuthLoginWithoutDiscord(t *testing.T) {
	s, _ := newTestServer(t) // nil Discord client, Discord disabled
	for _, path := range []string{"/auth/login", "/auth/callback?state=x&code=y"} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == auth.OAuthCookie {
				t.Fatalf("%s set an OAuth cookie", path)
			}
		}
	}
}

func TestOAuthStatesStayBounded(t *testing.T) {
	o := &oauthStates{m: map[string]oauthState{}}

	// Expired states are swept once the map is full, even under a login flood.
	for i := 0; i < oauthStateMax; i++ {
		o.m[fmt.Sprintf("old-%d", i)] = oauthState{verifier: "v", expires: time.Now().Add(-time.Minute)}
	}
	o.put("fresh", "verifier", time.Minute)
	if n := len(o.m); n != 1 {
		t.Fatalf("states=%d after expired sweep, want 1", n)
	}
	if v, ok := o.take("fresh"); !ok || v != "verifier" {
		t.Fatalf("fresh verifier=%q ok=%v", v, ok)
	}

	// Fresh states are capped too; the soonest-expiring one is retired.
	for i := 0; i < oauthStateMax+10; i++ {
		o.put(fmt.Sprintf("state-%d", i), "v", time.Duration(i+1)*time.Second)
	}
	if n := len(o.m); n > oauthStateMax {
		t.Fatalf("states=%d, want <= %d", n, oauthStateMax)
	}
}

// inProcessMock is a protocol-1 client that lives in the test process. The
// dashboard-facing tests use it to drive the real relay hub end to end.
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
		"sales":  map[string]any{"h1": 2, "h24": 22}, "purchases": map[string]any{"h24": 24},
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
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("redeem status=%d", resp.StatusCode)
	}
	var pr struct {
		InstallationID int64  `json:"installationId"`
		Credential     string `json:"credential"`
		WSURL          string `json:"wsUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		t.Fatal(err)
	}
	url := pr.WSURL
	if strings.HasPrefix(url, "https") {
		url = "wss" + strings.TrimPrefix(url, "http")
	}
	if strings.HasPrefix(url, "http") {
		url = "ws" + strings.TrimPrefix(url, "http")
	}
	conn, _, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer " + pr.Credential}})
	if err != nil {
		t.Fatal(err)
	}
	m := &inProcessMock{conn: conn, installationID: pr.InstallationID, panelFrames: make(chan map[string]any, 8)}
	if err := m.write(map[string]any{"type": "hello", "protocols": []int{1}, "build": "mock-1",
		"name": "Mock bot", "hive": "mock", "capabilities": []string{"pause", "resume", "snapshot", "panel"}}); err != nil {
		t.Fatal(err)
	}
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil || welcome["type"] != "welcome" {
		t.Fatalf("welcome=%v err=%v", welcome, err)
	}
	go func() {
		for {
			var f map[string]any
			if conn.ReadJSON(&f) != nil {
				return
			}
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
					reply["contentType"] = "application/json"
					reply["body"] = `{"ok":true}`
				case "act":
					reply["status"] = 204
					reply["contentType"] = "text/plain"
					reply["body"] = ""
				default:
					reply["status"] = 404
					reply["contentType"] = "text/plain"
					reply["body"] = "Not found"
				}
				_ = m.write(reply)
			}
		}
	}()
	return m
}

func (m *inProcessMock) close() { m.conn.Close() }

// TestEndToEndPairTelemetryCommandPanel walks the whole stack the way a mod
// and a browser would: dev sign-in, pairing-code creation, redeem, a real
// WebSocket, telemetry, a command, a relayed panel page, and a panel action.
func TestEndToEndPairTelemetryCommandPanel(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="gonuts-csrf" content="([^"]+)"`).FindSubmatch(page)
	if len(m) != 2 {
		t.Fatalf("no csrf in dashboard: %s", page)
	}
	csrf := string(m[1])

	req, _ := http.NewRequest("POST", ts.URL+"/dashboard/api/pair/code", nil)
	req.Header.Set("X-Gonuts-Csrf", csrf)
	req.Header.Set("Origin", ts.URL)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var pairCode struct {
		Code string `json:"code"`
	}
	json.NewDecoder(resp.Body).Decode(&pairCode)
	resp.Body.Close()
	if pairCode.Code == "" {
		t.Fatal("no pairing code")
	}

	mock := startInProcessMock(t, ts.URL, pairCode.Code)
	defer mock.close()
	waitWeb(t, "online", func() bool { return hub.Online(mock.installationID) })
	if err := mock.telemetry("MockAccount"); err != nil {
		t.Fatal(err)
	}

	state := func() map[string]any {
		req, _ := http.NewRequest("GET", ts.URL+"/dashboard/api/state", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	waitWeb(t, "telemetry", func() bool {
		b := state()
		list, _ := b["installations"].([]any)
		if len(list) != 1 {
			return false
		}
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
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("command status=%d", resp.StatusCode)
	}
	waitWeb(t, "command result", func() bool {
		b := state()
		list, _ := b["installations"].([]any)
		if len(list) != 1 {
			return false
		}
		last, _ := list[0].(map[string]any)["lastCommand"].(map[string]any)
		return last != nil && last["state"] == "completed"
	})

	panelURL := ts.URL + "/dashboard/panel/" + strconv.FormatInt(mock.installationID, 10) + "/"
	resp, err = client.Get(panelURL)
	if err != nil {
		t.Fatal(err)
	}
	panel, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
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
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("act status=%d", resp.StatusCode)
	}
	select {
	case f := <-mock.panelFrames:
		if f["op"] != "page" {
			t.Fatalf("first panel frame=%v", f)
		}
	case <-time.After(time.Second):
		t.Fatal("mock did not receive page request")
	}
	select {
	case f := <-mock.panelFrames:
		if f["op"] != "act" {
			t.Fatalf("act frame=%v", f)
		}
	case <-time.After(time.Second):
		t.Fatal("mock did not receive act")
	}
}

func waitWeb(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// newLocalServer builds a panel that only offers the local password form. The
// hash uses a low iteration count so the test stays fast.
func newLocalServer(t *testing.T, password, user string) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, err := auth.HashPassword(password, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return New(config.Config{
		PublicBaseURL:     "https://panel.example.com",
		LocalPasswordHash: hash,
		LocalUser:         user,
	}, st, nil, nil), st
}

// localLogin posts the sign-in form. An empty origin omits the header; an
// empty ip leaves the recorder's default remote address.
func localLogin(s *Server, password, origin, ip string) *httptest.ResponseRecorder {
	body := url.Values{"password": {password}, "remember": {"1"}}.Encode()
	req := httptest.NewRequest("POST", "/auth/local", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if ip != "" {
		req.RemoteAddr = ip + ":1234"
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestHiddenLocalLoginOffersNoPasswordForm(t *testing.T) {
	s, _ := newLocalServer(t, "hunter2", "owner")
	s.Cfg.HideLocalLogin = true
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/dashboard", nil))
	page := rec.Body.String()
	if strings.Contains(page, "local-password") {
		t.Fatal("password form still shown while hidden")
	}
}

func TestLocalLoginWithoutOriginSameHost(t *testing.T) {
	s, _ := newLocalServer(t, "hunter2", "owner")
	body := url.Values{"password": {"hunter2"}, "remember": {"1"}}.Encode()
	post := func(origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/auth/local", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.Host = "panel.example.com"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := post(""); rec.Code != http.StatusSeeOther {
		t.Fatalf("same-host post without Origin status=%d", rec.Code)
	}
	if rec := post("https://evil.example"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin post status=%d", rec.Code)
	}
	if rec := post("null"); rec.Code != http.StatusSeeOther {
		t.Fatalf("null-origin same-host status=%d", rec.Code)
	}
	{
		req := httptest.NewRequest("POST", "/auth/local", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", "https://panel.example.com/dashboard")
		req.Host = "panel.example.com"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("same-host referer status=%d", rec.Code)
		}
	}
}

func TestLocalLoginWithoutRememberIsSessionCookie(t *testing.T) {
	s, _ := newLocalServer(t, "hunter2", "owner")
	body := url.Values{"password": {"hunter2"}}.Encode()
	req := httptest.NewRequest("POST", "/auth/local", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://panel.example.com")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status=%d", rec.Code)
	}
	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			found = true
			if c.MaxAge != 0 {
				t.Fatalf("unchecked remember should omit Max-Age, got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Fatal("no session cookie")
	}
}

func TestLocalLoginCreatesSession(t *testing.T) {
	s, st := newLocalServer(t, "hunter2", "owner")

	rec := localLogin(s, "hunter2", "https://panel.example.com", "")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("status=%d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	var token string
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			token = c.Value
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 30*24*60*60 {
				t.Fatalf("session cookie=%+v", c)
			}
		}
	}
	if token == "" {
		t.Fatal("local sign-in set no session cookie")
	}
	sess, ok := st.Session(token, time.Now())
	if !ok || sess.DiscordID != "owner" || sess.CSRF == "" {
		t.Fatalf("session=%+v ok=%v", sess, ok)
	}
	user, ok := st.User("owner")
	if !ok || user.Username != "owner" || user.GlobalName != "owner" || user.CreatedAt == 0 {
		t.Fatalf("user=%+v ok=%v", user, ok)
	}

	// The new session reaches the dashboard shell rather than the sign-in page.
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	page := httptest.NewRecorder()
	s.Handler().ServeHTTP(page, req)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `name="gonuts-csrf" content="`+sess.CSRF+`"`) {
		t.Fatalf("dashboard status=%d body=%s", page.Code, page.Body)
	}

	// The default account id is a fixed string, not attacker input.
	s2, st2 := newLocalServer(t, "hunter2", "")
	if rec := localLogin(s2, "hunter2", "https://panel.example.com", ""); rec.Code != http.StatusSeeOther {
		t.Fatalf("default-user status=%d body=%s", rec.Code, rec.Body)
	}
	if _, ok := st2.User("local"); !ok {
		t.Fatal("default local user was not stored as \"local\"")
	}
}

func TestLocalLoginWrongPasswordAndOrigin(t *testing.T) {
	s, st := newLocalServer(t, "hunter2", "owner")

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"wrong password": localLogin(s, "hunter3", "https://panel.example.com", ""),
		"empty password": localLogin(s, "", "https://panel.example.com", ""),
	} {
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/dashboard?error=local" {
			t.Fatalf("%s: status=%d location=%q", name, rec.Code, rec.Header().Get("Location"))
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == auth.CookieName {
				t.Fatalf("%s: a failed sign-in set a session cookie", name)
			}
		}
	}
	if n := len(st.State().Sessions); n != 0 {
		t.Fatalf("failed sign-ins created %d sessions", n)
	}

	// Mutations must come from the panel's own origin.
	for name, origin := range map[string]string{"missing origin": "", "cross origin": "https://evil.example"} {
		rec := localLogin(s, "hunter2", origin, "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d body=%s", name, rec.Code, rec.Body)
		}
	}
	if n := len(st.State().Sessions); n != 0 {
		t.Fatalf("origin-rejected sign-ins created %d sessions", n)
	}

	// The sign-in page reports the generic error and keeps the form.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/dashboard?error=local", nil))
	page := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(page, "Incorrect password.") ||
		!strings.Contains(page, `action="/auth/local"`) {
		t.Fatalf("error page status=%d body=%s", rec.Code, page)
	}
	// Without the flag the error is absent.
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/dashboard", nil))
	if strings.Contains(rec.Body.String(), "Incorrect password.") {
		t.Fatal("sign-in page shows an error without ?error=local")
	}
}

func TestLocalLoginRateLimit(t *testing.T) {
	s, _ := newLocalServer(t, "hunter2", "owner")
	s.LocalLimiter = newLimiter(1, 1) // one attempt per minute, burst of one

	if rec := localLogin(s, "wrong", "https://panel.example.com", "192.0.2.1"); rec.Code != http.StatusSeeOther {
		t.Fatalf("first attempt status=%d body=%s", rec.Code, rec.Body)
	}
	rec := localLogin(s, "hunter2", "https://panel.example.com", "192.0.2.1")
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"status":429`) {
		t.Fatalf("second attempt status=%d body=%s", rec.Code, rec.Body)
	}
	// Another client IP has its own bucket.
	if rec := localLogin(s, "hunter2", "https://panel.example.com", "192.0.2.2"); rec.Code != http.StatusSeeOther {
		t.Fatalf("other IP status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestLocalLoginPlaintextFallback(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(config.Config{
		PublicBaseURL: "https://panel.example.com",
		LocalPassword: "hunter2",
		LocalUser:     "owner",
	}, st, nil, nil)

	if rec := localLogin(s, "hunter2", "https://panel.example.com", ""); rec.Code != http.StatusSeeOther {
		t.Fatalf("plaintext sign-in status=%d body=%s", rec.Code, rec.Body)
	}
	if rec := localLogin(s, "wrong", "https://panel.example.com", ""); rec.Header().Get("Location") != "/dashboard?error=local" {
		t.Fatalf("plaintext wrong password location=%q", rec.Header().Get("Location"))
	}

	// A configured hash takes precedence over the plaintext fallback.
	hash, err := auth.HashPassword("hashed", 1000)
	if err != nil {
		t.Fatal(err)
	}
	s.Cfg.LocalPasswordHash = hash
	if rec := localLogin(s, "hunter2", "https://panel.example.com", ""); rec.Header().Get("Location") != "/dashboard?error=local" {
		t.Fatal("plaintext password accepted while a hash is configured")
	}
	if rec := localLogin(s, "hashed", "https://panel.example.com", ""); rec.Code != http.StatusSeeOther {
		t.Fatalf("hashed sign-in status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestLocalLoginUnconfiguredIs404(t *testing.T) {
	s, _ := newTestServer(t) // neither Discord nor a local password
	rec := localLogin(s, "hunter2", "https://panel.example.com", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestLoginPageSignInModes(t *testing.T) {
	hash, err := auth.HashPassword("hunter2", 1000)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		cfg     config.Config
		want    []string
		notWant []string
	}{
		{
			name:    "local only",
			cfg:     config.Config{LocalPasswordHash: hash},
			want:    []string{`action="/auth/local"`, `type="password"`, `autocomplete="current-password"`, "Sign in"},
			notWant: []string{"/auth/login", "No sign-in method configured", `class="login-divider"`, "{{"},
		},
		{
			name:    "discord only",
			cfg:     config.Config{DiscordEnabled: true},
			want:    []string{`href="/auth/login"`, "Sign in with Discord"},
			notWant: []string{`action="/auth/local"`, "No sign-in method configured", `class="login-divider"`, "{{"},
		},
		{
			name:    "both",
			cfg:     config.Config{DiscordEnabled: true, LocalPasswordHash: hash},
			want:    []string{`action="/auth/local"`, `href="/auth/login"`, `class="login-divider"`},
			notWant: []string{"No sign-in method configured", "{{"},
		},
		{
			name:    "neither",
			cfg:     config.Config{},
			want:    []string{"No sign-in method configured"},
			notWant: []string{`action="/auth/local"`, `href="/auth/login"`, "{{"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := store.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			tc.cfg.PublicBaseURL = "https://panel.example.com"
			s := New(tc.cfg, st, nil, nil)
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/dashboard", nil))
			page := rec.Body.String()
			if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "text/html") ||
				rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d headers=%v", rec.Code, rec.Header())
			}
			for _, want := range tc.want {
				if !strings.Contains(page, want) {
					t.Fatalf("page missing %q:\n%s", want, page)
				}
			}
			for _, notWant := range tc.notWant {
				if strings.Contains(page, notWant) {
					t.Fatalf("page contains %q:\n%s", notWant, page)
				}
			}
		})
	}

	// The error text is only rendered when a local password can be tried.
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(config.Config{PublicBaseURL: "https://panel.example.com", DiscordEnabled: true}, st, nil, nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/dashboard?error=local", nil))
	if strings.Contains(rec.Body.String(), "Incorrect password.") {
		t.Fatal("Discord-only page renders the local password error")
	}
}

func TestAuthDisabledAutoLogin(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(config.Config{
		PublicBaseURL:   "http://127.0.0.1:8080",
		AuthDisabled:    true,
		LocalUser:       "local",
		PanelCacheBytes: 1 << 20,
	}, st, nil, nil)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/dashboard", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `gonuts-csrf`) {
		t.Fatalf("dashboard status=%d body=%s", rec.Code, rec.Body)
	}
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			session = c
		}
	}
	if session == nil || session.Value == "" {
		t.Fatal("auto-login did not set a session cookie")
	}

	req := httptest.NewRequest("GET", "/dashboard/api/state", nil)
	req.AddCookie(session)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"id":"local"`) {
		t.Fatalf("state status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestCanonicalHostRedirectsAliasDomains(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(config.Config{
		PublicBaseURL: "https://gonuts.cyou",
		ExtraOrigins: []string{
			"https://vanillavn.xyz",
			"https://www.vanillavn.xyz",
			"https://gonuts-panel.onrender.com",
		},
	}, st, nil, nil)
	handler := s.Handler()
	serve := func(method, target, host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	for _, alias := range []string{"vanillavn.xyz", "www.vanillavn.xyz", "gonuts-panel.onrender.com"} {
		rec := serve("GET", "/dashboard", alias)
		if rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "https://gonuts.cyou/dashboard" {
			t.Fatalf("alias %s status=%d location=%q", alias, rec.Code, rec.Header().Get("Location"))
		}
	}
	if rec := serve("GET", "/dashboard", "gonuts.cyou"); rec.Code == http.StatusPermanentRedirect {
		t.Fatal("canonical host must not redirect")
	}
	if rec := serve("GET", "/healthz", "vanillavn.xyz"); rec.Code != http.StatusOK {
		t.Fatalf("health alias status=%d", rec.Code)
	}
	if rec := serve("POST", "/dashboard/api/pair/redeem", "vanillavn.xyz"); rec.Code == http.StatusPermanentRedirect {
		t.Fatal("pairing transport must not redirect")
	}
	if rec := serve("GET", "/dashboard", "unlisted.example"); rec.Code == http.StatusPermanentRedirect {
		t.Fatal("unknown host must not redirect")
	}
}
