package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

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
	token, csrf, err := st.CreateSession("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := st.CreateCode("u1", time.Now())
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

	// apiPairCode belongs to a later task; the stubbed route must be honest
	// about it rather than silently succeeding.
	if rec := mutate("/dashboard/api/pair/code", ""); rec.Code != http.StatusNotImplemented {
		t.Fatalf("pair code status=%d body=%s", rec.Code, rec.Body)
	}

	redeemBody := `{"code":"` + code + `","protocols":[1],"name":"Bot","build":"b","hive":"","capabilities":["panel"]}`
	req := httptest.NewRequest("POST", "/dashboard/api/pair/redeem", strings.NewReader(redeemBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("redeem status=%d body=%s", rec.Code, rec.Body)
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
	if rec := post(`{"code":"ABC","protocols":[1],"capabilities":["shell"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("capabilities status=%d", rec.Code)
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

func TestDeferredHandlersAnswer501(t *testing.T) {
	s, _ := newTestServer(t)
	cases := []struct{ method, path string }{
		{"GET", "/dashboard"},
		{"GET", "/auth/login"},
		{"GET", "/auth/callback"},
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
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s status=%d body=%s", c.method, c.path, rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "credentialHash") {
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
	updates  chan struct{}
	panel    func(context.Context, int64, map[string]any) (*relay.PanelResult, error)
}

func (f *fakeRelay) Online(int64) bool { return f.online }

func (f *fakeRelay) SendCommand(_ int64, c string) (string, error) {
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

func (f *fakeRelay) CloseInstallation(int64, int, string)       {}
func (f *fakeRelay) Updates() <-chan struct{}                   { return f.updates }
func (f *fakeRelay) ServeWS(http.ResponseWriter, *http.Request) {}

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

	if rec := f.get(f.base + "logo.png"); rec.Code != 200 {
		t.Fatalf("logo status=%d", rec.Code)
	}
	logo := fr.frames[len(fr.frames)-1]
	if logo["op"] != "asset" || logo["asset"] != "logo" {
		t.Fatalf("logo frame=%+v", logo)
	}

	fontRec := f.get(f.base + "font.ttf")
	if fontRec.Code != 200 || fontRec.Header().Get("Content-Type") != "font/ttf" {
		t.Fatalf("font status=%d type=%q", fontRec.Code, fontRec.Header().Get("Content-Type"))
	}
	font := fr.frames[len(fr.frames)-1]
	if font["op"] != "asset" || font["asset"] != "font" {
		t.Fatalf("font frame=%+v", font)
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

	// The logo/font assets keep the asset cache: a repeat costs no frame.
	for i := 0; i < 2; i++ {
		if rec := f.get(f.base + "font.ttf"); rec.Code != 200 {
			t.Fatalf("font %d status=%d", i, rec.Code)
		}
	}
	if len(fr.frames) != 3 {
		t.Fatalf("font frames=%d, want one relay plus one cache hit", len(fr.frames))
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
