package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
		{"GET", "/dashboard/panel/1/"},
		{"GET", "/dashboard/panel/1/state"},
		{"POST", "/dashboard/panel/1/act"},
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
