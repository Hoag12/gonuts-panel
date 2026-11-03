package web

import (
	"encoding/json"
	"errors"
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
