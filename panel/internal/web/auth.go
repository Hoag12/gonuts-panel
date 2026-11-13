package web

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"gonutspanel/internal/auth"
	"gonutspanel/internal/config"
	"gonutspanel/internal/store"
)

// oauthState holds the PKCE verifier for one in-flight sign-in.
type oauthState struct {
	verifier string
	expires  time.Time
}

// oauthStates is the short-lived server-side store for OAuth state values. The
// verifier is kept here, never in a cookie: the browser only carries the opaque
// state, so a stolen cookie cannot bypass PKCE.
type oauthStates struct {
	mu sync.Mutex
	m  map[string]oauthState
}

// oauthStateMax bounds the map. /auth/login is unauthenticated, so without a
// cap a stream of abandoned sign-ins would grow memory for the state TTL.
const oauthStateMax = 1024

// put records a verifier for state until it expires.
func (o *oauthStates) put(state, verifier string, ttl time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now()
	if len(o.m) >= oauthStateMax {
		// Drop expired entries first; only then retire the soonest-expiring
		// one, which costs at most one abandoned sign-in.
		for k, v := range o.m {
			if now.After(v.expires) {
				delete(o.m, k)
			}
		}
		if len(o.m) >= oauthStateMax {
			var oldestKey string
			var oldest time.Time
			found := false
			for k, v := range o.m {
				if !found || v.expires.Before(oldest) {
					oldestKey, oldest, found = k, v.expires, true
				}
			}
			if found {
				delete(o.m, oldestKey)
			}
		}
	}
	o.m[state] = oauthState{verifier: verifier, expires: now.Add(ttl)}
}

// take consumes state and returns its verifier. Each state can be used once.
func (o *oauthStates) take(state string) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.m[state]
	delete(o.m, state)
	if !ok || time.Now().After(v.expires) {
		return "", false
	}
	return v.verifier, true
}

// oauthStateTTL is how long an authorize redirect may be answered.
const oauthStateTTL = 10 * time.Minute

// authLogin starts the Discord authorization-code flow with PKCE. The verifier
// is kept server-side and the state is bound to a short-lived cookie. Without
// Discord credentials the route does not exist.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.DiscordEnabled || s.Discord == nil {
		http.NotFound(w, r)
		return
	}
	state, err := auth.RandomToken(24)
	if err != nil {
		http.Error(w, "sign-in unavailable", http.StatusInternalServerError)
		return
	}
	verifier, err := auth.NewVerifier()
	if err != nil {
		http.Error(w, "sign-in unavailable", http.StatusInternalServerError)
		return
	}
	s.States.put(state, verifier, oauthStateTTL)
	auth.SetOAuthCookie(w, state, s.Cfg.CookieSecure)
	http.Redirect(w, r, s.Discord.AuthorizeURLFor(state, auth.Challenge(verifier)), http.StatusFound)
}

// authCallback completes the Discord flow: it validates the state against the
// cookie and the server-side verifier store, exchanges the code, checks the
// optional allowlist, and creates a browser session. The OAuth cookie is
// cleared on every outcome. Without Discord credentials the route does not
// exist.
func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.DiscordEnabled {
		http.NotFound(w, r)
		return
	}
	queryState := r.URL.Query().Get("state")
	c, cookieErr := r.Cookie(auth.OAuthCookie)
	cookieState := ""
	if cookieErr == nil {
		cookieState = c.Value
	}
	auth.ClearOAuthCookie(w, s.Cfg.CookieSecure)

	// Empty values are rejected explicitly: auth.Equal("", "") is true.
	if cookieErr != nil || cookieState == "" || queryState == "" ||
		!auth.Equal(cookieState, queryState) {
		http.Error(w, "invalid sign-in state", http.StatusBadRequest)
		return
	}
	verifier, ok := s.States.take(cookieState)
	if !ok {
		http.Error(w, "sign-in expired", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("error") != "" {
		http.Error(w, "Discord sign-in was cancelled", http.StatusBadRequest)
		return
	}
	if s.Discord == nil {
		http.Error(w, "sign-in unavailable", http.StatusServiceUnavailable)
		return
	}
	token, err := s.Discord.Exchange(r.Context(), r.URL.Query().Get("code"), verifier)
	if err != nil {
		// The error may quote Discord's response; only a fixed line is logged.
		log.Printf("oauth exchange failed")
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}
	du, err := s.Discord.Me(r.Context(), token)
	if err != nil {
		log.Printf("oauth user failed")
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}
	if du.ID == "" {
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}
	if len(s.Cfg.AllowedDiscordIDs) > 0 && !s.Cfg.AllowedDiscordIDs[du.ID] {
		http.Error(w, "this Discord account is not allowed", http.StatusForbidden)
		return
	}
	if err := s.Store.UpsertUser(store.User{
		ID:         du.ID,
		Username:   du.Username,
		GlobalName: du.GlobalName,
		Avatar:     du.Avatar,
		CreatedAt:  time.Now().UnixMilli(),
	}); err != nil {
		http.Error(w, "sign-in failed", http.StatusInternalServerError)
		return
	}
	sessToken, _, err := s.Store.CreateSession(du.ID, time.Now())
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, sessToken, s.Cfg.CookieSecure)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// authLocal signs in with the configured local password. It is a form POST
// from the panel's own sign-in page, so it requires a matching Origin, is rate
// limited per client IP, and never logs the submitted password. Failures
// redirect back to the sign-in page with a generic error instead of a status
// code, so the browser flow stays uniform.
func (s *Server) authLocal(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.LocalAuthEnabled() {
		http.NotFound(w, r)
		return
	}
	if !s.LocalLimiter.allow("local:"+s.clientIP(r), time.Now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"message": "too many sign-in attempts",
			"status":  http.StatusTooManyRequests,
		})
		return
	}
	if !s.originAllowed(r) {
		http.Error(w, "invalid request origin", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid sign-in request", http.StatusBadRequest)
		return
	}
	if !s.verifyLocalPassword(r.PostForm.Get("password")) {
		http.Redirect(w, r, "/dashboard?error=local", http.StatusSeeOther)
		return
	}
	id := s.Cfg.LocalUser
	if id == "" {
		id = "local"
	}
	if err := s.Store.UpsertUser(store.User{
		ID:         id,
		Username:   id,
		GlobalName: id,
		CreatedAt:  time.Now().UnixMilli(),
	}); err != nil {
		http.Error(w, "sign-in failed", http.StatusInternalServerError)
		return
	}
	token, _, err := s.Store.CreateSession(id, time.Now())
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusInternalServerError)
		return
	}
	if r.PostForm.Get("remember") != "" {
		auth.SetSessionCookie(w, token, s.Cfg.CookieSecure)
	} else {
		auth.SetSessionCookieSession(w, token, s.Cfg.CookieSecure)
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// verifyLocalPassword checks a submitted password against the configured hash,
// falling back to a constant-time compare for the plaintext form. Anything
// unconfigured or empty fails closed.
func (s *Server) verifyLocalPassword(password string) bool {
	if password == "" {
		return false
	}
	if s.Cfg.LocalPasswordHash != "" {
		return auth.VerifyPassword(s.Cfg.LocalPasswordHash, password)
	}
	if s.Cfg.LocalPassword != "" {
		return auth.Equal(s.Cfg.LocalPassword, password)
	}
	return false
}

// authDev creates a local test session. It is disabled unless GONUTS_DEV_LOGIN
// is set and never touches Discord.
func (s *Server) authDev(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.DevLogin || !config.IsLoopbackBaseURL(s.Cfg.PublicBaseURL) {
		http.NotFound(w, r)
		return
	}
	id := "dev"
	if q := strings.TrimSpace(r.URL.Query().Get("user")); q != "" {
		id = "dev-" + strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, strings.ToLower(q))
	}
	if err := s.Store.UpsertUser(store.User{
		ID:         id,
		Username:   id,
		GlobalName: id,
		CreatedAt:  time.Now().UnixMilli(),
	}); err != nil {
		http.Error(w, "dev sign-in failed", http.StatusInternalServerError)
		return
	}
	token, _, err := s.Store.CreateSession(id, time.Now())
	if err != nil {
		http.Error(w, "dev sign-in failed", http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, token, s.Cfg.CookieSecure)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// authLogout drops the current session and clears the cookie. Because sign-out
// is a mutation it carries the same CSRF and origin checks as the JSON APIs:
// either the X-Gonuts-Csrf header or the form's hidden csrf field is accepted.
// A request without a session has nothing to revoke, so it only clears any
// stale cookie and redirects.
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.session(r)
	if !ok {
		auth.ClearSessionCookie(w, s.Cfg.CookieSecure)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	_ = r.ParseForm()
	token := r.Header.Get(auth.CSRFHeader)
	if token == "" {
		token = r.PostForm.Get("csrf")
	}
	if !auth.Equal(token, sess.CSRF) || !s.originAllowed(r) {
		http.Error(w, "invalid request origin or token", http.StatusForbidden)
		return
	}
	_ = s.Store.DeleteSession(auth.CookieToken(r))
	auth.ClearSessionCookie(w, s.Cfg.CookieSecure)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
