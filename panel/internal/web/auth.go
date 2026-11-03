package web

import (
	"net/http"
	"sync"
	"time"
)

// oauthState holds the PKCE verifier for one in-flight sign-in.
type oauthState struct {
	verifier string
	expires  time.Time
}

// oauthStates is the short-lived server-side store for OAuth state values.
type oauthStates struct {
	mu sync.Mutex
	m  map[string]oauthState
}

// put records a verifier for state until it expires.
func (o *oauthStates) put(state, verifier string, ttl time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.m[state] = oauthState{verifier: verifier, expires: time.Now().Add(ttl)}
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

// The Discord sign-in handlers are implemented in Task 8.

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request)    { notImplemented(w) }
func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) { notImplemented(w) }
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request)   { notImplemented(w) }
func (s *Server) authDev(w http.ResponseWriter, r *http.Request)      { notImplemented(w) }
