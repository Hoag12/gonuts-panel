// Package web serves the panel's HTTP endpoints: the dashboard shell, the
// Discord sign-in flow, the pairing and bearer-check endpoints used by the
// mod, and the relayed client panel.
//
// The route table is complete from the first version so later tasks only
// replace handler bodies. Handlers owned by later tasks currently answer 501.
package web

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"gonutspanel/internal/auth"
	"gonutspanel/internal/config"
	"gonutspanel/internal/relay"
	"gonutspanel/internal/store"
	webassets "gonutspanel/web"
)

// dashboardCSP is the default policy for panel-authored HTML. Relayed panel
// pages override it with the panel policy (Task 7).
const dashboardCSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
	"script-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; " +
	"base-uri 'none'; form-action 'self'"

// Relay is implemented by *relay.Hub and by test fakes.
type Relay interface {
	Online(id int64) bool
	SendCommand(id int64, command string) (string, error)
	PanelRequest(ctx context.Context, id int64, frame map[string]any) (*relay.PanelResult, error)
	CloseInstallation(id int64, code int, reason string)
	Updates() <-chan struct{}
	ServeWS(w http.ResponseWriter, r *http.Request)
}

type Server struct {
	Cfg        config.Config
	Store      *store.Store
	Hub        Relay
	Discord    *auth.Discord
	States     *oauthStates
	Limiter    *limiter
	SSE        *sseHub
	PanelCache *panelCache
}

// New builds a Server. A nil hub is replaced by an offline no-op so auth and
// pairing tests can omit the WebSocket layer.
func New(cfg config.Config, st *store.Store, hub Relay, d *auth.Discord) *Server {
	if hub == nil {
		hub = noopRelay{}
	}
	return &Server{
		Cfg:        cfg,
		Store:      st,
		Hub:        hub,
		Discord:    d,
		States:     &oauthStates{m: map[string]oauthState{}},
		Limiter:    newLimiter(120, 120),
		SSE:        newSSEHub(5),
		PanelCache: newPanelCache(cfg.PanelCacheBytes),
	}
}

// Handler returns the complete route table wrapped in the security middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", pageRedirect("/dashboard"))
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /dashboard", s.dashboardPage)
	mux.HandleFunc("GET /auth/login", s.authLogin)
	mux.HandleFunc("GET /auth/callback", s.authCallback)
	mux.HandleFunc("POST /auth/logout", s.authLogout)
	mux.HandleFunc("GET /auth/dev", s.authDev)
	mux.HandleFunc("GET /dashboard/api/state", s.apiState)
	mux.HandleFunc("POST /dashboard/api/pair/code", s.apiPairCode)
	mux.HandleFunc("POST /dashboard/api/installations/{id}/command", s.apiCommand)
	mux.HandleFunc("POST /dashboard/api/installations/{id}/rename", s.apiRename)
	mux.HandleFunc("DELETE /dashboard/api/installations/{id}", s.apiUnlink)
	mux.HandleFunc("GET /dashboard/events", s.sse)
	mux.HandleFunc("POST /dashboard/api/pair/redeem", s.apiRedeem)
	mux.HandleFunc("POST /dashboard/api/client/check", s.apiCheck)
	mux.HandleFunc("GET /dashboard/ws/client", s.Hub.ServeWS)
	mux.HandleFunc("GET /dashboard/panel/{id}/{$}", s.panelPage)
	mux.HandleFunc("GET /dashboard/panel/{id}/{path...}", s.panelGet)
	mux.HandleFunc("POST /dashboard/panel/{id}/{path...}", s.panelPost)
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(webassets.Assets))))
	return s.middleware(mux)
}

// middleware sets the baseline security headers on every response and turns a
// handler panic into a 500 instead of killing the process. It never logs
// request bodies, cookies, or credentials.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", dashboardCSP)
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("web: recovered panic serving %s", r.URL.Path)
				writeJSON(w, http.StatusInternalServerError, map[string]any{
					"message": "internal error",
					"status":  http.StatusInternalServerError,
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) session(r *http.Request) (*store.Session, *store.User, bool) {
	tok := auth.CookieToken(r)
	sess, ok := s.Store.Session(tok, time.Now())
	if !ok {
		return nil, nil, false
	}
	user, ok := s.Store.User(sess.DiscordID)
	if !ok {
		return nil, nil, false
	}
	return sess, user, true
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) (*store.Session, *store.User, bool) {
	sess, user, ok := s.session(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"message": "sign in required",
			"status":  http.StatusUnauthorized,
		})
		return nil, nil, false
	}
	return sess, user, true
}

func (s *Server) requireMutation(w http.ResponseWriter, r *http.Request) (*store.Session, *store.User, bool) {
	sess, user, ok := s.requireSession(w, r)
	if !ok {
		return nil, nil, false
	}
	if !auth.Equal(r.Header.Get(auth.CSRFHeader), sess.CSRF) ||
		!auth.OriginAllowed(r, s.Cfg.PublicBaseURL) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"message": "invalid request origin or token",
			"status":  http.StatusForbidden,
		})
		return nil, nil, false
	}
	return sess, user, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func pageRedirect(to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, to, http.StatusFound)
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// clientIP returns the caller's address. X-Forwarded-For is honoured only when
// the operator has explicitly enabled proxy trust.
func (s *Server) clientIP(r *http.Request) string {
	if s.Cfg.TrustProxy {
		if x := r.Header.Get("X-Forwarded-For"); x != "" {
			return strings.TrimSpace(strings.Split(x, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// noopRelay is an offline Relay used when no WebSocket hub is supplied.
type noopRelay struct{}

func (noopRelay) Online(int64) bool { return false }

func (noopRelay) SendCommand(int64, string) (string, error) { return "", relay.ErrOffline }

func (noopRelay) PanelRequest(context.Context, int64, map[string]any) (*relay.PanelResult, error) {
	return nil, relay.ErrOffline
}

func (noopRelay) CloseInstallation(int64, int, string) {}

func (noopRelay) Updates() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (noopRelay) ServeWS(http.ResponseWriter, *http.Request) {}

// notImplemented answers routes whose handlers belong to a later task.
func notImplemented(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"message": "not implemented",
		"status":  http.StatusNotImplemented,
	})
}

// dashboardPage serves the dashboard shell when signed in and the sign-in page
// otherwise. Task 8 replaces this stub.
func (s *Server) dashboardPage(w http.ResponseWriter, r *http.Request) { notImplemented(w) }
