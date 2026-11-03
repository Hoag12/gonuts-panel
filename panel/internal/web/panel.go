package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gonutspanel/internal/auth"
	"gonutspanel/internal/panel"
	"gonutspanel/internal/relay"
	"gonutspanel/internal/store"
)

const (
	// panelPageTTL bounds how long a relayed page is reused. The mod's Page
	// HTML only changes with its build, which is part of the cache key.
	panelPageTTL = 10 * time.Minute
	// panelAssetTTL bounds how long relayed icons and assets are reused.
	panelAssetTTL = 10 * time.Minute
	// panelFormBytes and panelQueryBytes match the mod's DashboardPanel limits.
	panelFormBytes  = 64 << 10
	panelQueryBytes = 64 << 10
	panelMaxPairs   = 256
	// panelCSP is the dashboard policy plus inline scripts, because the mod's
	// own panel page runs its script inline and must keep working unchanged.
	panelCSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
		"script-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self'; " +
		"frame-ancestors 'none'; base-uri 'none'"
)

// The patterns below mirror the validation in the mod's DashboardPanel, so a
// malformed path is refused here instead of being relayed.
var (
	panelNamePattern = regexp.MustCompile(`^[a-z]{1,24}$`)
	panelActPattern  = regexp.MustCompile(`^[a-z]{1,16}:[A-Za-z0-9_.-]{1,48}$`)
	panelItemPattern = regexp.MustCompile(`^([a-z0-9_.-]{1,40}:)?[a-z0-9_.-]{1,64}$`)
)

// panelContentTypes is the allow-list for relayed Content-Type headers. The mod
// is not trusted with header syntax: anything else becomes a download.
var panelContentTypes = map[string]bool{
	"text/html":        true,
	"application/json": true,
	"image/png":        true,
	"font/ttf":         true,
	"text/plain":       true,
}

var panelCharsets = map[string]bool{
	"utf-8":    true,
	"us-ascii": true,
}

// cachedPage is the raw panel page for one installation build.
type cachedPage struct {
	body    string
	expires time.Time
}

// cachedAsset is a decoded binary panel asset (icon, logo, font).
type cachedAsset struct {
	body        []byte
	contentType string
	expires     time.Time
}

// panelCache is a bounded in-memory cache for relayed panel responses. Pages
// hold the raw (unrewritten) HTML so the session CSRF token is injected per
// request. bytes and max account for assets only; expired pages are pruned
// whenever a page is stored.
type panelCache struct {
	mu     sync.Mutex
	pages  map[string]cachedPage
	assets map[string]cachedAsset
	bytes  int64
	max    int64
}

func newPanelCache(max int64) *panelCache {
	if max <= 0 {
		max = 16 << 20
	}
	return &panelCache{
		pages:  map[string]cachedPage{},
		assets: map[string]cachedAsset{},
		max:    max,
	}
}

// page returns a cached page body while it is fresh.
func (c *panelCache) page(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pages[key]
	if !ok || time.Now().After(p.expires) {
		if ok {
			delete(c.pages, key)
		}
		return "", false
	}
	return p.body, true
}

// putPage stores a page body for ttl.
func (c *panelCache) putPage(key, body string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, p := range c.pages {
		if now.After(p.expires) {
			delete(c.pages, k)
		}
	}
	c.pages[key] = cachedPage{body: body, expires: now.Add(ttl)}
}

// asset returns a cached binary response while it is fresh.
func (c *panelCache) asset(key string) (cachedAsset, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.assets[key]
	if !ok {
		return cachedAsset{}, false
	}
	if time.Now().After(a.expires) {
		delete(c.assets, key)
		c.bytes -= int64(len(a.body))
		return cachedAsset{}, false
	}
	return a, true
}

// putAsset stores a binary response for ttl and keeps the cache within max.
// The body is copied so a caller cannot mutate a cached entry.
func (c *panelCache) putAsset(key string, body []byte, contentType string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.assets[key]; ok {
		c.bytes -= int64(len(old.body))
	}
	stored := append([]byte(nil), body...)
	c.assets[key] = cachedAsset{body: stored, contentType: contentType, expires: time.Now().Add(ttl)}
	c.bytes += int64(len(stored))
	if c.bytes <= c.max {
		return
	}
	// Simple and safe: drop the asset cache instead of tracking usage order.
	// Assets are cheap to re-request; the page cache stays for offline use.
	for k, a := range c.assets {
		c.bytes -= int64(len(a.body))
		delete(c.assets, k)
	}
	if c.bytes < 0 {
		c.bytes = 0
	}
}

// panelSession resolves the browser session. The panel needs only the Discord
// id and CSRF token; it does not need the stored profile row.
func (s *Server) panelSession(r *http.Request) (*store.Session, bool) {
	sess, ok := s.Store.Session(auth.CookieToken(r), time.Now())
	return sess, ok
}

// panelMutation enforces the same CSRF and origin rules as requireMutation but
// without requiring the profile row, so a session alone can drive a panel.
func (s *Server) panelMutation(w http.ResponseWriter, r *http.Request) (*store.Session, bool) {
	sess, ok := s.panelSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"message": "sign in required",
			"status":  http.StatusUnauthorized,
		})
		return nil, false
	}
	if !auth.Equal(r.Header.Get(auth.CSRFHeader), sess.CSRF) ||
		!auth.OriginAllowed(r, s.Cfg.PublicBaseURL) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"message": "invalid request origin or token",
			"status":  http.StatusForbidden,
		})
		return nil, false
	}
	return sess, true
}

// panelInstallation parses the route id and enforces ownership. A missing or
// foreign installation is always 404, so ids cannot be probed.
func (s *Server) panelInstallation(w http.ResponseWriter, r *http.Request, owner string) (*store.Installation, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return nil, false
	}
	inst, ok := s.Store.Installation(id)
	if !ok || inst.DiscordID != owner {
		http.NotFound(w, r)
		return nil, false
	}
	return inst, true
}

// panelPage serves the mod's own complete panel page.
func (s *Server) panelPage(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.panelSession(r)
	if !ok {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	inst, ok := s.panelInstallation(w, r, sess.DiscordID)
	if !ok {
		return
	}

	key := fmt.Sprintf("%d|%s", inst.ID, inst.Build)
	raw, cached := s.PanelCache.page(key)
	if !cached {
		res, err := s.Hub.PanelRequest(r.Context(), inst.ID, map[string]any{"op": "page"})
		switch {
		case err != nil:
			// Another request may have filled the cache while this one was
			// waiting; serve it rather than failing a reachable page.
			if body, hit := s.PanelCache.page(key); hit {
				raw = body
			} else if errors.Is(err, relay.ErrOffline) {
				writePanelOffline(w)
				return
			} else {
				s.writePanelFailure(w, err)
				return
			}
		case res == nil:
			http.Error(w, "the client gave no panel page", http.StatusBadGateway)
			return
		case res.Status != http.StatusOK:
			http.Error(w, "the client refused the panel page", panelRefusedStatus(res.Status))
			return
		default:
			// The cache keeps the raw page; the session token is injected per
			// request below so one session's token is never served to another.
			raw = string(res.Body)
			s.PanelCache.putPage(key, raw, panelPageTTL)
		}
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", panelCSP)
	_, _ = w.Write([]byte(panel.Rewrite(raw, sess.CSRF)))
}

// panelGet relays panel data, images, icons, and assets. State and the live
// panel image are never cached; stable binaries are cached per installation
// and path.
func (s *Server) panelGet(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.panelSession(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	inst, ok := s.panelInstallation(w, r, sess.DiscordID)
	if !ok {
		return
	}
	path := strings.TrimPrefix(r.PathValue("path"), "/")

	switch {
	case path == "state":
		s.panelData(w, r, inst.ID, map[string]any{"op": "state"})
	case path == "panel.png":
		s.panelImage(w, r, inst.ID)
	case strings.HasPrefix(path, "api/"):
		name := strings.TrimPrefix(path, "api/")
		if !panelNamePattern.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		query, ok := panelQuery(r)
		if !ok {
			http.Error(w, "the panel query is too large", http.StatusBadRequest)
			return
		}
		s.panelData(w, r, inst.ID, map[string]any{"op": "data", "name": name, "query": query})
	case strings.HasPrefix(path, "item/"):
		item := strings.TrimSuffix(strings.TrimPrefix(path, "item/"), ".png")
		if !strings.HasSuffix(path, ".png") || !panelItemPattern.MatchString(item) {
			http.NotFound(w, r)
			return
		}
		s.panelAsset(w, r, inst.ID, path, map[string]any{"op": "icon", "item": item})
	case path == "logo.png":
		s.panelAsset(w, r, inst.ID, path, map[string]any{"op": "asset", "asset": "logo"})
	case path == "font.ttf":
		s.panelAsset(w, r, inst.ID, path, map[string]any{"op": "asset", "asset": "font"})
	default:
		http.NotFound(w, r)
	}
}

// panelPost relays panel mutations. It requires the session, the CSRF token,
// a matching origin, and the panel's X-GoNuts marker.
func (s *Server) panelPost(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-GoNuts") != "1" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"message": "missing panel request marker",
			"status":  http.StatusForbidden,
		})
		return
	}
	sess, ok := s.panelMutation(w, r)
	if !ok {
		return
	}
	inst, ok := s.panelInstallation(w, r, sess.DiscordID)
	if !ok {
		return
	}
	path := strings.TrimPrefix(r.PathValue("path"), "/")

	switch {
	case path == "act":
		s.panelAct(w, r, inst.ID)
	case strings.HasPrefix(path, "api/"):
		name := strings.TrimPrefix(path, "api/")
		if !panelNamePattern.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		form, ok := panelForm(w, r)
		if !ok {
			return
		}
		s.panelData(w, r, inst.ID, map[string]any{"op": "change", "name": name, "form": form})
	default:
		http.NotFound(w, r)
	}
}

// panelData relays a state or change request and returns the mod's JSON.
func (s *Server) panelData(w http.ResponseWriter, r *http.Request, id int64, frame map[string]any) {
	res, err := s.Hub.PanelRequest(r.Context(), id, frame)
	if err != nil {
		s.writePanelFailure(w, err)
		return
	}
	if res == nil {
		http.Error(w, "the client gave no answer", http.StatusBadGateway)
		return
	}
	if res.Status != http.StatusOK {
		http.Error(w, "the client refused the panel request", panelRefusedStatus(res.Status))
		return
	}
	writePanelBody(w, res.Body, safePanelContentType(res.ContentType), "no-store")
}

// panelAsset relays and caches a stable binary panel response. Item icons and
// the logo/font assets only change with the client build, so they are reused
// for panelAssetTTL.
func (s *Server) panelAsset(w http.ResponseWriter, r *http.Request, id int64, path string, frame map[string]any) {
	key := fmt.Sprintf("%d|%s", id, path)
	if cached, ok := s.PanelCache.asset(key); ok {
		writePanelBody(w, cached.body, cached.contentType, "private, max-age=300")
		return
	}
	s.panelBinary(w, r, id, frame, func(body []byte, contentType string) {
		if len(body) > 0 {
			s.PanelCache.putAsset(key, body, contentType, panelAssetTTL)
		}
	})
}

// panelImage relays the live panel image. The mod appends ?t= to panel.png to
// defeat the browser cache, but the server cache key is path-only; caching the
// image there froze the image and summary view for the whole TTL. The image
// therefore bypasses the asset cache: every request relays a fresh "png" op.
func (s *Server) panelImage(w http.ResponseWriter, r *http.Request, id int64) {
	s.panelBinary(w, r, id, map[string]any{"op": "png"}, nil)
}

// panelBinary relays one binary panel response and hands a successful body to
// store when it is non-nil. It never caches on its own.
func (s *Server) panelBinary(w http.ResponseWriter, r *http.Request, id int64, frame map[string]any, store func(body []byte, contentType string)) {
	res, err := s.Hub.PanelRequest(r.Context(), id, frame)
	if err != nil {
		s.writePanelFailure(w, err)
		return
	}
	if res == nil {
		http.Error(w, "the client gave no answer", http.StatusBadGateway)
		return
	}
	if res.Status != http.StatusOK {
		http.Error(w, "the client refused the panel asset", panelRefusedStatus(res.Status))
		return
	}
	contentType := safePanelContentType(res.ContentType)
	if store != nil {
		store(res.Body, contentType)
	}
	writePanelBody(w, res.Body, contentType, "private, max-age=300")
}

// panelAct relays one panel action and answers 204, like the mod's own panel.
func (s *Server) panelAct(w http.ResponseWriter, r *http.Request, id int64) {
	form, ok := panelForm(w, r)
	if !ok {
		return
	}
	action := form["id"]
	if !panelActPattern.MatchString(action) {
		http.Error(w, "invalid panel action", http.StatusBadRequest)
		return
	}
	act := map[string]any{"id": action}
	if text, present := form["text"]; present {
		act["text"] = text
	} else if value, present := form["value"]; present {
		act["value"] = value
	}
	res, err := s.Hub.PanelRequest(r.Context(), id, map[string]any{"op": "act", "act": act})
	if err != nil {
		s.writePanelFailure(w, err)
		return
	}
	if res == nil || (res.Status != http.StatusOK && res.Status != http.StatusNoContent) {
		status := http.StatusBadGateway
		if res != nil {
			status = panelRefusedStatus(res.Status)
		}
		http.Error(w, "the client refused the panel action", status)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// panelForm parses a bounded urlencoded body. Only the body fields are
// forwarded; query parameters are not part of a panel mutation.
func panelForm(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, panelFormBytes)
	if err := r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "the panel form is too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid panel form", http.StatusBadRequest)
		}
		return nil, false
	}
	if len(r.PostForm) > panelMaxPairs {
		http.Error(w, "the panel form has too many fields", http.StatusBadRequest)
		return nil, false
	}
	form := make(map[string]string, len(r.PostForm))
	for key, values := range r.PostForm {
		if len(values) > 0 {
			form[key] = values[0]
		}
	}
	return form, true
}

// panelQuery converts the URL query into the mod's flat string map, bounding
// the number of fields and the encoded size.
func panelQuery(r *http.Request) (map[string]string, bool) {
	values := r.URL.Query()
	if len(values) > panelMaxPairs {
		return nil, false
	}
	query := make(map[string]string, len(values))
	size := 0
	for key, list := range values {
		value := ""
		if len(list) > 0 {
			value = list[0]
		}
		size += len(key) + len(value) + 2
		query[key] = value
	}
	if size > panelQueryBytes {
		return nil, false
	}
	return query, true
}

// writePanelBody writes one relayed body with a sanitized content type.
func writePanelBody(w http.ResponseWriter, body []byte, contentType, cacheControl string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", cacheControl)
	h.Set("Content-Security-Policy", panelCSP)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// safePanelContentType accepts only the media types the panel can produce, an
// optional ASCII charset, and nothing else. Any other value becomes a download
// so a hostile client cannot inject header syntax.
func safePanelContentType(raw string) string {
	const fallback = "application/octet-stream"
	parts := strings.Split(raw, ";")
	base := strings.ToLower(strings.TrimSpace(parts[0]))
	if !panelContentTypes[base] {
		return fallback
	}
	charset := ""
	for _, param := range parts[1:] {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}
		key, value, ok := strings.Cut(param, "=")
		if !ok || strings.ToLower(strings.TrimSpace(key)) != "charset" {
			return fallback
		}
		value = strings.ToLower(strings.Trim(strings.TrimSpace(value), `"`))
		if !panelCharsets[value] {
			return fallback
		}
		if charset == "" {
			charset = value
		}
	}
	if charset != "" {
		return base + "; charset=" + charset
	}
	return base
}

// panelRefusedStatus is the HTTP status reported when the client itself
// refused a request. Values outside the error range become 502.
func panelRefusedStatus(status int) int {
	if status >= 400 && status <= 599 {
		return status
	}
	return http.StatusBadGateway
}

// writePanelFailure maps a relay error to its contract status. It never relays
// the client's error body or logs it.
func (s *Server) writePanelFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, relay.ErrOffline):
		http.Error(w, "the client is not connected", http.StatusServiceUnavailable)
	case errors.Is(err, relay.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		http.Error(w, "the client did not answer in time", http.StatusGatewayTimeout)
	case errors.Is(err, relay.ErrBusy):
		http.Error(w, "the client is busy; try again", http.StatusTooManyRequests)
	case errors.Is(err, relay.ErrNoPanel):
		http.Error(w, "the client does not support the panel", http.StatusNotImplemented)
	default:
		http.Error(w, "the client could not be reached", http.StatusBadGateway)
	}
}

// writePanelOffline serves the styled 503 shown when an installation is
// offline and no cached page exists.
func writePanelOffline(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", panelCSP)
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(panelOfflineHTML))
}

const panelOfflineHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
	`<meta name="viewport" content="width=device-width,initial-scale=1">` +
	`<title>Panel unavailable</title><style>` +
	`:root{color-scheme:dark}*{box-sizing:border-box}` +
	`body{margin:0;background:#0c121b;color:#f0eee7;font:15px/1.55 system-ui,"Segoe UI",sans-serif}` +
	`main{width:100%;max-width:640px;margin:0 auto;padding:48px 16px}` +
	`h1{margin:0 0 12px;color:#f4cd7a;font-size:22px;font-weight:600}` +
	`p{margin:0 0 12px;color:#b6c2cd}` +
	`a{color:#56dccb}` +
	`</style></head><body><main>` +
	`<h1>The client is not connected</h1>` +
	`<p>This panel is drawn by the mod inside Minecraft. The game is not answering right now, so the panel cannot be loaded.</p>` +
	`<p>Start the game and open the world again, then reload this page.</p>` +
	`<p><a href="/dashboard">Back to the dashboard</a></p>` +
	`</main></body></html>`
