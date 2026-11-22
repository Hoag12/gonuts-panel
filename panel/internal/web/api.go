package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"gonutspanel/internal/relay"
	"gonutspanel/internal/store"
)

// apiRedeem consumes a pairing code and returns the one-time client
// credential. The request body is never logged and never echoed back.
func (s *Server) apiRedeem(w http.ResponseWriter, r *http.Request) {
	// A pairing answer carries a credential, and a failure may be replayed.
	w.Header().Set("Cache-Control", "no-store")
	ip := s.clientIP(r)
	if !s.PairLimiter.allow("redeem:"+ip, time.Now()) ||
		!s.CommandLimiter.allow("redeem:global", time.Now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"message": "too many pairing attempts",
			"status":  http.StatusTooManyRequests,
		})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	var body struct {
		Code         string   `json:"code"`
		Protocols    []int    `json:"protocols"`
		Name         string   `json:"name"`
		Build        string   `json:"build"`
		Hive         string   `json:"hive"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message": "invalid pairing request",
			"status":  http.StatusBadRequest,
		})
		return
	}
	if !hasProtocol(body.Protocols, 1) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message": "protocol 1 is required",
			"status":  http.StatusBadRequest,
		})
		return
	}
	// Trim before validating and before redeeming: the validators and the
	// stored value must agree, otherwise padded whitespace could carry a
	// value past the 48/60/64 character limits.
	name := strings.TrimSpace(body.Name)
	build := strings.TrimSpace(body.Build)
	hive := strings.TrimSpace(body.Hive)
	if !relay.ValidName(name) || !relay.ValidBuild(build) ||
		!relay.ValidHive(hive) || !relay.ValidCaps(body.Capabilities) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message": "invalid pairing details",
			"status":  http.StatusBadRequest,
		})
		return
	}

	inst, credential, err := s.Store.RedeemCode(
		body.Code, name, build, hive, body.Capabilities, time.Now())
	if err != nil {
		status, message := http.StatusServiceUnavailable, "pairing unavailable"
		switch {
		case errors.Is(err, store.ErrNotFound):
			status, message = http.StatusNotFound, "pairing code not found"
		case errors.Is(err, store.ErrUsed):
			status, message = http.StatusConflict, "pairing code already used"
		case errors.Is(err, store.ErrExpired):
			status, message = http.StatusGone, "pairing code expired"
		case errors.Is(err, store.ErrAttempts):
			status, message = http.StatusTooManyRequests, "too many pairing attempts"
		}
		writeJSON(w, status, map[string]any{"message": message, "status": status})
		return
	}
	writeJSON(w, http.StatusCreated,
		relay.PairResponse(s.Cfg.PublicBaseURL, inst.ID, credential, inst.Name))
}

// apiCheck verifies a client's bearer credential without revealing anything
// about other installations.
func (s *Server) apiCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"message": "invalid credential",
			"status":  http.StatusUnauthorized,
		})
		return
	}
	credential := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if credential == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"message": "invalid credential",
			"status":  http.StatusUnauthorized,
		})
		return
	}
	inst, ok := s.Store.InstallationByCredential(store.HashToken(credential))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"message": "invalid credential",
			"status":  http.StatusUnauthorized,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"installationId": inst.ID,
		"name":           inst.Name,
		"protocol":       1,
	})
}

func hasProtocol(list []int, want int) bool {
	for _, p := range list {
		if p == want {
			return true
		}
	}
	return false
}

// apiState returns everything the dashboard renders for the signed-in user.
// Fields are copied into explicit maps so store-only data (above all
// Installation.CredentialHash) can never reach the browser.
func (s *Server) apiState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.dashboardLimit(w, r) {
		return
	}
	sess, user, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.stateView(sess, user))
}

// stateView builds the dashboard payload. The dashboard page embeds the same
// map so its first paint does not wait for this endpoint; the endpoint stays
// for refreshes and for the live stream.
func (s *Server) stateView(sess *store.Session, user *store.User) map[string]any {
	installs := s.Store.InstallationsFor(user.ID)
	out := make([]map[string]any, 0, len(installs))
	hives := map[string]int{}
	for _, inst := range installs {
		if inst.Hive != "" {
			hives[inst.Hive]++
		}
		out = append(out, map[string]any{
			"id":          inst.ID,
			"name":        inst.Name,
			"build":       inst.Build,
			"hive":        inst.Hive,
			"online":      s.Hub.Online(inst.ID),
			"lastSeen":    inst.LastSeen,
			"telemetry":   store.CloneTelemetry(inst.Telemetry),
			"lastCommand": commandView(s.Store.LastCommand(inst.ID)),
		})
	}
	names := make([]string, 0, len(hives))
	for name := range hives {
		names = append(names, name)
	}
	sort.Strings(names)
	hiveList := make([]map[string]any, 0, len(names))
	for _, name := range names {
		hiveList = append(hiveList, map[string]any{"name": name, "count": hives[name]})
	}

	return map[string]any{
		"csrf": sess.CSRF,
		"user": map[string]any{
			"id":         user.ID,
			"username":   user.Username,
			"globalName": user.GlobalName,
			"avatar":     user.Avatar,
			"createdAt":  user.CreatedAt,
		},
		"now":           time.Now().UnixMilli(),
		"installations": out,
		"hives":         hiveList,
	}
}

// commandView exposes only the audit fields the dashboard shows.
func commandView(c *store.Command) map[string]any {
	if c == nil {
		return nil
	}
	return map[string]any{
		"id":        c.ID,
		"command":   c.Command,
		"state":     c.State,
		"reason":    c.Reason,
		"createdAt": c.CreatedAt,
		"expiresAt": c.ExpiresAt,
	}
}

// apiPairCode creates a short-lived pairing code for the signed-in user.
func (s *Server) apiPairCode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, user, ok := s.requireMutation(w, r)
	if !ok {
		return
	}
	if !s.PairLimiter.allow("pair:"+user.ID, time.Now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"message": "too many pairing codes",
			"status":  http.StatusTooManyRequests,
		})
		return
	}
	code, expiresAt, err := s.Store.CreateCode(user.ID, time.Now())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"message": "pairing code unavailable",
			"status":  http.StatusInternalServerError,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": code, "expiresAt": expiresAt})
}

// apiCommand forwards pause, resume, or snapshot to an online installation.
func (s *Server) apiCommand(w http.ResponseWriter, r *http.Request) {
	_, user, ok := s.requireMutation(w, r)
	if !ok {
		return
	}
	id, ok := s.ownedInstallation(w, r, user.ID)
	if !ok {
		return
	}
	if !s.CommandLimiter.allow("command:"+user.ID, time.Now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"message": "too many commands",
			"status":  http.StatusTooManyRequests,
		})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var body struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message": "invalid body",
			"status":  http.StatusBadRequest,
		})
		return
	}
	switch body.Command {
	case "pause", "resume", "snapshot":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message": "unsupported command",
			"status":  http.StatusBadRequest,
		})
		return
	}
	cmdID, err := s.Hub.SendCommand(id, body.Command)
	if errors.Is(err, relay.ErrOffline) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"message": "client is offline",
			"status":  http.StatusConflict,
		})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"message": "command failed",
			"status":  http.StatusBadGateway,
		})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"id": cmdID})
}

// apiRename changes the display name of one owned installation.
func (s *Server) apiRename(w http.ResponseWriter, r *http.Request) {
	_, user, ok := s.requireMutation(w, r)
	if !ok {
		return
	}
	id, ok := s.ownedInstallation(w, r, user.ID)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message": "invalid body",
			"status":  http.StatusBadRequest,
		})
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || !relay.ValidName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message": "invalid name",
			"status":  http.StatusBadRequest,
		})
		return
	}
	if err := s.Store.RenameInstallation(id, user.ID, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeNotFound(w)
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"message": "rename failed",
			"status":  http.StatusInternalServerError,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

// apiUnlink revokes an installation and closes its live socket.
func (s *Server) apiUnlink(w http.ResponseWriter, r *http.Request) {
	_, user, ok := s.requireMutation(w, r)
	if !ok {
		return
	}
	id, ok := s.ownedInstallation(w, r, user.ID)
	if !ok {
		return
	}
	if err := s.Store.DeleteInstallation(id, user.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeNotFound(w)
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"message": "unlink failed",
			"status":  http.StatusInternalServerError,
		})
		return
	}
	s.Hub.CloseInstallation(id, 4403, "unlinked from the dashboard")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ownedInstallation parses the route id and enforces ownership. A missing or
// foreign installation is always 404, so ids cannot be probed.
func (s *Server) ownedInstallation(w http.ResponseWriter, r *http.Request, owner string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeNotFound(w)
		return 0, false
	}
	inst, ok := s.Store.Installation(id)
	if !ok || inst.DiscordID != owner {
		writeNotFound(w)
		return 0, false
	}
	return id, true
}

func writeNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]any{
		"message": "not found",
		"status":  http.StatusNotFound,
	})
}
