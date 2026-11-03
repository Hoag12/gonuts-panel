package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"gonutspanel/internal/relay"
	"gonutspanel/internal/store"
)

// apiRedeem consumes a pairing code and returns the one-time client
// credential. The request body is never logged and never echoed back.
func (s *Server) apiRedeem(w http.ResponseWriter, r *http.Request) {
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
	if !relay.ValidName(body.Name) || !relay.ValidBuild(body.Build) ||
		!relay.ValidHive(body.Hive) || !relay.ValidCaps(body.Capabilities) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message": "invalid pairing details",
			"status":  http.StatusBadRequest,
		})
		return
	}

	inst, credential, err := s.Store.RedeemCode(
		body.Code, body.Name, body.Build, body.Hive, body.Capabilities, time.Now())
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

// The dashboard, SSE, command, and panel handlers are implemented in later
// tasks; until then they answer 501 so the route table stays complete.

func (s *Server) apiState(w http.ResponseWriter, r *http.Request)    { notImplemented(w) }
func (s *Server) apiPairCode(w http.ResponseWriter, r *http.Request) { notImplemented(w) }
func (s *Server) apiCommand(w http.ResponseWriter, r *http.Request)  { notImplemented(w) }
func (s *Server) apiRename(w http.ResponseWriter, r *http.Request)   { notImplemented(w) }
func (s *Server) apiUnlink(w http.ResponseWriter, r *http.Request)   { notImplemented(w) }
func (s *Server) sse(w http.ResponseWriter, r *http.Request)         { notImplemented(w) }
func (s *Server) panelPage(w http.ResponseWriter, r *http.Request)   { notImplemented(w) }
func (s *Server) panelGet(w http.ResponseWriter, r *http.Request)    { notImplemented(w) }
func (s *Server) panelPost(w http.ResponseWriter, r *http.Request)   { notImplemented(w) }
