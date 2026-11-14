package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"gonutspanel/internal/store"
	"gonutspanel/internal/swarm"
)

const swarmConsent = "share-observations-v1"

// swarmCapabilities advertises the wire this service accepts.
func (s *Server) swarmCapabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":              true,
		"schemas":              []int{1},
		"types":                swarm.Types,
		"regionField":          "region",
		"regionQueryParameter": "region",
		"networkScopes":        []string{swarm.Region},
	})
}

func swarmBearer(r *http.Request) string {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func swarmUnauthorized(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "invalid credential", "status": http.StatusUnauthorized})
}

// swarmEnroll turns a linked installation credential into a community
// credential. Consent is explicit in the request body.
func (s *Server) swarmEnroll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token := swarmBearer(r)
	if token == "" {
		swarmUnauthorized(w)
		return
	}
	inst, ok := s.Store.InstallationByCredential(store.HashToken(token))
	if !ok {
		swarmUnauthorized(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	var body struct {
		Schema           int      `json:"schema"`
		Build            string   `json:"build"`
		Consent          string   `json:"consent"`
		ObserverAccounts []string `json:"observerAccounts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Schema != 1 || body.Consent != swarmConsent {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid enrollment", "status": http.StatusBadRequest})
		return
	}
	accounts := body.ObserverAccounts
	if len(accounts) == 0 {
		accounts = []string{inst.Name}
	}
	credential, contributor, err := s.Swarm.Enroll(inst.ID, inst.DiscordID, accounts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "enrollment unavailable", "status": http.StatusInternalServerError})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"credential": credential, "contributorId": contributor})
}

// swarmAccounts registers the observer accounts behind one credential.
func (s *Server) swarmAccounts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token := swarmBearer(r)
	if token == "" {
		swarmUnauthorized(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	var body struct {
		ObserverAccounts []string `json:"observerAccounts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid accounts", "status": http.StatusBadRequest})
		return
	}
	if !s.Swarm.RegisterAccounts(token, body.ObserverAccounts) {
		swarmUnauthorized(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// swarmMe reports membership state.
func (s *Server) swarmMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, _, ok := s.Swarm.Authenticate(swarmBearer(r)); !ok {
		swarmUnauthorized(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"eligible": true})
}

// swarmUnenroll forgets a credential.
func (s *Server) swarmUnenroll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.Swarm.Unenroll(swarmBearer(r)) {
		swarmUnauthorized(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// swarmObservations accepts a bounded upload batch.
func (s *Server) swarmObservations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token := swarmBearer(r)
	if token == "" {
		swarmUnauthorized(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 600_000)
	var body struct {
		Schema  int `json:"schema"`
		Records []struct {
			Type       string `json:"type"`
			ItemKey    string `json:"itemKey"`
			UnitPrice  int64  `json:"unitPrice"`
			Total      int64  `json:"total"`
			Price      int64  `json:"price"`
			Quantity   int64  `json:"quantity"`
			ObservedAt int64  `json:"observedAt"`
		} `json:"records"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Schema != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid batch", "status": http.StatusBadRequest})
		return
	}
	records := make([]swarm.Observation, 0, len(body.Records))
	for _, record := range body.Records {
		obs := swarm.Observation{
			Type:      record.Type,
			ItemKey:   record.ItemKey,
			UnitPrice: record.UnitPrice,
			Total:     record.Total,
			Quantity:  record.Quantity,
			At:        record.ObservedAt,
		}
		if record.Type == "sale" {
			obs.Total = record.Price
			if record.Quantity > 0 {
				obs.UnitPrice = record.Price / record.Quantity
			}
		}
		records = append(records, obs)
	}
	accepted, replay, ok := s.Swarm.Observe(token, r.Header.Get("Idempotency-Key"), records, time.Now())
	if !ok {
		swarmUnauthorized(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"replay":   replay,
		"accepted": accepted,
		"rejected": []any{},
		"eligible": true,
	})
}

// swarmMarket answers one market key.
func (s *Server) swarmMarket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, _, ok := s.Swarm.Authenticate(swarmBearer(r)); !ok {
		swarmUnauthorized(w)
		return
	}
	key := r.PathValue("key")
	if !swarm.ValidKey(key) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid market", "status": http.StatusBadRequest})
		return
	}
	writeJSON(w, http.StatusOK, s.Swarm.Answer(key, time.Now()))
}

// swarmMarketBatch answers up to fifty keys in request order.
func (s *Server) swarmMarketBatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, _, ok := s.Swarm.Authenticate(swarmBearer(r)); !ok {
		swarmUnauthorized(w)
		return
	}
	raw := r.URL.Query().Get("items")
	keys := strings.Split(raw, ",")
	if raw == "" || len(keys) > 50 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid items", "status": http.StatusBadRequest})
		return
	}
	now := time.Now()
	items := make([]any, 0, len(keys))
	for _, key := range keys {
		if !swarm.ValidKey(key) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid items", "status": http.StatusBadRequest})
			return
		}
		items = append(items, s.Swarm.Answer(key, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// swarmHistory returns completed-sale history for the requested keys.
func (s *Server) swarmHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, _, ok := s.Swarm.Authenticate(swarmBearer(r)); !ok {
		swarmUnauthorized(w)
		return
	}
	raw := r.URL.Query().Get("items")
	keys := strings.Split(raw, ",")
	if raw == "" || len(keys) > 50 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid items", "status": http.StatusBadRequest})
		return
	}
	for _, key := range keys {
		if !swarm.ValidKey(key) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid items", "status": http.StatusBadRequest})
			return
		}
	}
	writeJSON(w, http.StatusOK, s.Swarm.History(keys, time.Now()))
}
