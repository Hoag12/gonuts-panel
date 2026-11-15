package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gonutspanel/internal/store"
)

func swarmInstallation(t *testing.T, st *store.Store) (string, int64) {
	t.Helper()
	if err := st.UpsertUser(store.User{ID: "swarm-user", Username: "swarm-user"}); err != nil {
		t.Fatal(err)
	}
	code, _, err := st.CreateCode("swarm-user", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inst, credential, err := st.RedeemCode(code, "actub", "test", "hive", []string{"pause"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return credential, inst.ID
}

func swarmPost(t *testing.T, handler http.Handler, path, token, idem string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func swarmGet(t *testing.T, handler http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestSwarmSharesObservedMarkets(t *testing.T) {
	s, st := newTestServer(t)
	handler := s.Handler()
	installation, _ := swarmInstallation(t, st)

	rec := swarmGet(t, handler, "/community/v1/capabilities", "")
	if rec.Code != 200 {
		t.Fatalf("capabilities status=%d", rec.Code)
	}
	var caps map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &caps); err != nil {
		t.Fatal(err)
	}
	if caps["enabled"] != true || caps["regionField"] != "region" || caps["regionQueryParameter"] != "region" {
		t.Fatalf("capabilities=%v", caps)
	}
	scopes, _ := caps["networkScopes"].([]any)
	if len(scopes) != 1 || scopes[0] != "net-donut" {
		t.Fatalf("scopes=%v", caps["networkScopes"])
	}

	rec = swarmPost(t, handler, "/community/v1/enroll", installation, "", map[string]any{
		"schema": 1, "build": "test", "consent": "share-observations-v1",
		"observerAccounts": []string{"actub"},
	})
	if rec.Code != 201 {
		t.Fatalf("enroll status=%d body=%s", rec.Code, rec.Body)
	}
	var enrolled struct {
		Credential    string `json:"credential"`
		ContributorID string `json:"contributorId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &enrolled); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enrolled.Credential, "gnc1_") || len(enrolled.Credential) != 48 {
		t.Fatalf("credential=%q", enrolled.Credential)
	}
	if !strings.HasPrefix(enrolled.ContributorID, "c_") || len(enrolled.ContributorID) != 14 {
		t.Fatalf("contributor=%q", enrolled.ContributorID)
	}

	put, _ := json.Marshal(map[string]any{"observerAccounts": []string{"actub"}})
	req := httptest.NewRequest("PUT", "/community/v1/me/accounts", strings.NewReader(string(put)))
	req.Header.Set("Authorization", "Bearer "+enrolled.Credential)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("accounts status=%d", rec.Code)
	}

	rec = swarmGet(t, handler, "/community/v1/me", enrolled.Credential)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"eligible":true`) {
		t.Fatalf("me status=%d body=%s", rec.Code, rec.Body)
	}

	now := time.Now().UnixMilli()
	rec = swarmPost(t, handler, "/community/v1/observations", enrolled.Credential, "batch-1", map[string]any{
		"schema": 1, "region": "net-donut", "sentAt": now,
		"records": []map[string]any{
			{"type": "ask", "itemKey": "minecraft:golden_apple|64", "seller": "someone", "stack": 64, "unitPrice": 35000, "observedAt": now},
			{"type": "price_level", "itemKey": "minecraft:golden_apple|64", "stack": 64, "unitPrice": 33000, "source": "probe", "observedAt": now},
			{"type": "order", "itemKey": "minecraft:golden_apple|64", "unitPrice": 30000, "observedAt": now},
			{"type": "sale", "itemKey": "minecraft:golden_apple|64", "quantity": 64, "price": 2_240_000, "account": "buyer", "observedAt": now},
		},
	})
	if rec.Code != 200 {
		t.Fatalf("observations status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"accepted":4`) {
		t.Fatalf("observations body=%s", rec.Body)
	}
	replay := swarmPost(t, handler, "/community/v1/observations", enrolled.Credential, "batch-1", map[string]any{
		"schema": 1, "records": []map[string]any{{"type": "ask", "itemKey": "minecraft:golden_apple|64", "unitPrice": 1, "observedAt": now}},
	})
	if !strings.Contains(replay.Body.String(), `"replay":true`) {
		t.Fatalf("idempotency body=%s", replay.Body)
	}

	key := url.PathEscape("minecraft:golden_apple|64")
	rec = swarmGet(t, handler, "/community/v1/market/"+key+"?region=net-donut", enrolled.Credential)
	if rec.Code != 200 {
		t.Fatalf("market status=%d body=%s", rec.Code, rec.Body)
	}
	var answer struct {
		ItemKey     string `json:"itemKey"`
		RegionScope string `json:"regionScope"`
		TTL         int64  `json:"ttlSeconds"`
		Asks        struct {
			Usability string `json:"usability"`
			Rows      []struct {
				UnitPrice int64 `json:"unitPrice"`
			} `json:"rows"`
		} `json:"asks"`
		Orders struct {
			Rows []struct {
				UnitPrice int64 `json:"unitPrice"`
			} `json:"rows"`
		} `json:"orders"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.ItemKey != "minecraft:golden_apple|64" || answer.RegionScope != "net-donut" || answer.TTL != 30 {
		t.Fatalf("answer=%+v", answer)
	}
	if answer.Asks.Usability != "history" || len(answer.Asks.Rows) != 1 || answer.Asks.Rows[0].UnitPrice != 35000 {
		t.Fatalf("asks=%+v", answer.Asks)
	}
	if len(answer.Orders.Rows) != 1 || answer.Orders.Rows[0].UnitPrice != 30000 {
		t.Fatalf("orders=%+v", answer.Orders)
	}

	rec = swarmGet(t, handler, "/community/v1/market?items="+urlQuery("minecraft:golden_apple|64,minecraft:diamond|64")+"&region=net-donut", enrolled.Credential)
	if rec.Code != 200 {
		t.Fatalf("batch status=%d", rec.Code)
	}
	var batch struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Items) != 2 || batch.Items[0]["itemKey"] != "minecraft:golden_apple|64" || batch.Items[1]["itemKey"] != "minecraft:diamond|64" {
		t.Fatalf("batch=%+v", batch.Items)
	}

	rec = swarmGet(t, handler, "/community/v1/sales/history?region=net-donut&limit=1000&items="+urlQuery("minecraft:golden_apple|64"), enrolled.Credential)
	if rec.Code != 200 {
		t.Fatalf("history status=%d body=%s", rec.Code, rec.Body)
	}
	var history struct {
		Schema      int    `json:"schema"`
		Kind        string `json:"kind"`
		RegionScope string `json:"regionScope"`
		GeneratedAt int64  `json:"generatedAt"`
		AsOf        int64  `json:"asOf"`
		WindowStart int64  `json:"windowStart"`
		Capped      bool   `json:"capped"`
		Rows        []struct {
			ID         string `json:"id"`
			ItemKey    string `json:"itemKey"`
			Quantity   int64  `json:"quantity"`
			Stack      int64  `json:"stack"`
			Total      int64  `json:"total"`
			UnitPrice  int64  `json:"unitPrice"`
			ObservedAt int64  `json:"observedAt"`
			Provenance struct {
				Kind               string `json:"kind"`
				OwnAccount         bool   `json:"ownAccount"`
				IndependentSources int64  `json:"independentSources"`
			} `json:"provenance"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	now = time.Now().UnixMilli()
	if history.Schema != 1 || history.Kind != "completed_sales" || history.RegionScope != "net-donut" ||
		history.GeneratedAt > now+5000 || now-history.GeneratedAt > 120000 ||
		history.AsOf != history.GeneratedAt || history.WindowStart != history.AsOf-86_400_000 || history.Capped {
		t.Fatalf("history envelope=%+v", history)
	}
	if len(history.Rows) != 1 {
		t.Fatalf("history rows=%+v", history.Rows)
	}
	row := history.Rows[0]
	if row.ID == "" || row.ItemKey != "minecraft:golden_apple|64" || row.Quantity != 64 || row.Stack != 64 ||
		row.Total != 2_240_000 || row.UnitPrice != 35000 || row.ObservedAt < history.WindowStart || row.ObservedAt > history.AsOf {
		t.Fatalf("history row=%+v", row)
	}
	if row.Provenance.Kind != "seller_receipt" || row.Provenance.OwnAccount || row.Provenance.IndependentSources < 1 {
		t.Fatalf("provenance=%+v", row.Provenance)
	}

	rec = swarmGet(t, handler, "/community/v1/market/"+key, "")
	if rec.Code != 401 {
		t.Fatalf("unauthenticated market status=%d", rec.Code)
	}

	rec = swarmPost(t, handler, "/community/v1/unenroll", enrolled.Credential, "", map[string]any{})
	if rec.Code != 204 {
		t.Fatalf("unenroll status=%d", rec.Code)
	}
	// Credentials are stateless HMACs, so unenroll clears the client's copy;
	// the service keeps answering the same math (no server-side revocation).
	if rec = swarmGet(t, handler, "/community/v1/me", enrolled.Credential); rec.Code != 200 {
		t.Fatalf("me after unenroll status=%d", rec.Code)
	}
}

func urlQuery(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "%2C", ",")
}

func TestSwarmRejectsWithoutConsent(t *testing.T) {
	s, st := newTestServer(t)
	installation, _ := swarmInstallation(t, st)
	rec := swarmPost(t, s.Handler(), "/community/v1/enroll", installation, "", map[string]any{"schema": 1})
	if rec.Code != 400 {
		t.Fatalf("enroll without consent status=%d body=%s", rec.Code, rec.Body)
	}
	if rec = swarmPost(t, s.Handler(), "/community/v1/enroll", "gni1_wrong", "", map[string]any{
		"schema": 1, "consent": "share-observations-v1",
	}); rec.Code != 401 {
		t.Fatalf("enroll with bad credential status=%d", rec.Code)
	}
}
