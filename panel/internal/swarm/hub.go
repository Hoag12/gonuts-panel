// Package swarm stores the public market observations every linked hive
// contributes and answers the shared queries those hives make. It keeps prices,
// quantities and completed sales; account names are never stored or echoed.
package swarm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Region is the only scope this service shares.
const Region = "net-donut"

// Types are the observation types the wire accepts.
var Types = []string{"sale", "ask", "price_level", "order_level", "order", "follow_trade", "payment"}

const (
	levelTTL       = 30 * time.Minute
	maxLevels      = 40
	saleWindow     = 24 * time.Hour
	maxSalesMarket = 3000
	maxHistoryRows = 1000
	idempotencyTTL = 10 * time.Minute
)

var (
	keyPattern    = regexp.MustCompile(`^[a-z0-9_.-]+:[a-z0-9_./-]+\|[1-9][0-9]?$`)
	accountFormat = regexp.MustCompile(`^\.?[A-Za-z0-9_]{2,20}$`)
)

// Observation is one sanitized record from an upload batch.
type Observation struct {
	Type      string
	ItemKey   string
	UnitPrice int64
	Total     int64
	Quantity  int64
	At        int64
}

// ValidKey reports whether key is an item|stack market key.
func ValidKey(key string) bool { return keyPattern.MatchString(key) }

// ValidAccount reports whether name is an acceptable observer account.
func ValidAccount(name string) bool { return accountFormat.MatchString(name) }

type credential struct {
	installationID int64
	discordID      string
	accounts       []string
}

type level struct {
	Unit int64
	At   int64
}

type marketLevels struct {
	asks, priceLevels, orders, orderLevels []level
}

type sale struct {
	ID       string
	ItemKey  string
	Quantity int64
	Total    int64
	At       int64
}

// Hub is the in-memory shared store. Entries expire on their own so a restart
// only loses recent contributions; hives upload continuously.
type Hub struct {
	mu             sync.Mutex
	creds          map[string]*credential // sha256(credential) -> owner
	byInstallation map[int64]string       // installation id -> credential hash
	idempotency    map[string]int64
	markets        map[string]*marketLevels
	sales          map[string][]sale
}

// New returns an empty hub.
func New() *Hub {
	return &Hub{
		creds:          map[string]*credential{},
		byInstallation: map[int64]string{},
		idempotency:    map[string]int64{},
		markets:        map[string]*marketLevels{},
		sales:          map[string][]sale{},
	}
}

func (h *Hub) pruneLocked(now time.Time) {
	cutoff := now.Add(-levelTTL).UnixMilli()
	for key, m := range h.markets {
		m.asks = trimLevels(m.asks, cutoff)
		m.priceLevels = trimLevels(m.priceLevels, cutoff)
		m.orders = trimLevels(m.orders, cutoff)
		m.orderLevels = trimLevels(m.orderLevels, cutoff)
		if len(m.asks)+len(m.priceLevels)+len(m.orders)+len(m.orderLevels) == 0 {
			delete(h.markets, key)
		}
	}
	saleCutoff := now.Add(-saleWindow).UnixMilli()
	for key, rows := range h.sales {
		kept := rows[:0]
		for _, row := range rows {
			if row.At >= saleCutoff {
				kept = append(kept, row)
			}
		}
		if len(kept) == 0 {
			delete(h.sales, key)
		} else {
			h.sales[key] = kept
		}
	}
	for key, until := range h.idempotency {
		if now.UnixMilli() >= until {
			delete(h.idempotency, key)
		}
	}
}

func trimLevels(rows []level, cutoff int64) []level {
	kept := rows[:0]
	for _, row := range rows {
		if row.At >= cutoff {
			kept = append(kept, row)
		}
	}
	if len(kept) > maxLevels {
		kept = kept[len(kept)-maxLevels:]
	}
	return kept
}

// Enroll issues a community credential for a linked installation.
func (h *Hub) Enroll(installationID int64, discordID string, accounts []string) (string, string, error) {
	secret, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	credit, err := randomToken(9)
	if err != nil {
		return "", "", err
	}
	value := "gnc1_" + secret
	contributor := "c_" + credit
	clean := sanitizeAccounts(accounts)
	h.mu.Lock()
	defer h.mu.Unlock()
	if previous, ok := h.byInstallation[installationID]; ok {
		delete(h.creds, previous)
	}
	hash := hashToken(value)
	h.creds[hash] = &credential{installationID: installationID, discordID: discordID, accounts: clean}
	h.byInstallation[installationID] = hash
	return value, contributor, nil
}

// Authenticate resolves a community credential.
func (h *Hub) Authenticate(token string) (installationID int64, accounts []string, ok bool) {
	if token == "" {
		return 0, nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	c, found := h.creds[hashToken(token)]
	if !found {
		return 0, nil, false
	}
	return c.installationID, append([]string(nil), c.accounts...), true
}

// RegisterAccounts replaces the observer accounts for a credential.
func (h *Hub) RegisterAccounts(token string, accounts []string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	c, found := h.creds[hashToken(token)]
	if !found {
		return false
	}
	c.accounts = sanitizeAccounts(accounts)
	return true
}

// Unenroll forgets a community credential.
func (h *Hub) Unenroll(token string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	hash := hashToken(token)
	c, found := h.creds[hash]
	if !found {
		return false
	}
	delete(h.creds, hash)
	if h.byInstallation[c.installationID] == hash {
		delete(h.byInstallation, c.installationID)
	}
	return true
}

func sanitizeAccounts(accounts []string) []string {
	out := make([]string, 0, len(accounts))
	seen := map[string]bool{}
	for _, name := range accounts {
		if ValidAccount(name) && !seen[name] {
			out = append(out, name)
			seen[name] = true
		}
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// Observe accepts one upload batch. It returns the accepted count, whether the
// idempotency key was already seen, and whether the credential was valid.
func (h *Hub) Observe(token, idempotencyKey string, records []Observation, now time.Time) (int, bool, bool) {
	hash := hashToken(token)
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, found := h.creds[hash]; !found {
		return 0, false, false
	}
	if idempotencyKey != "" {
		if until, seen := h.idempotency[idempotencyKey]; seen && now.UnixMilli() < until {
			return 0, true, true
		}
		h.idempotency[idempotencyKey] = now.Add(idempotencyTTL).UnixMilli()
	}
	latest := now.UnixMilli() + 5000
	oldest := now.Add(-levelTTL).UnixMilli()
	accepted := 0
	for _, record := range records {
		if !ValidKey(record.ItemKey) || record.UnitPrice <= 0 || record.UnitPrice > 1_000_000_000_000 {
			continue
		}
		if record.At <= 0 || record.At > latest || record.At < oldest {
			continue
		}
		switch record.Type {
		case "ask":
			h.addLevel(record.ItemKey, "ask", level{Unit: record.UnitPrice, At: record.At})
		case "price_level":
			h.addLevel(record.ItemKey, "price_level", level{Unit: record.UnitPrice, At: record.At})
		case "order":
			h.addLevel(record.ItemKey, "order", level{Unit: record.UnitPrice, At: record.At})
		case "order_level":
			h.addLevel(record.ItemKey, "order_level", level{Unit: record.UnitPrice, At: record.At})
		case "sale":
			if record.Quantity <= 0 || record.Total < record.Quantity || record.Total > 1_000_000_000_000 {
				continue
			}
			h.addSale(record)
		case "follow_trade", "payment":
			// Accepted for protocol completeness; actor names are never stored.
		default:
			continue
		}
		accepted++
	}
	return accepted, false, true
}

func (h *Hub) addLevel(itemKey, kind string, row level) {
	m := h.markets[itemKey]
	if m == nil {
		m = &marketLevels{}
		h.markets[itemKey] = m
	}
	switch kind {
	case "ask":
		m.asks = appendLevel(m.asks, row)
	case "price_level":
		m.priceLevels = appendLevel(m.priceLevels, row)
	case "order":
		m.orders = appendLevel(m.orders, row)
	case "order_level":
		m.orderLevels = appendLevel(m.orderLevels, row)
	}
}

func appendLevel(rows []level, row level) []level {
	rows = append(rows, row)
	sort.Slice(rows, func(i, j int) bool { return rows[i].At < rows[j].At })
	if len(rows) > maxLevels {
		rows = rows[len(rows)-maxLevels:]
	}
	return rows
}

func (h *Hub) addSale(record Observation) {
	sum := sha256.Sum256([]byte(record.ItemKey + "|" + itoa(record.Quantity) + "|" + itoa(record.Total) + "|" + itoa(record.At)))
	entry := sale{ID: hex.EncodeToString(sum[:16]), ItemKey: record.ItemKey, Quantity: record.Quantity, Total: record.Total, At: record.At}
	rows := h.sales[record.ItemKey]
	for _, existing := range rows {
		if existing.ID == entry.ID {
			return
		}
	}
	rows = append(rows, entry)
	sort.Slice(rows, func(i, j int) bool { return rows[i].At > rows[j].At })
	if len(rows) > maxSalesMarket {
		rows = rows[:maxSalesMarket]
	}
	h.sales[record.ItemKey] = rows
}

// Answer builds the shared market answer for one item|stack key.
func (h *Hub) Answer(itemKey string, now time.Time) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(now)
	m := h.markets[itemKey]
	block := func(rows []level, extra map[string]any) map[string]any {
		out := map[string]any{"usability": "history", "rows": []any{}}
		list := make([]any, 0, len(rows))
		for i := len(rows) - 1; i >= 0; i-- {
			row := map[string]any{"unitPrice": rows[i].Unit, "observedAt": rows[i].At}
			for k, v := range extra {
				row[k] = v
			}
			list = append(list, row)
		}
		out["rows"] = list
		return out
	}
	answer := map[string]any{
		"itemKey":        itemKey,
		"regionScope":    Region,
		"generatedAt":    now.UnixMilli(),
		"ttlSeconds":     30,
		"asks":           block(nilLevels(m, "ask"), nil),
		"priceLevels":    block(nilLevels(m, "price_level"), nil),
		"orders":         block(nilLevels(m, "order"), map[string]any{"remaining": 1}),
		"orderLevels":    block(nilLevels(m, "order_level"), map[string]any{"remaining": 1}),
		"followActivity": map[string]any{"usability": "history", "recent": []any{}},
	}
	return answer
}

func nilLevels(m *marketLevels, kind string) []level {
	if m == nil {
		return nil
	}
	switch kind {
	case "ask":
		return m.asks
	case "price_level":
		return m.priceLevels
	case "order":
		return m.orders
	case "order_level":
		return m.orderLevels
	}
	return nil
}

// History returns the completed-sales envelope for the requested keys.
func (h *Hub) History(items []string, now time.Time) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(now)
	wanted := map[string]bool{}
	for _, key := range items {
		if ValidKey(key) {
			wanted[key] = true
		}
	}
	windowStart := now.Add(-saleWindow)
	since := windowStart.UnixMilli()
	rows := make([]any, 0, 256)
	for key := range wanted {
		for _, entry := range h.sales[key] {
			if entry.At < since || entry.At > now.UnixMilli() || entry.Quantity > 64 {
				continue
			}
			stack := entry.Quantity
			rows = append(rows, map[string]any{
				"id":         entry.ID,
				"itemKey":    entry.ItemKey,
				"quantity":   entry.Quantity,
				"stack":      stack,
				"total":      entry.Total,
				"unitPrice":  entry.Total / entry.Quantity,
				"observedAt": entry.At,
				"provenance": map[string]any{"kind": "seller_receipt", "ownAccount": false, "independentSources": 1},
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].(map[string]any)["observedAt"].(int64) > rows[j].(map[string]any)["observedAt"].(int64)
	})
	capped := false
	if len(rows) > maxHistoryRows {
		rows = rows[:maxHistoryRows]
		capped = true
	}
	return map[string]any{
		"schema":      1,
		"kind":        "completed_sales",
		"regionScope": Region,
		"generatedAt": now.UnixMilli(),
		"asOf":        now.UnixMilli(),
		"windowStart": since,
		"capped":      capped,
		"rows":        rows,
		"next":        nil,
	}
}

// MarketCount reports the number of markets with shared data (for tests/ops).
func (h *Hub) MarketCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.markets)
}

func hashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
