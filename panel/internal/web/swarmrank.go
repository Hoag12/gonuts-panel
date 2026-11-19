package web

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	"gonutspanel/internal/store"
)

// The Swarm ranking reproduces the old hosted dashboard's card: hives are the
// Discord accounts that own at least one bot which reported in the last ten
// minutes, the headline rank orders hives by booked profit over 24 hours, and
// the score is the equal-weighted mean of a hive's percentile in each of the
// six metrics it reports. A metric reported by a single hive scores 100, so
// one active hive still has a score. Missing metrics are left out, never
// scored zero, and equal figures share a rank.
const (
	swarmActiveWindow = 10 * time.Minute
	swarmValidSeconds = 60
)

// swarmScoreMetrics are the six scored metrics, in display order.
var swarmScoreMetrics = []string{"sales1", "profit1", "profit24", "margin", "revenue24", "revenue1"}

type swarmMetric struct {
	Value float64 `json:"value"`
	Rank  int     `json:"rank"`
	Of    int     `json:"of"`
}

type swarmYou struct {
	Active       bool                   `json:"active"`
	Bank         *int64                 `json:"bank,omitempty"`
	Profit24     *int64                 `json:"profit24,omitempty"`
	Sales24      *int64                 `json:"sales24,omitempty"`
	Rank         int                    `json:"rank"`
	Of           int                    `json:"of"`
	Score        *float64               `json:"score,omitempty"`
	ScoreRank    int                    `json:"scoreRank,omitempty"`
	ScoreOf      int                    `json:"scoreOf,omitempty"`
	ScoreMetrics int                    `json:"scoreMetrics"`
	Metrics      map[string]swarmMetric `json:"metrics"`
}

type swarmPayload struct {
	ValidForSec int       `json:"validForSec"`
	GeneratedAt int64     `json:"generatedAt"`
	Hives       int       `json:"hives"`
	Bots        int       `json:"bots"`
	You         *swarmYou `json:"you"`
}

// hiveAgg is one Discord account's hive: the newest telemetry per Minecraft
// account, summed once the accounts are known.
type hiveAgg struct {
	key      string
	seen     int64
	accounts map[string]*store.Telemetry
}

func (h *hiveAgg) add(account string, t *store.Telemetry, seen int64) {
	if t == nil {
		return
	}
	if seen > h.seen {
		h.seen = seen
	}
	prev := h.accounts[account]
	if prev == nil || t.At >= prev.At {
		h.accounts[account] = t
	}
}

// hiveValues holds one scoreboard row. A nil field was not reported.
type hiveValues struct {
	Bank      *float64
	Sales1    *float64
	Sales24   *float64
	Profit1   *float64
	Profit24  *float64
	Margin    *float64
	Revenue1  *float64
	Revenue24 *float64
}

func (v hiveValues) metric(key string) *float64 {
	switch key {
	case "sales1":
		return v.Sales1
	case "profit1":
		return v.Profit1
	case "profit24":
		return v.Profit24
	case "margin":
		return v.Margin
	case "revenue24":
		return v.Revenue24
	case "revenue1":
		return v.Revenue1
	}
	return nil
}

func (h *hiveAgg) values() hiveValues {
	var bank, s1, s24, p1, p24, r1, r24 int64
	var hasBank, hasS1, hasS24, hasP1, hasP24, hasR1, hasR24 bool
	for _, t := range h.accounts {
		if t == nil {
			continue
		}
		if t.Bank != nil {
			bank += *t.Bank
			hasBank = true
		}
		if t.Sales != nil {
			if t.Sales.H1 != nil {
				s1 += *t.Sales.H1
				hasS1 = true
			}
			if t.Sales.H24 != nil {
				s24 += *t.Sales.H24
				hasS24 = true
			}
		}
		if t.Profit != nil {
			if t.Profit.H1 != nil {
				p1 += *t.Profit.H1
				hasP1 = true
			}
			if t.Profit.H24 != nil {
				p24 += *t.Profit.H24
				hasP24 = true
			}
		}
		if t.Revenue != nil {
			if t.Revenue.H1 != nil {
				r1 += *t.Revenue.H1
				hasR1 = true
			}
			if t.Revenue.H24 != nil {
				r24 += *t.Revenue.H24
				hasR24 = true
			}
		}
	}
	f := func(v int64) *float64 { c := float64(v); return &c }
	var out hiveValues
	if hasBank {
		out.Bank = f(bank)
	}
	if hasS1 {
		out.Sales1 = f(s1)
	}
	if hasS24 {
		out.Sales24 = f(s24)
	}
	if hasP1 {
		out.Profit1 = f(p1)
	}
	if hasP24 {
		out.Profit24 = f(p24)
	}
	if hasR1 {
		out.Revenue1 = f(r1)
	}
	if hasR24 {
		out.Revenue24 = f(r24)
	}
	if out.Profit24 != nil && out.Revenue24 != nil && *out.Revenue24 > 0 {
		m := *out.Profit24 / *out.Revenue24 * 100
		out.Margin = &m
	}
	return out
}

// rankOf returns the competition rank (1 plus the number of strictly larger
// values) and how many hives reported the metric at all.
func rankOf(values []*float64, v *float64) (int, int) {
	if v == nil {
		return 0, 0
	}
	rank, of := 1, 0
	for _, other := range values {
		if other == nil {
			continue
		}
		of++
		if *other > *v {
			rank++
		}
	}
	return rank, of
}

func percentile(values []*float64, v *float64) (float64, bool) {
	rank, of := rankOf(values, v)
	if rank == 0 || of == 0 {
		return 0, false
	}
	if of == 1 {
		return 100, true
	}
	return float64(of-rank) / float64(of-1) * 100, true
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// computeSwarm builds the ranking from every installation the panel knows.
// you is the caller's Discord id: a hive is that Discord account.
func computeSwarm(installs map[string]*store.Installation, you string, now time.Time) swarmPayload {
	cutoff := now.Add(-swarmActiveWindow).UnixMilli()
	hives := map[string]*hiveAgg{}
	for _, inst := range installs {
		if inst == nil || inst.DiscordID == "" {
			continue
		}
		seen := inst.LastSeen
		if inst.Telemetry != nil && inst.Telemetry.At > seen {
			seen = inst.Telemetry.At
		}
		if seen < cutoff {
			continue
		}
		h := hives[inst.DiscordID]
		if h == nil {
			h = &hiveAgg{key: inst.DiscordID, accounts: map[string]*store.Telemetry{}}
			hives[inst.DiscordID] = h
		}
		account := ""
		if inst.Telemetry != nil {
			account = inst.Telemetry.Account
		}
		if account == "" {
			account = fmt.Sprintf("#%d", inst.ID)
		}
		h.add(account, inst.Telemetry, seen)
	}

	keys := make([]string, 0, len(hives))
	for k := range hives {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	values := make([]hiveValues, len(keys))
	bots := 0
	for i, k := range keys {
		values[i] = hives[k].values()
		bots += len(hives[k].accounts)
	}

	// Score every hive: equal-weighted mean of the percentiles of the metrics
	// it reports.
	scores := make([]*float64, len(keys))
	counted := make([]int, len(keys))
	for _, key := range swarmScoreMetrics {
		column := columnOf(values, key)
		for i := range values {
			p, ok := percentile(column, values[i].metric(key))
			if !ok {
				continue
			}
			counted[i]++
			if scores[i] == nil {
				v := 0.0
				scores[i] = &v
			}
			*scores[i] += p
		}
	}
	for i, s := range scores {
		if s == nil {
			continue
		}
		*s = round1(*s / float64(counted[i]))
	}

	payload := swarmPayload{
		ValidForSec: swarmValidSeconds,
		GeneratedAt: now.UnixMilli(),
		Hives:       len(keys),
		Bots:        bots,
	}
	youIdx := indexOf(keys, you)
	if youIdx < 0 {
		payload.You = &swarmYou{Active: false, Metrics: map[string]swarmMetric{}}
		return payload
	}

	v := values[youIdx]
	out := &swarmYou{
		Active:       true,
		Bank:         intPtr(v.Bank),
		Profit24:     intPtr(v.Profit24),
		Sales24:      intPtr(v.Sales24),
		Metrics:      map[string]swarmMetric{},
		ScoreMetrics: counted[youIdx],
	}
	for _, key := range swarmScoreMetrics {
		value := v.metric(key)
		if value == nil {
			continue
		}
		rank, of := rankOf(columnOf(values, key), value)
		out.Metrics[key] = swarmMetric{Value: *value, Rank: rank, Of: of}
	}
	out.Rank, out.Of = rankOf(columnOf(values, "profit24"), v.Profit24)
	if out.Rank == 0 {
		out.Of = len(keys)
	}
	if scores[youIdx] != nil {
		s := *scores[youIdx]
		out.Score = &s
		out.ScoreRank, out.ScoreOf = rankOf(scores, scores[youIdx])
	}
	payload.You = out
	return payload
}

func columnOf(values []hiveValues, key string) []*float64 {
	out := make([]*float64, len(values))
	for i := range values {
		out[i] = values[i].metric(key)
	}
	return out
}

func indexOf(keys []string, want string) int {
	for i, k := range keys {
		if k == want {
			return i
		}
	}
	return -1
}

func intPtr(v *float64) *int64 {
	if v == nil {
		return nil
	}
	n := int64(math.Round(*v))
	return &n
}

// swarmRank serves the card's data. It is scoped to the caller: no other
// hive's figures leave the server, only ranks and counts.
func (s *Server) swarmRank(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.dashboardLimit(w, r) {
		return
	}
	sess, _, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	state := s.Store.State()
	writeJSON(w, http.StatusOK, computeSwarm(state.Installations, sess.DiscordID, time.Now()))
}
