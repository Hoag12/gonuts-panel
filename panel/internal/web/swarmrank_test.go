package web

import (
	"testing"
	"time"

	"gonutspanel/internal/store"
)

func mkInst(id int64, discordID, account string, seen time.Time, bank, p1, p24, r1, r24, s1, s24 int64) *store.Installation {
	t := &store.Telemetry{At: seen.UnixMilli(), Account: account}
	iv := func(a, b int64) *store.Interval {
		return &store.Interval{H1: &a, H24: &b}
	}
	t.Bank = &bank
	t.Profit = iv(p1, p24)
	t.Revenue = iv(r1, r24)
	t.Sales = iv(s1, s24)
	return &store.Installation{ID: id, DiscordID: discordID, Name: account, LastSeen: seen.UnixMilli(), Telemetry: t, Online: true}
}

func TestComputeSwarmRanksAndScore(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-2 * time.Minute)
	installs := map[string]*store.Installation{
		"1": mkInst(1, "A", "a1", recent, 100, 20, 200, 100, 1000, 5, 50),
		"2": mkInst(2, "B", "b1", recent, 50, 10, 400, 200, 2000, 8, 80),
		"3": mkInst(3, "C", "c1", recent, 200, 30, 100, 50, 500, 1, 10),
	}
	got := computeSwarm(installs, "A", now)
	if got.Hives != 3 || got.Bots != 3 {
		t.Fatalf("hives/bots = %d/%d, want 3/3", got.Hives, got.Bots)
	}
	you := got.You
	if you == nil || !you.Active {
		t.Fatalf("you should be active: %+v", you)
	}
	if you.Rank != 2 || you.Of != 3 {
		t.Fatalf("profit rank = %d of %d, want 2 of 3", you.Rank, you.Of)
	}
	if you.Bank == nil || *you.Bank != 100 || you.Profit24 == nil || *you.Profit24 != 200 || you.Sales24 == nil || *you.Sales24 != 50 {
		t.Fatalf("hero values = %v/%v/%v", you.Bank, you.Profit24, you.Sales24)
	}
	if m := you.Metrics["margin"]; m.Rank != 1 || m.Of != 3 {
		t.Fatalf("margin rank = %+v, want rank 1 of 3 (tied)", m)
	}
	if m := you.Metrics["profit1"]; m.Rank != 2 || m.Of != 3 {
		t.Fatalf("profit1 rank = %+v, want rank 2 of 3", m)
	}
	if you.Score == nil || *you.Score != 58.3 {
		t.Fatalf("score = %v, want 58.3", you.Score)
	}
	if you.ScoreRank != 2 || you.ScoreOf != 3 || you.ScoreMetrics != 6 {
		t.Fatalf("score rank = %d of %d over %d, want 2 of 3 over 6", you.ScoreRank, you.ScoreOf, you.ScoreMetrics)
	}
}

func TestComputeSwarmSingleHive(t *testing.T) {
	now := time.Now()
	installs := map[string]*store.Installation{
		"1": mkInst(1, "A", "a1", now, 100, 20, 200, 100, 1000, 5, 50),
	}
	got := computeSwarm(installs, "A", now)
	you := got.You
	if got.Hives != 1 || you.Of != 1 || you.Rank != 1 {
		t.Fatalf("single hive = %d, rank %d of %d", got.Hives, you.Rank, you.Of)
	}
	if you.Score == nil || *you.Score != 100 {
		t.Fatalf("single hive score = %v, want 100", you.Score)
	}
	if you.ScoreRank != 1 || you.ScoreOf != 1 || you.ScoreMetrics != 6 {
		t.Fatalf("single hive score rank = %d of %d over %d, want 1 of 1 over 6", you.ScoreRank, you.ScoreOf, you.ScoreMetrics)
	}
}

func TestComputeSwarmExcludesStaleAndKeepsNewestPerAccount(t *testing.T) {
	now := time.Now()
	old := now.Add(-20 * time.Minute)
	recent := now.Add(-time.Minute)
	installs := map[string]*store.Installation{
		"1": mkInst(1, "A", "shared", now.Add(-10*time.Minute), 50, 1, 10, 1, 10, 1, 1),
		"2": mkInst(2, "A", "shared", recent, 100, 2, 20, 2, 20, 2, 2),
		"3": mkInst(3, "B", "stale", old, 999, 999, 999, 999, 999, 999, 999),
	}
	got := computeSwarm(installs, "A", now)
	if got.Hives != 1 || got.Bots != 1 {
		t.Fatalf("hives/bots = %d/%d, want 1/1 (stale excluded, account deduped)", got.Hives, got.Bots)
	}
	if got.You.Bank == nil || *got.You.Bank != 100 {
		t.Fatalf("dedupe kept %v, want the newest frame (100)", got.You.Bank)
	}
}

func TestComputeSwarmExcludesOfflineBots(t *testing.T) {
	now := time.Now()
	online := mkInst(1, "A", "a1", now, 100, 20, 200, 100, 1000, 5, 50)
	gone := mkInst(2, "B", "b1", now.Add(-time.Minute), 50, 10, 400, 200, 2000, 8, 80)
	gone.Online = false
	installs := map[string]*store.Installation{"1": online, "2": gone}
	got := computeSwarm(installs, "A", now)
	if got.Hives != 1 || got.Bots != 1 {
		t.Fatalf("hives/bots = %d/%d, want 1/1 (offline bot is not an active hive)", got.Hives, got.Bots)
	}
	if !got.You.Active || got.You.Of != 1 {
		t.Fatalf("caller = %+v, want active rank 1 of 1", got.You)
	}
}

func TestComputeSwarmTiesShareRank(t *testing.T) {
	now := time.Now()
	installs := map[string]*store.Installation{
		"1": mkInst(1, "A", "a1", now, 10, 1, 200, 1, 100, 1, 1),
		"2": mkInst(2, "B", "b1", now, 20, 1, 200, 1, 100, 2, 2),
	}
	got := computeSwarm(installs, "A", now)
	if got.You.Rank != 1 || got.You.Of != 2 {
		t.Fatalf("tie = rank %d of %d, want 1 of 2", got.You.Rank, got.You.Of)
	}
	if m := got.You.Metrics["profit24"]; m.Rank != 1 || m.Of != 2 {
		t.Fatalf("profit24 tie = %+v", m)
	}
}

func TestComputeSwarmUnknownCaller(t *testing.T) {
	now := time.Now()
	installs := map[string]*store.Installation{
		"1": mkInst(1, "A", "a1", now, 10, 1, 200, 1, 100, 1, 1),
	}
	got := computeSwarm(installs, "Z", now)
	if got.You == nil || got.You.Active {
		t.Fatalf("caller without a hive should be inactive: %+v", got.You)
	}
}

func TestComputeSwarmMissingMetricNotScored(t *testing.T) {
	now := time.Now()
	a := mkInst(1, "A", "a1", now, 10, 1, 200, 1, 100, 1, 1)
	b := mkInst(2, "B", "b1", now, 10, 1, 100, 1, 200, 1, 1)
	b.Telemetry.Sales = nil // B does not report sale counts
	installs := map[string]*store.Installation{"1": a, "2": b}
	got := computeSwarm(installs, "A", now)
	you := got.You
	if you.ScoreMetrics != 6 {
		t.Fatalf("scored metrics = %d, want 6 (a lone reporter scores 100)", you.ScoreMetrics)
	}
	if _, ok := you.Metrics["sales1"]; !ok {
		t.Fatalf("your own sales1 is reported and should still be shown with a rank of 1 of 1")
	}
	if m := you.Metrics["sales1"]; m.Of != 1 {
		t.Fatalf("sales1 of = %d, want 1 (only you report it)", m.Of)
	}
	if you.Score == nil {
		t.Fatalf("score should still exist from the remaining metrics")
	}
}
