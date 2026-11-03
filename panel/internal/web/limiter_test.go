package web

import (
	"fmt"
	"testing"
	"time"
)

func TestLimiterBurstAndRefill(t *testing.T) {
	l := newLimiter(60, 2) // one token per second, burst 2
	now := time.Unix(0, 0)
	if !l.allow("ip", now) || !l.allow("ip", now) {
		t.Fatal("burst should allow two")
	}
	if l.allow("ip", now) {
		t.Fatal("third immediate request should fail")
	}
	if !l.allow("ip", now.Add(time.Second)) {
		t.Fatal("should refill one token after a second")
	}
	if !l.allow("other", now) {
		t.Fatal("keys must be independent")
	}
}

// TestLimiterEvictsOldestWithEmptyKey proves the eviction pick uses an explicit
// found flag rather than "" as a sentinel: with the empty string as the oldest
// bucket's key, a sentinel comparison silently picks whichever bucket the map
// happened to iterate last.
func TestLimiterEvictsOldestWithEmptyKey(t *testing.T) {
	l := newLimiter(60, 4)
	base := time.Unix(1700000000, 0)
	if !l.allow("", base) {
		t.Fatal("empty key denied")
	}
	for i := 0; i < limiterMaxBuckets-1; i++ {
		if !l.allow(fmt.Sprintf("young-%d", i), base.Add(time.Second)) {
			t.Fatalf("young-%d denied", i)
		}
	}
	if n := len(l.buckets); n != limiterMaxBuckets {
		t.Fatalf("buckets=%d, want %d", n, limiterMaxBuckets)
	}

	// This insert overflows the map, so eviction must drop the oldest bucket.
	if !l.allow("new", base.Add(time.Second)) {
		t.Fatal("overflow insert denied")
	}
	if _, ok := l.buckets[""]; ok {
		t.Fatal("oldest bucket with an empty key was not evicted")
	}
	if _, ok := l.buckets["new"]; !ok {
		t.Fatal("new bucket missing after eviction")
	}
	if n := len(l.buckets); n != limiterMaxBuckets {
		t.Fatalf("buckets=%d after eviction, want %d", n, limiterMaxBuckets)
	}
}
