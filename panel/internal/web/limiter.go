package web

import (
	"math"
	"sync"
	"time"
)

// bucket is one key's token-bucket state.
type bucket struct {
	tokens float64
	last   time.Time
}

// Buckets are attacker-controlled because callers key them by IP or other
// untrusted strings, so the map must stay bounded. Above limiterMaxBuckets a
// sweep drops every bucket idle for limiterBucketTTL; if everything is still
// fresh the single oldest bucket is dropped instead.
const (
	limiterMaxBuckets = 1024
	limiterBucketTTL  = 10 * time.Minute
)

// limiter is an in-memory token bucket keyed by caller-supplied strings
// (an IP, a Discord id, or a session hash). It is safe for concurrent use.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
}

// newLimiter allows perMinute requests sustained, with bursts of up to burst.
func newLimiter(perMinute, burst float64) *limiter {
	return &limiter{rate: perMinute / 60, burst: burst, buckets: map[string]*bucket{}}
}

// allow takes one token from key's bucket. It reports false when the bucket is
// empty. A fresh key starts full.
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= limiterMaxBuckets {
			l.evictLocked(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictLocked removes idle buckets, or the oldest bucket when none is idle, so
// the map never grows past limiterMaxBuckets. It runs O(n) only on overflow.
func (l *limiter) evictLocked(now time.Time) {
	cutoff := now.Add(-limiterBucketTTL)
	var oldestKey string
	var oldest time.Time
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
			continue
		}
		if oldestKey == "" || b.last.Before(oldest) {
			oldestKey, oldest = k, b.last
		}
	}
	if len(l.buckets) >= limiterMaxBuckets && oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}
