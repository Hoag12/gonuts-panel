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
