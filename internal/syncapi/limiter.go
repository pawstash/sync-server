package syncapi

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type tokenBucket struct {
	tokens    float64
	lastCheck time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	limits  map[string]*tokenBucket
	rate    float64 // tokens added per second
	burst   float64 // maximum bucket capacity
	lastHit map[string]time.Time
	stop    chan struct{}
}

func newRateLimiter(rate float64, burst float64) *rateLimiter {
	rl := &rateLimiter{
		limits:  make(map[string]*tokenBucket),
		rate:    rate,
		burst:   burst,
		lastHit: make(map[string]time.Time),
		stop:    make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *rateLimiter) close() {
	select {
	case <-rl.stop:
	default:
		close(rl.stop)
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rl.lastHit[key] = now

	bucket, exists := rl.limits[key]
	if !exists {
		rl.limits[key] = &tokenBucket{
			tokens:    rl.burst - 1,
			lastCheck: now,
		}
		return true
	}

	elapsed := now.Sub(bucket.lastCheck).Seconds()
	bucket.lastCheck = now
	bucket.tokens += elapsed * rl.rate
	if bucket.tokens > rl.burst {
		bucket.tokens = rl.burst
	}

	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true
	}

	return false
}

func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for k, t := range rl.lastHit {
				if t.Before(cutoff) {
					delete(rl.limits, k)
					delete(rl.lastHit, k)
				}
			}
			rl.mu.Unlock()
		case <-rl.stop:
			return
		}
	}
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
