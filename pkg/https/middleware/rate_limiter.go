package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"

	"github.com/harshabose/services/pkg/https/utils"
)

type RateLimiter struct {
	bucket *expirable.LRU[string, *rate.Limiter] // NOTE: LRU is thread-safe by default
}

func NewRateLimiter(size int, ttl time.Duration) *RateLimiter {
	return &RateLimiter{
		bucket: expirable.NewLRU[string, *rate.Limiter](size, nil, ttl),
	}
}

func (m *RateLimiter) Handler(limit int, burst int) Middleware {
	// NOTE: limit is in requests per second
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := utils.GetClientIP(r)

			limiter, exists := m.bucket.Get(ip)
			if !exists {
				limiter = rate.NewLimiter(rate.Limit(limit), burst)
				m.bucket.Add(ip, limiter)
			}

			if !limiter.Allow() {
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit*60))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))

				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit*60))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatFloat(limiter.TokensAt(time.Now()), 'f', -1, 64))

			// Continue to the next handler in the chain
			handler.ServeHTTP(w, r)
		})
	}
}
