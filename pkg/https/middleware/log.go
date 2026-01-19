package middleware

import (
	"log"
	"net/http"
	"time"

	"github.com/harshabose/services/pkg/https/utils"
)

func Logger() func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapper := utils.NewResponseWriter(w, 200)

			handler.ServeHTTP(wrapper, r)

			duration := time.Since(start)
			clientIP := utils.GetClientIP(r)

			log.Printf("%s %s %s %d %v %s",
				r.Method,
				r.URL.Path,
				clientIP,
				wrapper.StatusCode(),
				duration,
				r.UserAgent(),
			)
		})
	}
}
