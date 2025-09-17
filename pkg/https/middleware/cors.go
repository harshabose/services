package middleware

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/emirpasic/gods/v2/sets/hashset"
)

var (
	ErrOriginNotAllowed = errors.New("origin not allowed")
	ErrHeaderNotAllowed = errors.New("header not allowed")
	ErrMethodNotAllowed = errors.New("method not allowed")
)

type CORSSettings struct {
	AllowedOrigins   []string
	AllowedHeaders   []string
	AllowedMethods   []string
	AllowCredentials bool
	ExposedHeaders   []string

	StrictMode    bool
	AllowWildcard bool
	LogViolations bool
	MaxAge        int
}

func (m *CORSSettings) check(settings *CORSSettings) bool {
	return m.check2(settings, func(s *CORSSettings) []string { return s.AllowedMethods }) &&
		m.check2(settings, func(s *CORSSettings) []string { return s.AllowedOrigins }) &&
		m.check2(settings, func(s *CORSSettings) []string { return s.AllowedHeaders })

}

func (m *CORSSettings) check2(settings *CORSSettings, getter func(*CORSSettings) []string) bool {
	var paramField, memberField []string

	if settings != nil {
		paramField = getter(settings)
	}

	memberField = getter(m)

	return paramField != nil || memberField != nil
}

type Cors struct {
	settings *CORSSettings
}

func NewCors(settings *CORSSettings) *Cors {
	return &Cors{
		settings: settings,
	}
}

func (m *Cors) Handler(settings *CORSSettings) Middleware {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !m.isSettingsValid(settings) {
				http.Error(w, "invalid CORS settings for the handler", http.StatusInternalServerError)
				return
			}

			if r.Method == http.MethodOptions {
				if err := m.isPreflightAllowed(r, settings); err != nil {
					http.Error(w, err.Error(), http.StatusForbidden)
					return
				}

				m.writeCORS(w, r, settings)
				w.WriteHeader(http.StatusOK)
				return
			}

			if err := m.isCORSAllowed(r, settings); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}

			m.writeCORS(w, r, settings)
			handler.ServeHTTP(w, r)
		})
	}
}

func (m *Cors) isCORSAllowed(r *http.Request, settings *CORSSettings) error {
	origin := r.Header.Get("Origin")
	if err := m.isOriginAllowed(origin, settings); err != nil {
		m.logCORSViolation(err, r, settings)

		return err
	}

	if err := m.isMethodAllowed(r.Method, settings); err != nil {
		m.logCORSViolation(err, r, settings)

		return err
	}

	for header := range r.Header {
		if err := m.isHeaderAllowed(header, settings); err != nil {
			m.logCORSViolation(err, r, settings)

			return err
		}
	}

	return nil
}

func (m *Cors) isPreflightAllowed(r *http.Request, settings *CORSSettings) error {
	requestedMethod := r.Header.Get("Access-Control-Request-Method")
	requestedHeaders := r.Header.Get("Access-Control-Request-Headers")

	origin := r.Header.Get("Origin")
	if err := m.isOriginAllowed(origin, settings); err != nil {
		m.logCORSViolation(err, r, settings)

		return err
	}

	if err := m.isMethodAllowed(requestedMethod, settings); err != nil {
		m.logCORSViolation(err, r, settings)

		return err
	}

	headers := strings.Split(requestedHeaders, ",")

	for _, header := range headers {
		if err := m.isHeaderAllowed(header, settings); err != nil {
			m.logCORSViolation(err, r, settings)

			return err
		}
	}

	return nil
}

func (m *Cors) isOriginAllowed(origin string, settings *CORSSettings) error {
	allowed := func() bool {
		if origin == "" {
			return true
		}

		var allowed []string = nil

		if m.settings != nil && m.settings.AllowedOrigins != nil {
			allowed = m.settings.AllowedOrigins
		}

		if settings != nil && settings.AllowedOrigins != nil {
			allowed = settings.AllowedOrigins
		}

		for _, allow := range allowed {
			if allow == origin {
				return true
			}

			if strings.HasPrefix(allow, "*.") {
				domain := allow[2:]
				if strings.HasSuffix(origin, "."+domain) || origin == domain {
					return true
				}
			}
		}

		return false
	}()

	if !allowed {
		if settings != nil && settings.StrictMode || m.settings != nil && m.settings.StrictMode {
			return ErrOriginNotAllowed
		}
	}

	return nil
}

func (m *Cors) isMethodAllowed(method string, settings *CORSSettings) error {
	allowed := func() bool {
		if method == "" {
			return false
		}

		var allowed []string = nil

		if m.settings != nil && m.settings.AllowedMethods != nil {
			allowed = m.settings.AllowedMethods
		}

		if settings != nil && settings.AllowedMethods != nil {
			allowed = settings.AllowedMethods
		}

		for _, allow := range allowed {
			if allow == method {
				return true
			}
		}

		return false
	}()

	if !allowed {
		if settings != nil && settings.StrictMode || m.settings != nil && m.settings.StrictMode {
			return ErrMethodNotAllowed
		}
	}

	return nil
}

func (m *Cors) isHeaderAllowed(header string, settings *CORSSettings) error {
	allowed := func() bool {
		if header == "" {
			return false
		}

		if hashset.New("accept", "accept-language", "content-language", "user-agent",
			"content-type", "cache-control", "expires", "last-modified", "pragma").
			Contains(strings.TrimSpace(strings.ToLower(header))) {
			return true
		}

		var allowed []string = nil

		if m.settings != nil && m.settings.AllowedHeaders != nil {
			allowed = m.settings.AllowedHeaders
		}

		if settings != nil && settings.AllowedHeaders != nil {
			allowed = settings.AllowedHeaders
		}

		for _, allow := range allowed {
			if strings.TrimSpace(strings.ToLower(allow)) == strings.TrimSpace(strings.ToLower(header)) {
				return true
			}
		}

		return false
	}()

	if !allowed {
		if settings != nil && settings.StrictMode || m.settings != nil && m.settings.StrictMode {
			return fmt.Errorf("CORS: header (%s) not allowed", header)
		}
	}

	return nil
}

func (m *Cors) logCORSViolation(err error, r *http.Request, settings *CORSSettings) {
	l := (settings != nil && settings.LogViolations) ||
		(m.settings != nil && m.settings.LogViolations)

	if l {
		log.Printf("CORS violation: %s - Origin: %s, Method: %s, Headers: %s",
			err.Error(),
			r.Header.Get("Origin"),
			r.Header.Get("Access-Control-Request-Method"),
			r.Header.Get("Access-Control-Request-Headers"))
	}
}

func (m *Cors) writeCORS(w http.ResponseWriter, r *http.Request, settings *CORSSettings) {
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	// CORS METHODS
	w.Header().Set("Access-Control-Allow-Methods", "*")

	if m.settings != nil && m.settings.AllowedMethods != nil {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(m.settings.AllowedMethods, ", "))
	}

	if settings != nil && settings.AllowedMethods != nil {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(settings.AllowedMethods, ", "))
	}

	// CORS HEADERS
	w.Header().Set("Access-Control-Allow-Headers", "*")

	if m.settings != nil && m.settings.AllowedHeaders != nil {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(m.settings.AllowedHeaders, ", "))
	}

	if settings != nil && settings.AllowedHeaders != nil {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(settings.AllowedHeaders, ", "))
	}

	// CORS CREDENTIALS
	if m.settings != nil && m.settings.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if settings != nil && settings.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if origin == "" {
		w.Header().Del("Access-Control-Allow-Credentials")
	}

	// CORS MAX-AGE
	if m.settings != nil && m.settings.MaxAge > 0 {
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(m.settings.MaxAge))
	}

	if settings != nil && settings.MaxAge > 0 {
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(settings.MaxAge))
	}

	// CORS EXPOSED HEADERS
	if m.settings != nil && m.settings.ExposedHeaders != nil && len(m.settings.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(m.settings.ExposedHeaders, ", "))
	}

	if settings != nil && settings.ExposedHeaders != nil && len(settings.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(settings.ExposedHeaders, ", "))
	}

	w.Header().Add("Vary", "Origin")
	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.Header().Add("Vary", "Access-Control-Request-Headers")
}

func (m *Cors) isSettingsValid(settings *CORSSettings) bool {
	if settings == nil && m.settings == nil {
		return false
	}

	return m.hasRequiredField(settings, func(s *CORSSettings) []string { return s.AllowedMethods }) &&
		m.hasRequiredField(settings, func(s *CORSSettings) []string { return s.AllowedOrigins }) &&
		m.hasRequiredField(settings, func(s *CORSSettings) []string { return s.AllowedHeaders })
}

func (m *Cors) hasRequiredField(settings *CORSSettings, getter func(*CORSSettings) []string) bool {
	var paramField, memberField []string

	if settings != nil {
		paramField = getter(settings)
	}

	if m.settings != nil {
		memberField = getter(m.settings)
	}

	// At least one must be non-nil
	return paramField != nil || memberField != nil
}
