package middleware

import "net/http"

// Middleware is a function that takes a handler and returns a wrapped handler
type Middleware func(http.Handler) http.Handler

type Builder struct {
	router      *http.ServeMux
	middlewares []Middleware
}

// NewBuilder creates a new middleware builder
func NewBuilder(router *http.ServeMux) *Builder {
	return &Builder{
		router:      router,
		middlewares: make([]Middleware, 0),
	}
}

// AddMiddleware adds middlewares to the builder
func (b *Builder) AddMiddleware(middlewares ...Middleware) *Builder {
	b.middlewares = append(b.middlewares, middlewares...)
	return b
}

// Build creates a handler that applies all middlewares in reverse order (last added wraps first),
// with the final handler being embedded and called by the middleware chain
func (b *Builder) Build(pattern string, handler http.Handler) http.Handler {
	// Build the chain in reverse order so that the first middleware added
	// is the outermost wrapper
	result := handler
	for i := len(b.middlewares) - 1; i >= 0; i-- {
		result = b.middlewares[i](result)
	}

	b.router.HandleFunc(pattern, result.ServeHTTP)
	return result
}

// BuildFunc is like Build but accepts http.HandlerFunc
func (b *Builder) BuildFunc(pattern string, handler http.HandlerFunc) http.Handler {
	return b.Build(pattern, handler)
}

// Reset clears all middlewares from the builder
func (b *Builder) Reset() *Builder {
	b.middlewares = b.middlewares[:0]
	return b
}
