package https

import "net/http"

type Middleware func(http.Handler) http.Handler

type MiddlewareBuilder struct {
	middlewares []Middleware
}

func NewMiddlewareBuilder() *MiddlewareBuilder {
	return &MiddlewareBuilder{
		middlewares: make([]Middleware, 0),
	}
}

// Add adds middlewares to the builder
func (b *MiddlewareBuilder) Add(middlewares ...Middleware) *MiddlewareBuilder {
	b.middlewares = append(b.middlewares, middlewares...)
	return b
}

func (b *MiddlewareBuilder) build(router *http.ServeMux, pattern string, handler http.Handler) http.Handler {
	h := handler
	for i := len(b.middlewares) - 1; i >= 0; i-- {
		h = b.middlewares[i](h)
	}

	router.HandleFunc(pattern, h.ServeHTTP)
	return h
}

func (b *MiddlewareBuilder) buildFunc(router *http.ServeMux, pattern string, handler http.HandlerFunc) http.Handler {
	return b.build(router, pattern, handler)
}

// Reset clears all middlewares from the builder
func (b *MiddlewareBuilder) Reset() *MiddlewareBuilder {
	b.middlewares = b.middlewares[:0]
	return b
}
