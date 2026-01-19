package https

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/harshabose/services/pkg/https/middleware"
	"github.com/harshabose/tools/pkg/metrics"
)

type Server struct {
	httpServer *http.Server
	router     *http.ServeMux

	once   sync.Once
	ctx    context.Context
	cancel context.CancelFunc
	mux    sync.RWMutex
	wg     sync.WaitGroup

	RateLimiter *middleware.RateLimiter
	CORS        *middleware.Cors

	metrics     *metrics.UnifiedMetrics
	keepHosting bool
	certPath    string
	keyPath     string
}

func NewHTTPSServer(ctx context.Context, config Config) *Server {
	ctx2, cancel := context.WithCancel(ctx)
	router := http.NewServeMux()

	s := &Server{
		router: router,
		httpServer: &http.Server{
			Addr:              fmt.Sprintf("%s:%d", config.Addr, config.Port),
			ReadHeaderTimeout: config.ReadTimeout,
			WriteTimeout:      config.WriteTimeout,
			Handler:           router,
		},
		metrics:     metrics.NewUnifiedMetrics(ctx2, fmt.Sprintf("HTTP SERVER (%s:%d)", config.Addr, config.Port), 10, 30*time.Second),
		RateLimiter: middleware.NewRateLimiter(config.RateLimiterMaxSize, time.Hour),
		CORS:        middleware.NewCors(nil),
		keepHosting: config.KeepHosting,
		certPath:    config.CertPath,
		keyPath:     config.KeyFile,
		ctx:         ctx2,
		cancel:      cancel,
	}

	s.AddHandler(NewMiddlewareBuilder().Add(
		// middleware.Logger(),
		s.CORS.Handler(&middleware.CORSSettings{
			AllowedOrigins: []string{"*"},
			AllowedHeaders: []string{
				"Accept",
				"Accept-Language",
				"Content-Language",
				"Content-Type",
				"Authorization",
				"X-Requested-With",
			},
			AllowedMethods:   []string{"GET"},
			AllowCredentials: true,
			ExposedHeaders: []string{
				"X-RateLimit-Limit",
				"X-RateLimit-Remaining",
				"X-RateLimit-Reset",
			},
			StrictMode:    true,
			AllowWildcard: true,
			LogViolations: true,
			MaxAge:        1800, // 30 minutes for status checks
		}),
		s.RateLimiter.Handler(120, 20),
	), "GET /internal/http/metrics", s.metricsHandler())

	return s
}

func (s *Server) AddHandler(builder *MiddlewareBuilder, pattern string, handler http.Handler) {
	builder.build(s.router, pattern, handler)
}

func (s *Server) AddHandlerFunc(builder *MiddlewareBuilder, pattern string, handler http.HandlerFunc) {
	builder.build(s.router, pattern, handler)
}

func (s *Server) Serve() {
	go s.start()
}

func (s *Server) Done() <-chan struct{} {
	return s.ctx.Done()
}

func (s *Server) start() {
	s.wg.Add(1)
	defer s.wg.Done()
	defer s.metrics.SetState(metrics.DisconnectedState)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			s.metrics.SetState(metrics.ConnectedState)

			var err error
			if s.certPath != "" && s.keyPath != "" {
				err = s.httpServer.ListenAndServeTLS(s.certPath, s.keyPath)
			} else {
				err = s.httpServer.ListenAndServe()
			}

			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.metrics.SetState(metrics.ErrorState)
				s.metrics.AddErrors(err)

				if !s.keepHosting {
					return
				}

				fmt.Println("failed to host server, retrying in 5 seconds...")
				time.Sleep(5 * time.Second)
			} else {
				return
			}
		}
	}
}

// GET /internal/http/metrics
func (s *Server) metricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := s.metrics.GetSnapshot()
		data, err := snap.Marshal()
		if err != nil {
			s.metrics.AddErrors(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(data); err != nil {
			s.metrics.AddErrors(err)
			return
		}
	}
}

func (s *Server) Close() error {
	var err error = nil

	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}

		s.wg.Wait()

		s.mux.Lock()
		defer s.mux.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err = s.httpServer.Shutdown(ctx); err != nil {
			fmt.Printf("graceful shutdown not possible. closing forcibly...")
			if err := s.httpServer.Close(); err != nil {
				fmt.Printf("error while closing http server: %v", err)
			}
		}
	})

	return err
}
