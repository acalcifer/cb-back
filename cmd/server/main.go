// Command server runs the cb-back signaling and authentication API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"cb-back/internal/auth"
	"cb-back/internal/config"
	"cb-back/internal/database"
	"cb-back/internal/httpx"
	"cb-back/internal/rooms"
	"cb-back/internal/signaling"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 15 * time.Second
	startupTimeout    = 30 * time.Second
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		// The logger needs no configuration to report a configuration error.
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)
	cfg.WarnUnsafe(logger)

	if err := run(cfg, logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped cleanly")
}

func run(cfg config.Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startupCtx, cancelStartup := context.WithTimeout(ctx, startupTimeout)
	defer cancelStartup()

	pool, err := database.Connect(startupCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	logger.Info("connected to postgres")

	if err := database.Migrate(startupCtx, pool, logger); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	rdb, err := connectRedis(startupCtx, cfg.RedisURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := rdb.Close(); err != nil {
			logger.Error("close redis failed", "error", err)
		}
	}()
	logger.Info("connected to redis")

	policy, err := httpx.NewOriginPolicy(cfg.AllowedOrigins, logger)
	if err != nil {
		return fmt.Errorf("ALLOWED_ORIGINS: %w", err)
	}

	sessions := auth.NewSessionStore(rdb, cfg.SessionIdleTTL, cfg.SessionAbsoluteTTL, cfg.WSTicketTTL)
	service := auth.NewService(auth.NewUserStore(pool), sessions, auth.NewRateLimiter(rdb), logger)
	middleware := auth.NewMiddleware(service, logger, auth.MiddlewareOptions{
		CookieName:   cfg.CookieName,
		CookieDomain: cfg.CookieDomain,
		CookieSecure: cfg.CookieSecure,
		AbsoluteTTL:  cfg.SessionAbsoluteTTL,
		TrustProxy:   cfg.TrustProxy,
	})

	hub := signaling.NewHub(logger)
	hubDone := make(chan struct{})
	go func() {
		defer close(hubDone)
		hub.Run(ctx)
	}()

	roomService := rooms.NewService(rooms.NewStore(pool))

	mux := http.NewServeMux()
	auth.NewHandlers(service, middleware, logger).Routes(mux, middleware.Require)
	rooms.NewHandlers(roomService, logger).Routes(mux, middleware.Require)

	// Translates the rooms package's not-found into the one the signaling
	// handler answers 404 for, so neither package has to know the other.
	resolveRoom := func(ctx context.Context, slug string) (string, error) {
		room, err := roomService.BySlug(ctx, slug)
		if errors.Is(err, rooms.ErrNotFound) {
			return "", signaling.ErrRoomNotFound
		}
		if err != nil {
			return "", err
		}
		return room.ID, nil
	}

	// The websocket handler authenticates internally so it can accept a
	// single-use ticket, which Require does not know about.
	mux.Handle("GET /ws", signaling.NewHandler(hub, logger, policy.CheckOrigin, middleware, resolveRoom))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.JSON(w, logger, http.StatusOK, map[string]any{"status": "ok", "clients": hub.ClientCount()})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		readyCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		checks := map[string]string{"postgres": "ok", "redis": "ok"}
		status := http.StatusOK

		if err := pool.Ping(readyCtx); err != nil {
			checks["postgres"] = err.Error()
			status = http.StatusServiceUnavailable
		}
		if err := rdb.Ping(readyCtx).Err(); err != nil {
			checks["redis"] = err.Error()
			status = http.StatusServiceUnavailable
		}
		httpx.JSON(w, logger, status, checks)
	})

	deny := func(w http.ResponseWriter, r *http.Request, reason string) {
		logger.Warn("request blocked by CSRF guard", "path", r.URL.Path, "origin", r.Header.Get("Origin"))
		httpx.Error(w, logger, http.StatusForbidden, "forbidden_origin", reason)
	}

	// Outermost first: a panic anywhere below still returns a 500.
	handler := httpx.Recover(logger, httpx.SecurityHeaders(httpx.CSRF(policy, deny, mux)))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		// No ReadTimeout/WriteTimeout: they would kill long-lived websocket
		// connections. Per-message deadlines in the signaling package cover
		// those, and ReadHeaderTimeout still bounds the handshake.
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Addr)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("listen: %w", err)
		}
	case <-ctx.Done():
		logger.Info("shutdown signal received", "timeout", shutdownTimeout)
	}

	// Stop accepting new connections. Shutdown does not wait on hijacked
	// websocket connections, so the hub closing each client's send channel is
	// what actually drains them.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	shutdownErr := srv.Shutdown(shutdownCtx)

	select {
	case <-hubDone:
	case <-shutdownCtx.Done():
		return errors.New("timed out waiting for clients to disconnect")
	}

	if shutdownErr != nil {
		return fmt.Errorf("shutdown: %w", shutdownErr)
	}
	return nil
}

func connectRedis(ctx context.Context, url string) (*redis.Client, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse REDIS_URL: %w", err)
	}
	opts.MaxRetries = 3
	opts.DialTimeout = 5 * time.Second
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second

	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		if closeErr := rdb.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return rdb, nil
}
