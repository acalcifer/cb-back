// Package config loads and validates runtime configuration from the
// environment. Every value is resolved once at startup so a misconfiguration
// fails the process immediately instead of the first request that needs it.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr           string
	LogLevel       slog.Level
	AllowedOrigins string
	TrustProxy     bool

	DatabaseURL string
	RedisURL    string

	CookieName   string
	CookieDomain string
	CookieSecure bool

	// SessionIdleTTL slides forward on each authenticated request, so a user
	// who visits at least weekly stays signed in. SessionAbsoluteTTL never
	// slides, so a stolen session cannot be kept alive indefinitely by an
	// attacker who keeps using it.
	SessionIdleTTL     time.Duration
	SessionAbsoluteTTL time.Duration
	WSTicketTTL        time.Duration

	// Both empty disables TURN; half-set is a startup error.
	TURNSecret        string
	TURNURLs          []string
	TURNCredentialTTL time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Addr:               envOr("ADDR", ":8080"),
		AllowedOrigins:     os.Getenv("ALLOWED_ORIGINS"),
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		RedisURL:           os.Getenv("REDIS_URL"),
		CookieName:         envOr("SESSION_COOKIE_NAME", "cb_session"),
		CookieDomain:       os.Getenv("SESSION_COOKIE_DOMAIN"),
		SessionIdleTTL:     7 * 24 * time.Hour,
		SessionAbsoluteTTL: 30 * 24 * time.Hour,
		WSTicketTTL:        30 * time.Second,
		TURNSecret:         envOr("TURN_SECRET", ""),
		TURNURLs:           splitCSV(os.Getenv("TURN_URLS")),
		TURNCredentialTTL:  time.Hour,
	}

	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	var err error
	if cfg.LogLevel, err = parseLevel(envOr("LOG_LEVEL", "info")); err != nil {
		collect(err)
	}
	if cfg.CookieSecure, err = parseBool("COOKIE_SECURE", true); err != nil {
		collect(err)
	}
	if cfg.TrustProxy, err = parseBool("TRUST_PROXY", false); err != nil {
		collect(err)
	}
	if cfg.SessionIdleTTL, err = parseDuration("SESSION_IDLE_TTL", cfg.SessionIdleTTL); err != nil {
		collect(err)
	}
	if cfg.SessionAbsoluteTTL, err = parseDuration("SESSION_ABSOLUTE_TTL", cfg.SessionAbsoluteTTL); err != nil {
		collect(err)
	}
	if cfg.TURNCredentialTTL, err = parseDuration("TURN_CREDENTIAL_TTL", cfg.TURNCredentialTTL); err != nil {
		collect(err)
	}

	if (cfg.TURNSecret == "") != (len(cfg.TURNURLs) == 0) {
		collect(errors.New("TURN_SECRET and TURN_URLS must both be set, or both left empty to disable TURN"))
	}

	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		collect(errors.New("DATABASE_URL is required"))
	}
	if strings.TrimSpace(cfg.RedisURL) == "" {
		collect(errors.New("REDIS_URL is required"))
	}
	if cfg.SessionIdleTTL > cfg.SessionAbsoluteTTL {
		collect(fmt.Errorf("SESSION_IDLE_TTL (%s) must not exceed SESSION_ABSOLUTE_TTL (%s)",
			cfg.SessionIdleTTL, cfg.SessionAbsoluteTTL))
	}

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
}

// WarnUnsafe reports settings that are fine locally but dangerous in
// production, so they show up in logs rather than in an incident.
func (c Config) WarnUnsafe(logger *slog.Logger) {
	if !c.CookieSecure {
		logger.Warn("COOKIE_SECURE=false sends the session cookie over plaintext HTTP; use it only for local development")
	}
	if c.TrustProxy {
		logger.Warn("TRUST_PROXY=true honours X-Forwarded-For; only enable this behind a proxy that overwrites the header")
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func parseLevel(raw string) (slog.Level, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(raw)); err != nil {
		return slog.LevelInfo, fmt.Errorf("LOG_LEVEL %q: %w", raw, err)
	}
	return lvl, nil
}

func parseBool(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback, fmt.Errorf("%s %q: want true or false", key, raw)
	}
	return v, nil
}

// splitCSV parses a comma-separated environment value into its non-empty,
// trimmed entries. An empty or all-blank input yields a nil slice.
func splitCSV(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback, fmt.Errorf("%s %q: %w", key, raw, err)
	}
	if d <= 0 {
		return fallback, fmt.Errorf("%s must be positive, got %s", key, d)
	}
	return d, nil
}
