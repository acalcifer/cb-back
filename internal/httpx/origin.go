// Package httpx holds HTTP plumbing shared by the auth and signaling layers.
package httpx

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// OriginPolicy decides whether a request's Origin header is acceptable. It
// backs both the websocket upgrade check and the CSRF guard, so a single
// allowlist governs every cross-site entry point.
type OriginPolicy struct {
	permitted map[string]struct{}
	allowAny  bool
}

// NewOriginPolicy builds a policy from a comma-separated allowlist. An empty
// list means same-host only; "*" disables the check and is logged loudly
// because it re-opens cross-site websocket hijacking and CSRF.
func NewOriginPolicy(allowed string, logger *slog.Logger) (*OriginPolicy, error) {
	allowed = strings.TrimSpace(allowed)

	if allowed == "*" {
		logger.Warn("ALLOWED_ORIGINS=* accepts any origin; this allows cross-site websocket hijacking and CSRF")
		return &OriginPolicy{allowAny: true}, nil
	}

	permitted := make(map[string]struct{})
	for _, raw := range strings.Split(allowed, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parse origin %q: %w", raw, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("origin %q must include scheme and host, e.g. https://example.com", raw)
		}
		permitted[strings.ToLower(u.Scheme+"://"+u.Host)] = struct{}{}
	}

	if len(permitted) == 0 {
		logger.Info("ALLOWED_ORIGINS unset; accepting same-host origins only")
	}
	return &OriginPolicy{permitted: permitted}, nil
}

// Allow reports whether the request may proceed. A missing Origin is accepted:
// browsers always send one on the requests this defends against, so absence
// means a non-browser client, which carries no ambient credentials.
func (p *OriginPolicy) Allow(r *http.Request) bool {
	if p.allowAny {
		return true
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	if len(p.permitted) == 0 {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	}

	_, ok := p.permitted[strings.ToLower(origin)]
	return ok
}

// CheckOrigin adapts the policy to the gorilla/websocket upgrader.
func (p *OriginPolicy) CheckOrigin(r *http.Request) bool { return p.Allow(r) }

var safeMethods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodOptions: {},
}

// CSRF rejects state-changing requests whose Origin is not allowed.
//
// Cookie-authenticated requests are the only ones at risk: the browser attaches
// the session cookie automatically, so a form on an attacker's page could act
// as the user. Requests carrying an Authorization header are exempt because a
// bearer token is never sent ambiently — the attacker's page cannot supply one.
// This runs alongside SameSite=Lax rather than instead of it.
func CSRF(policy *OriginPolicy, deny func(http.ResponseWriter, *http.Request, string), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, safe := safeMethods[r.Method]; safe {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, r)
			return
		}
		if !policy.Allow(r) {
			deny(w, r, "origin not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}
