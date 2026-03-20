package proxy

import (
	"net/http"
	"net/url"
)

// With inspiration from https://github.com/unrolled/secure
//
// TODO: Add Content-Security-Report header?
var securityHeaders = map[string]string{
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options":        "SAMEORIGIN",
	"X-XSS-Protection":       "1; mode=block",
}

// setHeaders ensures that every response includes some basic security headers.
//
// Note: the Strict-Transport-Security header is set by the requireHTTPS
// middleware below, to avoid issues with development environments that must
// allow plain HTTP.
func setHeaders(h http.Handler, headers map[string]string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		for key, val := range headers {
			rw.Header().Set(key, val)
		}
		h.ServeHTTP(rw, req)
	})
}

func setSecurityHeaders(h http.Handler) http.Handler {
	return setHeaders(h, securityHeaders)
}

func (p *OAuthProxy) setResponseHeaderOverrides(upstreamConfig *UpstreamConfig, h http.Handler) http.Handler {
	return setHeaders(h, upstreamConfig.HeaderOverrides)
}

func requireHTTPS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if !isSecureScheme(req.URL.Scheme) && !isSecureScheme(req.Header.Get("X-Forwarded-Proto")) {
			dest := &url.URL{
				Scheme:   redirectScheme(req),
				Host:     req.Host,
				Path:     req.URL.Path,
				RawQuery: req.URL.RawQuery,
			}
			http.Redirect(rw, req, dest.String(), http.StatusMovedPermanently)
			return
		}
		h.ServeHTTP(rw, req)
	})
}

func redirectScheme(req *http.Request) string {
	if req.Header.Get("X-Forwarded-Proto") == "ws" || req.URL.Scheme == "ws" {
		return "wss"
	}

	return "https"
}

func isSecureScheme(scheme string) bool {
	switch scheme {
	case "https", "wss":
		return true
	default:
		return false
	}
}

func setHealthCheck(healthcheckPath string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthcheckPath {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
