package devproxy

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
func setSecurityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		for key, val := range securityHeaders {
			rw.Header().Set(key, val)
		}
		h.ServeHTTP(rw, req)
	})
}

func (p *DevProxy) setResponseHeaderOverrides(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		route, ok := p.router(req)
		if ok && route.upstreamConfig.HeaderOverrides != nil {
			for key, val := range route.upstreamConfig.HeaderOverrides {
				rw.Header().Set(key, val)
			}
		}
		h.ServeHTTP(rw, req)
	})
}

// validateHost ensures that each request's host is valid
func (p *DevProxy) validateHost(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if _, ok := p.router(req); !ok {
			p.UnknownHost(rw, req)
			return
		}
		h.ServeHTTP(rw, req)
	})
}

func requireHTTPS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if req.URL.Scheme != "https" && req.Header.Get("X-Forwarded-Proto") != "https" {
			dest := &url.URL{
				Scheme:   "https",
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
