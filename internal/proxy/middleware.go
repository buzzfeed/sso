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

// setHeaders middleware that sets the reponse headers
func setHeaders(headers map[string]string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, val := range headers {
			w.Header().Set(key, val)
		}
		h.ServeHTTP(w, r)
	})
}

// setSecurityHeaders sets minimum security headers for all upstreams
func setSecurityHeaders(h http.Handler) http.Handler {
	return setHeaders(securityHeaders, h)
}
