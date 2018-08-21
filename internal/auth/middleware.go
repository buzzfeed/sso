package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// With inspiration from https://github.com/unrolled/secure and
// https://content-security-policy.com
var securityHeaders = map[string]string{
	"Strict-Transport-Security": "max-age=31536000",
	"X-Frame-Options":           "DENY",
	"X-Content-Type-Options":    "nosniff",
	"X-XSS-Protection":          "1; mode=block",
	"Content-Security-Policy":   "default-src 'none'; style-src 'self'; img-src 'self';",
	"Referrer-Policy":           "Same-origin",
}

// setHeaders ensures that every response includes some basic security headers
func setHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		for key, val := range securityHeaders {
			rw.Header().Set(key, val)
		}
		h.ServeHTTP(rw, req)
	})
}

// withMethods writes an error response if the method of the request is not included.
func (p *Authenticator) withMethods(f http.HandlerFunc, methods ...string) http.HandlerFunc {
	methodMap := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		methodMap[m] = struct{}{}
	}
	return func(rw http.ResponseWriter, req *http.Request) {
		if _, ok := methodMap[req.Method]; !ok {
			p.ErrorResponse(rw, req, fmt.Sprintf("method %s not allowed", req.Method), http.StatusMethodNotAllowed)
			return
		}
		f(rw, req)
	}
}

// validateClientID checks the request body or url for the client id and returns an error
// if it does not match the proxy client id
func (p *Authenticator) validateClientID(f http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		tags := []string{fmt.Sprintf("action:%s", GetActionTag(req))}
		// try to get the client id from the request body
		err := req.ParseForm()
		if err != nil {
			p.ErrorResponse(rw, req, err.Error(), http.StatusInternalServerError)
			return
		}

		clientID := req.FormValue("client_id")
		if clientID == "" {
			// try to get the clientID from the query parameters
			clientID = req.URL.Query().Get("client_id")
		}

		if clientID != p.ProxyClientID {
			tags = append(tags, "error:invalid_client_id")
			p.StatsdClient.Incr("application_error", tags, 1.0)
			p.ErrorResponse(rw, req, "Invalid client_id parameter", http.StatusUnauthorized)
			return
		}
		f(rw, req)
	}
}

// validateClientSecret checks the request header for the client secret and returns
// an error if it does not match the proxy client secret
func (p *Authenticator) validateClientSecret(f http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		tags := []string{fmt.Sprintf("action:%s", GetActionTag(req))}
		err := req.ParseForm()
		if err != nil {
			p.ErrorResponse(rw, req, err.Error(), http.StatusInternalServerError)
			return
		}
		clientSecret := req.Form.Get("client_secret")
		// check the request header for the client secret
		if clientSecret == "" {
			clientSecret = req.Header.Get("X-Client-Secret")
		}
		if clientSecret != p.ProxyClientSecret {
			tags = append(tags, "error:invalid_client_secret")
			p.StatsdClient.Incr("application_error", tags, 1.0)
			p.ErrorResponse(rw, req, "Invalid client secret", http.StatusUnauthorized)
			return
		}
		f(rw, req)
	}
}

// validateRedirectURI checks the redirect uri in the query parameters and ensures that
// the url's domain is one in the list of proxy root domains.
func (p *Authenticator) validateRedirectURI(f http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		tags := []string{fmt.Sprintf("action:%s", GetActionTag(req))}
		err := req.ParseForm()
		if err != nil {
			p.ErrorResponse(rw, req, err.Error(), http.StatusBadRequest)
			return
		}
		redirectURI := req.Form.Get("redirect_uri")
		if !validRedirectURI(redirectURI, p.ProxyRootDomains) {
			tags = append(tags, "error:invalid_redirect_parameter")
			p.StatsdClient.Incr("application_error", tags, 1.0)
			p.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
			return
		}

		f(rw, req)
	}
}

func validRedirectURI(uri string, rootDomains []string) bool {
	redirectURL, err := url.Parse(uri)
	if uri == "" || err != nil || redirectURL.Host == "" {
		return false
	}
	for _, domain := range rootDomains {
		if strings.HasSuffix(redirectURL.Hostname(), domain) {
			return true
		}
	}
	return false
}

func (p *Authenticator) validateSignature(f http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			p.ErrorResponse(rw, req, err.Error(), http.StatusBadRequest)
			return
		}
		redirectURI := req.Form.Get("redirect_uri")
		sigVal := req.Form.Get("sig")
		timestamp := req.Form.Get("ts")
		if !validSignature(redirectURI, sigVal, timestamp, p.ProxyClientSecret) {
			p.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
			return
		}

		f(rw, req)
	}
}

func validSignature(redirectURI, sigVal, timestamp, secret string) bool {
	if redirectURI == "" || sigVal == "" || timestamp == "" || secret == "" {
		return false
	}
	_, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	requestSig, err := base64.URLEncoding.DecodeString(sigVal)
	if err != nil {
		return false
	}
	i, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	tm := time.Unix(i, 0)
	ttl := 5 * time.Minute
	if time.Now().Sub(tm) > ttl {
		return false
	}
	localSig := redirectURLSignature(redirectURI, tm, secret)
	return hmac.Equal(requestSig, localSig)
}

func redirectURLSignature(rawRedirect string, timestamp time.Time, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(rawRedirect))
	h.Write([]byte(fmt.Sprint(timestamp.Unix())))
	return h.Sum(nil)
}
