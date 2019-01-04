package devproxy

import (
	"net/http"
)

// GetActionTag returns the action triggered by an http.Request .
func GetActionTag(req *http.Request) string {
	// only log metrics for these paths and actions
	pathToAction := map[string]string{
		"/favicon.ico":     "favicon",
		"/oauth2/sign_out": "sign_out",
		"/oauth2/callback": "callback",
		"/oauth2/auth":     "auth",
		"/ping":            "ping",
		"/robots.txt":      "robots",
	}
	// get the action from the url path
	path := req.URL.Path
	if action, ok := pathToAction[path]; ok {
		return action
	}
	return "proxy"
}
