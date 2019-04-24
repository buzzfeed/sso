package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/buzzfeed/sso/internal/auth/providers"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
)

var (
	// ErrUserNotAuthorized is an error for unauthorized users.
	ErrUserNotAuthorized = errors.New("user not authorized")
	// ErrUnknownIdentityProvider denotes an unknown provider
	ErrUnknownIdentityProvider = errors.New("unknown identity provider")
)

// HTTPError stores the status code and a message for a given HTTP error.
type HTTPError struct {
	Code    int
	Message string
}

// Error fulfills the error interface, returning a string representation of the error.
func (h HTTPError) Error() string {
	return fmt.Sprintf("%d %s: %s", h.Code, http.StatusText(h.Code), h.Message)
}

func codeForError(err error) int {
	switch err {
	case providers.ErrBadRequest:
		return 400
	case providers.ErrTokenRevoked:
		return 401
	case providers.ErrRateLimitExceeded:
		return 429
	case providers.ErrServiceUnavailable:
		return 503
	case ErrUserNotAuthorized:
		return 401
	}
	return 500
}

// ErrorResponse renders an error page for errors given a message and a status code.
func (p *Authenticator) ErrorResponse(rw http.ResponseWriter, req *http.Request, message string, code int) {
	logger := log.NewLogEntry()

	if req.Header.Get("Accept") == "application/json" {
		var response struct {
			Error string `json:"error"`
		}
		response.Error = message
		writeJSONResponse(rw, code, response)
	} else {
		title := http.StatusText(code)
		logger.WithHTTPStatus(code).WithPageTitle(title).WithPageMessage(message).Info(
			"error page")
		rw.WriteHeader(code)
		t := struct {
			Code    int
			Title   string
			Message string
		}{
			Code:    code,
			Title:   title,
			Message: message,
		}
		p.templates.ExecuteTemplate(rw, "error.html", t)
	}
}
