// largely adapted from https://github.com/gorilla/handlers/blob/master/handlers.go
// to add logging of request duration as last value (and drop referrer)

package auth

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/datadog/datadog-go/statsd"
)

// responseLogger is wrapper of http.ResponseWriter that keeps track of its HTTP status
// code and body size
type responseLogger struct {
	w         http.ResponseWriter
	status    int
	size      int
	proxyHost string
	authInfo  string
}

func (l *responseLogger) Header() http.Header {
	return l.w.Header()
}

func (l *responseLogger) ExtractGAPMetadata() {
	authInfo := l.w.Header().Get("GAP-Auth")
	if authInfo != "" {
		l.authInfo = authInfo

		l.w.Header().Del("GAP-Auth")
	}
}

func (l *responseLogger) Write(b []byte) (int, error) {
	if l.status == 0 {
		// The status will be StatusOK if WriteHeader has not been called yet
		l.status = http.StatusOK
	}
	l.ExtractGAPMetadata()
	size, err := l.w.Write(b)
	l.size += size
	return size, err
}

func (l *responseLogger) WriteHeader(s int) {
	l.ExtractGAPMetadata()
	l.w.WriteHeader(s)
	l.status = s
}

func (l *responseLogger) Status() int {
	return l.status
}

func (l *responseLogger) Size() int {
	return l.size
}

// loggingHandler is the http.Handler implementation for LoggingHandlerTo and its friends
type loggingHandler struct {
	writer       io.Writer
	StatsdClient *statsd.Client
	handler      http.Handler
	enabled      bool
}

// NewLoggingHandler creates a new loggingHandler
func NewLoggingHandler(out io.Writer, h http.Handler, v bool, StatsdClient *statsd.Client) http.Handler {
	return loggingHandler{
		writer:       out,
		handler:      h,
		enabled:      v,
		StatsdClient: StatsdClient,
	}
}

// getProxyHost attempts to get the proxy host from the redirect_uri parameter
func getProxyHost(req *http.Request) string {
	err := req.ParseForm()
	if err != nil {
		return ""
	}
	redirect := req.Form.Get("redirect_uri")
	redirectURL, err := url.Parse(redirect)
	if err != nil {
		return ""
	}
	return redirectURL.Host
}

func (h loggingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	t := time.Now()
	url := *req.URL
	logger := &responseLogger{w: w, proxyHost: getProxyHost(req)}
	h.handler.ServeHTTP(logger, req)
	if !h.enabled {
		return
	}
	requestDuration := time.Now().Sub(t)
	logRequest(logger.proxyHost, logger.authInfo, req, url, requestDuration, logger.Status(), h.StatsdClient)
}

// logRequests creates a log message from the request status, method, url, proxy host and duration of the request
func logRequest(proxyHost, user string, req *http.Request, url url.URL, requestDuration time.Duration, status int, StatsdClient *statsd.Client) {
	// Convert duration to floating point milliseconds
	// https://github.com/golang/go/issues/5491#issuecomment-66079585
	durationMS := requestDuration.Seconds() * 1e3

	logger := log.NewLogEntry()
	logger.WithHTTPStatus(status).WithRequestMethod(req.Method).WithRequestURI(
		url.RequestURI()).WithProxyHost(proxyHost).WithUser(user).WithUserAgent(
		req.Header.Get("User-Agent")).WithRemoteAddress(
		getRemoteAddr(req)).WithRequestDurationMs(
		durationMS).WithAction(GetActionTag(req)).Info()
	logRequestMetrics(proxyHost, req, requestDuration, status, StatsdClient)
}

// getRemoteAddr returns the client IP address from a request. If present, the
// X-Forwarded-For header is assumed to be set by a load balancer, and its
// rightmost entry (the client IP that connected to the LB) is returned.
func getRemoteAddr(req *http.Request) string {
	addr := req.RemoteAddr
	forwardedHeader := req.Header.Get("X-Forwarded-For")
	if forwardedHeader != "" {
		forwardedList := strings.Split(forwardedHeader, ",")
		forwardedAddr := strings.TrimSpace(forwardedList[len(forwardedList)-1])
		if forwardedAddr != "" {
			addr = forwardedAddr
		}
	}
	return addr
}
