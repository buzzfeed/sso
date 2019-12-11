// largely adapted from https://github.com/gorilla/handlers/blob/master/handlers.go
// to add logging of request duration as last value (and drop referrer)

package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/datadog/datadog-go/statsd"
)

// Used to stash the authenticated user in the response for access when logging requests.
const loggingUserHeader = "SSO-Authenticated-User"

// responseLogger is wrapper of http.ResponseWriter that keeps track of its HTTP status
// code and body size
type responseLogger struct {
	w        http.ResponseWriter
	status   int
	size     int
	authInfo string
}

func (l *responseLogger) Header() http.Header {
	return l.w.Header()
}

func (l *responseLogger) extractUser() {
	authInfo := l.w.Header().Get(loggingUserHeader)
	if authInfo != "" {
		l.authInfo = authInfo
		l.w.Header().Del(loggingUserHeader)
	}
}

// Support Websockets
func (l *responseLogger) Hijack() (rwc net.Conn, buf *bufio.ReadWriter, err error) {
	if hij, ok := l.w.(http.Hijacker); ok {
		return hij.Hijack()
	}
	return nil, nil, errors.New("http.Hijacker is not available on writer")
}

func (l *responseLogger) Write(b []byte) (int, error) {
	if l.status == 0 {
		// The status will be StatusOK if WriteHeader has not been called yet
		l.status = http.StatusOK
	}
	l.extractUser()
	size, err := l.w.Write(b)
	l.size += size
	return size, err
}

func (l *responseLogger) WriteHeader(s int) {
	l.extractUser()
	l.w.WriteHeader(s)
	l.status = s
}

func (l *responseLogger) Status() int {
	return l.status
}

func (l *responseLogger) Size() int {
	return l.size
}

func (l *responseLogger) Flush() {
	f := l.w.(http.Flusher)
	f.Flush()
}

// loggingHandler is the http.Handler implementation for LoggingHandlerTo and its friends
type loggingHandler struct {
	writer       io.Writer
	handler      http.Handler
	StatsdClient *statsd.Client
	enabled      bool
}

// NewLoggingHandler returns a new loggingHandler that wraps a handler, statsd client, and writer.
func NewLoggingHandler(out io.Writer, h http.Handler, lc LoggingConfig, StatsdClient *statsd.Client) http.Handler {
	return loggingHandler{writer: out,
		handler:      h,
		enabled:      lc.Enable,
		StatsdClient: StatsdClient,
	}
}

func (h loggingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	now := time.Now()
	url := *req.URL
	logger := &responseLogger{w: w}
	h.handler.ServeHTTP(logger, req)
	if !h.enabled {
		return
	}
	logRequest(logger.authInfo, req, url, now, logger.Status(), h.StatsdClient)
}

// logRequest logs information about a request
func logRequest(username string, req *http.Request, url url.URL, ts time.Time, status int, StatsdClient *statsd.Client) {
	duration := time.Now().Sub(ts)

	// Convert duration to floating point milliseconds
	// https://github.com/golang/go/issues/5491#issuecomment-66079585
	durationMS := duration.Seconds() * 1e3

	uri := req.Host + url.RequestURI()

	logger := log.NewLogEntry()
	logger.WithHTTPStatus(status).WithRequestMethod(req.Method).WithRequestURI(
		uri).WithUserAgent(req.Header.Get("User-Agent")).WithRemoteAddress(
		getRemoteAddr(req)).WithRequestDurationMs(durationMS).WithUser(
		username).WithAction(GetActionTag(req)).Info()
	logRequestMetrics(req, duration, status, StatsdClient)
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
