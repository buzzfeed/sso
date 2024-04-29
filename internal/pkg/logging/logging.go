package logging

import (
	"net/url"
	"os"
	"time"

	logrus "github.com/sirupsen/logrus"
)

var serviceName = "sso"

func init() {
	logrus.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.JSONFormatter{TimestampFormat: "2006-01-02 15:04:05.000Z"})
}

// SetServiceName configures the service name to log with each LogEntry.
func SetServiceName(name string) {
	serviceName = name
}

// LogEntry is a wrapper around a logrus entry
type LogEntry struct {
	logger *logrus.Entry
}

// NewLogEntry creates a new logrus Entry
func NewLogEntry() *LogEntry {
	// initialize logging
	return &LogEntry{logger: logrus.WithField("service", serviceName)}
}

// Fields returns all the fields that are in the logs
func (l *LogEntry) Fields() map[string]interface{} {
	return l.logger.Data
}

// Wrappers around logging actions

// Info wraps the logrus Info function
func (l *LogEntry) Info(args ...interface{}) {
	l.logger.Info(args...)
}

// Warn wraps the logrus Warn function
func (l *LogEntry) Warn(args ...interface{}) {
	l.logger.Warn(args...)
}

// Error wraps the logrus Error function
func (l *LogEntry) Error(err interface{}, args ...interface{}) {
	l.withField("error", err).logger.Error(args...)
}

// Fatal wraps the logrus Fatal function
func (l *LogEntry) Fatal(args ...interface{}) {
	l.logger.Fatal(args...)
}

// Debug wraps the logrus Debug function
func (l *LogEntry) Debug(args ...interface{}) {
	l.logger.Debug(args...)
}

// Panic wraps the logrus Panic function
func (l *LogEntry) Panic(args ...interface{}) {
	l.logger.Panic(args...)
}

// Printf wraps the logrus Printf function
func (l *LogEntry) Printf(format string, args ...interface{}) {
	l.logger.Printf(format, args...)
}

// withField is a helper function for adding a key-value pair to the log fields
func (l *LogEntry) withField(key string, val interface{}) *LogEntry {
	return &LogEntry{l.logger.WithField(key, val)}

}

// WithAllowedGroups appends an `allowed_groups` tag to a LogEntry.
func (l *LogEntry) WithAllowedGroups(groups []string) *LogEntry {
	return l.withField("allowed_groups", groups)
}

// WithBackoffDuration appends a `backoff_duration` tag to a LogEntry.
func (l *LogEntry) WithBackoffDuration(resetDuration time.Duration) *LogEntry {
	return l.withField("backoff_duration", resetDuration)
}

// WithBackoffReset appends a `backoff_reset` tag to a LogEntry.
func (l *LogEntry) WithBackoffReset(resetTime time.Time) *LogEntry {
	return l.withField("backoff_reset", resetTime)
}

// WithCircuitChangeFrom appends a `circuit_change_from` tag to a LogEntry.
func (l *LogEntry) WithCircuitChangeFrom(from interface{}) *LogEntry {
	return l.withField("circuit_change_from", from)
}

// WithCircuitChangeTo appends a `circuit_change_to` tag to a LogEntry.
func (l *LogEntry) WithCircuitChangeTo(to interface{}) *LogEntry {
	return l.withField("circuit_change_to", to)
}

// WithClientID appends a `client_id` tag to a LogEntry.
func (l *LogEntry) WithClientID(clientID string) *LogEntry {
	return l.withField("client_id", clientID)
}

// WithCookieDomain appends a `cookie_domain` tag to a LogEntry.
func (l *LogEntry) WithCookieDomain(domain string) *LogEntry {
	return l.withField("cookie_domain", domain)
}

// WithCookieExpire appends a `cookie_expire` tag to a LogEntry.
func (l *LogEntry) WithCookieExpire(expiration time.Duration) *LogEntry {
	return l.withField("cookie_expire", expiration)
}

// WithCookieHTTPOnly appends a `cookie_http_only` tag to a LogEntry.
func (l *LogEntry) WithCookieHTTPOnly(httpOnly bool) *LogEntry {
	return l.withField("cookie_http_only", httpOnly)
}

// WithCookieName appends a `cookie_name` tag to a LogEntry.
func (l *LogEntry) WithCookieName(name string) *LogEntry {
	return l.withField("cookie_name", name)
}

// WithCookieRefresh appends a `cookie_refresh` tag to a LogEntry.
func (l *LogEntry) WithCookieRefresh(refresh time.Duration) *LogEntry {
	return l.withField("cookie_refresh", refresh)
}

// WithCookieSecure appends a `cookie_secure` tag to a LogEntry.
func (l *LogEntry) WithCookieSecure(isSecure bool) *LogEntry {
	return l.withField("cookie_secure", isSecure)
}

// WithEndpoint appends an `endpoint` tag to a LogEntry.
func (l *LogEntry) WithEndpoint(endpoint string) *LogEntry {
	return l.withField("endpoint", endpoint)
}

// WithAuthorizedUpstream appends an `authorized_upstream` tag to a LogEntry.
func (l *LogEntry) WithAuthorizedUpstream(upstream string) *LogEntry {
	return l.withField("authorized_upstream", upstream)
}

// WithError appends an `error` tag to a LogEntry. Useful for annotating non-Error log
// entries (e.g. Fatal messages) with an `error` object.
func (l *LogEntry) WithError(err error) *LogEntry {
	return l.withField("error", err)
}

// WithHTTPStatus appends an `http_status` tag to a LogEntry.
func (l *LogEntry) WithHTTPStatus(status int) *LogEntry {
	return l.withField("http_status", status)
}

// WithInGroups appends an `in_groups` tag to a LogEntry.
func (l *LogEntry) WithInGroups(groups []string) *LogEntry {
	return l.withField("in_groups", groups)
}

// WithNumCookieBytes appends a `num_cookie_bytes` tag to a LogEntry.
func (l *LogEntry) WithNumCookieBytes(sz int) *LogEntry {
	return l.withField("num_cookie_bytes", sz)
}

// WithPageMessage appends a `page_message` tag to a LogEntry.
func (l *LogEntry) WithPageMessage(msg string) *LogEntry {
	return l.withField("page_message", msg)
}

// WithPageTitle appends a `page_title` tag to a LogEntry.
func (l *LogEntry) WithPageTitle(title string) *LogEntry {
	return l.withField("page_title", title)
}

// WithProvider appends a `provider` tag to a LogEntry.
func (l *LogEntry) WithProvider(provider string) *LogEntry {
	return l.withField("provider", provider)
}

// WithProxyHost appends a `proxy_host` tag to a LogEntry.
func (l *LogEntry) WithProxyHost(host string) *LogEntry {
	return l.withField("proxy_host", host)
}

// WithRedeemURL appends a `redeem_url` tag to a LogEntry.
func (l *LogEntry) WithRedeemURL(url string) *LogEntry {
	return l.withField("redeem_url", url)
}

// WithRemoteAddress appends a `remote_address` tag to a LogEntry.
func (l *LogEntry) WithRemoteAddress(address string) *LogEntry {
	return l.withField("remote_address", address)
}

// WithRequestDurationMs appends a `request_duration` tag to a LogEntry.
func (l *LogEntry) WithRequestDurationMs(duration float64) *LogEntry {
	return l.withField("request_duration", duration)
}

// WithRequestHost appends a `request_host` tag to a LogEntry.
func (l *LogEntry) WithRequestHost(host string) *LogEntry {
	return l.withField("request_host", host)
}

// WithRequestURI appends a `request_uri` tag to a LogEntry.
func (l *LogEntry) WithRequestURI(uri string) *LogEntry {
	return l.withField("request_uri", uri)
}

// WithRequestMethod appends a `request_method` tag to a LogEntry.
func (l *LogEntry) WithRequestMethod(method string) *LogEntry {
	return l.withField("request_method", method)
}

// WithResponseBody appends a `response_body` tag to a LogEntry.
func (l *LogEntry) WithResponseBody(body []byte) *LogEntry {
	return l.withField("response_body", body)
}

// WithRewriteRoute appends a `rewrite_route` tag to a LogEntry.
func (l *LogEntry) WithRewriteRoute(route interface{}) *LogEntry {
	return l.withField("rewrite_route", route)
}

// WithRefreshDeadline appends a `refresh_deadline` tag to a LogEntry.
func (l *LogEntry) WithRefreshDeadline(refresh time.Time) *LogEntry {
	return l.withField("refresh_deadline", refresh)
}

// WithSessionValid appends a `session_valid` tag to a LogEntry.
func (l *LogEntry) WithSessionValid(valid time.Time) *LogEntry {
	return l.withField("session_valid", valid)
}

// WithLifetimeDeadline appends a `lifetime_deadline` tag to a LogEntry.
func (l *LogEntry) WithLifetimeDeadline(valid time.Time) *LogEntry {
	return l.withField("lifetime_deadline", valid)
}

// WithSignInURL appends a `sign_in_url` tag to a LogEntry.
func (l *LogEntry) WithSignInURL(url *url.URL) *LogEntry {
	return l.withField("sign_in_url", url)
}

// WithStatsdHost appends a `statsd_host` tag to a LogEntry.
func (l *LogEntry) WithStatsdHost(host string) *LogEntry {
	return l.withField("statsd_host", host)
}

// WithStatsdPort appends a `statsd_port` tag to a LogEntry.
func (l *LogEntry) WithStatsdPort(port int) *LogEntry {
	return l.withField("statsd_port", port)
}

// WithURLParam appends a `url_param` tag to a LogEntry.
func (l *LogEntry) WithURLParam(param string) *LogEntry {
	return l.withField("url_param", param)
}

// WithUser appends a `user` tag to a LogEntry.
func (l *LogEntry) WithUser(user string) *LogEntry {
	return l.withField("user", user)
}

// WithUserAgent appends a `user_agent` tag to a LogEntry.
func (l *LogEntry) WithUserAgent(agent string) *LogEntry {
	return l.withField("user_agent", agent)
}

// WithUserGroup appends a `user_group` tag to a LogEntry.
func (l *LogEntry) WithUserGroup(group string) *LogEntry {
	return l.withField("user_group", group)
}

// WithAction appends an `action` tag to a LogEntry indicating the URL action triggered.
func (l *LogEntry) WithAction(action string) *LogEntry {
	return l.withField("action", action)
}
