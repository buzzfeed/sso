package hostmux

import (
	"net/http"
	"regexp"
	"sync"
)

var (
	// This is a compile-time check to make sure our types correctly implement the interface:
	// https://medium.com/@matryer/golang-tip-compile-time-checks-to-ensure-your-type-satisfies-an-interface-c167afed3aae
	_ Route = &StaticRoute{}
	_ Route = &RegexpRoute{}
	_ Route = &DefaultRoute{}
)

// misdirected replies to the request with an HTTP 421 misdirected error.
func misdirected(rw http.ResponseWriter, req *http.Request) {
	http.Error(rw, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
}

// Router is a generic host router that has support for static, regexp, and default routes
type Router struct {
	mu sync.Mutex

	// StaticRoutes have the highest precedence, and match keys to http.Request.Host values exactly.
	// Added to a router by HandleStatic().
	StaticRoutes map[string]*StaticRoute

	// RegexpRoutes match http.Request.Host based on regular expressions, if no exact match is found.
	// Added to a router by HandleRegexp().
	RegexpRoutes []*RegexpRoute

	// DefaultRoute matches any remaining requests.
	//Added by HandleDefault()
	DefaultRoute *DefaultRoute
}

type Route interface {
	Handler() http.Handler
}

// StaticRoute matches hosts staticly based on a simple string match
type StaticRoute struct {
	host    string
	handler http.Handler
}

// Handler returns a reference to the underlying handler
func (sr *StaticRoute) Handler() http.Handler {
	return sr.handler
}

// RegexpRoute matches hosts based on a regexp
type RegexpRoute struct {
	regexp  *regexp.Regexp
	handler http.Handler
}

// Handler returns a reference to the underlying handler
func (rr *RegexpRoute) Handler() http.Handler {
	return rr.handler
}

// DefaultRoute doesn't match a host but serves a default if none others match
type DefaultRoute struct {
	handler http.Handler
}

// Handler returns a reference to the underlying handler
func (dr *DefaultRoute) Handler() http.Handler {
	return dr.handler
}

// NewRouter is convenience constructor for Router
func NewRouter() *Router {
	return &Router{
		StaticRoutes: make(map[string]*StaticRoute),
		RegexpRoutes: make([]*RegexpRoute, 0),
		DefaultRoute: &DefaultRoute{
			handler: http.HandlerFunc(misdirected),
		},
	}
}

// ServeHTTP matches host to either static or regexp routes. If there is no match,
// it serves the DefaultRoute
func (r *Router) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	r.Route(req).Handler().ServeHTTP(rw, req)
}

// Route returns the route used for the request, consulting first static, regexp, and
// then the default route
func (r *Router) Route(req *http.Request) Route {
	r.mu.Lock()
	defer r.mu.Unlock()

	sr, ok := r.StaticRoutes[req.Host]
	if ok {
		return sr
	}

	for _, rr := range r.RegexpRoutes {
		if rr.regexp.MatchString(req.Host) {
			return rr
		}
	}

	// Nothing matched, use default route
	return r.DefaultRoute
}

// HandleStatic registers the handler func for the given host string
func (r *Router) HandleStatic(host string, handler http.Handler) {
	r.mu.Lock()
	r.StaticRoutes[host] = &StaticRoute{
		host:    host,
		handler: handler,
	}
	r.mu.Unlock()
}

// HandleRegexp registers the handler func for the given regexp
func (r *Router) HandleRegexp(regexp *regexp.Regexp, handler http.Handler) {
	r.mu.Lock()
	r.RegexpRoutes = append(r.RegexpRoutes, &RegexpRoute{
		regexp:  regexp,
		handler: handler,
	})
	r.mu.Unlock()
}

// HandleDefault registers the default handler if there are no matches
func (r *Router) HandleDefault(handler http.Handler) {
	r.mu.Lock()
	r.DefaultRoute = &DefaultRoute{
		handler: handler,
	}
	r.mu.Unlock()
}
