package ping

import (
	"net/http"
)

type PingHandler struct {
	Handler http.Handler
	Path    string
}

func (p *PingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := "/ping"
	if p.Path != "" {
		path = p.Path
	}

	if r.URL.Path == path {
		w.WriteHeader(http.StatusOK)
		return
	}

	p.Handler.ServeHTTP(w, r)
}
