package httpserver

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/logging"
)

// OS signals that will initiate graceful shutdown of the http server.
//
// NOTE: defined in a variable so that they may be overridden by tests.
var shutdownSignals = []os.Signal{
	syscall.SIGINT,
	syscall.SIGTERM,
}

// Run runs an http server and ensures that it is shut down gracefully within
// the given shutdown timeout, allowing all in-flight requests to complete.
//
// Returns an error if a) the server fails to listen on its port or b) the
// shutdown timeout elapses before all in-flight requests are finished.
func Run(srv *http.Server, shutdownTimeout time.Duration, logger *logging.LogEntry) error {
	// Logic below copied from the stdlib http.Server ListenAndServe() method:
	// https://github.com/golang/go/blob/release-branch.go1.13/src/net/http/server.go#L2805-L2826
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return runWithListener(ln, srv, shutdownTimeout, logger)
}

// runWithListener does the heavy lifting for Run() above, and is decoupled
// only for testing purposes
func runWithListener(ln net.Listener, srv *http.Server, shutdownTimeout time.Duration, logger *logging.LogEntry) error {
	var (
		// shutdownCh triggers graceful shutdown on SIGINT or SIGTERM
		shutdownCh = make(chan os.Signal, 1)

		// exitCh will be closed when it is safe to exit, after graceful shutdown
		exitCh = make(chan struct{})

		// shutdownErr allows any error from srv.Shutdown to propagate out up
		// from the goroutine
		shutdownErr error
	)

	signal.Notify(shutdownCh, shutdownSignals...)

	go func() {
		sig := <-shutdownCh
		logger.Info("shutdown started by signal: ", sig)
		signal.Stop(shutdownCh)

		logger.Info("waiting for server to shut down in ", shutdownTimeout)
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		shutdownErr = srv.Shutdown(ctx)
		close(exitCh)
	}()

	if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
		return serveErr
	}

	<-exitCh
	logger.Info("shutdown finished")

	return shutdownErr
}
