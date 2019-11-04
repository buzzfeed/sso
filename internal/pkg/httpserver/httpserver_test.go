package httpserver

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/logging"
)

func newLocalListener(t *testing.T) net.Listener {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on a port: %v", err)
	}
	return l
}

func TestGracefulShutdown(t *testing.T) {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}

	// override shutdown signals used by Run for testing purposes
	shutdownSignals = []os.Signal{syscall.SIGUSR1}

	logger := logging.NewLogEntry()

	testCases := map[string]struct {
		shutdownTimeout   time.Duration
		requestDelay      time.Duration
		expectShutdownErr bool
		expectRequestErr  bool
	}{
		"clean shutdown": {
			shutdownTimeout:   1 * time.Second,
			requestDelay:      250 * time.Millisecond,
			expectShutdownErr: false,
			expectRequestErr:  false,
		},
		"timeout elapsed": {
			shutdownTimeout:   50 * time.Millisecond,
			requestDelay:      250 * time.Millisecond,
			expectShutdownErr: true,

			// In real usage, we would expect the request to be aborted when
			// the server is shut down and its process exits before it can
			// finish responding.
			//
			// But because we're running the server within the test process,
			// which does not exit after shutdown, the goroutine handling the
			// long-running request does not seem to get canceled and the
			// request ends up completing successfully even after the server
			// has shut down.
			//
			// Properly testing this would require something like re-running
			// the test binary as a subprocess to which we can send SIGTERM,
			// but doing that would add a lot more complexity (e.g. having it
			// bind to a random available port and then running a separate
			// subprocess to figure out the port to which it is bound, all in a
			// cross-platform way).
			//
			// If we wanted to go that route, some examples of the general
			// approach can be seen here:
			//
			// - http://cs-guy.com/blog/2015/01/test-main/#toc_3
			// - https://talks.golang.org/2014/testing.slide#23
			expectRequestErr: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var (
				ln   = newLocalListener(t)
				addr = ln.Addr().String()
				url  = fmt.Sprintf("http://%s", addr)
			)

			srv := &http.Server{
				Addr: addr,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(tc.requestDelay)
				}),
			}

			var (
				wg          sync.WaitGroup
				shutdownErr error
				requestErr  error
			)

			// Run our server and wait for a stop signal
			wg.Add(1)
			go func() {
				defer wg.Done()
				shutdownErr = runWithListener(ln, srv, tc.shutdownTimeout, logger)
			}()

			// give the server time to start listening
			<-time.After(50 * time.Millisecond)

			// make a request
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, requestErr = http.Get(url)
			}()

			// give the request some time to connect
			<-time.After(1 * time.Millisecond)

			// tell server to shut down gracefully
			proc.Signal(syscall.SIGUSR1)

			// wait for server to shut down and requests to complete
			wg.Wait()

			if tc.expectShutdownErr {
				if shutdownErr == nil {
					t.Fatalf("did not get expected shutdown error")
				}
			} else {
				if shutdownErr != nil {
					t.Fatalf("got unexpected shutdown error: %s", shutdownErr)
				}
			}

			if tc.expectRequestErr && requestErr == nil {
				if requestErr == nil {
					t.Fatalf("did not get expected request error")
				}
			} else {
				if requestErr != nil {
					t.Fatalf("got unexpected request error: %s", requestErr)
				}
			}
		})
	}
}
