package sessions

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/go-redis/redis"
)

// RedisStore represents all the cookie related configurations
type RedisStore struct {
	CookieStore
	CreatedAt              time.Time
	ConnectionURL          string
	UseSentinel            bool
	SentinelMasterName     string
	SentinelConnectionURLs []string
	client                 *redis.Client
}

// NewRedisStore returns a new session
func NewRedisStore(cookieName string, optFuncs ...func(*RedisStore) error) (*RedisStore, error) {
	r := &RedisStore{
		CookieStore: CookieStore{
			Name:           cookieName,
			CookieSecure:   true,
			CookieHTTPOnly: true,
			CookieExpire:   168 * time.Hour,
			CSRFCookieName: fmt.Sprintf("%v_%v", cookieName, "csrf"),
		},
	}

	for _, f := range optFuncs {
		err := f(r)
		if err != nil {
			return nil, err
		}
	}

	if r.UseSentinel {
		if r.SentinelMasterName == "" || len(r.SentinelConnectionURLs) == 0 {
			return nil, errors.New("must provide redis connection url or sentinel config")
		}
	} else {
		if r.ConnectionURL == "" {
			return nil, errors.New("must provide redis connection url or sentinel config")
		}
	}

	err := r.initRedisClient()
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r *RedisStore) initRedisClient() error {
	if r.UseSentinel {
		client := redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    r.SentinelMasterName,
			SentinelAddrs: r.SentinelConnectionURLs,
		})
		r.client = client
		return nil
	}

	opt, err := redis.ParseURL(r.ConnectionURL)
	if err != nil {
		return fmt.Errorf("unable to parse redis url: %s", err)
	}

	r.client = redis.NewClient(opt)
	return nil
}

// ClearSession clears the session cookie from a request
func (r *RedisStore) ClearSession(rw http.ResponseWriter, req *http.Request) {
	tokenCookie, err := req.Cookie(r.CookieStore.Name)
	if err == nil && tokenCookie.Value != "" {
		logger := log.NewLogEntry()
		err = r.client.Del(tokenCookie.Value).Err()
		if err != nil {
			logger.WithRequestHost(req.Host).WithError(err).Error("ignoring error clearing session")
		}
	}
	r.CookieStore.ClearSession(rw, req)
}

// LoadSession returns a SessionState from the Redis session store.
func (r *RedisStore) LoadSession(req *http.Request) (*SessionState, error) {
	logger := log.NewLogEntry()
	tokenCookie, err := req.Cookie(r.CookieStore.Name)
	if err != nil {
		// always http.ErrNoCookie
		return nil, err
	}

	result, err := r.client.Get(tokenCookie.Value).Result()
	if err != nil {
		logger.WithRequestHost(req.Host).WithError(err).Error("error retrieving session")
		return nil, err
	}

	session, err := UnmarshalSession(result, r.CookieStore.CookieCipher)
	if err != nil {
		logger.WithRequestHost(req.Host).WithError(err).Error("error unmarshaling session")
		return nil, ErrInvalidSession
	}
	return session, nil
}

// SaveSession saves a session state to the Redis session store.
func (r *RedisStore) SaveSession(rw http.ResponseWriter, req *http.Request, sessionState *SessionState) error {
	// Lack of a cookie is expected for new sessions, discard any errors.
	tokenCookie, _ := req.Cookie(r.CookieStore.Name)
	if tokenCookie == nil || tokenCookie.Value == "" {
		tokenRaw := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, tokenRaw); err != nil {
			return fmt.Errorf("failed to create initialization vector %s", err)
		}
		token := fmt.Sprintf("%x", tokenRaw)
		tokenCookie = r.makeSessionCookie(req, token, r.CookieStore.CookieExpire, time.Now())
		http.SetCookie(rw, tokenCookie)
	}

	value, err := MarshalSession(sessionState, r.CookieStore.CookieCipher)
	if err != nil {
		return err
	}

	err = r.client.Set(tokenCookie.Value, value, r.CookieStore.SessionLifetimeTTL).Err()
	if err != nil {
		return err
	}
	return nil
}
