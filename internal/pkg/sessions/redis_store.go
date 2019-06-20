package sessions

import (
	"errors"
	"fmt"
	"time"
)

// RedisStore represents all the cookie related configurations
type RedisStore struct {
	CookieStore
	RedisConnectionURL     string
	UseSentinel            bool
	SentinelMasterName     string
	SentinelConnectionURLs []string
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
		if r.RedisConnectionURL == "" {
			return nil, errors.New("must provide redis connection url or sentinel config")
		}
	}

	return r, nil
}
