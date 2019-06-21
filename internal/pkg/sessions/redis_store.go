package sessions

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis"
)

// TicketData is a structure representing the ticket used in server session storage
type TicketData struct {
	TicketID string
	Secret   []byte
}

// RedisStore represents all the cookie related configurations
type RedisStore struct {
	CookieStore
	RedisConnectionURL     string
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
		if r.RedisConnectionURL == "" {
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

	opt, err := redis.ParseURL(r.RedisConnectionURL)
	if err != nil {
		return fmt.Errorf("unable to parse redis url: %s", err)
	}

	r.client = redis.NewClient(opt)
	return nil
}
