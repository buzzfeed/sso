package groups

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/datadog/datadog-go/statsd"
)

const (
	defaultMaxJitter = 50 * time.Millisecond
)

// MemberSetCache represents a cache of members of a set
type MemberSetCache interface {
	// Get returns a MemberSet from the cache
	Get(string) (MemberSet, bool)
	// Update updates the MemberSet of a given key, return a boolean updated value, and and error
	Update(string) bool
	// RefreshLoop starts an update refresh loop for a given key and returns a boolean value of it was started
	RefreshLoop(string) bool
	// Stop is a function to stop all goroutines that may have been spun up for the cache.
	Stop()
}

// FillFunc is a function that computes the value of a cache entry given a string key
type FillFunc func(string) (MemberSet, error)

// MemberSet represents a set of all the members for a given group key in the cache
type MemberSet map[string]struct{}

// FillCache is a cache whose entries are calculated and filled on-demand
type FillCache struct {
	fillFunc  FillFunc
	cache     map[string]MemberSet
	inflight  map[string]struct{}
	maxJitter time.Duration

	refreshTTL        time.Duration
	refreshLoopGroups map[string]struct{}

	StatsdClient *statsd.Client

	mu     sync.RWMutex
	stopCh chan struct{}
}

// NewFillCache creates a `FillCache` whose entries will be computed by the given `FillFunc`
func NewFillCache(fillFunc FillFunc, refreshTTL time.Duration) *FillCache {
	return &FillCache{
		fillFunc:          fillFunc,
		cache:             make(map[string]MemberSet),
		inflight:          make(map[string]struct{}),
		refreshLoopGroups: make(map[string]struct{}),
		refreshTTL:        refreshTTL,
		stopCh:            make(chan struct{}),
	}
}

// Get returns the cache value for the given key, computing it as necessary
func (c *FillCache) Get(group string) (MemberSet, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, found := c.cache[group]
	return val, found
}

// Update recomputes the value for the given key, unless another goroutine is
// already computing the value, and returns a bool indicating whether the value
// was updated
func (c *FillCache) Update(group string) bool {
	logger := log.NewLogEntry()
	logger.WithUserGroup(group).Info("updating fill cache")

	c.mu.Lock()
	if _, waiting := c.inflight[group]; waiting {
		c.mu.Unlock()
		return false
	}

	c.inflight[group] = struct{}{}
	c.mu.Unlock()
	val, err := c.fillFunc(group)

	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.inflight, group)

	if err == nil {
		c.cache[group] = val
		return true
	}

	c.StatsdClient.Incr("groups_cache.error",
		[]string{
			fmt.Sprintf("group:%s", group),
			fmt.Sprintf("error:%s", err),
		}, 1.0)
	logger.WithUserGroup(group).Error(err, "error updating fill cache")
	return false
}

// RefreshLoop runs in a separate goroutine for the key in the cache and
// updates the cache value for that key every refreshTTL
func (c *FillCache) RefreshLoop(group string) bool {
	maxJitter := defaultMaxJitter
	// Add jitter before starting each refresh loop, up to refreshPeriod by
	// default (tests control maxJitter to ensure they run deterministically)
	if c.maxJitter != 0 {
		maxJitter = c.maxJitter
	}
	time.Sleep(time.Duration(rand.Float64() * float64(maxJitter)))

	c.mu.Lock()

	// check the inflight and the cache so that we don't start if they're already populated
	if _, waiting := c.refreshLoopGroups[group]; waiting {
		c.mu.Unlock()
		return false
	}

	c.refreshLoopGroups[group] = struct{}{}
	c.mu.Unlock()

	ticker := time.NewTicker(c.refreshTTL)
	go func() {
		logger := log.NewLogEntry()
		// cleanup if this goroutine exits
		defer func() {
			c.mu.Lock()
			delete(c.refreshLoopGroups, group)
			c.mu.Unlock()
		}()

		// we update the cache once before looping to ensure the cache is filled immediately,
		// instead of only after c.refreshTTL
		updated := c.Update(group)
		if !updated {
			logger.WithUserGroup(group).Info("cache was not updated")
		}

		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				updated = c.Update(group)
				if !updated {
					logger.WithUserGroup(group).Info("cache was not updated")
				}
			}
		}
	}()
	return true
}

// Stop halts all goroutines and waits for them to exit before returning
func (c *FillCache) Stop() {
	close(c.stopCh)
}
