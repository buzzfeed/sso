package groups

import (
	"time"

	"github.com/datadog/datadog-go/statsd"
	"golang.org/x/sync/syncmap"
)

// NewLocalCache returns a LocalCache instance
func NewLocalCache(
	ttl time.Duration,
	statsdClient *statsd.Client,
	tags []string,
) *LocalCache {
	return &LocalCache{
		ttl:            ttl,
		localCacheData: &syncmap.Map{},
		metrics:        statsdClient,
		tags:           tags,
	}
}

type LocalCache struct {
	// Cache configuration
	ttl     time.Duration
	metrics *statsd.Client
	tags    []string

	// Cache data
	localCacheData *syncmap.Map
}

// Cachekey defines the key used to store the data in the cache.
type CacheKey struct {
	Email         string
	AllowedGroups string
}

// CacheEntry defines the data we want to store in the cache.
type CacheEntry struct {
	ValidGroups []string
}

// get will attempt to retrieve an entry from the cache at the given key
func (lc *LocalCache) get(key CacheKey) (CacheEntry, bool) {
	val, ok := lc.localCacheData.Load(key)
	if ok {
		return val.(CacheEntry), ok
	}

	return CacheEntry{}, false
}

// set will attempt to set an entry in the cache to a given key
// for the prescribed TTL
func (lc *LocalCache) set(key CacheKey, data CacheEntry) {
	lc.localCacheData.Store(key, data)

	// Spawn the TTL cleanup goroutine if a TTL is set
	if lc.ttl > 0 {
		go func(key CacheKey) {
			<-time.After(lc.ttl)
			lc.Purge(key)
		}(key)
	}
}

// Get retrieves a key from a local cache. If found, it will create and return an
// 'Entry' using the returned values. If not found, it will return an empty 'Entry'
func (lc *LocalCache) Get(key CacheKey) (CacheEntry, bool) {
	val, ok := lc.get(key)
	if ok {
		lc.metrics.Incr("localcache.hit", lc.tags, 1.0)
		return val, ok
	}

	lc.metrics.Incr("localcache.miss", lc.tags, 1.0)
	return CacheEntry{}, false
}

// Set will set an entry within the current cache
func (lc *LocalCache) Set(key CacheKey, entry CacheEntry) {
	lc.metrics.Incr("localcache.set", lc.tags, 1.0)
	lc.set(key, entry)
}

// Purge will remove a set of keys from the local cache map
func (lc *LocalCache) Purge(key CacheKey) {
	lc.metrics.Incr("localcache.purge", lc.tags, 1.0)
	lc.localCacheData.Delete(key)
}
