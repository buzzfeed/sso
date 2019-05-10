package groups

import (
	"reflect"
	"testing"
	"time"

	//"github.com/cactus/go-statsd-client/statsd/statsdtest"
	"github.com/datadog/datadog-go/statsd"
	//"github.com/cactus/go-statsd-client/statsd"
)

func TestNotAvailableAfterTTL(t *testing.T) {
	// Create a cache with a 10 millisecond TTL
	statsdClient, _ := statsd.New("127.0.0.1:8125")
	cache := NewLocalCache(time.Millisecond*10, statsdClient, []string{"test_case"})

	// Create a cache Key and Entry and insert it into the cache
	cacheKey := CacheKey{
		Email:         "email@test.com",
		AllowedGroups: "testGroup",
	}
	cacheData := CacheEntry{
		ValidGroups: []string{"testGroup"},
	}
	cache.Set(cacheKey, cacheData)

	// Check the cached entry can be retrieved from the cache.
	if data, _ := cache.Get(cacheKey); !reflect.DeepEqual(data, cacheData) {
		t.Logf("     expected data to be '%+v'", cacheData)
		t.Logf("actual data returned was '%+v'", data)
		t.Fatalf("unexpected data returned")
	}

	// If we wait 10ms (or lets say, 50 for good luck), it will have been removed
	time.Sleep(time.Millisecond * 50)

	if _, found := cache.get(cacheKey); found {
		t.Fatalf("expected key not to be have been found after the TTL expired")
	}
}

func TestNotAvailableAfterPurge(t *testing.T) {
	statsdClient, _ := statsd.New("127.0.0.1:8125")
	cache := NewLocalCache(time.Duration(10)*time.Second, statsdClient, []string{"test_case"})

	// Create a cache Key and Entry and insert it into the cache
	cacheKey := CacheKey{
		Email:         "email@test.com",
		AllowedGroups: "testGroup",
	}
	cacheData := CacheEntry{
		ValidGroups: []string{"testGroup"},
	}
	cache.Set(cacheKey, cacheData)

	// Check the cached entry can be retrieved from the cache.
	if data, _ := cache.Get(cacheKey); !reflect.DeepEqual(data, cacheData) {
		t.Logf("     expected data to be '%+v'", cacheData)
		t.Logf("actual data returned was '%+v'", data)
		t.Fatalf("unexpected data returned")
	}

	cache.Purge(cacheKey)

	// Purge should have removed the entry, despite being within the cache TTL
	if _, found := cache.get(cacheKey); found {
		t.Fatalf("expected key not to be have been found after purging")
	}
}
