package groups

import (
	"fmt"
	"testing"
	"time"
)

func testFillFunc(members MemberSet, fillError error) func(string) (MemberSet, error) {
	return func(string) (MemberSet, error) {
		return members, fillError
	}
}

func TestFillCacheUpdate(t *testing.T) {
	testCases := []struct {
		name      string
		members   MemberSet
		fillError error
		updated   bool
	}{
		{
			name:    "successful update to empty cache",
			members: MemberSet{"a": {}, "b": {}, "c": {}},
			updated: true,
		},
		{
			name:      "unsuccessful update to cache",
			fillError: fmt.Errorf("fill error"),
			updated:   false,
		},
		{
			name:      "group removed if it can't be found",
			members:   MemberSet{"a": {}, "b": {}},
			fillError: ErrGroupNotFound,
			updated:   false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fillCache := NewFillCache(testFillFunc(tc.members, tc.fillError), time.Hour)
			defer fillCache.Stop()
			cacheKey := "groupKeyA"

			// ("group removed if it can't be found")
			// In order to test a group is removed from the cache if it can't be found, we
			// fill the cache, check the group is present, then update the cache before checking
			// the key has been removed
			if tc.fillError == ErrGroupNotFound {
				temporaryCacheKey := "groupKeyB"
				// add two cache keys, one of which should be deleted, one should not
				fillCache.cache[cacheKey] = tc.members
				fillCache.cache[temporaryCacheKey] = tc.members

				if _, ok := fillCache.Get(temporaryCacheKey); !ok {
					t.Errorf("cache should contain %q, but it does not", temporaryCacheKey)
				}

				// this should error with `ErrGroupNotFound`, causing the key to be removed
				if ok := fillCache.Update(temporaryCacheKey); ok != tc.updated {
					t.Errorf("expected updated to be %v but was %v", tc.updated, ok)
				}

				if val, ok := fillCache.Get(temporaryCacheKey); ok {
					t.Errorf("expected group to not be present in cache, but found %q", val)
				}
			}

			ok := fillCache.Update(cacheKey)
			if tc.updated != ok {
				t.Errorf("expected updated to be %v but was %v", tc.updated, ok)
			}

			// as well as checking the key is actually in the cache when it should be, this also tests that
			// unrelated groups aren't deleted when another group can't be found within the "group removed if it can't be found" test
			if tc.updated == true || tc.fillError == ErrGroupNotFound {
				_, ok = fillCache.Get(cacheKey)
				if ok != tc.updated {
					t.Errorf("cache should contain %q, but it does not", cacheKey)
				}
			}

		})
	}
}

func TestRefreshLoop(t *testing.T) {
	testCases := []struct {
		name              string
		refreshLoopGroups map[string]struct{}
		expectedStarted   bool
	}{
		{
			name:            "empty inflight and empty cache starts a refresh loop",
			expectedStarted: true,
		},
		{
			name:              "inflight update does not start refresh loop",
			refreshLoopGroups: map[string]struct{}{"group1": {}},
			expectedStarted:   false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fillCache := NewFillCache(testFillFunc(MemberSet{"a": {}}, nil), time.Hour)
			if tc.refreshLoopGroups != nil {
				fillCache.refreshLoopGroups = tc.refreshLoopGroups
			}

			started := fillCache.RefreshLoop("group1")

			if tc.expectedStarted != started {
				t.Errorf("expected started to be %v but was %v", tc.expectedStarted, started)
			}

			if tc.expectedStarted {
				// wait briefly to allow the cache to be updated
				time.Sleep(50 * time.Millisecond)
				_, ok := fillCache.Get("group1")
				if !ok {
					t.Errorf("expected the group cache to be updated immediately")
				}
			}

		})
	}

}
