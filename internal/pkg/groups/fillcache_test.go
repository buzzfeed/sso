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
		name          string
		members       MemberSet
		fillError     error
		updated       bool
		expectedError bool
	}{
		{
			name:    "update to empty cache, no fill errors",
			members: MemberSet{"a": {}, "b": {}, "c": {}},
			updated: true,
		},
		{
			name:          "update with fill function error",
			fillError:     fmt.Errorf("fill error"),
			expectedError: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fillCache := NewFillCache(testFillFunc(tc.members, tc.fillError), time.Hour)
			defer fillCache.Stop()
			ok, err := fillCache.Update("groupKey")
			if err == nil && tc.expectedError {
				t.Errorf("expected error but err was nil")
			}
			if err != nil && !tc.expectedError {
				t.Errorf("unexpected error %s", err)
			}
			if tc.updated != ok {
				t.Errorf("expected updated to be %v but was %v", tc.updated, ok)
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

		})
	}

}
