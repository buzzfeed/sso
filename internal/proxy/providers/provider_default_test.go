package providers

import (
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func TestRefresh(t *testing.T) {
	p := &ProviderData{}
	refreshed, err := p.RefreshSession(&SessionState{
		RefreshDeadline: time.Now().Add(time.Duration(-11) * time.Minute),
	},
		[]string{},
	)
	testutil.Equal(t, false, refreshed)
	testutil.Equal(t, nil, err)
}
