package providers

import (
	"testing"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func TestStripTokenNotPresent(t *testing.T) {
	test := "http://local.test/api/test?a=1&b=2"
	testutil.Equal(t, test, stripToken(test))
}

func TestStripToken(t *testing.T) {
	test := "http://local.test/api/test?access_token=deadbeef&b=1&c=2"
	expected := "http://local.test/api/test?access_token=dead...&b=1&c=2"
	testutil.Equal(t, expected, stripToken(test))
}
