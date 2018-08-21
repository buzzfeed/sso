package proxy

import (
	"testing"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func TestTemplatesCompile(t *testing.T) {
	templates := getTemplates()
	testutil.NotEqual(t, templates, nil)
}
