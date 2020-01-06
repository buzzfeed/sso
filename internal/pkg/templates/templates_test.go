package templates

import (
	"bytes"
	"strings"
	"testing"
)

func TestTemplatesCompile(t *testing.T) {

	templates := NewHTMLTemplate()
	if templates.templates == nil {
		t.Error("getTemplates() returned nil")
	}
}

func TestSignInMessage(t *testing.T) {

	testCases := []struct {
		name               string
		emailDomains       []string
		expectedSubstrings []string
	}{
		{
			name:               "single email domain",
			emailDomains:       []string{"example.com"},
			expectedSubstrings: []string{"<p>You may sign in with your <b>example.com</b> Google account.</p>"},
		},
		{
			name:               "single email that is a wildcard",
			emailDomains:       []string{"@*"},
			expectedSubstrings: []string{"<p>You may sign in with any Google account.</p>"},
		},
		{
			name:         "multiple email domains",
			emailDomains: []string{"foo.com", "bar.com"},
			expectedSubstrings: []string{
				"You may sign in with any of these Google accounts:<br>",
				"<b>foo.com</b>, <b>bar.com</b>",
			},
		},
		// TODO: should we reject this configuration? We don't really expect
		// multiple email domains that also use wildcards, so we don't have
		// special handling for this case in the templates.
		{
			name:         "multiple email domains including a wildcard",
			emailDomains: []string{"*", "foo.com", "bar.com"},
			expectedSubstrings: []string{
				"You may sign in with any of these Google accounts:<br>",
				"<b>*</b>, <b>foo.com</b>, <b>bar.com</b>",
			},
		},
	}

	templates := NewHTMLTemplate()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			ctx := struct {
				ProviderSlug string
				EmailDomains []string
			}{
				ProviderSlug: "Google",
				EmailDomains: tc.emailDomains,
			}
			templates.ExecuteTemplate(buf, "sign_in_message.html", ctx)
			result := buf.String()

			for _, substring := range tc.expectedSubstrings {
				if !strings.Contains(result, substring) {
					t.Errorf("substring %#v not found in rendered template:\n%s", substring, result)
				}
			}
		})
	}
}
