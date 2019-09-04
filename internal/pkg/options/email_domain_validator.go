package options

import (
	"fmt"
	"strings"
)

// NewEmailDomainValidator returns a function that checks whether a given email is valid based on a list
// of domains. The domain "*" is a wild card that matches any non-empty email.
func NewEmailDomainValidator(domains []string) func(string) bool {
	allowAll := false
	var emailDomains []string

	for _, domain := range domains {
		if domain == "*" {
			allowAll = true
		}
		emailDomain := fmt.Sprintf("@%s", strings.ToLower(domain))
		emailDomains = append(emailDomains, emailDomain)
	}

	if allowAll {
		return func(email string) bool { return email != "" }
	}

	return func(email string) bool {
		if email == "" {
			return false
		}
		email = strings.ToLower(email)
		for _, domain := range emailDomains {
			if strings.HasSuffix(email, domain) {
				return true
			}
		}
		return false
	}
}
