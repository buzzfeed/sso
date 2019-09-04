package options

import (
	"fmt"
	"strings"
)

// NewEmailAddressValidator returns a function that checks whether a given email is valid based on a list
// of email addresses. The address "*" is a wild card that matches any non-empty email.
func NewEmailAddressValidator(emails []string) func(string) bool {
	allowAll := false
	var emailAddresses []string

	for _, email := range emails {
		if email == "*" {
			allowAll = true
		}
		emailAddress := fmt.Sprintf("%s", strings.ToLower(email))
		emailAddresses = append(emailAddresses, emailAddress)
	}

	if allowAll {
		return func(email string) bool { return email != "" }
	}

	return func(email string) bool {
		if email == "" {
			return false
		}
		email = strings.ToLower(email)
		for _, emailItem := range emailAddresses {
			if email == emailItem {
				return true
			}
		}
		return false
	}
}
