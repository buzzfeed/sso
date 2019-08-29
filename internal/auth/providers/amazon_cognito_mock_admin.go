package providers

import (
	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

// MockAdminService is an implementation of the Amazon Cognito AdminService to be used for testing
type MockCognitoAdminService struct {
	Members            []string
	Groups             []string
	MembersError       error
	GroupsError        error
	UserName           string
	UserInfoError      error
	GlobalSignOutError error
}

// ListMemberships mocks the ListMemebership function
func (ms *MockCognitoAdminService) ListMemberships(string) ([]string, error) {
	return ms.Members, ms.MembersError
}

// CheckMemberships mocks the CheckMemberships function
func (ms *MockCognitoAdminService) CheckMemberships(string) ([]string, error) {
	return ms.Groups, ms.GroupsError
}

// GlobalSignOut mocks the GlobalSignOut function
func (ms *MockCognitoAdminService) GlobalSignOut(*sessions.SessionState) error {
	return ms.GlobalSignOutError
}
