package providers

// MockAdminService is an implementation of AdminService to be used for testing
type MockAdminService struct {
	Members      []string
	Groups       []string
	MembersError error
	GroupsError  error
}

// ListMemberships mocks the ListMemebership function
func (ms *MockAdminService) ListMemberships(string, int) ([]string, error) {
	return ms.Members, ms.MembersError
}

// CheckMemberships mocks the CheckMemberships function
func (ms *MockAdminService) CheckMemberships([]string, string) ([]string, error) {
	return ms.Groups, ms.GroupsError
}
