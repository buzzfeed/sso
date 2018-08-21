package providers

// MockAdminService is an implementation of AdminService to be used for testing
type MockAdminService struct {
	Members      []string
	Groups       []string
	MembersError error
	GroupsError  error
}

// GetMembers mocks the GetMembers function
func (ms *MockAdminService) GetMembers(string) ([]string, error) {
	return ms.Members, ms.MembersError
}

// GetGroups mocks the GetGroups function
func (ms *MockAdminService) GetGroups(string) ([]string, error) {
	return ms.Groups, ms.GroupsError
}
