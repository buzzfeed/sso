package providers

// MockAzureGraphService is an implementation of GraphService to be used for testing
type MockAzureGraphService struct {
	Groups      []string
	GroupsError error
}

// GetGroups mocks the GetGroups function
func (ms *MockAzureGraphService) GetGroups(string) ([]string, error) {
	return ms.Groups, ms.GroupsError
}
