package providers

// MockMSGraphService is an implementation of GraphService to be used for testing
type MockMSGraphService struct {
	Groups      []string
	GroupsError error
}

// GetGroups mocks the GetGroups function
func (ms *MockMSGraphService) GetGroups(string) ([]string, error) {
	return ms.Groups, ms.GroupsError
}
