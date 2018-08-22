package templates

import (
	"encoding/json"
	"io"
)

// MockTemplate mocks the template interface wrapper
type MockTemplate struct{}

// ExecuteTemplate write the data to the io.Writer
func (mt *MockTemplate) ExecuteTemplate(rw io.Writer, path string, data interface{}) {
	jsonBytes, _ := json.Marshal(data)
	rw.Write(jsonBytes)
}
