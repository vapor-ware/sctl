package utils

/*
testing.go - A collection of test helpers, structs, and other test based utilities
*/

import "os"

// Declare a state manager, defined in state.go line 16 that will not
// induce file IO, and can be overridden with arbitrary contents
//
type testStateManager struct {
	state      []byte
	raiseError error
}

func (tsm testStateManager) ReadFile() ([]byte, error) {
	if tsm.raiseError != nil {
		return tsm.state, tsm.raiseError
	}
	return tsm.state, nil

}

func (tsm testStateManager) WriteFile(data []byte, perm os.FileMode) error {
	if tsm.raiseError != nil {
		return tsm.raiseError
	}
	return nil
}

// CreateTestStateManager - A factory method to initialize a state manager for testing purposes.
func CreateTestStateManager(data string, raiseError error) StateManager {
	tsm := testStateManager{}
	tsm.state = []byte(data)
	tsm.raiseError = raiseError
	return tsm
}
