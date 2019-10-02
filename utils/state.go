package utils

import (
	"encoding/json"
	"os"
)

// StateManager - An interface to use when stubbing
// the filesystem operations. Implements the method signatures
// from ioutil. see structs.go - IOStateManager for a reference
// implementation
type StateManager interface {
	ReadFile() ([]byte, error)
	WriteFile(data []byte, perm os.FileMode) error
}

// ReadState -
func ReadState(sm StateManager) ([]Secret, error) {
	file, err := sm.ReadFile()
	// The file wont be present on first run and its not worth raising this
	// situation to the users attention. Instead when we encounter file IO
	// issues with our state file (for now), we'll default to returning an empty
	// secrets array.
	// TODO: Make this raise an error on everything but FileNotFound
	if err != nil {
		return []Secret{}, err
	}

	// Decode the json into a slice of Secret Structs
	var data []Secret
	err = json.Unmarshal([]byte(file), &data)
	return data, err
}

// WriteState -
func WriteState(sm StateManager, data []Secret) error {
	jsonData, _ := json.MarshalIndent(&data, "", " ")
	mode := int(0660) // file mode
	err := sm.WriteFile(jsonData, os.FileMode(mode))
	return err
}
