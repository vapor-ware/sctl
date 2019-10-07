package utils

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// defaultFile default filepath when no override is presented to the state
// file that is holding the data at rest. Defaults to `$PWD/.scuttle.json`
const defaultFile = ".scuttle.json"

// StateManager is An interface to use when designing state storage routines.
// at the time of writing this is only filesystem files, but could be extended
// to support remote backends like vault, cloud-memory-store, et-al.
type StateManager interface {
	ReadState() (Secrets, error)
	WriteState(Secrets) error
}

// IOStateManager declares a state manager that uses ioutil to serialize state to disk.
type IOStateManager struct {
	filename string
}

// ReadState will de-serialize the secrets state from JSON format storage on disk.
func (ism IOStateManager) ReadState() (Secrets, error) {
	file, err := ioutil.ReadFile(ism.filename)
	// Decode the json into a slice of Secret Structs
	if err != nil {
		return nil, err
	}
	var data []Secret
	err = json.Unmarshal([]byte(file), &data)
	return data, err
}

// WriteState will Serialize secret data state to JSON on disk.
func (ism IOStateManager) WriteState(data Secrets) error {
	jsonData, _ := json.MarshalIndent(&data, "", " ")
	mode := int(0660) // file mode
	return ioutil.WriteFile(ism.filename, jsonData, os.FileMode(mode))
}

// NewIOStateManager is a factory method to initialize an IOStateManager.
func NewIOStateManager(filename string) IOStateManager {

	if len(filename) > 0 {
		return IOStateManager{filename: filename}
	}
	return IOStateManager{filename: defaultFile}
}
