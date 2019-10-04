package utils

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// defaultScuttleFile - Constant default when no override is presented
// for which file is holding the data at rest. Defaults to `$PWD/.scuttle.json`
const defaultFile = ".scuttle.json"

// StateManager - An interface to use when stubbing
// the filesystem operations. Implements the method signatures
// from ioutil. see structs.go - IOStateManager for a reference
// implementation
type StateManager interface {
	ReadState() (Secrets, error)
	WriteState(Secrets) error
}

// IOStateManager - Declare a state manager that uses ioutil to actually invoke file IO.
// subscribes to the interface declared in state.go line 16, and is not consumed when testing
// so we can skip the disk IO and keep tests fast.
type IOStateManager struct {
	filename string
}

// ReadState - de-serialize the secrets state from JSON format storage on disk.
func (ism IOStateManager) ReadState() (Secrets, error) {
	file, err := ioutil.ReadFile(ism.filename)
	// Decode the json into a slice of Secret Structs
	var data []Secret
	err = json.Unmarshal([]byte(file), &data)
	return data, err
}

// WriteState - Serialize secret data state to JSON on disk.
func (ism IOStateManager) WriteState(data Secrets) error {
	jsonData, _ := json.MarshalIndent(&data, "", " ")
	mode := int(0660) // file mode
	err := ioutil.WriteFile(ism.filename, jsonData, os.FileMode(mode))

	return err
}

// NewIOStateManager - a factory method to initialize an IOStateManager.
func NewIOStateManager(filename string) IOStateManager {

	if len(filename) > 0 {
		return IOStateManager{filename: filename}
	}
	return IOStateManager{filename: defaultFile}
}
