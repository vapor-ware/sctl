package utils

import (
	"encoding/json"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
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
		if os.IsNotExist(err) {
			// The file doesn't exist, dont raise an error and return empty data to account
			// for first-run without a state serialized to disk.
			return []Secret{}, nil
		}
		return nil, err
	}
	var data []Secret
	err = json.Unmarshal([]byte(file), &data)
	return data, err
}

// WriteState will Serialize secret data state to JSON on disk.
func (ism IOStateManager) WriteState(data Secrets) error {
	jsonData, err := json.MarshalIndent(&data, "", " ")
	if err != nil {
		return err
	}
	log.Debug(string(jsonData))
	return ioutil.WriteFile(ism.filename, jsonData, os.FileMode(0660))
}

// NewIOStateManager is a factory method to initialize an IOStateManager.
func NewIOStateManager(filename string) IOStateManager {
	if len(filename) > 0 {
		return IOStateManager{filename: filename}
	}
	return IOStateManager{filename: defaultFile}
}

// VersionedLoader recalls V2 structs from serialized json on disk
type VersionedLoader struct {
	Filepath string
}

// ReadState Attempts to deserialize a V2 secret envelope. If it encounters an error unmarshalling
// the data structure, it will fall back and attempt to initialize a new V2 secret envelope, and populate
// with what we presume to be a V1 format. If that fails, we fail fatally.
func (vl VersionedLoader) ReadState() (V2, error) {
	data, err := ioutil.ReadFile(vl.Filepath)
	if err != nil {
		return V2{}, err
	}
	var envelope V2
	err = json.Unmarshal(data, &envelope)
	if err != nil {
		// Try loading from V1 into this struct as a fallback case
		log.Debug("Falling back to V1 parser")
		ism := NewIOStateManager(vl.Filepath)
		finalAttempt, werr := ism.ReadState()
		if werr != nil {
			return V2{}, werr
		}
		envelope.Secrets = finalAttempt
		return envelope, nil
	}
	return envelope, nil
}

// NewVersionedLoader is a factory method to instantiate new VersionedLoaders consistently.
// if no filepath is provided, it will default to ".scuttle.json"
func NewVersionedLoader(filepath string) VersionedLoader {
	if filepath == "" {
		filepath = defaultFile
	}
	return VersionedLoader{
		Filepath: filepath,
	}
}
