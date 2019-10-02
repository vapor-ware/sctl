package utils

import (
	"io/ioutil"
	"log"
	"os"
	"time"
)

// defaultScuttleFile - Constant default when no override is presented
// for which file is holding the data at rest. Defaults to `PWD/.scuttle.json`
const defaultFile = ".scuttle.json"

// Secret contains data and metadata related to a scuttle-managed secret.
//
// An example JSON-serialized secret:
//
//    {
//      "name": "A_SECRET",
//      "cypher": "0xD34DB33F",
//      "created": "2019-05-01 13:01:27.189242799 -0500 CDT m=+0.000075907",
//      "encoding": "plain"
//     }
type Secret struct {
	Name       string    `json:"name"`
	Cyphertext string    `json:"cypher"`
	Created    time.Time `json:"created"`
	Encoding   string    `json:"encoding"`
}

// IOStateManager - Declare a state manager that uses ioutil to actually invoke file IO.
// subscribes to the interface declared in state.go line 16, and is not consumed when testing
// so we can skip the disk IO and keep tests fast.
type IOStateManager struct {
	filename string
}

// ReadFile - Invoke the ioutil read file method, to serialize our data to disk.
func (ism IOStateManager) ReadFile() ([]byte, error) {
	file, err := ioutil.ReadFile(ism.filename)

	return file, err
}

// WriteFile -
func (ism IOStateManager) WriteFile(data []byte, perm os.FileMode) error {
	err := ioutil.WriteFile(ism.filename, data, perm)

	if err != nil {
		log.Fatal(err)
	}
	return err
}

// CreateIOStateManager - a factory method to initialize an IOStateManager.
func CreateIOStateManager(filename string) IOStateManager {

	if len(filename) > 0 {
		return IOStateManager{filename: filename}
	}
	return IOStateManager{filename: defaultFile}

}
