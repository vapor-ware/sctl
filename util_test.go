package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/stretchr/testify/assert"
)

// Convenience fixture to init the secret seed for tests
var fixture = Secret{
	Name:       "A_SECRET",
	Cyphertext: "abc==",
	Created:    time.Now(),
}

// Test that secrets are appended
func TestAddSecret_NoRotation(t *testing.T) {
	patch := monkey.Patch(ReadSecrets, func() []Secret {
		return []Secret{fixture}
	})
	patchWriter := monkey.Patch(WriteSecrets, func(secrets []Secret) {
		assert.Len(t, secrets, 2)
	})

	defer patch.Unpatch()
	defer patchWriter.Unpatch()

	to_add := Secret{
		Name:       "TEST_TO_ADD",
		Cyphertext: "abc==",
		Created:    time.Now(),
	}

	AddSecret(to_add)
}

// Test that secrets are upserted
func TestAddSecret_WithRotation(t *testing.T) {

	patch := monkey.Patch(ReadSecrets, func() []Secret {
		return []Secret{fixture}
	})
	patchWriter := monkey.Patch(WriteSecrets, func(secrets []Secret) {
		assert.Len(t, secrets, 1)
		assert.Equal(t, secrets[0].Cyphertext, "xyz==")
	})
	patchLogger := monkey.Patch(log.Printf, func(message string, opt ...interface{}) {
		assert.Equal(t, message, "Rotating entry %s")
	})

	defer patch.Unpatch()
	defer patchWriter.Unpatch()
	defer patchLogger.Unpatch()

	to_add := Secret{
		Name:       "A_SECRET",
		Cyphertext: "xyz==",
		Created:    time.Now(),
	}

	AddSecret(to_add)
}

// Test secret removal actually removes a secret
func TestRmSecret_Exists(t *testing.T) {

	patch := monkey.Patch(ReadSecrets, func() []Secret {
		return []Secret{fixture}
	})
	patchWriter := monkey.Patch(WriteSecrets, func(secrets []Secret) {
		assert.Len(t, secrets, 0)
	})
	patchLogger := monkey.Patch(log.Printf, func(message string, opt ...interface{}) {
		assert.Equal(t, message, "Removing entry %s")
	})

	defer patch.Unpatch()
	defer patchWriter.Unpatch()
	defer patchLogger.Unpatch()

	RmSecret("A_SECRET")
}

// Test that removing a secret that does not exist does nothing to the
// output state file
func TestRmSecret_NotExists(t *testing.T) {

	patch := monkey.Patch(ReadSecrets, func() []Secret {
		return []Secret{fixture}
	})
	patchWriter := monkey.Patch(WriteSecrets, func(secrets []Secret) {
		assert.Len(t, secrets, 1)
	})

	defer patch.Unpatch()
	defer patchWriter.Unpatch()

	RmSecret("ANOTHER_SECRET")
}

// Read the secrets from a file, and validate we have a slice of secrets
func TestReadSecrets_ValidJson(t *testing.T) {
	valid_json := `[{"name": "A_SECRET","cypher": "abc==", "created": "2019-07-18T09:56:53.76993767-05:00"}]`

	patch := monkey.Patch(ioutil.ReadFile, func(filename string) ([]byte, error) {
		return []byte(valid_json), nil
	})

	defer patch.Unpatch()

	foo := ReadSecrets()
	assert.Len(t, foo, 1)
	assert.Equal(t, foo[0].Name, "A_SECRET")
}

// Test a malformed json file. As intercepting log.Fatal is hard, all I'll check
// for is the presence of an error
func TestReadSecrets_InvalidJson(t *testing.T) {
	valid_json := `[{"name": "A_SECRET" "cypher": "abc==", "created": "2019-07-18T09:56:53.76993767-05:00"}]`

	patch := monkey.Patch(ioutil.ReadFile, func(filename string) ([]byte, error) {
		return []byte(valid_json), nil
	})

	fakeLogFatal := func(msg ...interface{}) {
		// Check for the presence of an error, i guess.
		assert.NotNil(t, msg)
		assert.IsType(t, &json.SyntaxError{}, msg[0])
	}

	logPatch := monkey.Patch(log.Fatal, fakeLogFatal)

	defer patch.Unpatch()
	defer logPatch.Unpatch()

	ReadSecrets()

}

func TestWriteSecrets(t *testing.T) {

	// just ensure that our written data looks exactly like what
	// we format here to prevent disruption to the format on future
	// iterations. not the most robust test, but accomplishes the idea
	bytes, _ := json.MarshalIndent([]Secret{fixture}, "", " ")

	patch := monkey.Patch(ioutil.WriteFile, func(filename string, data []byte, perm os.FileMode) error {
		assert.Equal(t, data, bytes)

		// presumed file path and modes
		assert.Equal(t, filename, ".scuttle.json")
		assert.Equal(t, perm, os.FileMode(0660))

		return nil
	})

	defer patch.Unpatch()

	WriteSecrets([]Secret{fixture})
}
