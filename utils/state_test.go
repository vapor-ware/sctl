// +build !unit

package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestDefaultCaseFactoryIniitalizer - Test the defaults of the initializer
func TestStateManagerFactoryDefault(t *testing.T) {
	ism := NewIOStateManager("")
	assert.Equal(t, ".scuttle.json", ism.filename)
}

// Test the supported paths of IO management which should result in successful parsing of
// serialized state, and yield no errors.
func TestStateManagementReader(t *testing.T) {
	var testTable = []struct {
		name  string
		sm    StateManager
		value []string
	}{
		{"Valid Single", NewIOStateManager("../testdata/test_single.json"), []string{"CiQArcZm2NqPRMBD38xkbUt0LDB3UPKTDq9bRPmZKRTw2B3Zv/ESOAClhb3LwQupwOSMn9K/GrBKlcBRwZorSqHFrKkM0i2yXjMYRG/hDgta2x4otKuAnpoxVCSxRiNY"}},
		{"Valid Multiple", NewIOStateManager("../testdata/test_integration.json"), []string{"CiQArcZm2It07gVRIxN091iI3S88Bemz+i7YYUb1LWJKd4kj9ccSMQClhb3LXy09yZJChRqnDTq+Ql5LNNoXmByltMN6WNJlAMD/9H2MLh5/hnhLm/lpPpM=", "CiQArcZm2OMpefBMf0KlBEprYw7UvAmlJxyuOAf8+avSe5l5QdwSPQClhb3LdTfq/FFjEDs7pXT/5P5Vq/81QIJaTQtNqOr7iVivDEdSXXC0OEvGJdQUK0QlHSVjULTMa4pP1ps="}},
		// Test case for when sctl has removed all secrets, but a state file remains
		{"Valid Empty", NewIOStateManager("../testdata/test_empty.json"), nil},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			secrets, err := tt.sm.ReadState()
			assert.NoError(t, err)

			for i, sec := range secrets {
				assert.Equal(t, tt.value[i], sec.Cyphertext)
			}
		})
	}
}

func TestStateManagementWriter(t *testing.T) {
	iosm := NewIOStateManager("../testdata/test_writer_temp.json")

	err := iosm.WriteState([]Secret{
		{Name: "TEST", Cyphertext: "ABC123", Created: time.Now()},
		{Name: "TEST2", Cyphertext: "0xD34DB33F", Created: time.Now()},
	})
	assert.NoError(t, err)

	// We've written state if we got this far. Recall from disk and inspect the structure
	secrets, err := iosm.ReadState()
	assert.NoError(t, err)
	assert.Len(t, secrets, 2)
	assert.Equal(t, "TEST", secrets[0].Name)

	secrets[0].Cyphertext = "123ABC"
	err = iosm.WriteState(secrets)
	assert.NoError(t, err)

	// Recall from serialized state
	secrets, err = iosm.ReadState()
	assert.NoError(t, err)
	assert.Equal(t, "123ABC", secrets[0].Cyphertext)
}

// Validate that we have not changed our default's expectations of working with .scuttle.json if
// nothing is declared during factory init
func TestNewVersionedLoaderDefaults(t *testing.T) {
	vl := NewVersionedLoader("")
	assert.Equal(t, ".scuttle.json", vl.Filepath)
}

// TestVersionedLoader will attempt to load V1 and V2 formats of scuttle's envelopes.
func TestVersionedLoader(t *testing.T) {
	var testTable = []struct {
		name  string
		sm    VersionedLoader
		value []string
	}{
		{"V1 Valid Single", NewVersionedLoader("../testdata/test_single.json"), []string{"CiQArcZm2NqPRMBD38xkbUt0LDB3UPKTDq9bRPmZKRTw2B3Zv/ESOAClhb3LwQupwOSMn9K/GrBKlcBRwZorSqHFrKkM0i2yXjMYRG/hDgta2x4otKuAnpoxVCSxRiNY"}},
		{"V1 Valid Multiple", NewVersionedLoader("../testdata/test_integration.json"), []string{"CiQArcZm2It07gVRIxN091iI3S88Bemz+i7YYUb1LWJKd4kj9ccSMQClhb3LXy09yZJChRqnDTq+Ql5LNNoXmByltMN6WNJlAMD/9H2MLh5/hnhLm/lpPpM=", "CiQArcZm2OMpefBMf0KlBEprYw7UvAmlJxyuOAf8+avSe5l5QdwSPQClhb3LdTfq/FFjEDs7pXT/5P5Vq/81QIJaTQtNqOr7iVivDEdSXXC0OEvGJdQUK0QlHSVjULTMa4pP1ps="}},
		// Test case for when sctl has removed all secrets, but a state file remains
		{"V1 Valid Empty", NewVersionedLoader("../testdata/test_empty.json"), nil},
		{"V2 Valid Single", NewVersionedLoader("../testdata/test_secret_v2.json"), []string{"0xD34DB33F"}},
		{"V2 Valid Multiple", NewVersionedLoader("../testdata/test_secret_v2_multiple.json"), []string{"0xN00DL3S", "0xD34DB33F"}},
		{"V2 Valid Empty", NewVersionedLoader("../testdata/test_secret_v2_empty.json"), nil},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			secrets, err := tt.sm.ReadState()
			assert.NoError(t, err)

			for i, sec := range secrets.Secrets {
				assert.Equal(t, tt.value[i], sec.Cyphertext)
			}
		})
	}
}
