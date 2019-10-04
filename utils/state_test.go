// +build !unit

package utils

import (
	"testing"
	"time"
)

// TestDefaultCaseFactoryIniitalizer - Test the defaults of the initiializer
func TestStateManagerFactoryDefault(t *testing.T) {
	ism := NewIOStateManager("")

	if ism.filename != ".scuttle.json" {
		t.Fatalf("Error in default IOStateManager factory filename. Wanted:  .scuttle.json  Got: %s", ism.filename)
	}
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

			if err != nil {
				t.Errorf("Case %s - Expected nil, got %s", tt.name, err)
			}
			for i, sec := range secrets {
				if sec.Cyphertext != tt.value[i] {
					t.Errorf("Expected Cyphertext value %s but got %s", tt.value, sec.Cyphertext)
				}
			}

		})
	}
}

func TestStateManagementWriter(t *testing.T) {
	iosm := NewIOStateManager("../testdata/test_writer_temp.json")

	iosm.WriteState([]Secret{
		Secret{Name: "TEST", Cyphertext: "ABC123", Created: time.Now()},
		Secret{Name: "TEST2", Cyphertext: "0xD34DB33F", Created: time.Now()},
	})

	// We've written state if we got this far. Recall from disk and inspect the structure
	secrets, err := iosm.ReadState()
	if err != nil {
		t.Errorf("Unexpected error. Wanted nil Got %s", err)
	}

	if len(secrets) != 2 {
		t.Errorf("Unexpected Deserialize Length: Wanted 2, Got %v", len(secrets))
	}

	if secrets[0].Name != "TEST" {
		t.Errorf("Unexpected positional secret name. Wanted TEST Got %s", secrets[0].Name)
	}

	// Cache the value for comparison
	firstSecretCypher := secrets[0].Cyphertext
	secrets[0].Cyphertext = "123ABC"
	iosm.WriteState(secrets)
	// Recall from serialized state
	secrets, err = iosm.ReadState()
	if err != nil {
		t.Errorf("Unexpected error. Wanted nil Got %s", err)
	}

	if secrets[0].Cyphertext == firstSecretCypher {
		t.Errorf("Expected Rotation failed, Wanted: 123ABC, Got %s", secrets[0].Cyphertext)
	}

}

// func TestIOStateManagerRead(t *testing.T) {
// 	iosm := NewIOStateManager("../testdata/scuttle_integration.json")

// 	secrets, err := iosm.ReadState()
// 	if err != nil {
// 		t.Fatalf("Unexpected error, Expected: nil Got: %s", err)
// 	}

// 	if len(secrets) != 2 {
// 		t.Fatalf("Unexpected Length. Expected: 2  Got: %v", len(secrets))
// 	}

// 	if secrets[1].Name != "DOUBLEMINT" {
// 		t.Fatalf("Unexpected secret - Expected: DOUBLEMINT  Got: %s", secrets[1].Name)
// 	}
// }
