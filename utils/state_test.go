package utils

import (
	"errors"
	"testing"
)

// Valid json serialized state
var validJSON = `[
	{
	 "name": "TEST",
	 "cypher": "CiQArcZm2NqPRMBD38xkbUt0LDB3UPKTDq9bRPmZKRTw2B3Zv/ESOAClhb3LwQupwOSMn9K/GrBKlcBRwZorSqHFrKkM0i2yXjMYRG/hDgta2x4otKuAnpoxVCSxRiNY",
	 "created": "2019-09-30T12:19:20.797374136-05:00",
	 "encoding": "base64"
	}
   ]`

// Valid Json Many
var validManyJSON = `[
 {
  "name": "TEST",
  "cypher": "CiQArcZm2NqPRMBD38xkbUt0LDB3UPKTDq9bRPmZKRTw2B3Zv/ESOAClhb3LwQupwOSMn9K/GrBKlcBRwZorSqHFrKkM0i2yXjMYRG/hDgta2x4otKuAnpoxVCSxRiNY",
  "created": "2019-09-30T12:19:20.797374136-05:00",
  "encoding": "base64"
 },
 {
  "name": "TEST2",
  "cypher": "CiQArcZm2JwpsNvf4q9Xbyx2nfMfhs/+TqWNnqZpFDD7o+QZ6fESNQClhb3LRJmvtCS481wCu1yWtq2M7eRHQx0Aj3xL3EHJwEexT2CZGXSZIBlQrfFI7QG07zPS",
  "created": "2019-09-30T15:42:25.872448036-05:00",
  "encoding": "base64"
 }
]`

// missing the closing bracket
var invalidJSON = `[
	{
	 "name": "TEST",
	 "cypher": "CiQArcZm2NqPRMBD38xkbUt0LDB3UPKTDq9bRPmZKRTw2B3Zv/ESOAClhb3LwQupwOSMn9K/GrBKlcBRwZorSqHFrKkM0i2yXjMYRG/hDgta2x4otKuAnpoxVCSxRiNY",
	 "created": "2019-09-30T12:19:20.797374136-05:00",
	 "encoding": "base64"
	}
`

// valid JSON, no data.
var emptyJSON = `[{}]`

// test table
var validStateTests = []struct {
	name  string
	sm    StateManager
	value []string
}{
	{"valid json", CreateTestStateManager(validJSON, nil), []string{"CiQArcZm2NqPRMBD38xkbUt0LDB3UPKTDq9bRPmZKRTw2B3Zv/ESOAClhb3LwQupwOSMn9K/GrBKlcBRwZorSqHFrKkM0i2yXjMYRG/hDgta2x4otKuAnpoxVCSxRiNY"}},
	{"valid json many", CreateTestStateManager(validManyJSON, nil), []string{"CiQArcZm2NqPRMBD38xkbUt0LDB3UPKTDq9bRPmZKRTw2B3Zv/ESOAClhb3LwQupwOSMn9K/GrBKlcBRwZorSqHFrKkM0i2yXjMYRG/hDgta2x4otKuAnpoxVCSxRiNY", "CiQArcZm2JwpsNvf4q9Xbyx2nfMfhs/+TqWNnqZpFDD7o+QZ6fESNQClhb3LRJmvtCS481wCu1yWtq2M7eRHQx0Aj3xL3EHJwEexT2CZGXSZIBlQrfFI7QG07zPS"}},
	{"emtpy set json", CreateTestStateManager(emptyJSON, nil), []string{""}},
}

// test-table runner
func TestStateManagement(t *testing.T) {
	for _, tt := range validStateTests {
		t.Run(tt.name, func(t *testing.T) {
			secrets, err := ReadState(tt.sm)

			if err != nil {
				t.Fatalf("Expected no errors, got %s", err)
			}
			for i, sec := range secrets {
				if sec.Cyphertext != tt.value[i] {
					t.Fatalf("Expected Cyphertext value %s but got %s", tt.value, sec.Cyphertext)
				}
			}

		})
	}
}

// test table
var invalidStateTests = []struct {
	name string
	in   StateManager
}{
	{"invalid json", CreateTestStateManager(invalidJSON, nil)},
	{"valid json fopen error", CreateTestStateManager(validJSON, errors.New("open .scuttle.json permission denied"))},
}

// test-table runner
func TestInvalidStateManagement(t *testing.T) {
	for _, tt := range invalidStateTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadState(tt.in)

			if err == nil {
				t.Fatalf("%s : Expected an error, got nil", tt.name)
			}
		})
	}
}

// test table
var validStateWriterTests = []struct {
	name string
	sm   StateManager
	data []Secret
}{
	{"valid json", CreateTestStateManager(validJSON, nil), []Secret{
		Secret{
			Name:       "Test1",
			Cyphertext: "CiQArcZm2NqPRMBD38xkbUt0LDB3UPKTDq9bRPmZKRTw2B3Zv/ESOAClhb3LwQupwOSMn9K/GrBKlcBRwZorSqHFrKkM0i2yXjMYRG/hDgta2x4otKuAnpoxVCSxRiNY",
			Encoding:   "base64",
		},
	}},
	{"emtpy set json", CreateTestStateManager(emptyJSON, nil), []Secret{}},
}

func TestStateManagementWriter(t *testing.T) {
	for _, tt := range validStateWriterTests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteState(tt.sm, tt.data)
			if err != nil {
				t.Fatalf("Expected no error, received %s", err)
			}
		})
	}
}

var errantStateWriterTests = []struct {
	name string
	sm   StateManager
}{
	{"write fopen error", CreateTestStateManager(emptyJSON, errors.New("permission denied"))},
}

func TestStateManagementWriterErrors(t *testing.T) {
	for _, tt := range errantStateWriterTests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteState(tt.sm, nil)
			if err == nil {
				t.Fatalf("%s - Expected error, received nil", tt.name)
			}
		})
	}
}
