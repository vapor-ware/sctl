package utils

import (
	"testing"
	"time"
)

// test table
var base64DecodeTests = []struct {
	name    string
	encoded string
	decoded string
}{
	{"simple decode", "dGVzdDEyMzQ=", "test1234"},
	{"multi-line decode", "dGVzdCAxCnRlc3QgMgp0ZXN0IDMK",
		`test 1
test 2
test 3
`},
}

func TestB64Decode(t *testing.T) {
	for _, tt := range base64DecodeTests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := b64Decode([]byte(tt.encoded))
			if err != nil {
				t.Fatalf("Expected no error, received %s", err)
			}
			if string(result) != tt.decoded {
				t.Fatalf("Value Mismatch. Expected: \n %s \n Got: \n %s", tt.decoded, string(result))
			}
		})
	}
}

// test table
var base64EncodeTests = []struct {
	name     string
	toEncode string
	encoded  string
}{
	{"single line encoding", "test1234", "dGVzdDEyMzQ="},
	{"multi-line encoding", `test 1
test2
test3`, "dGVzdCAxCnRlc3QyCnRlc3Qz"},
}

func TestB64Encode(t *testing.T) {
	for _, tt := range base64EncodeTests {
		t.Run(tt.name, func(t *testing.T) {
			result := b64Encode([]byte(tt.toEncode))

			if string(result) != tt.encoded {
				t.Fatalf("Value Mismatch. Expected: \n %s \n Got: \n %s", tt.encoded, string(result))
			}
		})
	}
}

func TestUpsertSecret(t *testing.T) {
	s := Secret{
		Name:       "TESTSECRET",
		Cyphertext: "ABC123",
		Created:    time.Now(),
		Encoding:   "base64",
	}

	// Test insert
	secrets := UpsertSecret([]Secret{}, s)

	if len(secrets) <= 0 {
		t.Fatalf("Expected len of 1, got 0")
	}
	if secrets[0].Name != "TESTSECRET" {
		t.Fatalf("Expected singular entry TESTSECRET, got %s", secrets[0].Name)
	}

	// Test Upsert
	s.Cyphertext = "123ABC"
	newsecrets := UpsertSecret(secrets, s)

	if len(newsecrets) <= 0 {
		t.Fatalf("Expected len of 1, got 0")
	}
	if newsecrets[0].Name != "TESTSECRET" {
		t.Fatalf("Expected singular entry TESTSECRET, got %s", secrets[0].Name)
	}
	if newsecrets[0].Cyphertext != "123ABC" {
		t.Fatalf("Unexpected Cyphertext. Rotation presumed failed. Expected: %s got %s", "123ABC", newsecrets[0].Cyphertext)
	}
}

func TestRmSecret(t *testing.T) {
	secrets := []Secret{
		Secret{
			Name:       "TEST",
			Cyphertext: "ABC123",
			Created:    time.Now(),
			Encoding:   "base64",
		},
		Secret{
			Name:       "DOUBLEMINT",
			Cyphertext: "ABC123",
			Created:    time.Now(),
			Encoding:   "base64",
		},
	}

	modified := RmSecret(secrets, "TEST")

	if len(modified) != 1 {
		t.Fatalf("Unexpected length of data, expected 1, got: %v", len(modified))
	}

	if modified[0].Name != "DOUBLEMINT" {
		t.Fatalf("Expected secret DOUBLEMENT, GOT: %s", modified[0].Name)
	}
}
