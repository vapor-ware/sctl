package utils

import (
	"testing"
	"time"
)

func TestUtilIntegration(t *testing.T) {
	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	AddSecret(hush)
	state := ReadSecrets()
	if len(state) != 1 {
		t.Errorf("Unexpected Slice Length, Wanted: 1, Got: %v", len(state))
	}
	DeleteSecret("TEST")
	state = ReadSecrets()

	if len(state) != 0 {
		t.Errorf("Unexpected Slice Length, Wanted: 0, Got: %v", len(state))
	}
}
