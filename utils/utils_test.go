package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestUtilIntegration validates the full functionality of secrets, adding, and removing.
func TestUtilIntegration(t *testing.T) {
	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	AddSecret(hush, "")
	state, _, _ := ReadSecrets()
	fmt.Printf("%+v", state)
	if len(state) != 1 {
		t.Errorf("Unexpected Slice Length, Wanted: 1, Got: %v", len(state))
	}
	DeleteSecret("TEST")
	state, _, _ = ReadSecrets()

	if len(state) != 0 {
		t.Errorf("Unexpected Slice Length, Wanted: 0, Got: %v", len(state))
	}
}

func TestEOFKeySequenceText(t *testing.T) {
	current := eofKeySequenceText()

	if runtime.GOOS == "windows" {
		if current != "Ctrl+Z and Enter" {
			t.Errorf("Unexpected EOF key sequence text. Wanted: Ctrl+Z and Enter  Got: %v", current)
		}
	}

	if current != "Ctrl+D" {
		t.Errorf("Unexpected EOF key sequence text. Wanted: Ctrl+D Got: %v", current)
	}
}

func TestAddSecretHelper(t *testing.T) {

	// Test New Secret in New Context
	tempPath, tempPathErr := ioutil.TempDir("", "TestAddSecretHelper")
	currPath, _ := os.Getwd()

	if tempPathErr != nil {
		t.Skipf("Failed to create temporary path with error: %v", tempPathErr)
	}
	defer os.RemoveAll(tempPath)
	os.Chdir(tempPath)

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	AddSecret(hush, "")
	state, _, _ := ReadSecrets()
	fmt.Printf("%+v", state)
	if len(state) != 1 {
		t.Errorf("Unexpected Slice Length, Wanted: 1, Got: %v", len(state))
	}

	os.Chdir(currPath)

}
