package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"testing"
	"time"
)

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

// Test the complex function of the AddSecret helper method in a temporary path to ensure
// we have validated the "from scratch" use case.
func TestAddSecretHelper(t *testing.T) {

	// Test New Secret in New Context
	tempPath, tempPathErr := ioutil.TempDir("", "TestAddSecretHelper")
	currPath, _ := os.Getwd()
	t.Logf("Using temporary path %v", tempPath)
	if tempPathErr != nil {
		t.Skipf("Failed to create temporary path with error: %v", tempPathErr)
	}
	defer os.RemoveAll(tempPath)
	os.Chdir(tempPath)

	currWD, _ := os.Getwd()
	t.Logf("In current path %v", currWD)
	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	AddSecret(hush, "", true)
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

	// Now rotate Hush so we exercise the full codePath of AddSecret()
	AddSecret(hush, "", true)

	// now declare a key uri and try to change it
	AddSecret(hush, "foo", true)

	// TODO: Validate the KeyError Fatal messaging / codepath. testing log.Fatal is hard.

	os.Chdir(currPath)
}
