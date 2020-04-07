package utils

import (
	"io/ioutil"
	"os"
	"runtime"
	"testing"
	"time"
)

// Test Case Setup
func testContextSetup(temp string, t *testing.T) (string, string, string) {
	// Test New Secret in New Context
	tempPath, tempPathErr := ioutil.TempDir("", temp)
	tempFile := tempPath + "/.scuttle.json"
	currPath, _ := os.Getwd()
	t.Logf("Using temporary path %v", tempPath)
	if tempPathErr != nil {
		t.Skipf("Failed to create temporary path with error: %v", tempPathErr)
	}
	err := os.Chdir(tempPath)
	if err != nil {
		t.Skipf("failed to change to directory %s: %v", tempPath, err)
	}

	return tempPath, currPath, tempFile
}

// Test Case Cleanup
func testContextSwitch(t *testing.T, tempPath string, currPath string) {
	err := os.RemoveAll(tempPath)
	if err != nil {
		t.Errorf("failed to clean up temp path %s: %v", tempPath, err)
	}
	err = os.Chdir(currPath)
	if err != nil {
		t.Errorf("failed to change path to %s: %v", currPath, err)
	}
}

// Validate we haven't broken the EOFKey Sequence text
func TestEOFKeySequenceText(t *testing.T) {
	current := eofKeySequenceText()

	if runtime.GOOS == "windows" {
		if current != "Ctrl+Z and Enter" {
			t.Errorf("Unexpected EOF key sequence text. Wanted: Ctrl+Z and Enter  Got: %v", current)
		}
	}

	if current != "Enter and Ctrl+D" {
		t.Errorf("Unexpected EOF key sequence text. Wanted: Enter and Ctrl+D Got: %v", current)
	}
}

// Test adding a single secret without a KeyURI
func TestAddSecretHelperAddSingleNoKeyURI(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup("TestAddSecretHelperAddSingle", t)
	defer testContextSwitch(t, tempPath, currPath)

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err := AddSecret(hush, "", true, tempFile)
	if err != nil {
		t.Errorf("Unexpected error during AddSecret: %v", err)
	}

	state, keyURI, err := ReadSecrets(tempFile)
	if err != nil {
		t.Error(err)
	}
	if keyURI != "" {
		t.Errorf("Unexpected KeyIdentifier. Wanted: '', Got: %v", keyURI)
	}
	if len(state) != 1 {
		t.Errorf("Unexpected Slice Length, Wanted: 1, Got: %v", len(state))
	}

	if state[0].Name != "TEST" {
		t.Errorf("Unexpected Secret Value for Name, Wanted: TEST, Got: %v", state[0].Name)
	}
	if state[0].Cyphertext != "TESTCASEADDSECRET" {
		t.Errorf("Unexpected Value for Cyphertext, Wanted: TESTCASEADDSECRET, Got: %v", state[0].Cyphertext)
	}
	if state[0].Encoding != "plain" {
		t.Errorf("Unexpected Value for Encoding, Wanted: plain, Got: %v", state[0].Encoding)
	}
}

// Test adding a single secret with a KeyURI
func TestAddSecretHelperAddSingleWithKeyURI(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup("TestAddSecretHelperAddSingle", t)
	defer testContextSwitch(t, tempPath, currPath)

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err := AddSecret(hush, "/path/to/key", true, tempFile)
	if err != nil {
		t.Errorf("Unexpected error during AddSecret: %v", err)
	}

	state, keyURI, err := ReadSecrets(tempFile)
	if err != nil {
		t.Errorf("Unexpected error when attempting to ReadSecrets. Got: %v", err)
	}
	if len(state) != 1 {
		t.Errorf("Unexpected Slice Length, Wanted: 1, Got: %v", len(state))
	}

	if state[0].Name != "TEST" {
		t.Errorf("Unexpected Secret Value for Name, Wanted: TEST, Got: %v", state[0].Name)
	}
	if state[0].Cyphertext != "TESTCASEADDSECRET" {
		t.Errorf("Unexpected Value for Cyphertext, Wanted: TESTCASEADDSECRET, Got: %v", state[0].Cyphertext)
	}
	if state[0].Encoding != "plain" {
		t.Errorf("Unexpected Value for Encoding, Wanted: plain, Got: %v", state[0].Encoding)
	}
	if keyURI != "/path/to/key" {
		t.Errorf("Unexpected value for keyURI, Wanted: /google/keys/somekey, Got: %v", keyURI)
	}
}

// Test adding a secret to the v2 envelope, and rotating it
func TestAddSecretHelperRotation(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup("TestAddSecretHelperRotation", t)

	defer testContextSwitch(t, tempPath, currPath)

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err := AddSecret(hush, "/google/keys/somekey", true, tempFile)
	if err != nil {
		t.Errorf("Unexpected error during AddSecret: %v", err)
	}

	state, keyURI, err := ReadSecrets(tempFile)
	if len(state) != 1 {
		t.Errorf("Unexpected Slice Length, Wanted: 1, Got: %v", len(state))
	}
	if keyURI != "/google/keys/somekey" {
		t.Errorf("Unexpected value for keyURI, Wanted: /google/keys/somekey, Got: %v", keyURI)
	}
	if err != nil {
		t.Errorf("Unexpected error when attempting to ReadSecrets. Got: %v", err)
	}

	// Now actually rotate the entry
	hush.Cyphertext = "UpdatedCyphertext"
	err = AddSecret(hush, "/google/keys/somekey", true, tempFile)
	if err != nil {
		t.Errorf("Unexpected error during AddSecret: %v", err)
	}

	// re-evaluate the serialized data recalled from disk and inspect for variant behavior
	state, keyURI, err = ReadSecrets(tempFile)
	if len(state) != 1 {
		t.Errorf("Unexpected Slice Length, Wanted: 1, Got: %v", len(state))
	}
	if keyURI != "/google/keys/somekey" {
		t.Errorf("Unexpected value for keyURI, Wanted: /google/keys/somekey, Got: %v", keyURI)
	}
	if state[0].Cyphertext != "UpdatedCyphertext" {
		t.Errorf("Unexpected value for Cyphertext, Wanted: UpdatedCyphertext, Got: %v", state[0].Cyphertext)
	}
	if err != nil {
		t.Errorf("Unexpected error when attempting to ReadSecrets. Got: %v", err)
	}
}

// Test adding a secret without a KeyURI embedded in the envelope (or phaux v1 support using the v2 object)
// and then rotate that entry and key the file.
func TestAddSecretHelperPartialV2UpdateSupport(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup("TestAddSecretHelperPartialV2UpdateSupport", t)

	defer testContextSwitch(t, tempPath, currPath)

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err := AddSecret(hush, "", true, tempFile)
	if err != nil {
		t.Errorf("Unexpected error during AddSecret: %v", err)
	}

	state, keyURI, err := ReadSecrets(tempFile)
	if err != nil {
		t.Errorf("Unexpected error when attempting to ReadSecrets. Got: %v", err)
	}
	if len(state) != 1 {
		t.Errorf("Unexpected Slice Length, Wanted: 1, Got: %v", len(state))
	}
	if keyURI != "" {
		t.Errorf("Unexpected value for keyURI, Wanted: '', Got: %v", keyURI)
	}

	// Now actually rotate the entry
	hush.Cyphertext = "UpdatedCyphertext"
	// Note that we re-key the envelope here, silently.
	err = AddSecret(hush, "/google/keys/somekey", true, tempFile)
	if err != nil {
		t.Errorf("Unexpected error during AddSecret: %v", err)
	}

	// re-evaluate the serialized data recalled from disk and inspect for variant behavior
	state, keyURI, err = ReadSecrets(tempFile)
	if err != nil {
		t.Errorf("Unexpected error when attempting to ReadSecrets. Got: %v", err)
	}
	if len(state) != 1 {
		t.Errorf("Unexpected Slice Length, Wanted: 1, Got: %v", len(state))
	}
	if keyURI != "/google/keys/somekey" {
		t.Errorf("Unexpected value for keyURI, Wanted: /google/keys/somekey, Got: %v", keyURI)
	}
}

func TestAddSecretHelperV1ToV2(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup("TestAddSecretHelperV1ToV2", t)
	defer testContextSwitch(t, tempPath, currPath)

	s := Secrets{}
	s.Add(Secret{Name: "TESTV1UPGRADE", Cyphertext: "Banana", Created: time.Now(), Encoding: "plain"})

	v1Writer := NewIOStateManager(tempFile)
	err := v1Writer.WriteState(s)
	if err != nil {
		t.Errorf("Unexpected error during WriteState: %v", err)
	}

	upgrade, keyURI, err := ReadSecrets(tempFile)
	// Unexpected error? just dump out the error.
	if err != nil {
		t.Error(err)
	}
	// Did we translate?
	if len(upgrade) != 1 {
		t.Errorf("Unexpected V1 Slice Length, Wanted: 1, Got: %v", len(upgrade))
	}

	// Add a secret
	err = AddSecret(Secret{Name: "TestV2Upgrade", Cyphertext: "Mango", Created: time.Now(), Encoding: "plain"}, "path/to/key", true, tempFile)
	if err != nil {
		t.Errorf("Unexpected error during AddSecret: %v", err)
	}
	// re-evaluate the serialized data recalled from disk and inspect for variant behavior
	state, keyURI, err := ReadSecrets(tempFile)
	if err != nil {
		t.Errorf("Unexpected error when attempting to ReadSecrets. Got: %v", err)
	}
	if len(state) != 2 {
		t.Errorf("Unexpected V2 Slice Length, Wanted: 1, Got: %v", len(state))
	}
	if keyURI != "path/to/key" {
		t.Errorf("Unexpected value for keyURI, Wanted: /google/keys/somekey, Got: %v", keyURI)
	}
}

func TestMultiEnvelopeSamePath(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup("TestMultiEnvelopeSamePath", t)
	defer testContextSwitch(t, tempPath, currPath)

	s := Secrets{}

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	s.Add(hush)

	defaultWriter := NewIOStateManager(tempFile)
	err := defaultWriter.WriteState(s)
	if err != nil {
		t.Errorf("Unexpected error during WriteState: %v", err)
	}

	err = AddSecret(hush, "", true, tempFile)
	if err != nil {
		t.Errorf("Unexpected error during AddSecret: %v", err)
	}

	state, keyURI, err := ReadSecrets(tempFile)
	if err != nil {
		t.Errorf("Unexpected error when attempting to ReadSecrets. Got: %v", err)
	}
	if len(state) != 1 {
		t.Errorf("Unexpected Slice Length, Wanted: 1, Got: %v", len(state))
	}
	if keyURI != "" {
		t.Errorf("Unexpected value for keyURI, Wanted: '', Got: %v", keyURI)
	}

	// Now add another envelope in the same path, and perform the same operations on another file
	hush = Secret{
		Name:       "EXTRA",
		Cyphertext: "EXTRACYPHER",
		Created:    time.Now(),
		Encoding:   "plain",
	}
	s.Add(hush)
	extraFile := tempPath + "/extra.json"

	extraWriter := NewIOStateManager(extraFile)
	extraWriter.WriteState(s)

	state, keyURI, err = ReadSecrets(extraFile)
	if err != nil {
		t.Errorf("Unexpected error when attempting to ReadSecrets. Got: %v", err)
	}
	if len(state) != 2 {
		t.Errorf("Unexpected Slice Length, Wanted: 2, Got: %v", len(state))
	}
	if keyURI != "" {
		t.Errorf("Unexpected value for keyURI, Wanted: '', Got: %v", keyURI)
	}

}
