package utils

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test Case Setup
func testContextSetup(t *testing.T) (string, string, string) {
	// Test New Secret in New Context
	tempPath, tempPathErr := ioutil.TempDir("", t.Name())
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
	tempPath, currPath, tempFile := testContextSetup(t)
	defer testContextSwitch(t, tempPath, currPath)

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err := AddSecret(hush, "", true, tempFile)
	assert.NoError(t, err)

	state, keyURI, err := ReadSecrets(tempFile)
	assert.NoError(t, err)
	assert.Equal(t, "", keyURI)
	assert.Len(t, state, 1)
	assert.Equal(t, "TEST", state[0].Name)
	assert.Equal(t, "TESTCASEADDSECRET", state[0].Cyphertext)
	assert.Equal(t, "plain", state[0].Encoding)
}

// Test adding a single secret with a KeyURI
func TestAddSecretHelperAddSingleWithKeyURI(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup(t)
	defer testContextSwitch(t, tempPath, currPath)

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err := AddSecret(hush, "/path/to/key", true, tempFile)
	assert.NoError(t, err)

	state, keyURI, err := ReadSecrets(tempFile)
	assert.NoError(t, err)
	assert.Equal(t, "/path/to/key", keyURI)
	assert.Len(t, state, 1)
	assert.Equal(t, "TEST", state[0].Name)
	assert.Equal(t, "TESTCASEADDSECRET", state[0].Cyphertext)
	assert.Equal(t, "plain", state[0].Encoding)
}

// Test adding a secret to the v2 envelope, and rotating it
func TestAddSecretHelperRotation(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup(t)

	defer testContextSwitch(t, tempPath, currPath)

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err := AddSecret(hush, "/google/keys/somekey", true, tempFile)
	assert.NoError(t, err)

	state, keyURI, err := ReadSecrets(tempFile)
	assert.NoError(t, err)
	assert.Len(t, state, 1)
	assert.Equal(t, "/google/keys/somekey", keyURI)

	// Now actually rotate the entry
	hush.Cyphertext = "UpdatedCyphertext"
	err = AddSecret(hush, "/google/keys/somekey", true, tempFile)
	assert.NoError(t, err)

	// re-evaluate the serialized data recalled from disk and inspect for variant behavior
	state, keyURI, err = ReadSecrets(tempFile)
	assert.NoError(t, err)
	assert.Len(t, state, 1)
	assert.Equal(t, "/google/keys/somekey", keyURI)
	assert.Equal(t, "UpdatedCyphertext", state[0].Cyphertext)
}

// Test adding a secret without a KeyURI embedded in the envelope (or phaux v1 support using the v2 object)
// and then rotate that entry and key the file.
func TestAddSecretHelperPartialV2UpdateSupport(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup(t)

	defer testContextSwitch(t, tempPath, currPath)

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err := AddSecret(hush, "", true, tempFile)
	assert.NoError(t, err)

	state, keyURI, err := ReadSecrets(tempFile)
	assert.NoError(t, err)
	assert.Len(t, state, 1)
	assert.Equal(t, "", keyURI)

	// Now actually rotate the entry
	hush.Cyphertext = "UpdatedCyphertext"
	// Note that we re-key the envelope here, silently.
	err = AddSecret(hush, "/google/keys/somekey", true, tempFile)
	assert.NoError(t, err)

	// re-evaluate the serialized data recalled from disk and inspect for variant behavior
	state, keyURI, err = ReadSecrets(tempFile)
	assert.NoError(t, err)
	assert.Len(t, state, 1)
	assert.Equal(t, "/google/keys/somekey", keyURI)
}

func TestAddSecretHelperV1ToV2(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup(t)
	defer testContextSwitch(t, tempPath, currPath)

	s := Secrets{}
	s.Add(Secret{Name: "TESTV1UPGRADE", Cyphertext: "Banana", Created: time.Now(), Encoding: "plain"})

	v1Writer := NewIOStateManager(tempFile)
	err := v1Writer.WriteState(s)
	assert.NoError(t, err)

	upgrade, keyURI, err := ReadSecrets(tempFile)
	assert.NoError(t, err)
	assert.Len(t, upgrade, 1)

	// Add a secret
	err = AddSecret(Secret{Name: "TestV2Upgrade", Cyphertext: "Mango", Created: time.Now(), Encoding: "plain"}, "path/to/key", true, tempFile)
	assert.NoError(t, err)

	// re-evaluate the serialized data recalled from disk and inspect for variant behavior
	state, keyURI, err := ReadSecrets(tempFile)
	assert.NoError(t, err)
	assert.Len(t, state, 2)
	assert.Equal(t, "path/to/key", keyURI)
}

func TestMultiEnvelopeSamePath(t *testing.T) {
	tempPath, currPath, tempFile := testContextSetup(t)
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
	assert.NoError(t, err)

	err = AddSecret(hush, "", true, tempFile)
	assert.NoError(t, err)

	state, keyURI, err := ReadSecrets(tempFile)
	assert.NoError(t, err)
	assert.Len(t, state, 1)
	assert.Equal(t, "", keyURI)

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
	assert.NoError(t, err)
	assert.Len(t, state, 2)
	assert.Equal(t, "", keyURI)
}

// Successfully load the contents of an envelope.
func TestLoadEnvelope(t *testing.T) {
	tempPath, err := ioutil.TempDir("", t.Name())
	assert.NoError(t, err)

	defer os.RemoveAll(tempPath)
	tempFile := filepath.Join(tempPath, ".scuttle.json")

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err = AddSecret(hush, "", true, tempFile)
	assert.NoError(t, err)

	envelope, err := LoadEnvelope(tempFile)
	assert.NoError(t, err)
	assert.Len(t, envelope.Secrets, 1)
	assert.Equal(t, "", envelope.Filepath)
	assert.Equal(t, "", envelope.KeyIdentifier)
	assert.Equal(t, "2", envelope.Version)
}

// Fail to load because of an error with the provided path.
func TestLoadEnvelopeBadPath(t *testing.T) {
	_, err := LoadEnvelope("path/does/not/exist")
	assert.Error(t, err)
}

// Fail to load because we are unable to read the file state correctly.
func TestLoadEnvelopeBadFileData(t *testing.T) {
	tempPath, err := ioutil.TempDir("", t.Name())
	assert.NoError(t, err)

	defer os.RemoveAll(tempPath)
	tempFile := filepath.Join(tempPath, ".scuttle.json")

	err = ioutil.WriteFile(tempFile, []byte("invalid data"), 0777)
	assert.NoError(t, err)

	_, err = LoadEnvelope(tempFile)
	assert.Error(t, err)
}

// The envelope path does not resolve to a file/directory.
func TestGetEnvelopePathDoesNotExist(t *testing.T) {
	path, err := getEnvelopePath("path/does/not/exist")
	assert.Error(t, err)
	assert.Equal(t, "", path)
}

// The envelope path is empty and should resolve to the default file.
func TestGetEnvelopePathDefaultFile(t *testing.T) {
	path, err := getEnvelopePath("")
	assert.NoError(t, err)
	assert.Equal(t, ".scuttle.json", path)
}

// The envelope path is a directory and should get the default file appended.
func TestGetEnvelopePathDirectory(t *testing.T) {
	tempPath, err := ioutil.TempDir("", t.Name())
	assert.NoError(t, err)

	defer os.RemoveAll(tempPath)
	tempFile := filepath.Join(tempPath, ".scuttle.json")

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err = AddSecret(hush, "", true, tempFile)
	assert.NoError(t, err)

	path, err := getEnvelopePath(tempPath)
	assert.NoError(t, err)
	assert.Equal(t, tempFile, path)
}

// The envelope path specifies an existing file.
func TestGetEnvelopePathFullPath(t *testing.T) {
	tempPath, err := ioutil.TempDir("", t.Name())
	assert.NoError(t, err)

	defer os.RemoveAll(tempPath)
	tempFile := filepath.Join(tempPath, ".scuttle.json")

	hush := Secret{
		Name:       "TEST",
		Cyphertext: "TESTCASEADDSECRET",
		Created:    time.Now(),
		Encoding:   "plain",
	}

	err = AddSecret(hush, "", true, tempFile)
	assert.NoError(t, err)

	path, err := getEnvelopePath(tempFile)
	assert.NoError(t, err)
	assert.Equal(t, tempFile, path)
}
