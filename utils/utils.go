package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
)

// UserInput will Display a prompt on STDOUT for data to be encrypted.
// reads from STDIN until EOF character is received.
// returns []byte encoded array of STDIN input.
func UserInput(message string) ([]byte, error) {
	if message == "" {
		message = "Enter the data you want to encrypt."
	}
	// Read STDIN (keyboard, interactive) until the user sends a manual EOF
	// with CTRL+D on WIN keyboards, CMD+D on mac.
	fmt.Printf("%s. END with %s\n", message, eofKeySequenceText())
	rdr := bufio.NewReader(os.Stdin)
	var lines []byte
	for {
		line, err := rdr.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "error on user input")
		}

		// append scanned input to the array
		lines = append(lines, line...)

	}
	return bytes.TrimRight(lines, "\r\n"), nil
}

// eofKeySequenceText is a helper to determine the currently running
// operating system and returns the correct EOF key presses, which vary
// between darwin, linux, and windows.
func eofKeySequenceText() string {
	// Detect the OS and return the help text for userInputs
	if runtime.GOOS == "windows" {
		return "Ctrl+Z and Enter"
	}

	return "Enter and Ctrl+D"
}

// AddSecret Recalls state if present, and appends a secret to the state file
func AddSecret(toAdd Secret, keyURI string, keyCheck bool, envelope string) error {
	stateFile := V2{Filepath: envelope}
	stateFile.KeyIdentifier = keyURI
	nvl := NewVersionedLoader(envelope)

	contents, err := nvl.ReadState()
	if err != nil {
		// First run case with FileNotFound exception. Mask this and save
		if os.IsNotExist(err) {
			stateFile.Secrets.Add(toAdd)
			return stateFile.Save()
		}
		// Handle any other parsing errors in a Fatal fashion
		if err != nil {
			return errors.Wrap(err, "failed parsing all known envelope formats")
		}
	}

	// keyCheck overrides if we bother with the key evaluation. This is problematic
	// when doing re-key operations on a post-v2 migrated envelope.
	if keyCheck {
		// If we load contents and the user has a different keyURI, intercept
		// and warn before they save a multi-key sealed envelope of secrets
		if !contents.SameKey(keyURI) {
			return fmt.Errorf("key mismatch detected - refusing to save with different key identifiers. Envelope Provided: %s  User Provided: %s", contents.KeyIdentifier, keyURI)
		}
	}

	jsonData, err := json.MarshalIndent(stateFile, "", " ")
	// No idea how we would get here, but if this fails, we'll need to halt execution otherwise we're
	// likely to corrupt state.
	if err != nil {
		return errors.Wrap(err, "unable to marshall secret envelope for storage on disk")
	}
	log.Debugf("Saving secret envelope with: %v", string(jsonData))
	stateFile.Secrets = contents.Secrets

	stateFile.Secrets.Add(toAdd)
	return stateFile.Save()
}

// ReadSecrets is a Wrapper to return an array of Secrets for processing
// Along with any KeyIdentifier found in the envelope for decryption
func ReadSecrets(envelope string) (Secrets, string, error) {
	nvl := NewVersionedLoader(envelope)

	contents, err := nvl.ReadState()
	// First run case with FileNotFound exception. Mask this and return empty placeholders
	if os.IsNotExist(err) {
		return Secrets{}, "", nil
	}
	if err != nil {
		return nil, "", errors.Wrap(err, "failed parsing all known envelope formats")
	}
	return contents.Secrets, contents.KeyIdentifier, nil
}

// DeleteSecret is a Wrapper to remove a secret from state
// toRemove - string - named key of the secret to eject from the state storage
func DeleteSecret(toRemove string, envelope string) error {
	nvl := NewVersionedLoader(envelope)

	contents, err := nvl.ReadState()
	if err != nil {
		return errors.Wrap(err, "failed parsing all known envelope formats - refusing to remove secret")
	}
	contents.Secrets.Remove(toRemove)
	contents.Filepath = envelope
	return contents.Save()
}
