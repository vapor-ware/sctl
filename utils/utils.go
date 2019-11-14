package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"

	log "github.com/sirupsen/logrus"
)

// UserInput will Display a prompt on STDOUT for data to be encrypted.
// reads from STDIN until EOF character is received.
// returns []byte encoded array of STDIN input.
func UserInput(message string) []byte {
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
			log.Fatalf("Error on input: %s", err)
		}

		// append scanned input to the array
		lines = append(lines, line...)

	}
	return bytes.TrimRight(lines, "\r\n")
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
func AddSecret(toAdd Secret, keyURI string, keyCheck bool) {
	envelope := V2{Filepath: defaultFile}
	envelope.KeyIdentifier = keyURI
	nvl := NewVersionedLoader(defaultFile)

	contents, err := nvl.ReadState()
	if err != nil {
		// First run case with FileNotFound exception. Mask this and save
		if os.IsNotExist(err) {
			envelope.Secrets.Add(toAdd)
			envelope.Save()
			return
		}
		// Handle any other parsing errors in a Fatal fashion
		if err != nil {
			log.WithFields(log.Fields{"method": "AddSecret"}).Fatalf("Failed parsing all known envelope formats. Failed with %v", err)
		}
	}

	// Keycheck overrides if we bother with the key evaluation. This is problematic
	// when doing re-key operations on a post-v2 migrated envelope.
	if keyCheck {
		// If we load contents and the user has a different keyURI, intercept
		// and warn before they save a multi-key sealed envelope of secrets
		if !contents.SameKey(keyURI) {
			log.Fatalf("Key mismatch detected, Refusing to save with different key identifiers. Envelope Provided: %s  User Provided: %s", contents.KeyIdentifier, keyURI)
		}
	}

	jsonData, jerr := json.MarshalIndent(envelope, "", " ")
	// No idea how we would get here, but if this fails, we'll need to halt execution otherwise we're
	// likely to corrupt state.
	if jerr != nil {
		log.Fatalf("Unable to marshall secret envelope for storage on disk. Errored with %v", jerr)
	}
	log.Debugf("Saving secret envelope with: %v", string(jsonData))
	envelope.Secrets = contents.Secrets

	envelope.Secrets.Add(toAdd)
	envelope.Save()
}

// ReadSecrets is a Wrapper to return an array of Secrets for processing
// Along with any KeyIdentifier found in the envelope for decryption
func ReadSecrets() (Secrets, string, error) {
	nvl := NewVersionedLoader(defaultFile)

	contents, err := nvl.ReadState()
	if err != nil {
		log.WithFields(log.Fields{"method": "ReadSecrets"}).Fatalf("Failed parsing all known envelope formats. Failed with %v", err)
	}
	return contents.Secrets, contents.KeyIdentifier, nil
}

// DeleteSecret is a Wrapper to remove a secret from state
// toRemove - string - named key of the secret to eject from the state storage
func DeleteSecret(toRemove string) {
	nvl := NewVersionedLoader(defaultFile)

	contents, err := nvl.ReadState()
	if err != nil {
		log.WithFields(log.Fields{"method": "DeleteSecret"}).Warn("Failed parsing all known envelope formats.")
		log.Fatal("Refusing to remove secret from unprocessable envelope format.")
	}
	contents.Secrets.Remove(toRemove)
	contents.Filepath = defaultFile
	serr := contents.Save()
	if serr != nil {
		log.Fatalf("Failed saving file with error: %v", err)
	}
}
