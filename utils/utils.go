package utils

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
)

// Convenience method to decode base64 encoded data
func b64Decode(encoded []byte) ([]byte, error) {
	// Introduced in v0.7 - we base64 wrap all raw data now, so we have to
	// attempt to decode. This will return the error object if it fails
	// and should only be invoked when encoding is set to base64
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))

	return decoded, err
}

// Convenience method to encode as base64 data
func b64Encode(plaintext []byte) string {
	encoded := base64.StdEncoding.EncodeToString(plaintext)
	return encoded
}

func userInput() []byte {
	// Read STDIN (keyboard, interactive) until the user sends a manual EOF
	// with CTRL+D on WIN keyboards, CMD+D on mac.
	fmt.Printf("Enter the data you want to encrypt. END with %s\n", eofKeySequenceText())
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

// EOFKeySequenceText is a helper to determine the currently running
// operating system and returns the correct EOF key presses, which vary
// between darwin, linux, and windows.
func eofKeySequenceText() string {
	// Detect the OS and return the help text for userInputs
	if runtime.GOOS == "windows" {
		return "Ctrl+Z and Enter"
	}

	if runtime.GOOS == "darwin" {
		return "⌘+D"
	}

	return "Ctrl+D"
}

// UpsertSecret - Insert or Update a secret contained in
// the listing of secrets
func UpsertSecret(secrets []Secret, toAdd Secret) []Secret {
	// Adds or Updates a secret
	for index, element := range secrets {
		if element.Name == toAdd.Name {
			log.Printf("Rotating entry %s", element.Name)
			secrets[index] = secrets[len(secrets)-1] // copy last element to index i
			secrets[len(secrets)-1] = Secret{}       // erase last element (zero value)
			secrets = secrets[:len(secrets)-1]       // truncate slice
		}
	}
	return append(secrets, toAdd)

}

// RmSecret - Remove a secret from a slice of Secrets by name.
// secrets is the slice of secrets
// toRemove is the secret to be expunged from the list
// Returns the truncated list of secrets
func RmSecret(secrets []Secret, toRemove string) []Secret {
	for index, element := range secrets {
		if element.Name == toRemove {
			log.Printf("Removing entry %s", element.Name)
			secrets[index] = secrets[len(secrets)-1] // copy last element to index i
			secrets[len(secrets)-1] = Secret{}       // erase last element (zero it out basically)
			secrets = secrets[:len(secrets)-1]       // truncate the slice
		}
	}
	return secrets
}

// AddSecret - Recalls state if present, and appends a secret to the state file.
func AddSecret(toAdd Secret) {
	ism := CreateIOStateManager(defaultFile)
	secrets, _ := ReadState(ism)

	revised := UpsertSecret(secrets, toAdd)
	WriteState(ism, revised)
}

// ReadSecrets - Wrapper to return an array of Secrets for processing
func ReadSecrets() []Secret {
	ism := CreateIOStateManager(defaultFile)
	secrets, err := ReadState(ism)
	if err != nil {
		log.Fatalf("Error reading state - %s", err)
	}
	return secrets
}

// DeleteSecret - Wrapper to remove a secret from state
// toRemove - string - named key of the secret to eject from the state storage
func DeleteSecret(toRemove string) {
	ism := CreateIOStateManager(defaultFile)
	secrets, err := ReadState(ism)
	if err != nil {
		log.Fatalf("Error reading state - %s", err)
	}
	truncated := RmSecret(secrets, toRemove)
	WriteState(ism, truncated)
}
