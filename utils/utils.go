package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
)

// UserInput - Display a prompt on STDOUT for data to be encrypted
// reads from STDIN until EOF character is received.
// returns []byte encoded array of STDIN input.
func UserInput() []byte {
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

// AddSecret - Recalls state if present, and appends a secret to the state file.
func AddSecret(toAdd Secret) {
	ism := NewIOStateManager(defaultFile)
	secrets, _ := ism.ReadState()

	secrets.Add(toAdd)
	ism.WriteState(secrets)
}

// ReadSecrets - Wrapper to return an array of Secrets for processing
func ReadSecrets() Secrets {
	ism := NewIOStateManager(defaultFile)
	secrets, err := ism.ReadState()
	if err != nil {
		log.Fatalf("Error reading state - %s", err)
	}
	return secrets
}

// DeleteSecret - Wrapper to remove a secret from state
// toRemove - string - named key of the secret to eject from the state storage
func DeleteSecret(toRemove string) {
	ism := NewIOStateManager(defaultFile)
	secrets, err := ism.ReadState()
	if err != nil {
		log.Fatalf("Error reading state - %s", err)
	}
	secrets.Remove(toRemove)
	ism.WriteState(secrets)
}
