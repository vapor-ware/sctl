package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"

	cloudkms "cloud.google.com/go/kms/apiv1"
	b64 "encoding/base64"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// Serialized secret
// { "name": "A_SECRET",
// "cypher": "0xD34DB33F",
// "created": "2019-05-01 13:01:27.189242799 -0500 CDT m=+0.000075907"
// "encoding": "plain"
// }
type Secret struct {
	Name       string    `json:"name"`
	Cyphertext string    `json:"cypher"`
	Created    time.Time `json:"created"`
	Encoding   string    `json:"encoding"`
}

// AddSecret appends a secret to a given .scuttle.json file to rest
func AddSecret(to_add Secret) {
	// Adds or Updates a secret
	var secrets = ReadSecrets()
	for index, element := range secrets {
		if element.Name == to_add.Name {
			log.Printf("Rotating entry %s", element.Name)
			secrets[index] = secrets[len(secrets)-1] // copy last element to index i
			secrets[len(secrets)-1] = Secret{}       // erase last element (zero value)
			secrets = secrets[:len(secrets)-1]       // truncate slice
		}
	}
	secrets = append(secrets, to_add)
	WriteSecrets(secrets)
}

// RmSecret removes a secret by name from a given .scuttle.json file
func RmSecret(secret_name string) {
	// Remove a secret from the scuttle.json
	var secrets = ReadSecrets()
	for index, element := range secrets {
		if element.Name == secret_name {
			log.Printf("Removing entry %s", element.Name)
			secrets[index] = secrets[len(secrets)-1] // copy last element to index i
			secrets[len(secrets)-1] = Secret{}       // erase last element (zero value)
			secrets = secrets[:len(secrets)-1]       // truncate slice
		}
	}
	WriteSecrets(secrets)
}

// ReadSecrets Returns all the secrets as a map from the .scuttle.json file
func ReadSecrets() []Secret {
	file, err := ioutil.ReadFile(".scuttle.json")
	if err != nil {
		return []Secret{}
	}

	var data []Secret
	err = json.Unmarshal([]byte(file), &data)
	if err != nil {
		log.Fatal(err)
	}
	return data
}

// WriteSecrets atomically writes the .scuttle.json state file
func WriteSecrets(data []Secret) {
	jsonData, _ := json.MarshalIndent(&data, "", " ")
	mode := int(0660)
	err := ioutil.WriteFile(".scuttle.json", jsonData, os.FileMode(mode))
	if err != nil {
		log.Fatal(err)
	}
}

// Convenience method to decode base64 encoded data
func b64Decode(encoded []byte) ([]byte, error) {
	// Introduced in v0.7 - we base64 wrap all raw data now, so we have to
	// attempt to decode. This will return the error object if it fails
	// and should only be invoked when encoding is set to base64
	decoded, err := b64.StdEncoding.DecodeString(string(encoded))

	return decoded, err
}

// Convenience method to encode as base64 data
func b64Encode(plaintext []byte) string {
	encoded := b64.StdEncoding.EncodeToString(plaintext)
	return encoded
}

// encrypt will encrypt the input plaintext with the specified symmetric key
// example keyName: "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID"
func encryptSymmetric(keyName string, plaintext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	// Build the request.
	req := &kmspb.EncryptRequest{
		Name:      keyName,
		Plaintext: plaintext,
	}
	// Call the API.
	resp, err := client.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

// decrypt will decrypt the input ciphertext bytes using the specified symmetric key
// example keyName: "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID"
func decryptSymmetric(keyName string, ciphertext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:       keyName,
		Ciphertext: ciphertext,
	}
	// Call the API.
	resp, err := client.Decrypt(ctx, req)
	if err != nil {
		// if this fails, its likely network or permissions related
		return nil, err
	}

	// return the decrypted data, and the error object
	return resp.Plaintext, err

}

func userInput() []byte {
	// Read STDIN (keyboard, interactive) until the user sends a manual EOF
	// with CTRL+D on WIN keyboards, CMD+D on mac.
	fmt.Println("Enter the data you want to encrypt. END with CTRL+D or CMD+D")
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
	return lines
}
