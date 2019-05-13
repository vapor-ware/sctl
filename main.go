package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/shlex"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	cloudkms "cloud.google.com/go/kms/apiv1"
	b64 "encoding/base64"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	exec "os/exec"
)

// Serialized secret
// { "name": "A_SECRET", "cypher": "0xD34DB33F", "created": "2019-05-01 13:01:27.189242799 -0500 CDT m=+0.000075907"}
type Secret struct {
	Name       string    `json:"name"`
	Cyphertext string    `json:"cypher"`
	Created    time.Time `json:"created"`
}

func addSecret(to_add Secret) {
	// Adds or Updates a secret
	var secrets = readSecrets()
	for index, element := range secrets {
		if element.Name == to_add.Name {
			log.Printf("Rotating entry %s", element.Name)
			secrets[index] = secrets[len(secrets)-1] // copy last element to index i
			secrets[len(secrets)-1] = Secret{}       // erase last element (zero value)
			secrets = secrets[:len(secrets)-1]       // truncate slice
		}
	}
	secrets = append(secrets, to_add)
	writeSecrets(secrets)
}

func rmSecret(secret_name string) {
	// Remove a secret from the scuttle.json
	var secrets = readSecrets()
	for index, element := range secrets {
		if element.Name == secret_name {
			log.Printf("Removing entry %s", element.Name)
			secrets[index] = secrets[len(secrets)-1] // copy last element to index i
			secrets[len(secrets)-1] = Secret{}       // erase last element (zero value)
			secrets = secrets[:len(secrets)-1]       // truncate slice
		}
	}
	writeSecrets(secrets)
}

func readSecrets() []Secret {
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

func writeSecrets(data []Secret) {
	jsonData, _ := json.MarshalIndent(&data, "", " ")
	mode := int(0660)
	err := ioutil.WriteFile(".scuttle.json", jsonData, os.FileMode(mode))
	if err != nil {
		log.Fatal(err)
	}

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
		return nil, err
	}
	return resp.Plaintext, nil
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
			log.Fatal("Error on input: %s", err)
		}

		line = bytes.Trim(line, "\n")

		// append scanned input to the array
		lines = append(lines, line...)

	}
	return lines
}

func checkEnv(key string) bool {
	value := os.Getenv(key)
	if len(value) == 0 {
		return false
	}
	return true
}

func main() {
	app := cli.NewApp()
	app.Name = "sctl"
	app.Usage = "Manage secrets encrypted by KMS"
	app.Version = "0.4.1"

	app.Commands = []cli.Command{
		{
			Name:  "add",
			Usage: "add secret",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "GCloud KMS Key URI",
				},
			},
			Action: func(c *cli.Context) error {
				// Determine if the app is configured
				if !checkEnv("SCTL_KEY") {
					log.Fatal("Missing Env configuration: SCTL_KEY")
				}
				var plaintext []byte
				// disallow empty key data
				if c.Args().First() == "" {
					log.Fatal("Usage: sctl add SECRET_ALIAS")
				}

				// Determine if we have data available on STDIN
				stat, _ := os.Stdin.Stat()
				if (stat.Mode() & os.ModeCharDevice) == 0 {
					// we presume data is being piped to stdin
					raw_input, err := ioutil.ReadAll(os.Stdin)
					if err != nil {
						log.Fatal(err)
					}
					plaintext = bytes.Trim(raw_input, "\n")
				} else {
					// we're at a terminal. data is either arg after
					// alias or prompt the user for data.
					if len(c.Args()) > 1 {
						plaintext = []byte(c.Args()[1])
					} else {
						plaintext = userInput()
						if len(plaintext) == 0 {
							log.Fatal("Empty input detected. Aborting")
						}
					}
				}
				secret_name := c.Args().First()
				cypher, err := encryptSymmetric(c.String("key"), plaintext)
				if err != nil {
					log.Fatal(err)
				}
				encoded := b64.StdEncoding.EncodeToString(cypher)
				to_add := Secret{
					Name:       strings.ToUpper(secret_name),
					Cyphertext: encoded,
					Created:    time.Now(),
				}
				addSecret(to_add)
				return nil
			},
		},
		{
			Name:  "rm",
			Usage: "rm a secret",
			Action: func(c *cli.Context) error {
				secret_name := strings.ToUpper(c.Args().First())
				rmSecret(secret_name)
				return nil
			},
		},
		{
			Name:  "list",
			Usage: "list known secrets",
			Action: func(c *cli.Context) error {
				var secrets []Secret
				secrets = readSecrets()
				var known_keys = []string{}
				for _, secret := range secrets {
					known_keys = append(known_keys, secret.Name)
				}
				sort.Strings(known_keys)
				for _, k := range known_keys {
					fmt.Println(k)
				}
				return nil
			},
		},
		{
			Name:  "run",
			Usage: "run a command with secrets exported as env",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "GCloud KMS Key URI",
				},
			},
			Action: func(c *cli.Context) error {
				if !checkEnv("SCTL_KEY") {
					log.Fatal("Missing Env configuration: SCTL_KEY")
				}

				var secrets []Secret

				cmd := exec.Command(c.Args().First())
				cmd.Args, _ = shlex.Split(strings.Join(c.Args(), ", "))
				cmd.Env = os.Environ()
				secrets = readSecrets()
				for _, secret := range secrets {
					// uncan the base64
					decoded, err := b64.StdEncoding.DecodeString(secret.Cyphertext)
					if err != nil {
						log.Fatal(err)
					}
					// Decrypt the raw encrypted secret w/ kms
					cypher, err := decryptSymmetric(c.String("key"), decoded)
					if err != nil {
						log.Fatal(err)
					}
					// Format the decrypted data for ENV consumption
					skrt := fmt.Sprintf("%s=\"%s\"", secret.Name, cypher)
					// Append it to the command exec environment
					cmd.Env = append(cmd.Env, skrt)
				}
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				err := cmd.Run()
				if err != nil {
					log.Fatal(err)
				}

				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
