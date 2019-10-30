package commands

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/urfave/cli"
	"github.com/vapor-ware/sctl/cloud"
	"github.com/vapor-ware/sctl/credentials"
	"github.com/vapor-ware/sctl/utils"
)

const statecategory = "State management"
const quickcategory = "Quick encrypt"

// BuildContextualMenu - Assemble the CLI commands, subcommands, and flags
// Handles the majority of the CLI interface.
// Returns an array of cli.Command configuration
func BuildContextualMenu() []cli.Command {
	return []cli.Command{
		{
			Name:  "add",
			Usage: "Add a secret",
			Category: statecategory,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "KMS Key URI",
				},
				cli.BoolFlag{
					Name:  "no-decode",
					Usage: "When reading the secret, do not base64 decode",
				},
			},
			Action: func(c *cli.Context) error {

				// Check for KMS key uri, and presence of the secrets name
				err := validateContext(c, "add")
				if err != nil {
					log.Fatal(err)
				}

				var plaintext []byte

				// Scan for data being piped via STDIN and favor this over alternate inputs
				plaintext = stdinScan()
				if plaintext == nil {
					// NO data detected on stdin, attempt to scan for args after keyname
					if len(c.Args()) > 1 {
						plaintext = []byte(c.Args()[1])
					} else {
						// Everything else has failed finally resort to prompting for manual input
						plaintext = utils.UserInput("Enter the data you want to encrypt.")
						// if we have nothing at this phase, log an error and abort
						if len(plaintext) == 0 {
							log.Fatal("Empty input detected. Aborting")
						}
					}
				}

				secretName := c.Args().First()

				secretEncoding := ""
				// determine if we need to base64 the raw text, defaults
				// to true.
				if c.Bool("no-decode") {
					// skip encoding, encode as plain value
					secretEncoding = "plain"
				} else {
					// encode value as base64 compressed string
					secretEncoding = "base64"
					plaintext = []byte(base64.StdEncoding.EncodeToString(plaintext))
				}

				// Init a KMS client
				client := cloud.NewGCPKMS(c.String("key"))

				cypher, err := client.Encrypt(plaintext)
				if err != nil {
					log.Fatal(err)
				}
				// re-encode the binary data we got back.
				encoded := base64.StdEncoding.EncodeToString(cypher)
				toAdd := utils.Secret{
					Name:       strings.ToUpper(secretName),
					Cyphertext: encoded,
					Created:    time.Now(),
					Encoding:   secretEncoding,
				}

				utils.AddSecret(toAdd)

				return nil
			},
		},
		{
			Name:  "credential",
			Usage: "Manage cloud credentials",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "cloud",
					Usage: "cloud, must be one of [GCP]",
					Value: "GCP",
				},
			},
			Subcommands: []cli.Command{
				{
					Name:  "add",
					Usage: "Add a default credential",
					Action: func(c *cli.Context) error {
						var cred credentials.GoogleCredential
						conf := utils.ReadConfiguration()
						conf.Init()

						if len(conf.GoogleClient.Data) == 0 {
							clientData := utils.UserInput("Enter your organizations Sctl google client JSON")
							conf.GoogleClient = utils.Client{Data: string(clientData)}
						}

						err := cred.Login(conf, "default")
						conf.Save()
						if err != nil {
							log.Fatal(err)
						}
						return nil
					},
				},
				{
					Name:  "rm",
					Usage: "Remove default credential",
					Action: func(c *cli.Context) error {
						var cred credentials.GoogleCredential
						return cred.DeleteCredential("default")
					},
				},
			},
		},
		{
			Name:     "decrypt",
			Usage:    "Decrypt an encrypted secret",
			Category: quickcategory,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "KMS Key URI",
				},
			},
			Action: func(c *cli.Context) error {
				if len(c.Args()) >= 1 {
					decoded, err := base64.StdEncoding.DecodeString(c.Args().First())
					if err != nil {
						log.Fatal(err)
					}
					client := cloud.NewGCPKMS(c.String("key"))
					cypher, err := client.Decrypt(decoded)
					if err != nil {
						log.Fatal(err)
					}

					fmt.Println(string(cypher))
				}
				return nil
			},
		},
		{
			Name:     "encrypt",
			Usage:    "Encrypt a secret for copy/paste without storing in state",
			Category: quickcategory,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "KMS Key URI",
				},
			},
			Action: func(c *cli.Context) error {

				err := validateContext(c, "send")
				if err != nil {
					log.Fatal(err)
				}
				var plaintext []byte

				// attempt stdin scan, SEND should be pipeable for things like cat'ing a file.
				plaintext = stdinScan()
				if plaintext == nil {
					plaintext = utils.UserInput("Enter the data you want to encrypt.")
				}
				if len(plaintext) == 0 {
					log.Fatal("Empty input detected. Aborting")
				}

				client := cloud.NewGCPKMS(c.String("key"))
				cypher, err := client.Encrypt(plaintext)
				if err != nil {
					log.Fatal(err)
				}
				encoded := base64.StdEncoding.EncodeToString(cypher)

				fmt.Println("```")
				cmd := fmt.Sprintf("sctl decrypt --key=%s %s", c.String("key"), encoded)
				fmt.Println(cmd)
				fmt.Println("```")
				return nil
			},
		},
		{
			Name:     "list",
			Usage:    "List known secrets",
			Category: statecategory,
			Action: func(c *cli.Context) error {
				secrets := utils.ReadSecrets()
				var knownKeys []string
				for _, secret := range secrets {
					knownKeys = append(knownKeys, secret.Name)
				}
				sort.Strings(knownKeys)
				for _, k := range knownKeys {
					fmt.Println(k)
				}
				return nil
			},
		},
		{
			Name:     "rekey",
			Usage:    "Re-encrypt a statefile to a new key-version",
			Category: statecategory,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "KMS Key URI",
				},
				cli.StringFlag{
					Name:  "newkey",
					Usage: "New KMS Key URI (optional)",
				},
			},
			Action: func(c *cli.Context) error {
				sctlKey := c.String("key")
				newKey := c.String("newkey")

				secrets := utils.ReadSecrets()
				client := cloud.NewGCPKMS(sctlKey)

				for _, secret := range secrets {
					// uncan the base64
					decoded, err := base64.StdEncoding.DecodeString(secret.Cyphertext)
					if err != nil {
						log.Fatalf("CLI - DECODING - %s", err)
					}
					decrypted, err := client.Decrypt(decoded)
					if err != nil {
						log.Fatalf("CLI - DECRYPT - %s", err)
					}

					if newKey != "" {
						// Init a KMS client
						newClient := cloud.NewGCPKMS(newKey)

						newCypher, err := newClient.Encrypt(decrypted)
						if err != nil {
							log.Fatal(err)
						}
						// re-encode the binary data we got back.
						encoded := base64.StdEncoding.EncodeToString(newCypher)
						toAdd := utils.Secret{
							Name:       strings.ToUpper(secret.Name),
							Cyphertext: encoded,
							Created:    time.Now(),
							Encoding:   secret.Encoding,
						}

						utils.AddSecret(toAdd)
						continue
					}

					newCypher, err := client.Encrypt(decrypted)
					if err != nil {
						log.Fatal(err)
					}
					// re-encode the binary data we got back.
					encoded := base64.StdEncoding.EncodeToString(newCypher)

					toAdd := utils.Secret{
						Name:       strings.ToUpper(secret.Name),
						Cyphertext: encoded,
						Created:    time.Now(),
						Encoding:   secret.Encoding,
					}

					utils.AddSecret(toAdd)

				}
				return nil
			},
		},
		{
			Name:     "rm",
			Usage:    "Delete a secret from state",
			Category: statecategory,
			Action: func(c *cli.Context) error {
				secretName := strings.ToUpper(c.Args().First())
				utils.DeleteSecret(secretName)
				return nil
			},
		},
		{
			Name:           "run",
			Usage:          "Run a command with secrets exported as env",
			Category:       statecategory,
			SkipArgReorder: true,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "KMS Key URI",
				},
				cli.BoolFlag{
					Name:  "interactive, i",
					Usage: "Run the command in an interactive session",
				},
			},
			Action: func(c *cli.Context) error {
				validateContext(c, "run")

				var secrets []utils.Secret
				var arguments []string = c.Args()

				cmd := exec.Command(arguments[0], arguments[1:]...)
				cmd.Env = os.Environ()
				secrets = utils.ReadSecrets()
				for _, secret := range secrets {
					// uncan the base64
					decoded, err := base64.StdEncoding.DecodeString(secret.Cyphertext)
					if err != nil {
						log.Fatalf("CLI - DECODING - %s", err)
					}
					client := cloud.NewGCPKMS(c.String("key"))
					cypher, err := client.Decrypt(decoded)
					if err != nil {
						log.Fatalf("CLI - DECRYPT - %s", err)
					}
					// switch output if encoding == base64
					if secret.Encoding == "base64" {
						cypher, err = base64.StdEncoding.DecodeString(string(cypher))
						if err != nil {
							log.Fatalf("CLI - ENCODING - %s", err)
						}
					} else {
						log.Printf("skipping decode of %v due to encoding != base64", secret.Name)
					}
					// Format the decrypted data for ENV consumption
					skrt := fmt.Sprintf("%s=%v", secret.Name, string(cypher))
					// Append it to the command exec environment
					cmd.Env = append(cmd.Env, skrt)
				}
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if c.Bool("interactive") {
					cmd.Stdin = os.Stdin
				}
				err := cmd.Run()
				if err != nil {
					log.Fatal(err)
				}

				return nil
			},
		},
	}
}

// validateContext - A bespoke method to validate the CLI context per command
func validateContext(c *cli.Context, context string) error {

	switch context {
	case "add":
		// disallow empty key data
		if len(c.String("key")) == 0 {
			return errors.New("Missing configuration for key")
		}
		// disallow empty secret name
		if c.Args().First() == "" {
			return errors.New("Usage: sctl add SECRET_ALIAS")
		}
	case "default":
		if len(c.String("key")) == 0 {
			return errors.New("Missing configuration for key")
		}
	}

	// we fell through the switch statement, return no error.
	return nil
}

// stdinScan - read if we have data on STDIN and return to execution
func stdinScan() []byte {
	// Determine if we have data available on STDIN
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		// we presume data is being piped to stdin
		rawInput, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		return bytes.TrimRight(rawInput, "\r\n")
	}
	return nil
}
