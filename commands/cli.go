package commands

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/urfave/cli"
	"github.com/vapor-ware/sctl/cloud"
	"github.com/vapor-ware/sctl/utils"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// BuildContextualMenu - Assemble the CLI commands, subcommands, and flags
// Handles the majority of the CLI interface.
// Retuns an array of cli.Command configuration
func BuildContextualMenu() []cli.Command {
	return []cli.Command{
		{
			Name:  "add",
			Usage: "add secret",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "GCloud KMS Key URI",
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
					// NO data deteced on stdin, attempt to scan for args after keyname
					if len(c.Args()) > 1 {
						plaintext = []byte(c.Args()[1])
					} else {
						// Everything else has failed finally resort to prompting for manual input
						plaintext = utils.UserInput()
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
				if c.Bool("no-decode") == true {
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
			Name:  "send",
			Usage: "Encode/Decode a secret for copy/paste",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "GCloud KMS Key URI",
				},
			},
			Action: func(c *cli.Context) error {

				err := validateContext(c, "send")
				if err != nil {
					log.Fatalf("%s", err)
				}
				var plaintext []byte

				// attempt stdin scan, SEND should be pipeable for things like cat'ing a file.
				plaintext = stdinScan()
				if plaintext == nil {
					plaintext = utils.UserInput()
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

				fmt.Println("Hello, I've shared some data with you with sctl! https://github.com/vapor-ware/sctl")
				fmt.Println("Once installed, run the following commands to view this sensitive information")
				fmt.Println("")
				fmt.Println("```")
				cmd := fmt.Sprintf("sctl receive --key=%s %s", c.String("key"), encoded)
				fmt.Println(cmd)
				fmt.Println("```")
				return nil
			},
		},
		{
			Name:  "receive",
			Usage: "Read a plaintext encoded secret",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "Gcloud KMS Key URI",
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
			Name:  "rm",
			Usage: "rm a secret",
			Action: func(c *cli.Context) error {
				secretName := strings.ToUpper(c.Args().First())
				utils.DeleteSecret(secretName)
				return nil
			},
		},
		{
			Name:  "list",
			Usage: "list known secrets",
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
			Name:           "run",
			Usage:          "run a command with secrets exported as env",
			SkipArgReorder: true,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "GCloud KMS Key URI",
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
						log.Fatal(err)
					}
					client := cloud.GCPKMS{}
					cypher, err := client.Decrypt(decoded)
					if err != nil {
						log.Fatal(err)
					}
					// switch output if encoding == base64
					if secret.Encoding == "base64" {
						cypher, err = base64.StdEncoding.DecodeString(string(cypher))
						if err != nil {
							log.Fatal(err)
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

// stdinScan - read if we have data on STDIN and return to exection
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
