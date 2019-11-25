package commands

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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
			Name:     "add",
			Usage:    "Add a secret",
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
					return err
				}

				var plaintext []byte

				// Scan for data being piped via STDIN and favor this over alternate inputs
				plaintext, err = stdinScan()
				if err != nil {
					return err
				}
				if plaintext == nil {
					// NO data detected on stdin, attempt to scan for args after keyname
					if len(c.Args()) > 1 {
						plaintext = []byte(c.Args()[1])
					} else {
						// Everything else has failed finally resort to prompting for manual input
						plaintext, err = utils.UserInput("Enter the data you want to encrypt.")
						if err != nil {
							return err
						}
						// if we have nothing at this phase, log an error and abort
						if len(plaintext) == 0 {
							return errors.New("empty input detected - aborting")
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
					return err
				}
				// re-encode the binary data we got back.
				encoded := base64.StdEncoding.EncodeToString(cypher)
				toAdd := utils.Secret{
					Name:       strings.ToUpper(secretName),
					Cyphertext: encoded,
					Created:    time.Now(),
					Encoding:   secretEncoding,
				}

				return utils.AddSecret(toAdd, c.String("key"), true)
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
						conf, err := utils.ReadConfiguration()
						if err != nil {
							// Only return the error if it is a config load error, as the
							// config may fail to load on first run.
							if !utils.IsConfigLoadErr(err) {
								return err
							}
						}
						if err := conf.Init(); err != nil {
							return err
						}

						if len(conf.GoogleClient.Data) == 0 {
							clientData, err := utils.UserInput("Enter your organizations Sctl google client JSON")
							if err != nil {
								return err
							}
							conf.GoogleClient = utils.Client{Data: string(clientData)}
						}

						err = cred.Login(conf, "default")
						if err != nil {
							return err
						}
						return conf.Save()
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
				err := validateContext(c, "decrypt")
				if err != nil {
					return err
				}
				if len(c.Args()) >= 1 {
					decoded, err := base64.StdEncoding.DecodeString(c.Args().First())
					if err != nil {
						return err
					}
					client := cloud.NewGCPKMS(c.String("key"))
					cypher, err := client.Decrypt(decoded)
					if err != nil {
						return err
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
				err := validateContext(c, "encrypt")
				if err != nil {
					return err
				}
				var plaintext []byte

				// attempt stdin scan, encrypt should be pipeable for things like cat'ing a file.
				plaintext, err = stdinScan()
				if err != nil {
					return err
				}
				if plaintext == nil {
					plaintext, err = utils.UserInput("Enter the data you want to encrypt.")
					if err != nil {
						return err
					}
				}
				if len(plaintext) == 0 {
					return errors.New("empty input detected - aborting")
				}

				client := cloud.NewGCPKMS(c.String("key"))
				cypher, err := client.Encrypt(plaintext)
				if err != nil {
					return err
				}
				encoded := base64.StdEncoding.EncodeToString(cypher)

				fmt.Println("```")
				fmt.Printf("sctl decrypt --key=%s %s\n", c.String("key"), encoded)
				fmt.Println("```")
				return nil
			},
		},
		{
			Name:     "list",
			Usage:    "List known secrets",
			Category: statecategory,
			Action: func(c *cli.Context) error {
				secrets, _, err := utils.ReadSecrets()
				if err != nil {
					return err
				}
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
			Name:     "read",
			Usage:    "Decrypt and display a named secret",
			Category: statecategory,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key",
					EnvVar: "SCTL_KEY",
					Usage:  "KMS Key URI",
				},
			},
			Action: func(c *cli.Context) error {
				ctxerr := validateContext(c, "read")
				if ctxerr != nil {
					return ctxerr
				}

				secrets, keyURI, err := utils.ReadSecrets()
				if err != nil {
					return err
				}

				searchTerm := c.Args().First()

				toDecrypt, findErr := secrets.Find(strings.ToUpper(searchTerm))
				if findErr != nil {
					return findErr
				}

				locatedSecret := secrets[toDecrypt]

				// uncan the base64
				decoded, err := base64.StdEncoding.DecodeString(locatedSecret.Cyphertext)
				if err != nil {
					return errors.Wrap(err, "failed secret decode")
				}
				// Work with the envelope's provided key or switch to CLI flags/env
				var client cloud.KMS
				if keyURI == "" {
					log.Warn("No KeyURI found in envelope. Required usage of flag/env config.")
					err := validateContext(c, "read")
					if err != nil {
						return err
					}
					client = cloud.NewGCPKMS(c.String("key"))
				} else {
					log.Debug("Found Key Identifier: ", keyURI)
					client = cloud.NewGCPKMS(keyURI)
				}
				cypher, err := client.Decrypt(decoded)
				if err != nil {
					return errors.Wrap(err, "failed secret decrypt")
				}

				// switch output if encoding == base64
				if locatedSecret.Encoding == "base64" {
					cypher, err = base64.StdEncoding.DecodeString(string(cypher))
					if err != nil {
						return errors.Wrap(err, "failed secret decode")
					}
				} else {
					log.Debugf("skipping decode of %v due to encoding != base64", locatedSecret.Name)
				}

				fmt.Println(string(cypher))

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
				var sctlKey string
				newKey := c.String("newkey")

				secrets, keyURI, err := utils.ReadSecrets()
				if err != nil {
					return err
				}

				if keyURI == "" {
					log.Debug("No KeyURI found in envelope. Using flag/env config.")
					sctlKey = c.String("key")
				} else {
					log.Debug("Using key found in envelope: ", keyURI)
					sctlKey = keyURI
				}

				client := cloud.NewGCPKMS(sctlKey)
				for _, secret := range secrets {
					// uncan the base64
					decoded, err := base64.StdEncoding.DecodeString(secret.Cyphertext)
					if err != nil {
						return errors.Wrap(err, "failed secret decode")
					}
					decrypted, err := client.Decrypt(decoded)
					if err != nil {
						return errors.Wrap(err, "failed secret decrypt")
					}

					if newKey != "" {
						// Init a KMS client
						newClient := cloud.NewGCPKMS(newKey)

						newCypher, err := newClient.Encrypt(decrypted)
						if err != nil {
							return err
						}
						// re-encode the binary data we got back.
						encoded := base64.StdEncoding.EncodeToString(newCypher)
						toAdd := utils.Secret{
							Name:       strings.ToUpper(secret.Name),
							Cyphertext: encoded,
							Created:    time.Now(),
							Encoding:   secret.Encoding,
						}
						log.Debug("Saving new secret: ", toAdd.Name, " With key: ", newKey)
						// ReKeying with a new secret is an explicit process. Invoke addSecret without
						// key validation
						err = utils.AddSecret(toAdd, newKey, false)
						if err != nil {
							return err
						}
						continue
					}

					newCypher, err := client.Encrypt(decrypted)
					if err != nil {
						return err
					}
					// re-encode the binary data we got back.
					encoded := base64.StdEncoding.EncodeToString(newCypher)

					toAdd := utils.Secret{
						Name:       strings.ToUpper(secret.Name),
						Cyphertext: encoded,
						Created:    time.Now(),
						Encoding:   secret.Encoding,
					}

					err = utils.AddSecret(toAdd, sctlKey, true)
					if err != nil {
						return err
					}
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
				return utils.DeleteSecret(secretName)
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

				var secrets []utils.Secret
				var arguments []string = c.Args()
				var keyURI string
				// TODO: Not real crazy about this pattern but we have to satisfy
				// moving the validateContext() into the path-evaluation below
				var err error

				cmd := exec.Command(arguments[0], arguments[1:]...)
				cmd.Env = os.Environ()
				// TODO: Clean this up and handle the error case.
				secrets, keyURI, err = utils.ReadSecrets()
				if err != nil {
					return err
				}
				for _, secret := range secrets {
					// uncan the base64
					decoded, err := base64.StdEncoding.DecodeString(secret.Cyphertext)
					if err != nil {
						return errors.Wrap(err, "failed secret decode")
					}
					// Work with the envelope's provided key or switch to CLI flags/env
					var client cloud.KMS
					if keyURI == "" {
						log.Warn("No KeyURI found in envelope. Required usage of flag/env config.")
						err := validateContext(c, "run")
						if err != nil {
							return err
						}
						client = cloud.NewGCPKMS(c.String("key"))
					} else {
						log.Debug("Found Key Identifier: ", keyURI)
						client = cloud.NewGCPKMS(keyURI)
					}
					cypher, err := client.Decrypt(decoded)
					if err != nil {
						return errors.Wrap(err, "failed secret decrypt")
					}
					// switch output if encoding == base64
					if secret.Encoding == "base64" {
						cypher, err = base64.StdEncoding.DecodeString(string(cypher))
						if err != nil {
							return errors.Wrap(err, "failed secret decode")
						}
					} else {
						log.Debugf("skipping decode of %v due to encoding != base64", secret.Name)
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
				return cmd.Run()
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
			return errors.New("missing configuration for key")
		}
		// disallow empty secret name
		if c.Args().First() == "" {
			return errors.New("usage: sctl add SECRET_ALIAS")
		}
	case "read":
		if len(c.Args()) == 0 {
			return errors.New("usage: sctl read SECRET_ALIAS")
		}
	default:
		if len(c.String("key")) == 0 {
			return errors.New("missing configuration for key")
		}
	}

	// we fell through the switch statement, return no error.
	return nil
}

// stdinScan - read if we have data on STDIN and return to execution
func stdinScan() ([]byte, error) {
	// Determine if we have data available on STDIN
	stat, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		// we presume data is being piped to stdin
		rawInput, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(rawInput, "\r\n"), nil
	}
	return nil, nil
}
