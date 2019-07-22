package main

import (
	"bytes"
	"fmt"
	"github.com/google/shlex"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	exec "os/exec"
)

func main() {
	app := cli.NewApp()
	app.Name = "sctl"
	app.Usage = "Manage secrets encrypted by KMS"
	app.Version = "0.8.0"

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
				cli.BoolFlag{
					Name:  "no-decode",
					Usage: "When reading the secret, do not base64 decode",
				},
			},
			Action: func(c *cli.Context) error {
				// Determine if the app is configured
				if !CheckEnv("SCTL_KEY") {
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
					plaintext = bytes.TrimRight(raw_input, "\r\n")
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

				secret_encoding := ""
				// determine if we need to base64 the raw text, defaults
				// to true.
				if c.Bool("no-decode") == true {
					// skip encoding, encode as plain value
					secret_encoding = "plain"
				} else {
					// encode value as base64 compressed string
					secret_encoding = "base64"
					plaintext = []byte(b64Encode(plaintext))
				}

				// encryption doesn't care about format, give it everything we've
				// pre-processed up to this point.
				cypher, err := encryptSymmetric(c.String("key"), plaintext)
				if err != nil {
					log.Fatal(err)
				}
				// re-encode the binary data we got back.
				encoded := b64Encode(cypher)
				to_add := Secret{
					Name:       strings.ToUpper(secret_name),
					Cyphertext: encoded,
					Created:    time.Now(),
					Encoding:   secret_encoding,
				}
				AddSecret(to_add)
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

				plaintext := userInput()
				if len(plaintext) == 0 {
					log.Fatal("Empty input detected. Aborting")
				}

				cypher, err := encryptSymmetric(c.String("key"), plaintext)
				if err != nil {
					log.Fatal(err)
				}
				encoded := b64Encode(cypher)

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
					decoded, err := b64Decode([]byte(c.Args().First()))
					if err != nil {
						log.Fatal(err)
					}

					cypher, err := decryptSymmetric(c.String("key"), decoded)
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
				secret_name := strings.ToUpper(c.Args().First())
				RmSecret(secret_name)
				return nil
			},
		},
		{
			Name:  "list",
			Usage: "list known secrets",
			Action: func(c *cli.Context) error {
				var secrets []Secret
				secrets = ReadSecrets()
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
				if !CheckEnv("SCTL_KEY") {
					log.Fatal("Missing Env configuration: SCTL_KEY")
				}

				var secrets []Secret

				cmd := exec.Command(c.Args().First())
				cmd.Args, _ = shlex.Split(strings.Join(c.Args(), ", "))
				cmd.Env = os.Environ()
				secrets = ReadSecrets()
				for _, secret := range secrets {
					// uncan the base64
					decoded, err := b64Decode([]byte(secret.Cyphertext))
					if err != nil {
						log.Fatal(err)
					}
					// Decrypt the raw encrypted secret w/ kms
					cypher, err := decryptSymmetric(c.String("key"), decoded)
					if err != nil {
						log.Fatal(err)
					}
					// switch output if encoding == base64
					if secret.Encoding == "base64" {
						cypher, err = b64Decode(cypher)
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

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
