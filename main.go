package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/fatih/color"
	"github.com/tcnksm/go-latest"
	"github.com/urfave/cli"
	"github.com/vapor-ware/sctl/commands"
	"github.com/vapor-ware/sctl/version"
)

func main() {
	app := cli.NewApp()
	app.Name = "sctl"
	app.Usage = "Manage secrets encrypted by KMS"
	app.Version = version.Version
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:   "debug",
			EnvVar: "SCTL_DEBUG",
			Usage:  "Enable debug logging statements",
		},
	}

	app.Before = func(c *cli.Context) error {
		// Allow debugging of the config loading process
		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
		}
		return nil
	}

	// TODO (etd): This functionality could be moved to utils or elsewhere, but since the
	//   current version is defined here, we need to be within the app scope to get to it.
	//   This could be alleviated by encoding the version elsewhere or using build-time
	//   args to pass in version information.
	app.After = func(context *cli.Context) error {
		tag := &latest.GithubTag{
			Owner:      "vapor-ware",
			Repository: "sctl",
		}

		res, err := latest.Check(tag, app.Version)
		if err != nil {
			// A failure to check should not result in a failure to use the tool. Just
			// log the issue and continue on.
			log.Debugf("failed to check for latest version: %v", err)
			return nil
		}
		if res.Outdated {
			color.Yellow("\nA new version of sctl is available: current=%s, latest=%s", app.Version, res.Current)
		}
		return nil
	}

	app.Commands = commands.BuildContextualMenu()

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
