package main

import (
	"github.com/urfave/cli"
	"github.com/vapor-ware/sctl/commands"
	"log"
	"os"
)

func main() {
	app := cli.NewApp()
	app.Name = "sctl"
	app.Usage = "Manage secrets encrypted by KMS"
	app.Version = "1.0.0-RC5"

	app.Commands = commands.BuildContextualMenu()

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
