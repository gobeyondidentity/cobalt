// bluectl is the CLI for managing DPUs via Fabric Console.
package main

import (
	"os"

	"github.com/gobeyondidentity/cobalt/cmd/bluectl/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
