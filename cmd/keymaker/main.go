// keymaker (km) is the CLI for credential management in Secure Infrastructure.
package main

import (
	"os"

	"github.com/gobeyondidentity/cobalt/cmd/keymaker/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
