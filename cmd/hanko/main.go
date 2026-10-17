// Command hanko makes certificates available to services (ADR 0001).
package main

import (
	"fmt"
	"os"

	"github.com/scorsi/hanko/internal/config"
)

const usage = `usage: hanko check <config.toml>

commands:
  check  validate the configuration file and exit
`

func main() {
	if len(os.Args) != 3 || os.Args[1] != "check" {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if _, err := config.Load(os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
