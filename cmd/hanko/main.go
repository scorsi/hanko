// Command hanko is the operator CLI: it checks the configuration and reports the certificates
// that hanko-node maintains (ADR 0011, ADR 0014).
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/logging"
	"github.com/scorsi/hanko/internal/run"
)

const usage = `usage: hanko check|status <config.toml>

commands:
  check   validate the configuration file and exit
  status  print each certificate's names, expiry and last run result on stdout, read from
          the state directory as its owner; exit 1 if a certificate is not valid now
`

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "check" && os.Args[1] != "status") {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	log := logging.New(os.Stderr, slog.LevelInfo)
	cfg, err := config.Load(os.Args[2])
	if err != nil {
		log.Error("", "event", "config-invalid", "err", err)
		os.Exit(1)
	}
	if os.Args[1] == "check" {
		return
	}
	// The report itself, one schema v1 line per certificate, goes to stdout (ADR 0011).
	if run.Status(config.StateDir(), cfg.Certificates, logging.New(os.Stdout, slog.LevelInfo)) != nil {
		os.Exit(1)
	}
}
