// Command hanko-ca is the internal signer: it signs X.509-SVIDs for the hanko instances of
// the overlay (ADR 0004).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/scorsi/hanko/internal/ca"
	"github.com/scorsi/hanko/internal/logging"
)

const usage = `usage: hanko-ca check|serve <ca.toml>

commands:
  check   validate the configuration file and exit (reads neither key nor certificate)
  serve   load the CA key and certificate and serve Sign and Bundle until stopped
`

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "check" && os.Args[1] != "serve") {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	log := logging.New(os.Stderr, slog.LevelInfo)
	data, err := os.ReadFile(os.Args[2])
	var cfg *ca.Config
	if err == nil {
		cfg, err = ca.ParseConfig(data)
	}
	if err != nil {
		log.Error("", "event", "config-invalid", "err", err)
		os.Exit(1)
	}
	if os.Args[1] == "check" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := ca.Serve(ctx, cfg, log); err != nil {
		log.Error("", "event", "ca-failed", "err", err)
		os.Exit(1)
	}
}
