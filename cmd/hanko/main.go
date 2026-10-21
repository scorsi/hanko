// Command hanko makes certificates available to services (ADR 0001).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/issuer"
	"github.com/scorsi/hanko/internal/logging"
	"github.com/scorsi/hanko/internal/run"
)

const usage = `usage: hanko check|run <config.toml>

commands:
  check  validate the configuration file and exit
  run    renew every due certificate, write its files, reload its units, and exit
`

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "check" && os.Args[1] != "run") {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	// Schema v1 lines on stderr for check and run alike (ADR 0007).
	log := logging.New(os.Stderr, slog.LevelInfo)
	cfg, err := config.Load(os.Args[2])
	if err != nil {
		log.Error("", "event", "config-invalid", "err", err)
		os.Exit(1)
	}
	if os.Args[1] == "check" {
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	state := config.StateDir()

	r := &run.Runner{StateDir: state, Reload: run.Systemctl, Log: log}
	if cfg.ACME != nil {
		r.Issuer = &issuer.Issuer{ACME: *cfg.ACME, DNSConfig: *cfg.DNS, Log: log}
	}
	if err := r.Run(ctx, cfg.Certificates); err != nil {
		os.Exit(1) // already logged by Run (certificate-failed or run-failed)
	}
}
