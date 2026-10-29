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
	"github.com/scorsi/hanko/internal/svid"
)

const usage = `usage: hanko check|run|status <config.toml>

commands:
  check   validate the configuration file and exit
  run     renew every due certificate, write its files, reload its units, and exit
  status  print each certificate's names, expiry and last run result on stdout, read from
          the state directory as its owner; exit 1 if a certificate is not valid now
`

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "check" && os.Args[1] != "run" && os.Args[1] != "status") {
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
	if os.Args[1] == "status" {
		// The report itself, one schema v1 line per certificate, goes to stdout (ADR 0011).
		if run.Status(config.StateDir(), cfg.Certificates, logging.New(os.Stdout, slog.LevelInfo)) != nil {
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	state := config.StateDir()

	r := &run.Runner{StateDir: state, Reload: run.Systemctl, Log: log}
	if cfg.ACME != nil {
		r.Issuer = &issuer.Issuer{ACME: *cfg.ACME, DNSConfig: *cfg.DNS, Log: log}
	}
	if cfg.Internal != nil {
		r.Internal = &svid.Client{Addr: cfg.Internal.CA}
	}
	if err := r.Run(ctx, cfg.Certificates); err != nil {
		os.Exit(1) // already logged by Run (certificate-failed or run-failed)
	}
}
