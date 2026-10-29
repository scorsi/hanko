// Command hanko-node is the per-host oneshot that obtains and renews certificates and makes
// them available to services (ADR 0001, ADR 0014).
package main

import (
	"context"
	"errors"
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

// exitNoQuickRetry: some certificate failed for a reason a retry within minutes cannot fix
// (issuer.ErrNoQuickRetry); the module sets RestartPreventExitStatus= to it (ADR 0001).
const exitNoQuickRetry = 10

const usage = `usage: hanko-node check|run <config.toml>

commands:
  check   validate the configuration file and exit
  run     renew every due certificate, write its files, reload its units, and exit
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
	if cfg.Internal != nil {
		r.Internal = &svid.Client{Addr: cfg.Internal.CA}
		r.RenewFraction = cfg.Internal.Fraction()
	}
	if err := r.Run(ctx, cfg.Certificates); errors.Is(err, issuer.ErrNoQuickRetry) {
		os.Exit(exitNoQuickRetry) // already logged by Run (certificate-failed)
	} else if err != nil {
		os.Exit(1) // already logged by Run (certificate-failed or run-failed)
	}
}
