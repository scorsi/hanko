// Command hanko is the operator CLI: it checks the configuration, reports the certificates
// that hanko-node maintains and creates hanko-ca's CA (ADR 0011, ADR 0014).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/scorsi/hanko/internal/ca"
	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/logging"
	"github.com/scorsi/hanko/internal/run"
)

const usage = `usage: hanko check|status <config.toml>
       hanko ca keygen --name CN [--days N] --cert FILE

commands:
  check   validate the configuration file and exit
  status  print each certificate's names, expiry and last run result on stdout, read from
          the state directory as its owner; exit 1 if a certificate is not valid now
  ca keygen
          create a CA for hanko-ca: an ECDSA P-256 key, printed on stdout only (pipe it
          to age -e or sops, it becomes key_file), and a self-signed certificate valid
          N days (default 3650) written to FILE, which must not exist (cert_file)
`

func main() {
	if len(os.Args) >= 3 && os.Args[1] == "ca" && os.Args[2] == "keygen" {
		// A closed pipe (age exited) must fail the write, not kill us before the cleanup.
		signal.Ignore(syscall.SIGPIPE)
		if err := caKeygen(os.Args[3:], os.Stdout, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "hanko ca keygen:", err)
			if errors.Is(err, flag.ErrHelp) || errors.Is(err, errUsage) {
				fmt.Fprint(os.Stderr, usage)
				os.Exit(2)
			}
			os.Exit(1)
		}
		return
	}
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

var errUsage = errors.New("usage error")

// caKeygen writes the certificate to --cert, created exclusively, then the key to stdout. The
// key never touches a file, argv or a log; a failed write of it removes the certificate, so a
// rerun starts clean and no certificate exists without its key.
func caKeygen(args []string, stdout io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("hanko ca keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String("name", "", "")
	days := fs.Int("days", 3650, "")
	certPath := fs.String("cert", "", "")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if fs.NArg() > 0 || *name == "" || *certPath == "" {
		return fmt.Errorf("%w: --name and --cert are required, no argument is taken", errUsage)
	}
	keyPEM, certPEM, err := ca.Generate(*name, *days, now)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*certPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(certPEM)
	if err = errors.Join(err, f.Sync(), f.Close()); err == nil {
		_, err = stdout.Write(keyPEM)
	}
	if err != nil {
		return errors.Join(err, os.Remove(*certPath))
	}
	return nil
}
