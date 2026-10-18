// Package run is one pass of the oneshot: renew what is due, write the files, reload the units
// (ADR 0001, ADR 0005).
package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/issuer"
)

// Bounds one certificate's order, propagation wait and validation included.
const orderTimeout = 10 * time.Minute

type Issuer interface {
	Issue(ctx context.Context, hosts []string) (chain, key []byte, err error)
}

type Runner struct {
	Issuer   Issuer
	StateDir string
	Reload   func(ctx context.Context, unit string) error
	Log      *slog.Logger
}

// Run handles every certificate and returns an error naming each one that was due and could
// not be obtained; a failed reload is logged only, the certificate on disk being valid (ADR 0001).
// A blocking flock on <state>/.lock serialises runs, so hanko.service and hanko-renew.service
// never overlap (e.g. a persistent timer catching up at boot): the second waits, then finds
// nothing due.
func (r *Runner) Run(ctx context.Context, certs []config.Certificate) error {
	lock, err := os.OpenFile(filepath.Join(r.StateDir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close() // releases the lock
	// shortcut: the wait ignores ctx, so SIGTERM is honoured only once the lock is held; systemd's
	// stop timeout still kills a waiting run. Upgrade if runs ever take long enough to matter.
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock %s: %w", lock.Name(), err)
	}

	var errs []error
	for _, c := range certs {
		if err := r.one(ctx, c); err != nil {
			r.Log.Error("certificate not obtained", "certificate", c.Name, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (r *Runner) one(ctx context.Context, c config.Certificate) error {
	dir := filepath.Join(r.StateDir, c.Name)
	chain, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	reason := issuer.Due(chain, c.Hosts, time.Now())
	if _, err := os.Stat(filepath.Join(dir, "key.pem")); reason == "" && err != nil {
		reason = "key absent"
	}
	if reason == "" {
		r.Log.Info("certificate valid", "certificate", c.Name)
		return nil
	}
	r.Log.Info("renewing", "certificate", c.Name, "reason", reason, "hosts", c.Hosts)

	ctx, cancel := context.WithTimeout(ctx, orderTimeout)
	defer cancel()
	chain, key, err := r.Issuer.Issue(ctx, c.Hosts)
	if err != nil {
		return err
	}
	// The certificate first, the key last: a reader never pairs a new key with an old
	// certificate missing it (ADR 0005). The setgid directory gives the consumer's group.
	if err := issuer.WriteFile(dir, "fullchain.pem", chain, 0o640); err != nil {
		return err
	}
	if err := issuer.WriteFile(dir, "key.pem", key, 0o640); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync() // persist the renames
		d.Close()
	}
	r.Log.Info("certificate written", "certificate", c.Name)
	for _, u := range c.Reload {
		if err := r.Reload(ctx, u); err != nil {
			r.Log.Error("reload failed", "certificate", c.Name, "unit", u, "err", err)
		}
	}
	return nil
}

// Systemctl reloads unit, restarting it when it cannot reload (no ExecReload); allowed for
// user hanko by the module's polkit rule (ADR 0005).
func Systemctl(ctx context.Context, unit string) error {
	if exec.CommandContext(ctx, "systemctl", "--no-ask-password", "reload", unit).Run() == nil {
		return nil
	}
	out, err := exec.CommandContext(ctx, "systemctl", "--no-ask-password", "restart", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %v: %s", unit, err, out)
	}
	return nil
}
