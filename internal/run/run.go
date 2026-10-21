// Package run is one pass of the oneshot: renew what is due, write the files, reload the units
// (ADR 0001, ADR 0005).
package run

import (
	"context"
	"crypto/tls"
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
	"github.com/scorsi/hanko/internal/logging"
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
	start := time.Now()
	lock, err := os.OpenFile(filepath.Join(r.StateDir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		r.Log.Error("", "event", "run-failed", "err", err)
		return err
	}
	defer lock.Close() // releases the lock
	// shortcut: the wait ignores ctx, so SIGTERM is honoured only once the lock is held; systemd's
	// stop timeout still kills a waiting run. Upgrade if runs ever take long enough to matter.
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		err = fmt.Errorf("lock %s: %w", lock.Name(), err)
		r.Log.Error("", "event", "run-failed", "err", err)
		return err
	}

	var errs []error
	renewed := 0
	for _, c := range certs {
		ok, err := r.one(ctx, c)
		if err != nil {
			r.Log.Error("", "event", "certificate-failed", "certificate", c.Name, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
		} else if ok {
			renewed++
		}
	}
	r.Log.Info("", "event", "run-completed", "certificates", len(certs), "renewed", renewed, "failed", len(errs), "dur_us", time.Since(start).Microseconds())
	return errors.Join(errs...)
}

// one reports whether it renewed c.
func (r *Runner) one(ctx context.Context, c config.Certificate) (bool, error) {
	dir := filepath.Join(r.StateDir, c.Name)
	chain, err := readOptional(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return false, err
	}
	key, err := readOptional(filepath.Join(dir, "key.pem"))
	if err != nil {
		return false, err
	}
	reason := issuer.Due(chain, c.Hosts, time.Now())
	// A run interrupted between the two renames leaves a new certificate with the old key.
	if _, err := tls.X509KeyPair(chain, key); reason == "" && err != nil {
		reason = "key absent or not matching the certificate"
	}
	if reason == "" {
		r.Log.Info("", "event", "certificate-valid", "certificate", c.Name, "not_after", notAfter(chain))
		return false, nil
	}
	r.Log.Info("", "event", "certificate-renewing", "certificate", c.Name, "reason", reason, "hosts", c.Hosts)
	// Before the order: a certificate that cannot be written must not be issued.
	if err := checkDir(dir); err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(ctx, orderTimeout)
	defer cancel()
	chain, key, err = r.Issuer.Issue(ctx, c.Hosts)
	if err != nil {
		return false, err
	}
	// The certificate first, the key last: a reader never pairs a new key with an old
	// certificate missing it (ADR 0005). The setgid directory gives the consumer's group.
	if err := issuer.WriteFiles(dir, 0o640, issuer.File{Name: "fullchain.pem", Data: chain}, issuer.File{Name: "key.pem", Data: key}); err != nil {
		return false, err
	}
	r.Log.Info("", "event", "certificate-written", "certificate", c.Name, "not_after", notAfter(chain))
	for _, u := range c.Reload {
		if err := r.Reload(ctx, u); errors.Is(err, ErrInactive) {
			r.Log.Info("unit not active", "event", "reload-skipped", "certificate", c.Name, "unit", u)
		} else if err != nil {
			r.Log.Error("", "event", "reload-failed", "certificate", c.Name, "unit", u, "err", err)
		}
	}
	return true, nil
}

// readOptional reads path; an absent file is empty, not an error.
func readOptional(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// checkDir fails unless dir can be the directory the module provisions (ADR 0005): owned by
// hanko, writable by hanko only, and able to take a new file. The setgid bit and the group are
// left to the provisioning checks of review finding H6.
func checkDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("certificate directory: %w", err)
	}
	st, _ := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.IsDir():
		return fmt.Errorf("certificate directory %s: not a directory", dir)
	case st != nil && int(st.Uid) != os.Getuid():
		return fmt.Errorf("certificate directory %s: owned by uid %d, not %d", dir, st.Uid, os.Getuid())
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("certificate directory %s: mode %v, want no group or other write (2750)", dir, info.Mode())
	}
	f, err := os.CreateTemp(dir, ".probe.*")
	if err != nil {
		return fmt.Errorf("certificate directory: %w", err)
	}
	f.Close()
	return os.Remove(f.Name())
}

// notAfter is the leaf's expiry in the log schema's ts format, "" when chain does not parse.
func notAfter(chain []byte) string {
	t, err := issuer.NotAfter(chain)
	if err != nil {
		return ""
	}
	return t.UTC().Format(logging.TS)
}

// ErrInactive is returned by Systemctl for a unit that is not active: nothing was reloaded.
var ErrInactive = errors.New("unit not active")

// Systemctl reloads unit, restarting it when it cannot reload (no ExecReload); allowed for
// user hanko by the module's polkit rule (ADR 0005). A unit that is not active is skipped
// (ErrInactive): at boot a consumer ordered After=hanko.service has a start job queued behind
// hanko, a reload would merge into it and wait for hanko; it reads the new files when it starts.
// is-active only reads a property, which needs no polkit authorisation.
func Systemctl(ctx context.Context, unit string) error {
	if exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() != nil {
		return ErrInactive
	}
	if exec.CommandContext(ctx, "systemctl", "--no-ask-password", "reload", unit).Run() == nil {
		return nil
	}
	out, err := exec.CommandContext(ctx, "systemctl", "--no-ask-password", "restart", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %v: %s", unit, err, out)
	}
	return nil
}
