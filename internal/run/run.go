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
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/issuer"
	"github.com/scorsi/hanko/internal/logging"
	"github.com/scorsi/hanko/internal/state"
)

// Bounds one certificate's order, propagation wait and validation included.
const orderTimeout = 10 * time.Minute

type Issuer interface {
	Issue(ctx context.Context, root *os.Root, hosts []string) (chain, key []byte, err error)
}

type Runner struct {
	Issuer   Issuer
	StateDir string
	Reload   func(ctx context.Context, unit string) error
	Log      *slog.Logger
}

// Run handles every certificate and returns an error naming each one that was due and could
// not be obtained or delivered. Pending reloads survive a crash and are retried without an order.
// A blocking flock on <state>/.lock serialises runs, so hanko.service and hanko-renew.service
// never overlap (e.g. a persistent timer catching up at boot): the second waits, then finds
// nothing due.
func (r *Runner) Run(ctx context.Context, certs []config.Certificate) error {
	start := time.Now()
	root, err := state.Open(r.StateDir)
	if err != nil {
		r.Log.Error("", "event", "run-failed", "err", err)
		return err
	}
	defer root.Close()
	lock, err := state.OpenFile(root, ".lock", os.O_CREATE|os.O_RDWR, 0o600, os.Getegid())
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
		ok, err := r.one(ctx, root, c)
		if err != nil {
			r.Log.Error("", "event", "certificate-failed", "certificate", c.Name, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
		}
		if ok {
			renewed++
		}
	}
	r.Log.Info("", "event", "run-completed", "certificates", len(certs), "renewed", renewed, "failed", len(errs), "dur_us", time.Since(start).Microseconds())
	return errors.Join(errs...)
}

// one reports whether it renewed c.
func (r *Runner) one(ctx context.Context, root *os.Root, c config.Certificate) (bool, error) {
	gid, err := strconv.Atoi(c.Group)
	if err != nil {
		group, err := user.LookupGroup(c.Group)
		if err != nil {
			return false, fmt.Errorf("certificate directory: lookup group: %w", err)
		}
		gid, err = strconv.Atoi(group.Gid)
		if err != nil {
			return false, err
		}
	}
	dir, err := state.Directory(root, c.Name, gid, true)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	chain, err := state.ReadOptional(dir, "fullchain.pem", 0o640, gid)
	if err != nil {
		return false, err
	}
	key, err := state.ReadOptional(dir, "key.pem", 0o640, gid)
	if err != nil {
		return false, err
	}
	pending, err := state.ReadOptional(dir, ".reload-pending", 0o600, gid)
	if err != nil {
		return false, err
	}
	reason := issuer.Due(chain, c.Hosts, time.Now())
	if _, err := tls.X509KeyPair(chain, key); reason == "" && err != nil {
		reason = "key absent or not matching the certificate"
	}
	renewed := false
	if reason == "" {
		r.Log.Info("", "event", "certificate-valid", "certificate", c.Name, "not_after", notAfter(chain))
	} else {
		r.Log.Info("", "event", "certificate-renewing", "certificate", c.Name, "reason", reason, "hosts", c.Hosts)
		// Persist intent before the order: also proves the directory is writable before spending it.
		if err := state.WriteFiles(dir, 0o600, state.File{Name: ".reload-pending", Data: []byte("pending\n")}); err != nil {
			return false, err
		}
		pending = []byte("pending")
		orderCtx, cancel := context.WithTimeout(ctx, orderTimeout)
		chain, key, err = r.Issuer.Issue(orderCtx, root, c.Hosts)
		cancel()
		if err != nil {
			return false, err
		}
		if err := state.WriteFiles(dir, 0o640, state.File{Name: "fullchain.pem", Data: chain}, state.File{Name: "key.pem", Data: key}); err != nil {
			return false, err
		}
		renewed = true
		r.Log.Info("", "event", "certificate-written", "certificate", c.Name, "not_after", notAfter(chain))
	}
	if pending != nil {
		return renewed, r.reload(ctx, dir, c)
	}
	return renewed, nil
}

func (r *Runner) reload(ctx context.Context, dir *os.Root, c config.Certificate) error {
	var errs []error
	for _, u := range c.Reload {
		// Each consumer has its own budget, independent of issuance and detached DNS cleanup.
		reloadCtx, cancel := context.WithTimeout(ctx, time.Minute)
		err := r.Reload(reloadCtx, u)
		cancel()
		if errors.Is(err, ErrInactive) {
			r.Log.Info("unit not active", "event", "reload-skipped", "certificate", c.Name, "unit", u)
		} else if err != nil {
			r.Log.Error("", "event", "reload-failed", "certificate", c.Name, "unit", u, "err", err)
			errs = append(errs, fmt.Errorf("reload %s: %w", u, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := dir.Remove(".reload-pending"); err != nil {
		return err
	}
	return state.Sync(dir)
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
// show only reads properties, which needs no polkit authorisation.
func Systemctl(ctx context.Context, unit string) error {
	// A property read distinguishes a stopped unit from a failed command or D-Bus connection.
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--property=LoadState,ActiveState,CanReload", "--", unit).Output()
	if err != nil {
		return fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	props := map[string]string{}
	for line := range strings.Lines(string(out)) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			props[k] = v
		}
	}
	if props["LoadState"] != "loaded" {
		return fmt.Errorf("systemctl show %s: unit not loaded", unit)
	}
	switch props["ActiveState"] {
	case "inactive", "failed", "activating", "deactivating":
		return ErrInactive
	case "active", "reloading":
	default:
		return fmt.Errorf("systemctl show %s: unknown active state", unit)
	}
	verb := "reload"
	switch props["CanReload"] {
	case "no":
		verb = "restart"
	case "yes":
	default:
		return fmt.Errorf("systemctl show %s: missing reload capability", unit)
	}
	if err := exec.CommandContext(ctx, "systemctl", "--no-ask-password", verb, "--", unit).Run(); err != nil {
		return fmt.Errorf("systemctl %s %s: %w", verb, unit, err)
	}
	return nil
}
