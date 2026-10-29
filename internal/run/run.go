// Package run is one pass of the oneshot: renew what is due, write the files, reload the units
// (ADR 0001, ADR 0005).
package run

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/issuer"
	"github.com/scorsi/hanko/internal/logging"
	"github.com/scorsi/hanko/internal/state"
	"github.com/scorsi/hanko/internal/svid"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// Bounds one certificate's order, propagation wait and validation included.
const orderTimeout = 10 * time.Minute

type Issuer interface {
	Issue(ctx context.Context, root *os.Root, hosts []string) (chain, key []byte, err error)
}

// Internal is hanko-ca seen from the oneshot (ADR 0004); *svid.Client in production. Both
// return PEM; the bundle holds the signing CA first.
type Internal interface {
	Sign(ctx context.Context, spiffeID string) (svid, key, bundle []byte, err error)
	Bundle(ctx context.Context) ([]byte, error)
}

type Runner struct {
	Issuer   Issuer
	Internal Internal
	StateDir string
	Reload   func(ctx context.Context, unit string) error
	Log      *slog.Logger
}

// Run handles every certificate and returns an error naming each one that was due and could
// not be obtained or delivered. The error matches issuer.ErrNoQuickRetry when any certificate
// failed for a reason a retry within minutes cannot fix (noQuickRetry), even if another one only
// needs hanko-ca or the network to come up: a quick retry would order that first one again. Pending reloads survive a crash and are retried without an order.
// A blocking flock on <state>/.lock serialises runs, so hanko-node.service and hanko-node-renew.service
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
	final := false
	renewed := 0
	last := lastRun{TS: time.Now().UTC(), Certificates: map[string]result{}}
	for _, c := range certs {
		ok, err := r.one(ctx, root, c)
		last.Certificates[c.Name] = result{Result: "ok"}
		if err != nil {
			r.Log.Error("", "event", "certificate-failed", "certificate", c.Name, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
			last.Certificates[c.Name] = result{Result: "failed", Err: err.Error()}
			final = final || noQuickRetry(err)
		}
		if ok {
			renewed++
		}
	}
	failed := len(errs)
	// Read by `hanko status` (ADR 0011). Owner-only, like every state file but the certificates.
	if data, err := json.Marshal(last); err != nil {
		errs = append(errs, err)
	} else if err := state.WriteFiles(root, 0o600, state.File{Name: lastRunFile, Data: data}); err != nil {
		r.Log.Error("", "event", "last-run-write-failed", "err", err)
		errs = append(errs, err)
	}
	r.Log.Info("", "event", "run-completed", "certificates", len(certs), "renewed", renewed, "failed", failed, "dur_us", time.Since(start).Microseconds())
	if final {
		errs = append(errs, issuer.ErrNoQuickRetry)
	}
	return errors.Join(errs...)
}

// noQuickRetry reports whether a certificate's failure is one a retry within minutes cannot fix:
// the ACME issuer's (issuer.ErrNoQuickRetry) or a refusal from hanko-ca (ADR 0004). Anything
// else, hanko-ca or the network unreachable included, may be gone by the next attempt.
func noQuickRetry(err error) bool {
	switch grpcstatus.Code(err) {
	case codes.InvalidArgument, codes.PermissionDenied, codes.FailedPrecondition:
		return true
	}
	return errors.Is(err, issuer.ErrNoQuickRetry)
}

// groupID resolves a certificate's group by name or number (ADR 0009).
func groupID(name string) (int, error) {
	if gid, err := strconv.Atoi(name); err == nil {
		return gid, nil
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("certificate directory: lookup group: %w", err)
	}
	return strconv.Atoi(group.Gid)
}

// one reports whether it renewed c.
func (r *Runner) one(ctx context.Context, root *os.Root, c config.Certificate) (bool, error) {
	gid, err := groupID(c.Group)
	if err != nil {
		return false, err
	}
	dir, err := state.Directory(root, c.Name, gid, true)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	internal := c.Issuer == "internal"
	chain, err := state.ReadOptional(dir, certFile(c), 0o640, gid)
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
	due := func(chain []byte) string { return issuer.Due(chain, c.Hosts, time.Now()) }
	// The internal issuer's bundle is refreshed on every run (ADR 0004): a CA added for a
	// rotation reaches every consumer within one timer period (ADR 0012).
	var bundle, newBundle []byte
	if internal {
		if bundle, err = state.ReadOptional(dir, "bundle.pem", 0o640, gid); err != nil {
			return false, err
		}
		if newBundle, err = r.Internal.Bundle(ctx); err != nil {
			return false, err
		}
		due = func(chain []byte) string { return svid.Due(chain, newBundle, c.SpiffeID, time.Now()) }
	}
	publish := func(newChain, newKey []byte) error {
		var files []state.File
		if internal {
			files = append(files, state.File{Name: "bundle.pem", Data: newBundle})
		}
		// The key last (ADR 0005).
		files = append(files, state.File{Name: certFile(c), Data: newChain}, state.File{Name: "key.pem", Data: newKey})
		if err := state.WriteFiles(dir, 0o640, files...); err != nil {
			return err
		}
		chain, key = newChain, newKey
		if internal {
			bundle = newBundle
		}
		r.Log.Info("", "event", "certificate-written", "certificate", c.Name, "not_after", notAfter(chain))
		return nil
	}
	renewed := false
	// A pair an earlier run issued but did not finish publishing is installed without a new
	// order: two renames are not atomic together (review H3, ADR 0009).
	if savedChain, savedKey, ok := issuedPair(pending); ok && due(savedChain) == "" &&
		!(bytes.Equal(savedChain, chain) && bytes.Equal(savedKey, key)) {
		if err := publish(savedChain, savedKey); err != nil {
			return false, err
		}
		renewed = true
	}
	reason := due(chain)
	if _, err := tls.X509KeyPair(chain, key); reason == "" && err != nil {
		reason = "key absent or not matching the certificate"
	}
	if reason == "" {
		r.Log.Info("", "event", "certificate-valid", "certificate", c.Name, "not_after", notAfter(chain))
	} else {
		names := []any{"hosts", c.Hosts}
		if internal {
			names = []any{"spiffe_id", c.SpiffeID}
		}
		r.Log.Info("", append([]any{"event", "certificate-renewing", "certificate", c.Name, "reason", reason}, names...)...)
		// Persist intent before the order: also proves the directory is writable before spending it.
		if err := state.WriteFiles(dir, 0o600, state.File{Name: ".reload-pending", Data: []byte("pending\n")}); err != nil {
			return false, err
		}
		pending = []byte("pending")
		orderCtx, cancel := context.WithTimeout(ctx, orderTimeout)
		var newChain, newKey []byte
		if internal {
			newChain, newKey, newBundle, err = r.Internal.Sign(orderCtx, c.SpiffeID)
		} else {
			newChain, newKey, err = r.Issuer.Issue(orderCtx, root, c.Hosts)
		}
		cancel()
		if err != nil {
			return false, err
		}
		// The issued pair is durable, owner-only, before publication starts.
		if err := state.WriteFiles(dir, 0o600, state.File{Name: ".reload-pending", Data: append(slices.Clip(newChain), newKey...)}); err != nil {
			return false, err
		}
		if err := publish(newChain, newKey); err != nil {
			return false, err
		}
		renewed = true
	}
	if internal && !bytes.Equal(bundle, newBundle) {
		// Consumers watch their files (ADR 0013): the atomic write is the whole delivery.
		if err := state.WriteFiles(dir, 0o640, state.File{Name: "bundle.pem", Data: newBundle}); err != nil {
			return false, err
		}
		r.Log.Info("", "event", "bundle-written", "certificate", c.Name)
	}
	if pending != nil {
		return renewed, r.reload(ctx, dir, c)
	}
	return renewed, nil
}

// certFile is the certificate's file name: fullchain.pem (ACME) or svid.pem (internal, ADR 0004).
func certFile(c config.Certificate) string {
	if c.Issuer == "internal" {
		return "svid.pem"
	}
	return "fullchain.pem"
}

// issuedPair splits a .reload-pending marker holding an issued chain followed by its key.
// The marker written before an order holds no pair.
func issuedPair(marker []byte) (chain, key []byte, ok bool) {
	n := bytes.Index(marker, []byte("-----BEGIN PRIVATE KEY-----"))
	if n <= 0 {
		return nil, nil, false
	}
	chain, key = marker[:n], marker[n:]
	_, err := tls.X509KeyPair(chain, key)
	return chain, key, err == nil
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
// (ErrInactive): at boot a consumer ordered After=hanko-node.service has a start job queued behind
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
