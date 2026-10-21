package run

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/logging"
	"github.com/scorsi/hanko/internal/testutil"
)

// stubIssuer self-signs 90-day certificates, or fails for the hosts in fail.
type stubIssuer struct {
	calls int
	fail  string
	last  []byte
	hold  func() // called inside Issue when set
}

func (s *stubIssuer) Issue(_ context.Context, _ *os.Root, hosts []string) ([]byte, []byte, error) {
	if s.hold != nil {
		s.hold()
	}
	s.calls++
	if slices.Contains(hosts, s.fail) {
		return nil, nil, errors.New("validation failed")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(s.calls)), DNSNames: hosts, NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	s.last = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return s.last, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), nil
}

func setup(t *testing.T) (*Runner, *stubIssuer, *[]string) {
	state := testutil.StateDir(t)
	for _, n := range []string{"home", "cv"} {
		// As the module provisions them (ADR 0005).
		dir := filepath.Join(state, n)
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		testutil.SetgidDir(t, dir)
	}
	iss := &stubIssuer{}
	var reloads []string
	r := &Runner{Issuer: iss, StateDir: state, Log: slog.New(slog.DiscardHandler)}
	r.Reload = func(_ context.Context, unit string) error {
		// Every file of the certificate is in place and matches before any reload.
		dir := filepath.Join(state, "home")
		chain, _ := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
		if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "key.pem")); err != nil || !bytes.Equal(chain, iss.last) {
			t.Errorf("reload of %s before the files were in place: %v", unit, err)
		}
		reloads = append(reloads, unit)
		return nil
	}
	return r, iss, &reloads
}

var home = config.Certificate{Name: "home", Group: strconv.Itoa(os.Getegid()), Issuer: "acme", Hosts: []string{"*.uchi.example.org", "uchi.example.org"}, Reload: []string{"genkan.service", "other.service"}}

func TestRunWritesThenReloads(t *testing.T) {
	r, iss, reloads := setup(t)
	if err := r.Run(context.Background(), []config.Certificate{home}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*reloads, home.Reload) {
		t.Fatalf("reloads %v", *reloads)
	}
	entries, _ := os.ReadDir(filepath.Join(r.StateDir, "home"))
	if len(entries) != 2 {
		t.Fatalf("want exactly fullchain.pem and key.pem, got %v", entries)
	}
	for _, e := range entries {
		if info, _ := e.Info(); info.Mode().Perm() != 0o640 {
			t.Fatalf("%s mode %v, want 0640", e.Name(), info.Mode().Perm())
		}
	}

	// Nothing due: no order, no reload.
	*reloads = nil
	if err := r.Run(context.Background(), []config.Certificate{home}); err != nil || iss.calls != 1 || len(*reloads) != 0 {
		t.Fatalf("second run: err %v, issues %d, reloads %v", err, iss.calls, *reloads)
	}

	// Hosts changed: renewed.
	changed := home
	changed.Hosts = []string{"uchi.example.org"}
	if err := r.Run(context.Background(), []config.Certificate{changed}); err != nil || iss.calls != 2 {
		t.Fatalf("hosts changed: err %v, issues %d", err, iss.calls)
	}

	// Missing key: renewed.
	os.Remove(filepath.Join(r.StateDir, "home", "key.pem"))
	if err := r.Run(context.Background(), []config.Certificate{changed}); err != nil || iss.calls != 3 {
		t.Fatalf("key absent: err %v, issues %d", err, iss.calls)
	}
}

// H3 of the 6959360 review: a run interrupted between the renames of fullchain.pem and key.pem
// leaves a new certificate with the old key; the next run must renew, not report it valid.
func TestRunRenewsMismatchedPair(t *testing.T) {
	r, iss, _ := setup(t)
	r.Reload = func(context.Context, string) error { return nil }
	var out bytes.Buffer
	r.Log = logging.New(&out, slog.LevelInfo)
	if err := r.Run(context.Background(), []config.Certificate{home}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(r.StateDir, "home")
	for _, bad := range [][]byte{nil, []byte("garbage")} {
		// The interrupted run: a fresh certificate for the same hosts renamed in, the key not.
		chain, _, _ := (&stubIssuer{}).Issue(context.Background(), nil, home.Hosts)
		os.WriteFile(filepath.Join(dir, "fullchain.pem"), chain, 0o640)
		if bad != nil {
			os.WriteFile(filepath.Join(dir, "key.pem"), bad, 0o640) // or a corrupt key
		}
		calls := iss.calls
		if err := r.Run(context.Background(), []config.Certificate{home}); err != nil || iss.calls != calls+1 {
			t.Fatalf("mismatched pair: err %v, issues %d, want %d", err, iss.calls, calls+1)
		}
		if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "key.pem")); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(out.String(), `"reason":"key absent or not matching the certificate"`) {
		t.Fatalf("log:\n%s", out.String())
	}
}

// Review H3 (batch 2): a publication that fails after renaming fullchain.pem but not key.pem
// is completed by the next run from the saved pair, without a second order.
func TestRunResumesInterruptedPublication(t *testing.T) {
	r, iss, reloads := setup(t)
	dir := filepath.Join(r.StateDir, "home")
	// Real fault: key.pem becomes a non-empty directory while the order runs, so its rename fails.
	iss.hold = func() {
		if err := os.MkdirAll(filepath.Join(dir, "key.pem", "x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Run(context.Background(), []config.Certificate{home}); err == nil {
		t.Fatal("failed publication reported success")
	}
	if len(*reloads) != 0 {
		t.Fatalf("reloaded a half-published pair: %v", *reloads)
	}
	iss.hold = nil
	if err := os.RemoveAll(filepath.Join(dir, "key.pem")); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background(), []config.Certificate{home}); err != nil {
		t.Fatal(err)
	}
	if iss.calls != 1 || !slices.Equal(*reloads, home.Reload) {
		t.Fatalf("orders %d, reloads %v", iss.calls, *reloads)
	}
	if _, err := os.Stat(filepath.Join(dir, ".reload-pending")); !os.IsNotExist(err) {
		t.Fatalf("marker not cleared: %v", err)
	}
}

// H5 of the 6959360 review: a certificate directory that is missing or not as the module makes
// it fails the certificate before any order, so no issued certificate is thrown away.
func TestRunChecksDirectoryBeforeOrdering(t *testing.T) {
	for name, spoil := range map[string]func(dir string) error{
		"missing":        os.Remove,
		"a file":         func(dir string) error { os.Remove(dir); return os.WriteFile(dir, nil, 0o600) },
		"group-writable": func(dir string) error { return os.Chmod(dir, 0o770) },
	} {
		t.Run(name, func(t *testing.T) {
			r, iss, _ := setup(t)
			if err := spoil(filepath.Join(r.StateDir, "home")); err != nil {
				t.Fatal(err)
			}
			err := r.Run(context.Background(), []config.Certificate{home})
			if err == nil || !strings.Contains(err.Error(), "directory") || iss.calls != 0 {
				t.Fatalf("err %v, issues %d, want an error and no order", err, iss.calls)
			}
		})
	}
}

func TestRunFailureKeepsGoing(t *testing.T) {
	r, iss, reloads := setup(t)
	iss.fail = "cv.example.org"
	cv := config.Certificate{Name: "cv", Group: strconv.Itoa(os.Getegid()), Issuer: "acme", Hosts: []string{"cv.example.org"}, Reload: []string{"cv.service"}}
	err := r.Run(context.Background(), []config.Certificate{cv, home})
	if err == nil || !strings.Contains(err.Error(), "cv:") || strings.Contains(err.Error(), "home") {
		t.Fatalf("want an error naming cv only, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.StateDir, "cv", "fullchain.pem")); !os.IsNotExist(err) {
		t.Fatal("files written for a failed certificate")
	}
	if !slices.Equal(*reloads, home.Reload) {
		t.Fatalf("reloads %v", *reloads)
	}
}

func TestConcurrentRunWaitsThenRenewsNothing(t *testing.T) {
	r, iss, _ := setup(t)
	r.Reload = func(context.Context, string) error { return nil }
	entered, release := make(chan struct{}), make(chan struct{})
	iss.hold = func() { close(entered); <-release }

	first, second := make(chan error), make(chan error)
	go func() { first <- r.Run(context.Background(), []config.Certificate{home}) }()
	select {
	case <-entered:
	case err := <-first:
		t.Fatalf("first run ended before issuing: %v", err)
	}
	r2 := *r // a separate open of the lock file, as a second process would have
	go func() { second <- r2.Run(context.Background(), []config.Certificate{home}) }()
	select {
	case err := <-second:
		t.Fatalf("second run finished while the first held the lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	iss.hold = nil
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil || iss.calls != 1 {
		t.Fatalf("second run: err %v, issues %d, want 1", err, iss.calls)
	}
}

// TestMain doubles as systemctl so command/transport failures are tested without systemd.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) != "systemctl" {
		os.Exit(m.Run())
	}
	f, _ := os.OpenFile(os.Getenv("FAKE_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	f.WriteString(strings.Join(os.Args[1:], " ") + "\n")
	f.Close()
	if slices.Contains(os.Args, "show") {
		if os.Getenv("FAKE_SHOW_FAIL") == "1" {
			os.Exit(1)
		}
		fmt.Print(os.Getenv("FAKE_PROPERTIES"))
	} else if os.Getenv("FAKE_ACTION_FAIL") == "1" {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestSystemctl(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.Symlink(exe, filepath.Join(bin, "systemctl")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	for _, tc := range []struct {
		name, props, action                  string
		showFail, actionFail, fail, inactive bool
	}{
		{name: "inactive", props: "LoadState=loaded\nActiveState=inactive\nCanReload=yes\n", inactive: true},
		{name: "activating", props: "LoadState=loaded\nActiveState=activating\nCanReload=yes\n", inactive: true},
		{name: "reload", props: "LoadState=loaded\nActiveState=active\nCanReload=yes\n", action: "reload"},
		{name: "no reload support", props: "LoadState=loaded\nActiveState=active\nCanReload=no\n", action: "restart"},
		{name: "reload failure never restarts", props: "LoadState=loaded\nActiveState=active\nCanReload=yes\n", action: "reload", actionFail: true, fail: true},
		{name: "restart failure", props: "LoadState=loaded\nActiveState=active\nCanReload=no\n", action: "restart", actionFail: true, fail: true},
		{name: "bus failure", showFail: true, fail: true},
		{name: "missing unit", props: "LoadState=not-found\nActiveState=inactive\nCanReload=no\n", fail: true},
		{name: "malformed properties", props: "LoadState=loaded\nActiveState=active\n", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := filepath.Join(t.TempDir(), "calls")
			t.Setenv("FAKE_LOG", log)
			t.Setenv("FAKE_PROPERTIES", tc.props)
			t.Setenv("FAKE_SHOW_FAIL", "0")
			if tc.showFail {
				t.Setenv("FAKE_SHOW_FAIL", "1")
			}
			t.Setenv("FAKE_ACTION_FAIL", "0")
			if tc.actionFail {
				t.Setenv("FAKE_ACTION_FAIL", "1")
			}
			err := Systemctl(context.Background(), "c.service")
			calls, _ := os.ReadFile(log)
			want := "show --property=LoadState,ActiveState,CanReload -- c.service\n"
			if tc.action != "" {
				want += "--no-ask-password " + tc.action + " -- c.service\n"
			}
			if (err != nil) != (tc.fail || tc.inactive) || errors.Is(err, ErrInactive) != tc.inactive || string(calls) != want {
				t.Fatalf("err %v, calls %q, want %q", err, calls, want)
			}
		})
	}
	t.Run("missing executable", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if err := Systemctl(context.Background(), "c.service"); err == nil || errors.Is(err, ErrInactive) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := Systemctl(ctx, "c.service"); err == nil || errors.Is(err, ErrInactive) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestRunSkipsInactiveUnits(t *testing.T) {
	r, _, _ := setup(t)
	var out bytes.Buffer
	r.Log = logging.New(&out, slog.LevelInfo)
	r.Reload = func(_ context.Context, unit string) error {
		if unit == "other.service" {
			return ErrInactive
		}
		return nil
	}
	if err := r.Run(context.Background(), []config.Certificate{home}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`"event":"certificate-written","certificate":"home","not_after":"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z"`),
		regexp.MustCompile(`"event":"reload-skipped","certificate":"home","unit":"other.service"`),
		regexp.MustCompile(`"event":"run-completed","certificates":1,"renewed":1,"failed":0,"dur_us":\d+}`),
	} {
		if !want.MatchString(s) {
			t.Errorf("no %s in log:\n%s", want, s)
		}
	}
	if strings.Contains(s, `"event":"reload-failed"`) {
		t.Fatalf("log:\n%s", s)
	}
}

// A run that fails before any certificate (here, no state directory for the lock) says so.
func TestRunLogsLockFailure(t *testing.T) {
	var out bytes.Buffer
	r := &Runner{StateDir: filepath.Join(t.TempDir(), "absent"), Log: logging.New(&out, slog.LevelInfo)}
	if err := r.Run(context.Background(), nil); err == nil {
		t.Fatal("want an error")
	}
	if s := out.String(); !strings.Contains(s, `"level":"error","v":1,"event":"run-failed","err":`) {
		t.Fatalf("log:\n%s", s)
	}
}

func TestRunRetriesFailedReloadWithoutIssuing(t *testing.T) {
	r, iss, _ := setup(t)
	var out bytes.Buffer
	r.Log = logging.New(&out, slog.LevelInfo)
	r.Reload = func(ctx context.Context, _ string) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > time.Minute || time.Until(deadline) < 50*time.Second {
			t.Errorf("reload deadline %v", deadline)
		}
		return errors.New("reload rejected")
	}
	if err := r.Run(context.Background(), []config.Certificate{home}); err == nil {
		t.Fatal("delivery failure reported success")
	}
	if !strings.Contains(out.String(), `"renewed":1,"failed":1`) {
		t.Fatalf("summary %s", &out)
	}
	marker := filepath.Join(r.StateDir, "home", ".reload-pending")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal(err)
	}
	next := *r
	calls := 0
	next.Reload = func(context.Context, string) error { calls++; return nil }
	if err := next.Run(context.Background(), []config.Certificate{home}); err != nil {
		t.Fatal(err)
	}
	if iss.calls != 1 || calls != len(home.Reload) {
		t.Fatalf("orders %d, reloads %d", iss.calls, calls)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker not cleared: %v", err)
	}
	// Crash after installing files and before reload: recover the durable intent next run.
	if err := os.WriteFile(marker, []byte("pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := next.Run(context.Background(), []config.Certificate{home}); err != nil {
		t.Fatal(err)
	}
	if iss.calls != 1 || calls != 2*len(home.Reload) {
		t.Fatalf("crash recovery: orders %d, reloads %d", iss.calls, calls)
	}
}

func TestRunChecksExistingState(t *testing.T) {
	for _, kind := range []string{"certificate symlink", "state symlink", "lock symlink", "key symlink", "key permissions", "missing setgid", "wrong group", "state writable"} {
		t.Run(kind, func(t *testing.T) {
			r, iss, _ := setup(t)
			if err := r.Run(context.Background(), []config.Certificate{home}); err != nil {
				t.Fatal(err)
			}
			c := home
			dir := filepath.Join(r.StateDir, c.Name)
			key := filepath.Join(dir, "key.pem")
			outside := t.TempDir()
			switch kind {
			case "certificate symlink":
				os.Rename(dir, dir+"-old")
				os.Symlink(outside, dir)
			case "state symlink":
				os.Rename(r.StateDir, r.StateDir+"-old")
				t.Cleanup(func() { os.RemoveAll(r.StateDir + "-old") })
				os.Symlink(outside, r.StateDir)
			case "lock symlink":
				os.Remove(filepath.Join(r.StateDir, ".lock"))
				os.Symlink(filepath.Join(outside, "lock"), filepath.Join(r.StateDir, ".lock"))
			case "key symlink":
				os.Rename(key, filepath.Join(outside, "key"))
				os.Symlink(filepath.Join(outside, "key"), key)
			case "key permissions":
				os.Chmod(key, 0o644)
			case "missing setgid":
				os.Chmod(dir, 0o750)
			case "wrong group":
				c.Group = strconv.Itoa(os.Getegid() + 1)
			case "state writable":
				os.Chmod(r.StateDir, 0o777)
			}
			if err := r.Run(context.Background(), []config.Certificate{c}); err == nil {
				t.Fatal("unsafe existing state accepted")
			}
			if iss.calls != 1 {
				t.Fatalf("unexpected order: %d", iss.calls)
			}
		})
	}
}

// This delivery-only check also runs on filesystems that cannot retain setgid.
func TestReloadFailurePreservesIntent(t *testing.T) {
	root, err := os.OpenRoot(testutil.StateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	root.WriteFile(".reload-pending", []byte("pending"), 0o600)
	r := &Runner{Log: slog.New(slog.DiscardHandler)}
	calls := 0
	r.Reload = func(ctx context.Context, unit string) error {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < 50*time.Second || time.Until(deadline) > time.Minute {
			t.Errorf("reload budget: %v", deadline)
		}
		return errors.New("rejected")
	}
	if err := r.reload(context.Background(), root, home); err == nil {
		t.Fatal("reload failure disappeared")
	}
	if calls != len(home.Reload) {
		t.Fatal("did not try every consumer")
	}
	if _, err := root.Stat(".reload-pending"); err != nil {
		t.Fatal("lost pending intent")
	}
	r.Reload = func(context.Context, string) error { return nil }
	if err := r.reload(context.Background(), root, home); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Stat(".reload-pending"); !os.IsNotExist(err) {
		t.Fatalf("intent not cleared: %v", err)
	}
}
