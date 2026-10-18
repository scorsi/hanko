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
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scorsi/hanko/internal/config"
)

// stubIssuer self-signs 90-day certificates, or fails for the hosts in fail.
type stubIssuer struct {
	calls int
	fail  string
	last  []byte
	hold  func() // called inside Issue when set
}

func (s *stubIssuer) Issue(_ context.Context, hosts []string) ([]byte, []byte, error) {
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
	state := t.TempDir()
	for _, n := range []string{"home", "cv"} {
		os.Mkdir(filepath.Join(state, n), 0o750)
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
		return errors.New("reload errors are logged only")
	}
	return r, iss, &reloads
}

var home = config.Certificate{Name: "home", Issuer: "acme", Hosts: []string{"*.uchi.example.org", "uchi.example.org"}, Reload: []string{"genkan.service", "other.service"}}

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

func TestRunFailureKeepsGoing(t *testing.T) {
	r, iss, reloads := setup(t)
	iss.fail = "cv.example.org"
	cv := config.Certificate{Name: "cv", Issuer: "acme", Hosts: []string{"cv.example.org"}, Reload: []string{"cv.service"}}
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
	<-entered
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

// TestMain doubles as a fake systemctl: Systemctl's tests put a "systemctl" symlink to this
// binary first in PATH. It logs its arguments; FAKE_ACTIVE=1 makes is-active succeed,
// FAKE_RELOAD=1 makes reload succeed; restart always succeeds.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) != "systemctl" {
		os.Exit(m.Run())
	}
	f, _ := os.OpenFile(os.Getenv("FAKE_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	f.WriteString(strings.Join(os.Args[1:], " ") + "\n")
	f.Close()
	if slices.Contains(os.Args, "is-active") && os.Getenv("FAKE_ACTIVE") != "1" ||
		slices.Contains(os.Args, "reload") && os.Getenv("FAKE_RELOAD") != "1" {
		os.Exit(3)
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
		active, reload string
		err            error
		calls          string
	}{
		{"0", "1", ErrInactive, "is-active --quiet c.service\n"},
		{"1", "1", nil, "is-active --quiet c.service\n--no-ask-password reload c.service\n"},
		{"1", "0", nil, "is-active --quiet c.service\n--no-ask-password reload c.service\n--no-ask-password restart c.service\n"},
	} {
		log := filepath.Join(t.TempDir(), "calls")
		t.Setenv("FAKE_LOG", log)
		t.Setenv("FAKE_ACTIVE", tc.active)
		t.Setenv("FAKE_RELOAD", tc.reload)
		err := Systemctl(context.Background(), "c.service")
		calls, _ := os.ReadFile(log)
		if !errors.Is(err, tc.err) || string(calls) != tc.calls {
			t.Errorf("active %s reload %s: err %v, calls %q", tc.active, tc.reload, err, calls)
		}
	}
}

func TestRunSkipsInactiveUnits(t *testing.T) {
	r, _, _ := setup(t)
	var out bytes.Buffer
	r.Log = slog.New(slog.NewTextHandler(&out, nil))
	r.Reload = func(_ context.Context, unit string) error {
		if unit == "other.service" {
			return ErrInactive
		}
		return nil
	}
	if err := r.Run(context.Background(), []config.Certificate{home}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, `msg="reload skipped, unit not active" certificate=home unit=other.service`) || strings.Contains(s, "reload failed") {
		t.Fatalf("log:\n%s", s)
	}
}
