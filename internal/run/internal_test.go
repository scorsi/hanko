package run

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/issuer"
	"github.com/scorsi/hanko/internal/logging"
	"github.com/scorsi/hanko/internal/svid"
	"github.com/scorsi/hanko/internal/testutil"
)

const idAPI = "spiffe://uchi.example.org/vm/api"

var api = config.Certificate{Name: "api", Group: strconv.Itoa(os.Getegid()), Issuer: "internal", SpiffeID: idAPI}

// internalSetup is a state directory with the api certificate directory and a runner that
// fails the test on any reload: consumers of internal certificates reload themselves (ADR 0013).
func internalSetup(t *testing.T, addr string) (*Runner, *bytes.Buffer) {
	state := testutil.StateDir(t)
	dir := filepath.Join(state, "api")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	testutil.SetgidDir(t, dir)
	var log bytes.Buffer
	r := &Runner{Internal: &svid.Client{Addr: addr}, StateDir: state, Log: logging.New(&log, nil), RenewFraction: 0.5}
	r.Reload = func(_ context.Context, unit string) error {
		t.Errorf("reload of %s for an internal certificate", unit)
		return nil
	}
	return r, &log
}

func read(t *testing.T, r *Runner, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.StateDir, "api", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestInternal follows an SVID through issuance, an idle run and the CA rotation of ADR 0012:
// the bundle alone is refreshed and delivered on every run, and the SVID is renewed once its
// CA leaves the bundle.
func TestInternal(t *testing.T) {
	ctx := context.Background()
	key, cert := testutil.CACert(t, time.Now().Add(365*24*time.Hour))
	r, log := internalSetup(t, testutil.ServeCA(t, key, cert, "24h", idAPI))
	if err := r.Run(ctx, []config.Certificate{api}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"svid.pem", "key.pem", "bundle.pem"} {
		if info, err := os.Stat(filepath.Join(r.StateDir, "api", f)); err != nil || info.Mode().Perm() != 0o640 {
			t.Fatalf("%s: %v %v", f, info, err)
		}
	}
	if _, err := os.Stat(filepath.Join(r.StateDir, "api", ".reload-pending")); !os.IsNotExist(err) {
		t.Fatalf(".reload-pending left: %v", err)
	}
	first := read(t, r, "svid.pem")
	if !bytes.Equal(read(t, r, "bundle.pem"), cert) ||
		!strings.Contains(log.String(), `"event":"certificate-renewing","certificate":"api","reason":"absent","spiffe_id":"`+idAPI+`"`) {
		t.Fatalf("first run: log %s", log)
	}

	// Nothing due, same bundle: no request but Bundle.
	log.Reset()
	if err := r.Run(ctx, []config.Certificate{api}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read(t, r, "svid.pem"), first) || !strings.Contains(log.String(), `"event":"certificate-valid"`) ||
		strings.Contains(log.String(), "bundle-written") {
		t.Fatalf("idle run: log %s", log)
	}

	// Rotation (a): the next CA joins cert_file. The bundle alone changes and is written.
	nextKey, next := testutil.CACert(t, time.Now().Add(2*365*24*time.Hour))
	r.Internal = &svid.Client{Addr: testutil.ServeCA(t, key, append(slices.Clip(cert), next...), "24h", idAPI)}
	log.Reset()
	if err := r.Run(ctx, []config.Certificate{api}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read(t, r, "svid.pem"), first) || !bytes.Equal(read(t, r, "bundle.pem"), append(slices.Clip(cert), next...)) ||
		!strings.Contains(log.String(), `"event":"bundle-written","certificate":"api"`) {
		t.Fatalf("new bundle: log %s", log)
	}

	// (b): the next key signs; the old SVID still verifies against the old CA in the bundle.
	r.Internal = &svid.Client{Addr: testutil.ServeCA(t, nextKey, append(slices.Clip(cert), next...), "24h", idAPI)}
	if err := r.Run(ctx, []config.Certificate{api}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read(t, r, "svid.pem"), first) || !bytes.Equal(read(t, r, "bundle.pem"), append(slices.Clip(next), cert...)) {
		t.Fatal("step (b) renewed the SVID or kept the old bundle")
	}

	// The old CA removed: the SVID it signed no longer verifies and is renewed by the new key.
	r.Internal = &svid.Client{Addr: testutil.ServeCA(t, nextKey, next, "24h", idAPI)}
	log.Reset()
	if err := r.Run(ctx, []config.Certificate{api}); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(read(t, r, "svid.pem"), first) || !bytes.Equal(read(t, r, "bundle.pem"), next) ||
		!strings.Contains(log.String(), `"reason":"not signed by a CA of the bundle"`) {
		t.Fatalf("old CA removed: log %s", log)
	}

	// An ID this address may not request is refused; the published SVID stays.
	current := read(t, r, "svid.pem")
	other := api
	other.SpiffeID = "spiffe://uchi.example.org/vm/git"
	log.Reset()
	if err := r.Run(ctx, []config.Certificate{other}); !errors.Is(err, issuer.ErrNoQuickRetry) || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("refused ID: %v", err)
	}
	if !bytes.Equal(read(t, r, "svid.pem"), current) ||
		!regexp.MustCompile(`"event":"certificate-failed","certificate":"api","not_after":"[0-9T:.-]+Z","err":`).MatchString(log.String()) ||
		!strings.Contains(log.String(), `"failed":1,"exit":10,`) ||
		!strings.Contains(log.String(), `"event":"certificate-renewing","certificate":"api","reason":"spiffe_id changed","spiffe_id":"spiffe://uchi.example.org/vm/git","not_after":"`) {
		t.Fatalf("refused ID: log %s", log)
	}
}

// TestInternalUnreachable: a run that cannot reach hanko-ca fails, even with a valid SVID, so
// a stale bundle is noticed (OnFailure); the files stay.
func TestInternalUnreachable(t *testing.T) {
	key, cert := testutil.CACert(t, time.Now().Add(365*24*time.Hour))
	r, log := internalSetup(t, testutil.ServeCA(t, key, cert, "24h", idAPI))
	if err := r.Run(context.Background(), []config.Certificate{api}); err != nil {
		t.Fatal(err)
	}
	r.Internal = &svid.Client{Addr: "127.0.0.1:1"}
	if err := r.Run(context.Background(), []config.Certificate{api}); err == nil || errors.Is(err, issuer.ErrNoQuickRetry) {
		t.Fatalf("run without hanko-ca: %v, want a retryable failure", err)
	}
	if !strings.Contains(log.String(), `"event":"certificate-failed","certificate":"api","not_after":"`) ||
		!strings.Contains(log.String(), `"failed":1,"exit":1,`) {
		t.Fatalf("log: %s", log)
	}
	line, err := status(t, r, api)
	if err != nil || line["valid"] != true || line["last_result"] != "failed" {
		t.Fatalf("status: %v %v", err, line)
	}
}

// TestInternalNearCAEnd: an SVID capped at its CA's end is not renewed on every run, and
// status warns that the CA expires soon.
func TestInternalNearCAEnd(t *testing.T) {
	key, cert := testutil.CACert(t, time.Now().Add(10*time.Minute))
	r, log := internalSetup(t, testutil.ServeCA(t, key, cert, "24h", idAPI))
	for range 2 {
		if err := r.Run(context.Background(), []config.Certificate{api}); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(log.String(), `"event":"certificate-written"`); n != 1 {
		t.Fatalf("%d issuances: %s", n, log)
	}
	line, err := status(t, r, api)
	if err != nil || line["level"] != "warn" || line["valid"] != true || line["ca_expiring"] != true ||
		line["spiffe_id"] != idAPI || line["ca_not_after"] == nil || line["issuer"] != "internal" {
		t.Fatalf("status: %v %v", err, line)
	}
}

func TestInternalStatus(t *testing.T) {
	key, cert := testutil.CACert(t, time.Now().Add(365*24*time.Hour))
	r, _ := internalSetup(t, testutil.ServeCA(t, key, cert, "24h", idAPI))
	if err := r.Run(context.Background(), []config.Certificate{api}); err != nil {
		t.Fatal(err)
	}
	line, err := status(t, r, api)
	if err != nil || line["level"] != "info" || line["valid"] != true || line["ca_expiring"] != false || line["spiffe_id"] != idAPI || line["hosts"] != nil {
		t.Fatalf("status: %v %v", err, line)
	}
}
