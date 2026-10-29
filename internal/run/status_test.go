package run

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/logging"
)

// status runs Status and decodes its single line.
func status(t *testing.T, r *Runner, c config.Certificate) (map[string]any, error) {
	t.Helper()
	var out bytes.Buffer
	err := Status(r.StateDir, []config.Certificate{c}, logging.New(&out, slog.LevelInfo))
	var line map[string]any
	if jerr := json.Unmarshal(out.Bytes(), &line); jerr != nil {
		t.Fatalf("%v: %q", jerr, out.String())
	}
	return line, err
}

func TestStatus(t *testing.T) {
	r, iss, _ := setup(t)

	line, err := status(t, r, home)
	if err == nil || line["level"] != "error" || line["valid"] != false || line["reason"] != "absent" || line["last_result"] != "none" || line["last_run"] != nil {
		t.Fatalf("before any run: err %v, line %v", err, line)
	}

	if err := r.Run(context.Background(), []config.Certificate{home}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(r.StateDir, lastRunFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%s: %v %v", lastRunFile, info, err)
	}
	line, err = status(t, r, home)
	if err != nil || line["event"] != "certificate-status" || line["level"] != "info" || line["valid"] != true ||
		line["last_result"] != "ok" || line["issuer"] != "acme" || line["not_after"] == nil || line["last_run"] == nil || line["err"] != nil {
		t.Fatalf("after a run: err %v, line %v", err, line)
	}
	if hosts, _ := line["hosts"].([]any); len(hosts) != 2 {
		t.Fatalf("hosts %v", line["hosts"])
	}

	// M3: a failed run (here the order fails, as with a broken TSIG key) exits non-zero, and
	// status still shows the published certificate valid, with the failure.
	broken := home
	broken.Hosts = append([]string{"new.example.org"}, home.Hosts...)
	iss.fail = "new.example.org"
	if err := r.Run(context.Background(), []config.Certificate{broken}); err == nil {
		t.Fatal("the failed run returned no error")
	}
	line, err = status(t, r, broken)
	if err != nil || line["level"] != "warn" || line["valid"] != true || line["last_result"] != "failed" || line["err"] != "validation failed" {
		t.Fatalf("after a failed run: err %v, line %v", err, line)
	}
}

func TestStatusRejectsUnreadableState(t *testing.T) {
	r, _, _ := setup(t)
	if err := os.WriteFile(filepath.Join(r.StateDir, lastRunFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	line, err := status(t, r, home)
	if err == nil || line["event"] != "status-failed" {
		t.Fatalf("err %v, line %v", err, line)
	}
}
