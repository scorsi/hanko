package issuer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/logging"
	"github.com/scorsi/hanko/internal/state"
	"github.com/scorsi/hanko/internal/testutil"
)

func TestAccountKeyPermissions(t *testing.T) {
	root, err := state.Open(testutil.StateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := accountKey(root, "account.key", true); err != nil {
		t.Fatal(err)
	}
	original, _ := root.ReadFile("account.key")
	root.Chmod("account.key", 0o644)
	if _, err := accountKey(root, "account.key", true); err == nil {
		t.Fatal("public account key accepted")
	}
	if got, _ := root.ReadFile("account.key"); !bytes.Equal(got, original) {
		t.Fatal("account key replaced")
	}
	root.Chmod("account.key", 0o600)
	root.Symlink("account.key", "alias")
	if _, err := accountKey(root, "alias", true); err == nil {
		t.Fatal("account key symlink accepted")
	}
	if _, err := accountKey(root, "account.key", false); err != nil {
		t.Fatal(err)
	}
}

func TestCAErrorsDoNotLogChallengeMaterial(t *testing.T) {
	const marker = "SECRET_CHALLENGE_MARKER"
	root, err := state.Open(testutil.StateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p := &acme.Error{StatusCode: 400, ProblemType: "urn:ietf:params:acme:error:dns", Detail: marker, Instance: marker,
		Subproblems: []acme.Subproblem{{Type: marker, Detail: marker}}}
	for _, raw := range []error{
		p, &acme.AuthorizationError{URI: marker, Identifier: marker, Errors: []error{p}},
		&acme.OrderError{OrderURL: marker, Status: marker, Problem: p},
		&acme.Error{StatusCode: 400, ProblemType: marker, Detail: marker}, errors.New(marker),
	} {
		i := &Issuer{}
		safe := i.failure(root, "validation", raw)
		var out bytes.Buffer
		logging.New(&out, slog.LevelInfo).Error("", "event", "certificate-failed", "err", safe)
		if strings.Contains(out.String(), marker) || strings.Contains(safe.Error(), marker) {
			t.Fatalf("secret leaked: %s", &out)
		}
	}
}

func TestRetryDeadlineSurvivesCertificatesAndRuns(t *testing.T) {
	for _, header := range []string{"7200", time.Now().Add(3 * time.Hour).UTC().Format(http.TimeFormat), ""} {
		t.Run(header, func(t *testing.T) {
			root, err := state.Open(testutil.StateDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			cfg := config.ACME{Directory: "https://ca.example.org/dir", AccountKeyFile: filepath.Join(root.Name(), "account.key")}
			i := &Issuer{ACME: cfg}
			err = i.failure(root, "new order", &acme.Error{StatusCode: 429, ProblemType: "urn:ietf:params:acme:error:rateLimited", Header: http.Header{"Retry-After": {header}}})
			if !strings.Contains(err.Error(), "retry deferred until") {
				t.Fatal(err)
			}
			for _, next := range []*Issuer{i, {ACME: cfg}} {
				// No DNS config or key exists: a deferred order must return before touching either.
				_, _, err := next.Issue(context.Background(), root, hosts)
				if err == nil || !strings.Contains(err.Error(), "retry deferred until") {
					t.Fatalf("retry contacted dependencies: %v", err)
				}
			}
			other := &Issuer{ACME: cfg}
			other.ACME.Directory = "https://staging.example.org/dir"
			if err := other.checkRetry(root); err != nil {
				t.Fatalf("unrelated CA blocked: %v", err)
			}
			saved, _ := json.Marshal(retryState{Scope: i.retryScope(), Until: time.Now().Add(-time.Second)})
			state.WriteFiles(root, 0o600, state.File{Name: ".retry-after", Data: saved})
			if err := (&Issuer{ACME: cfg}).checkRetry(root); err != nil {
				t.Fatalf("expired deadline blocks: %v", err)
			}
		})
	}
}

func TestRetryDeadlineErrors(t *testing.T) {
	root, err := state.Open(testutil.StateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	i := &Issuer{}
	root.WriteFile(".retry-after", []byte("SECRET"), 0o600)
	if err := i.checkRetry(root); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unsafe retry state: %v", err)
	}
	root.Remove(".retry-after")
	root.Mkdir(".retry-after", 0o700)
	err = i.failure(root, "order", &acme.OrderError{Problem: &acme.Error{StatusCode: 503, Header: http.Header{"Retry-After": {"3600"}}}})
	if err == nil || !i.retryUntil.After(time.Now()) {
		t.Fatalf("lost in-memory deadline on disk failure: %v", err)
	}
	if now := time.Now(); !retryAfter("9223372036854775807", now).IsZero() {
		t.Fatal("overflowing retry accepted")
	}
}

func TestRetryLegacyProblemAndPastDeadline(t *testing.T) {
	for _, p := range []*acme.Error{
		{StatusCode: 400, ProblemType: "urn:acme:error:RATELIMITED"},
		{StatusCode: 429, Header: http.Header{"Retry-After": {"0"}}},
		{StatusCode: 429, Header: http.Header{"Retry-After": {"Wed, 21 Oct 2015 07:28:00 GMT"}}},
	} {
		root, err := state.Open(testutil.StateDir(t))
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		i := &Issuer{}
		i.failure(root, "order", p)
		if !i.retryUntil.After(time.Now()) {
			t.Fatal("rate limit did not defer remaining certificates")
		}
	}
}
