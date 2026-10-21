package issuer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the full ACME HTTP handler without a listening socket; the original flow tests
// still cover loopback HTTP. Tests in this package are deliberately not parallel.
type handlerTransport struct{ ca *fakeCA }

func (h handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	w := httptest.NewRecorder()
	h.ca.ServeHTTP(w, r)
	return w.Result(), nil
}

func memorySetup(t *testing.T) (*Issuer, *fakeCA, *fakeDNS) {
	t.Helper()
	d := &fakeDNS{txt: map[string][]string{}}
	ca := makeCA(d)
	ca.srv = &httptest.Server{URL: "http://127.0.0.1"}
	previous := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: handlerTransport{ca}}
	t.Cleanup(func() { http.DefaultClient = previous })
	return issuerForCA(t, ca, d, true), ca, d
}

func TestIssueFailureCleanup(t *testing.T) {
	for _, kind := range []string{"propagation timeout", "CA rejection", "cancellation"} {
		t.Run(kind, func(t *testing.T) {
			i, ca, d := memorySetup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "propagation timeout":
				d.wait = func(context.Context) error { return context.DeadlineExceeded }
			case "CA rejection":
				ca.reject = true
			case "cancellation":
				d.wait = func(context.Context) error { cancel(); return ctx.Err() }
			}
			if _, _, err := issue(t, i, ctx, hosts); err == nil {
				t.Fatal("want failure")
			}
			for name, txt := range d.txt {
				if len(txt) != 0 {
					t.Fatalf("left challenge at %s", name)
				}
			}
			if d.cleanupCancelled {
				t.Fatal("cleanup used cancelled order context")
			}
			if len(d.log) != 7 {
				t.Fatalf("cleanup operations: %v", d.log)
			}
			if kind != "CA rejection" {
				for _, z := range ca.authzs {
					if z.status != "pending" {
						t.Fatal("accepted challenge after propagation failure")
					}
				}
			}
		})
	}
}

func TestIssueReusedAuthorization(t *testing.T) {
	i, ca, d := memorySetup(t)
	ca.reuse = true
	if _, _, err := issue(t, i, context.Background(), hosts); err != nil {
		t.Fatal(err)
	}
	if len(d.log) != 0 {
		t.Fatalf("revalidated reused authorization: %v", d.log)
	}
}

func TestIssueRejectsMismatchedCAOutput(t *testing.T) {
	for _, what := range []string{"key", "hosts"} {
		t.Run(what, func(t *testing.T) {
			i, ca, d := memorySetup(t)
			ca.mismatch = what
			if chain, key, err := issue(t, i, context.Background(), hosts); err == nil || len(chain) > 0 || len(key) > 0 {
				t.Fatal("mismatched output accepted")
			}
			for _, txt := range d.txt {
				if len(txt) > 0 {
					t.Fatal("challenge not cleaned up")
				}
			}
		})
	}
}

func TestIssueHTTPRateLimitPersists(t *testing.T) {
	i, ca, _ := memorySetup(t)
	ca.retry = "7200"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	if _, _, err := issue(t, i, ctx, hosts); err == nil || !strings.Contains(err.Error(), "retry deferred until") {
		t.Fatalf("rate limit: %v", err)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("slept inside HTTP retry instead of persisting deadline")
	}
	requests := ca.nonce
	for _, next := range []*Issuer{i, issuerForCA(t, ca, ca.dns, true)} {
		next.ACME = i.ACME
		if _, _, err := issue(t, next, context.Background(), hosts); err == nil {
			t.Fatal("retry was not blocked")
		}
	}
	if ca.nonce != requests {
		t.Fatalf("contacted CA %d more times", ca.nonce-requests)
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(i.ACME.AccountKeyFile), ".retry-after"))
	if err != nil || !strings.Contains(string(data), "until") {
		t.Fatalf("no persistent backoff: %v", err)
	}
}

func TestIssueCAErrorLogSanitization(t *testing.T) {
	i, ca, _ := memorySetup(t)
	ca.reject = true
	// A transport may expose the complete server body through an ordinary error as well.
	old := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("SECRET_CHALLENGE_MARKER") })}
	defer func() { http.DefaultClient = old }()
	if _, _, err := issue(t, i, context.Background(), hosts); err == nil || strings.Contains(err.Error(), "SECRET_CHALLENGE_MARKER") {
		t.Fatalf("unsafe error: %v", err)
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
