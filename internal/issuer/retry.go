package issuer

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/scorsi/hanko/internal/state"
)

// shortcut: one saved scope matches the single configured issuer; use per-scope files if multiple accounts are supported.
type retryState struct {
	Scope string    `json:"scope"`
	Until time.Time `json:"until"`
}

// ErrNoQuickRetry is matched by an Issue error that a retry within minutes cannot fix and that
// would spend the CA's limits again: any problem document from the CA (a failed validation
// among them), a retry deadline, or CA output that does not match the order. ADR 0010: such
// a failure waits for the next timer run. Run's error matches it too (ADR 0001 amendment).
var ErrNoQuickRetry = errors.New("a certificate failed for a reason a quick retry cannot fix")

type noQuickRetry struct{ error }

func (e noQuickRetry) Unwrap() error      { return e.error }
func (noQuickRetry) Is(target error) bool { return target == ErrNoQuickRetry }

func (i *Issuer) retryScope() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(i.ACME.Directory+"\x00"+i.ACME.AccountKeyFile)))
}

func (i *Issuer) checkRetry(root *os.Root) error {
	data, err := state.ReadOptional(root, ".retry-after", 0o600, os.Getegid())
	if err != nil {
		return err
	}
	if data != nil {
		var saved retryState
		if json.Unmarshal(data, &saved) != nil || saved.Scope == "" || saved.Until.IsZero() {
			return errors.New("invalid saved ACME retry deadline")
		}
		if saved.Scope == i.retryScope() && saved.Until.After(i.retryUntil) {
			i.retryUntil = saved.Until
		}
	}
	if time.Now().Before(i.retryUntil) {
		return noQuickRetry{fmt.Errorf("acme: retry deferred until %s", i.retryUntil.UTC().Format(time.RFC3339))}
	}
	return nil
}

// failure keeps only approved diagnostic fields. CA details, URLs, identifiers and subproblem
// text can contain challenge material and must never reach the log (ADR 0005).
func (i *Issuer) failure(root *os.Root, operation string, err error) error {
	problems := acmeProblems(err)
	status, problem := 0, "unknown"
	now := time.Now()
	for _, p := range problems {
		status, problem = p.StatusCode, problemName(p.ProblemType)
		header := i.lastRetryAfter // embedded order/authorization problems carry no headers
		if p.Header != nil {
			header = p.Header.Get("Retry-After")
		}
		until := retryAfter(header, now)
		_, limited := acme.RateLimit(p)
		if (limited || p.StatusCode == http.StatusTooManyRequests) && !until.After(now) {
			until = now.Add(time.Hour)
		}
		if until.After(i.retryUntil) {
			i.retryUntil = until
		}
	}
	safe := fmt.Errorf("acme %s failed (HTTP %d, problem %s)", operation, status, problem)
	if i.retryUntil.After(now) {
		data, _ := json.Marshal(retryState{Scope: i.retryScope(), Until: i.retryUntil})
		saveErr := state.WriteFiles(root, 0o600, state.File{Name: ".retry-after", Data: data})
		return noQuickRetry{errors.Join(safe, fmt.Errorf("acme: retry deferred until %s", i.retryUntil.UTC().Format(time.RFC3339)), saveErr)}
	}
	if len(problems) > 0 {
		return noQuickRetry{safe}
	}
	return safe // a transport error: the network or the CA not reachable yet
}

func acmeProblems(err error) []*acme.Error {
	var p *acme.Error
	if errors.As(err, &p) {
		return []*acme.Error{p}
	}
	var order *acme.OrderError
	if errors.As(err, &order) && order.Problem != nil {
		return []*acme.Error{order.Problem}
	}
	var auth *acme.AuthorizationError
	if errors.As(err, &auth) {
		var all []*acme.Error
		for _, e := range auth.Errors {
			all = append(all, acmeProblems(e)...)
		}
		return all
	}
	return nil
}

func retryAfter(s string, now time.Time) time.Time {
	if seconds, err := strconv.ParseUint(s, 10, 63); err == nil {
		// Reject durations that would overflow instead of wrapping into a past deadline.
		if seconds <= uint64((1<<63-1)/int64(time.Second)) {
			return now.Add(time.Duration(seconds) * time.Second)
		}
	}
	if t, err := http.ParseTime(s); err == nil {
		return t
	}
	return time.Time{}
}

func problemName(s string) string {
	s = strings.TrimPrefix(s, "urn:ietf:params:acme:error:")
	switch s {
	case "accountDoesNotExist", "alreadyRevoked", "badCSR", "badNonce", "badPublicKey", "badRevocationReason",
		"badSignatureAlgorithm", "caa", "compound", "connection", "dns", "externalAccountRequired", "incorrectResponse",
		"invalidContact", "malformed", "orderNotReady", "rateLimited", "rejectedIdentifier", "serverInternal", "tls",
		"unauthorized", "unsupportedContact", "unsupportedIdentifier", "userActionRequired":
		return s
	default:
		return "unknown"
	}
}
