package run

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/logging"
	"github.com/scorsi/hanko/internal/state"
)

// lastRunFile holds the outcome of the last run that held the lock (ADR 0011).
const lastRunFile = ".last-run"

type lastRun struct {
	TS           time.Time         `json:"ts"`
	Certificates map[string]result `json:"certificates"`
}

type result struct {
	Result string `json:"result"` // "ok" or "failed"
	Err    string `json:"err,omitempty"`
}

// Status writes one certificate-status line per certificate, read from the files only: no lock,
// no network. It returns an error when the state cannot be read or a certificate is not valid
// now; a failed last run alone is not an error, the certificate may still be served (ADR 0011).
func Status(stateDir string, certs []config.Certificate, log *slog.Logger) error {
	root, err := state.Open(stateDir)
	if err != nil {
		log.Error("", "event", "status-failed", "err", err)
		return err
	}
	defer root.Close()
	data, err := state.ReadOptional(root, lastRunFile, 0o600, os.Getegid())
	last := lastRun{}
	if err == nil && data != nil {
		err = json.Unmarshal(data, &last)
	}
	if err != nil {
		err = fmt.Errorf("%s: %w", lastRunFile, err)
		log.Error("", "event", "status-failed", "err", err)
		return err
	}

	var invalid []error
	for _, c := range certs {
		attrs := []any{"event", "certificate-status", "certificate", c.Name, "issuer", c.Issuer}
		leaf, reason := current(root, c)
		if leaf != nil {
			attrs = append(attrs, "hosts", leaf.DNSNames, "not_after", leaf.NotAfter.UTC().Format(logging.TS))
		}
		attrs = append(attrs, "valid", reason == "")
		if reason != "" {
			attrs = append(attrs, "reason", reason)
			invalid = append(invalid, fmt.Errorf("%s: %s", c.Name, reason))
		}
		res, ok := last.Certificates[c.Name]
		if !ok {
			res.Result = "none" // never run with this certificate configured
		} else {
			attrs = append(attrs, "last_run", last.TS.UTC().Format(logging.TS))
		}
		attrs = append(attrs, "last_result", res.Result)
		level := slog.LevelInfo
		if res.Err != "" {
			level = slog.LevelWarn
			attrs = append(attrs, "err", res.Err) // err only at warn or error (ADR 0007)
		}
		if reason != "" {
			level = slog.LevelError
		}
		log.Log(context.Background(), level, "", attrs...)
	}
	return errors.Join(invalid...)
}

// current returns the published leaf, if it parses, and why the pair cannot be served now ("" if it can).
func current(root *os.Root, c config.Certificate) (*x509.Certificate, string) {
	gid, err := groupID(c.Group)
	if err != nil {
		return nil, err.Error()
	}
	dir, err := state.Directory(root, c.Name, gid, true)
	if err != nil {
		return nil, err.Error()
	}
	defer dir.Close()
	chain, err := state.ReadOptional(dir, "fullchain.pem", 0o640, gid)
	if err != nil {
		return nil, err.Error()
	}
	key, err := state.ReadOptional(dir, "key.pem", 0o640, gid)
	if err != nil {
		return nil, err.Error()
	}
	if chain == nil {
		return nil, "absent"
	}
	block, _ := pem.Decode(chain)
	if block == nil {
		return nil, "unreadable"
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "unreadable"
	}
	if _, err := tls.X509KeyPair(chain, key); err != nil {
		return leaf, "key absent or not matching the certificate"
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return leaf, "expired or not yet valid"
	}
	return leaf, ""
}
