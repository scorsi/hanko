package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCAKeygen(t *testing.T) {
	cert := filepath.Join(t.TempDir(), "ca.pem")
	var out bytes.Buffer
	if err := caKeygen([]string{"--name", "hanko CA", "--cert", cert}, &out, time.Now()); err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(cert)
	if err != nil || !strings.HasPrefix(string(pem), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("cert file: %q %v", pem, err)
	}
	if !strings.HasPrefix(out.String(), "-----BEGIN PRIVATE KEY-----") || strings.Contains(out.String(), "CERTIFICATE") {
		t.Fatalf("stdout is not the key alone: %q", out.String())
	}

	// An existing --cert is never overwritten, and no key is printed.
	out.Reset()
	if err := caKeygen([]string{"--name", "x", "--cert", cert}, &out, time.Now()); !errors.Is(err, os.ErrExist) || out.Len() > 0 {
		t.Fatalf("existing cert: %v, stdout %d bytes", err, out.Len())
	}
	if again, _ := os.ReadFile(cert); !bytes.Equal(again, pem) {
		t.Fatal("existing cert changed")
	}

	fresh := filepath.Join(t.TempDir(), "ca.pem")
	for _, args := range [][]string{
		{"--cert", fresh},
		{"--name", "x"},
		{"--name", "x", "--cert", fresh, "extra"},
		{"--name", "x", "--cert", fresh, "--days", "y"},
	} {
		if err := caKeygen(args, &out, time.Now()); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v, want a usage error", args, err)
		}
	}
	for _, days := range []string{"0", "-1", "3000000", "99999999999999999999"} {
		if err := caKeygen([]string{"--name", "x", "--cert", fresh, "--days", days}, &out, time.Now()); err == nil {
			t.Errorf("--days %s accepted", days)
		}
	}
	if _, err := os.Stat(fresh); !errors.Is(err, os.ErrNotExist) || out.Len() > 0 {
		t.Fatalf("a refused run left a file (%v) or printed %d bytes", err, out.Len())
	}

	// A key nobody received leaves no certificate behind.
	if err := caKeygen([]string{"--name", "x", "--cert", fresh}, failWriter{}, time.Now()); err == nil {
		t.Fatal("failed stdout write reported success")
	}
	if _, err := os.Stat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("certificate left after a failed key write: %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }
