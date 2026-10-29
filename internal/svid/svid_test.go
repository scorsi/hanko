package svid

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/scorsi/hanko/internal/testutil"
)

const (
	idAPI = "spiffe://uchi.example.org/vm/api"
	idGit = "spiffe://uchi.example.org/vm/git"
)

func leafOf(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	if b == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSign(t *testing.T) {
	key, cert := testutil.CACert(t, time.Now().Add(365*24*time.Hour))
	c := &Client{Addr: testutil.ServeCA(t, key, cert, "24h", idAPI)}
	ctx := context.Background()

	s, k, bundle, err := c.Sign(ctx, idAPI)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(s, k); err != nil || !bytes.Contains(k, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("pair: %v", err)
	}
	leaf := leafOf(t, s)
	if leaf.URIs[0].String() != idAPI || !bytes.Equal(bundle, cert) || SigningCA(leaf, bundle) == nil {
		t.Fatalf("svid %v, bundle %q", leaf.URIs, bundle)
	}
	if r := Due(s, bundle, idAPI, 0.5, time.Now()); r != "" {
		t.Fatalf("fresh SVID due: %s", r)
	}

	// The caller's address is not allowed this ID (ADR 0004).
	if _, _, _, err := c.Sign(ctx, idGit); err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("other ID: %v", err)
	}

	b, err := c.Bundle(ctx)
	if err != nil || !bytes.Equal(b, cert) {
		t.Fatalf("bundle: %v", err)
	}
}

func TestBundleTwoCAs(t *testing.T) {
	key, cert := testutil.CACert(t, time.Now().Add(365*24*time.Hour))
	_, next := testutil.CACert(t, time.Now().Add(2*365*24*time.Hour))
	c := &Client{Addr: testutil.ServeCA(t, key, append(next, cert...), "24h", idAPI)}
	b, err := c.Bundle(context.Background())
	// The signing CA first, whatever the file's order.
	if err != nil || !bytes.Equal(b, append(cert, next...)) {
		t.Fatalf("bundle: %v %q", err, b)
	}
}

// TestDueRealLifetime: near the CA's end hanko-ca caps the SVID, so the half-life rule must use
// NotAfter − NotBefore, not the configured 24 h (or the SVID would be due as soon as issued).
func TestDueRealLifetime(t *testing.T) {
	key, cert := testutil.CACert(t, time.Now().Add(10*time.Minute))
	c := &Client{Addr: testutil.ServeCA(t, key, cert, "24h", idAPI)}
	s, _, bundle, err := c.Sign(context.Background(), idAPI)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafOf(t, s)
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life > 12*time.Minute {
		t.Fatalf("SVID not capped at the CA's end: %v", life)
	}
	now := time.Now()
	for _, tc := range []struct {
		name         string
		svid, bundle []byte
		id           string
		fraction     float64
		at           time.Time
		want         string
	}{
		{"fresh", s, bundle, idAPI, 0.5, now, ""},
		{"past half", s, bundle, idAPI, 0.5, now.Add(5 * time.Minute), "less than half of its lifetime left"},
		{"past half, renew at a quarter", s, bundle, idAPI, 0.25, now.Add(5 * time.Minute), ""},
		{"past three quarters", s, bundle, idAPI, 0.25, now.Add(8 * time.Minute), "less than 0.25 of its lifetime left"},
		{"before a 0.85 renewal point", s, bundle, idAPI, 0.85, now, ""},
		{"past a 0.85 renewal point", s, bundle, idAPI, 0.85, now.Add(2 * time.Minute), "less than 0.85 of its lifetime left"},
		{"absent", nil, bundle, idAPI, 0.5, now, "absent"},
		{"garbage", []byte("x"), bundle, idAPI, 0.5, now, "unreadable"},
		{"other id", s, bundle, idGit, 0.5, now, "spiffe_id changed"},
		{"CA gone from the bundle", s, func() []byte { _, c := testutil.CACert(t, now.Add(time.Hour)); return c }(), idAPI, 0.5, now, "not signed by a CA of the bundle"},
	} {
		if got := Due(tc.svid, tc.bundle, tc.id, tc.fraction, tc.at); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
