package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/scorsi/hanko/internal/ca"
	cav1 "github.com/scorsi/hanko/internal/gen/hanko/ca/v1"
)

// CACert returns a P-256 key (PKCS #8) and a self-signed CA certificate valid until notAfter, PEM.
func CACert(t *testing.T, notAfter time.Time) (key, cert []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hanko test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ServeCA serves an in-process hanko-ca on a loopback port until the test ends, allowing
// 127.0.0.1 the given IDs, and returns its address. certs is cert_file's content.
func ServeCA(t *testing.T, key, certs []byte, lifetime string, ids ...string) string {
	t.Helper()
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = fmt.Sprintf("%q", id)
	}
	cfg, err := ca.ParseConfig(fmt.Appendf(nil, `
[ca]
key_file = "/k"
cert_file = "/c"
listen = "127.0.0.1:4900"
svid_lifetime = %q
[[hosts]]
address = "127.0.0.1"
ids = [%s]
`, lifetime, strings.Join(quoted, ", ")))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.New(cfg, key, certs, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	cav1.RegisterCAServiceServer(srv, c)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}
