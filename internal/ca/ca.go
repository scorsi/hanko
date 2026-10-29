package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	cav1 "github.com/scorsi/hanko/internal/gen/hanko/ca/v1"
	"github.com/scorsi/hanko/internal/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// backdate absorbs small clock differences between hanko-ca and the peers verifying an SVID;
// the validity period stays exactly the configured lifetime.
const backdate = time.Minute

// CA signs X.509-SVIDs for the IDs each overlay address may request (ADR 0004).
type CA struct {
	cav1.UnimplementedCAServiceServer
	key      *ecdsa.PrivateKey
	cert     *x509.Certificate
	bundle   [][]byte // DER, the signing certificate first
	lifetime time.Duration
	allowed  map[netip.Addr]map[string]bool
	log      *slog.Logger
	now      func() time.Time
}

// New builds a CA from the PEM key (ECDSA P-256, SEC 1 or PKCS #8) and the PEM certificate
// file, which may hold several CA certificates; the one matching the key signs.
func New(cfg *Config, keyPEM, certsPEM []byte, log *slog.Logger) (*CA, error) {
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("key_file: %w", err)
	}
	var signing *x509.Certificate
	var others [][]byte
	for rest := certsPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("cert_file: unexpected PEM block %q", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cert_file: %w", err)
		}
		if !c.IsCA {
			return nil, errors.New("cert_file: a certificate is not a CA")
		}
		if signing == nil && key.PublicKey.Equal(c.PublicKey) {
			signing = c
		} else {
			others = append(others, c.Raw)
		}
	}
	if signing == nil {
		return nil, errors.New("cert_file: no CA certificate matches key_file")
	}
	return &CA{
		key:      key,
		cert:     signing,
		bundle:   append([][]byte{signing.Raw}, others...),
		lifetime: cfg.CA.Lifetime(),
		allowed:  cfg.Allowed(),
		log:      log,
		now:      time.Now,
	}, nil
}

func parseKey(data []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("no PEM block")
	}
	var k any
	var err error
	switch b.Type {
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(b.Bytes)
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	default:
		return nil, fmt.Errorf("unexpected PEM block %q", b.Type)
	}
	if err != nil {
		return nil, errors.New("unparsable private key") // never the key's bytes
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not an ECDSA P-256 key")
	}
	return ec, nil
}

var errDenied = errors.New("spiffe_id not allowed for this address")

// sign returns the DER X.509-SVID for id, or an error: errDenied, or a CSR problem.
func (c *CA) sign(from netip.Addr, csrDER []byte, id string) ([]byte, error) {
	if !c.allowed[from][id] {
		return nil, errDenied
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, errors.New("csr: unparsable")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("csr: bad signature")
	}
	if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("csr: key is not ECDSA P-256")
	}
	// Only the CSR's key is used; a SAN other than the requested ID means a confused caller.
	if len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses) > 0 ||
		len(csr.URIs) > 1 || len(csr.URIs) == 1 && csr.URIs[0].String() != id {
		return nil, errors.New("csr: SANs other than the requested spiffe_id")
	}
	u, _ := url.Parse(id) // valid: every allowed ID passed parseID
	start := c.now().Add(-backdate)
	tmpl := &x509.Certificate{
		// SerialNumber nil: CreateCertificate draws a random RFC 5280 serial.
		NotBefore:             start,
		NotAfter:              start.Add(c.lifetime),
		URIs:                  []*url.URL{u},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
}

// Sign is the gRPC method: the caller is its overlay source address (ADR 0004).
func (c *CA) Sign(ctx context.Context, req *cav1.SignRequest) (*cav1.SignResponse, error) {
	from := peerAddr(ctx)
	id := req.GetSpiffeId()
	der, err := c.sign(from, req.GetCsr(), id)
	if err != nil {
		c.log.Warn("", "event", "sign-refused", "peer", from.String(), "spiffe_id", trunc(id), "err", err)
		code := codes.InvalidArgument
		if errors.Is(err, errDenied) {
			code = codes.PermissionDenied
		}
		return nil, status.Error(code, err.Error())
	}
	leaf, _ := x509.ParseCertificate(der)
	c.log.Info("", "event", "svid-signed", "peer", from.String(), "spiffe_id", id,
		"serial", leaf.SerialNumber.Text(16), "not_after", leaf.NotAfter.UTC().Format(logging.TS))
	return &cav1.SignResponse{Svid: der, Bundle: c.bundle}, nil
}

// Bundle serves the CA certificates to any caller: they are public.
func (c *CA) Bundle(context.Context, *cav1.BundleRequest) (*cav1.BundleResponse, error) {
	return &cav1.BundleResponse{Bundle: c.bundle}, nil
}

// peerAddr is the caller's IP, IPv4-mapped addresses unmapped; the zero Addr matches no host.
func peerAddr(ctx context.Context) netip.Addr {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(p.Addr.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// trunc bounds a caller-supplied string before it reaches the journal.
func trunc(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}

// Serve reads the key and certificate, listens on the configured address and serves until ctx
// ends. Plaintext gRPC: the overlay is the authenticated transport (ADR 0004).
func Serve(ctx context.Context, cfg *Config, log *slog.Logger) error {
	// grpc-go's own logger writes plain text on stderr; keep stderr schema v1 (ADR 0007).
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, grpcErrors{log}))
	keyPEM, err := os.ReadFile(cfg.CA.KeyFile)
	if err != nil {
		return err
	}
	certsPEM, err := os.ReadFile(cfg.CA.CertFile)
	if err != nil {
		return err
	}
	c, err := New(cfg, keyPEM, certsPEM, log)
	if err != nil {
		return err
	}
	lis, err := net.Listen("tcp", cfg.CA.Listen)
	if err != nil {
		return err
	}
	srv := grpc.NewServer()
	cav1.RegisterCAServiceServer(srv, c)
	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()
	log.Info("", "event", "ca-started", "listen", cfg.CA.Listen, "hosts", len(cfg.Hosts),
		"ca_not_after", c.cert.NotAfter.UTC().Format(logging.TS))
	return srv.Serve(lis)
}

type grpcErrors struct{ log *slog.Logger }

func (w grpcErrors) Write(p []byte) (int, error) {
	w.log.Error("", "event", "grpc-error", "err", strings.TrimSpace(string(p)))
	return len(p), nil
}
