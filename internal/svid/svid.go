// Package svid obtains X.509-SVIDs and the trust bundle from hanko-ca, and decides when an
// SVID is due (ADR 0004).
package svid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	cav1 "github.com/scorsi/hanko/internal/gen/hanko/ca/v1"
)

// callTimeout bounds one call; hanko-ca itself closes every connection within 70 s.
const callTimeout = time.Minute

// Client calls hanko-ca at Addr over the overlay, one short connection per call. Plaintext
// gRPC: the overlay is the authenticated transport, the source address the credential.
type Client struct {
	Addr string
}

func (c *Client) call(ctx context.Context, f func(context.Context, cav1.CAServiceClient) error) error {
	conn, err := grpc.NewClient(c.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if err := f(ctx, cav1.NewCAServiceClient(conn)); err != nil {
		return fmt.Errorf("hanko-ca %s: %w", c.Addr, err)
	}
	return nil
}

// Bundle returns the CA certificates as PEM, the signing one first.
func (c *Client) Bundle(ctx context.Context) ([]byte, error) {
	var resp *cav1.BundleResponse
	err := c.call(ctx, func(ctx context.Context, cl cav1.CAServiceClient) (err error) {
		resp, err = cl.Bundle(ctx, &cav1.BundleRequest{})
		return err
	})
	if err != nil {
		return nil, err
	}
	return bundlePEM(resp.GetBundle())
}

// Sign generates a P-256 key, has hanko-ca sign an SVID for id and returns the SVID, the key
// (PKCS #8) and the bundle, all PEM. The reply is checked: hanko-ca is trusted, but a wrong
// SVID would only fail later, at every consumer.
func (c *Client) Sign(ctx context.Context, id string) (svid, key, bundle []byte, err error) {
	u, err := url.Parse(id)
	if err != nil {
		return nil, nil, nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{u}}, k)
	if err != nil {
		return nil, nil, nil, err
	}
	var resp *cav1.SignResponse
	err = c.call(ctx, func(ctx context.Context, cl cav1.CAServiceClient) (err error) {
		resp, err = cl.Sign(ctx, &cav1.SignRequest{Csr: csr, SpiffeId: id})
		return err
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if bundle, err = bundlePEM(resp.GetBundle()); err != nil {
		return nil, nil, nil, err
	}
	leaf, err := x509.ParseCertificate(resp.GetSvid())
	if err != nil {
		return nil, nil, nil, errors.New("hanko-ca returned an unparsable SVID")
	}
	if !k.PublicKey.Equal(leaf.PublicKey) || !hasID(leaf, id) || SigningCA(leaf, bundle) == nil {
		return nil, nil, nil, errors.New("hanko-ca returned an SVID for another key or ID, or not signed by its bundle")
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), bundle, nil
}

func bundlePEM(ders [][]byte) ([]byte, error) {
	if len(ders) == 0 {
		return nil, errors.New("hanko-ca returned an empty bundle")
	}
	var out []byte
	for _, d := range ders {
		if _, err := x509.ParseCertificate(d); err != nil {
			return nil, errors.New("hanko-ca returned an unparsable bundle")
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return out, nil
}

func hasID(leaf *x509.Certificate, id string) bool {
	return len(leaf.URIs) == 1 && leaf.URIs[0].String() == id
}

// SigningCA returns the certificate of bundle (PEM) that signed leaf, or nil.
func SigningCA(leaf *x509.Certificate, bundle []byte) *x509.Certificate {
	for rest := bundle; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return nil
		}
		if ca, err := x509.ParseCertificate(b.Bytes); err == nil && leaf.CheckSignatureFrom(ca) == nil {
			return ca
		}
	}
}

// Due returns why the SVID (PEM) must be renewed for id against bundle (PEM), or "" when it
// need not be. Half of its real lifetime, NotAfter − NotBefore: hanko-ca caps an SVID at its
// CA's expiry, so near that end an SVID is shorter than the configured lifetime.
func Due(svid, bundle []byte, id string, now time.Time) string {
	if len(svid) == 0 {
		return "absent"
	}
	b, _ := pem.Decode(svid)
	if b == nil {
		return "unreadable"
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	switch {
	case err != nil:
		return "unreadable"
	case !hasID(leaf, id):
		return "spiffe_id changed"
	case SigningCA(leaf, bundle) == nil:
		// e.g. its CA was removed from the bundle after a rotation (ADR 0012).
		return "not signed by a CA of the bundle"
	case leaf.NotAfter.Sub(now) < leaf.NotAfter.Sub(leaf.NotBefore)/2:
		return "less than half of its lifetime left"
	}
	return ""
}
