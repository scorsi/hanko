package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	cav1 "github.com/scorsi/hanko/internal/gen/hanko/ca/v1"
	"github.com/scorsi/hanko/internal/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	idAPI = "spiffe://uchi.example.org/vm/api"
	idGit = "spiffe://uchi.example.org/vm/git"
	idDB  = "spiffe://uchi.example.org/db/postgres"
)

const example = `
[ca]
key_file = "/run/secrets/hanko-ca-key"
cert_file = "/etc/hanko/ca.pem"
listen = "[fd12:3456:789a::1]:4900"
svid_lifetime = "24h"

[[hosts]]
address = "fd12:3456:789a::2"
ids = ["spiffe://uchi.example.org/vm/api", "spiffe://uchi.example.org/vm/git"]
`

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func caCert(t *testing.T, key *ecdsa.PrivateKey, cn string, edit ...func(*x509.Certificate)) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, e := range edit {
		e(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// newCA allows idAPI and idGit from 127.0.0.1 and idDB from fd12:3456:789a::3.
func newCA(t *testing.T, log *bytes.Buffer, edit ...func(*x509.Certificate)) *CA {
	t.Helper()
	cfg, err := ParseConfig([]byte(strings.Replace(example, `address = "fd12:3456:789a::2"`, `address = "127.0.0.1"`, 1) + `
[[hosts]]
address = "fd12:3456:789a::3"
ids = ["` + idDB + `"]
`))
	if err != nil {
		t.Fatal(err)
	}
	key := p256(t)
	c, err := New(cfg, keyPEM(t, key), caCert(t, key, "hanko test CA", edit...), logging.New(log, nil))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func csr(t *testing.T, key crypto.Signer, uris ...string) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{}
	for _, s := range uris {
		u, _ := url.Parse(s)
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

var local = netip.MustParseAddr("127.0.0.1")

func TestConfigExample(t *testing.T) {
	c, err := ParseConfig([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if c.CA.Lifetime() != 24*time.Hour || !c.Allowed()[netip.MustParseAddr("fd12:3456:789a::2")][idGit] {
		t.Fatalf("parsed %+v", c)
	}
}

func TestConfigInvalid(t *testing.T) {
	for name, tc := range map[string]struct{ old, new, want string }{
		"unknown key":       {`svid_lifetime`, `svid_lifetme`, "unknown key"},
		"relative key":      {`"/run/secrets/hanko-ca-key"`, `"secrets/key"`, "key_file"},
		"wildcard listen":   {`[fd12:3456:789a::1]:4900`, `[::]:4900`, "listen"},
		"mapped wildcard":   {`[fd12:3456:789a::1]:4900`, `[::ffff:0.0.0.0]:4900`, "listen"},
		"mapped listen":     {`[fd12:3456:789a::1]:4900`, `[::ffff:10.0.0.1]:4900`, "listen"},
		"mapped host any":   {`"fd12:3456:789a::2"`, `"::ffff:0.0.0.0"`, "address"},
		"mapped host":       {`"fd12:3456:789a::2"`, `"::ffff:10.0.0.2"`, "address"},
		"privileged port":   {`]:4900`, `]:443`, "listen"},
		"bad lifetime":      {`"24h"`, `"0s"`, "svid_lifetime"},
		"bad address":       {`"fd12:3456:789a::2"`, `"host.example.org"`, "address"},
		"bad scheme":        {`"spiffe://uchi.example.org/vm/api"`, `"https://uchi.example.org/vm/api"`, "ids[0]"},
		"one segment":       {`"spiffe://uchi.example.org/vm/api"`, `"spiffe://uchi.example.org/api"`, "ids[0]"},
		"upper domain":      {`"spiffe://uchi.example.org/vm/api"`, `"spiffe://UCHI.example.org/vm/api"`, "ids[0]"},
		"dot segment":       {`"spiffe://uchi.example.org/vm/api"`, `"spiffe://uchi.example.org/../api"`, "ids[0]"},
		"query":             {`"spiffe://uchi.example.org/vm/api"`, `"spiffe://uchi.example.org/vm/api?x"`, "ids[0]"},
		"two trust domains": {`"spiffe://uchi.example.org/vm/git"`, `"spiffe://other.example.org/vm/git"`, "trust domain"},
		"empty ids":         {`ids = ["spiffe://uchi.example.org/vm/api", "spiffe://uchi.example.org/vm/git"]`, `ids = []`, "ids must not be empty"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig([]byte(strings.Replace(example, tc.old, tc.new, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	dup := example + "\n[[hosts]]\naddress = \"fd12:3456:789a::2\"\nids = [\"" + idAPI + "\"]\n"
	if _, err := ParseConfig([]byte(dup)); err == nil || !strings.Contains(err.Error(), "duplicate address") {
		t.Fatalf("duplicate address: err = %v", err)
	}
}

func TestSignFields(t *testing.T) {
	c := newCA(t, &bytes.Buffer{})
	key := p256(t)
	for _, req := range [][]byte{csr(t, key), csr(t, key, idAPI)} {
		der, err := c.sign(local, req, idAPI)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != idAPI || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
			t.Errorf("SANs: %v %v %v %v", leaf.URIs, leaf.DNSNames, leaf.IPAddresses, leaf.EmailAddresses)
		}
		if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
			t.Errorf("keyUsage %v", leaf.KeyUsage)
		}
		if len(leaf.ExtKeyUsage) != 2 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || leaf.ExtKeyUsage[1] != x509.ExtKeyUsageClientAuth {
			t.Errorf("EKU %v", leaf.ExtKeyUsage)
		}
		if !leaf.BasicConstraintsValid || leaf.IsCA {
			t.Error("must be BasicConstraints CA:false")
		}
		if d := leaf.NotAfter.Sub(leaf.NotBefore); d != 24*time.Hour {
			t.Errorf("lifetime %v", d)
		}
		if leaf.NotBefore.After(time.Now()) {
			t.Error("not yet valid")
		}
		if !key.PublicKey.Equal(leaf.PublicKey) || leaf.SerialNumber.Sign() <= 0 {
			t.Error("wrong key or serial")
		}
		roots := x509.NewCertPool()
		roots.AddCert(c.cert)
		for _, eku := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{eku}}); err != nil {
				t.Errorf("verify %v: %v", eku, err)
			}
		}
	}
}

func TestSignRefusedID(t *testing.T) {
	c := newCA(t, &bytes.Buffer{})
	req := csr(t, p256(t))
	for name, tc := range map[string]struct {
		from netip.Addr
		id   string
	}{
		"other host's id": {local, idDB},
		"unknown id":      {local, "spiffe://uchi.example.org/vm/other"},
		"unknown address": {netip.MustParseAddr("127.0.0.2"), idAPI},
		"no address":      {netip.Addr{}, idAPI},
	} {
		if _, err := c.sign(tc.from, req, tc.id); !errors.Is(err, errDenied) {
			t.Errorf("%s: err = %v, want denied", name, err)
		}
	}
}

func TestSignRefusedCSR(t *testing.T) {
	c := newCA(t, &bytes.Buffer{})
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	badSig := csr(t, p256(t))
	badSig[len(badSig)-3] ^= 0xff // inside the signature BIT STRING
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaBadSig := csr(t, rsaKey)
	rsaBadSig[len(rsaBadSig)-3] ^= 0xff // refused for its key, before any signature check
	uri := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(idAPI)}
	oidBytes, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1})
	otherName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: append(oidBytes, 0xa0, 0x03, 0x0c, 0x01, 'x')}
	dn, _ := asn1.Marshal(pkix.Name{CommonName: "api"}.ToRDNSequence())
	dirName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: dn}
	regID := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: oidBytes[2:]}
	withDNS := func() []byte {
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"api.uchi.example.org"}}, p256(t))
		return der
	}()
	for name, tc := range map[string]struct {
		req  []byte
		want string
	}{
		"garbage":        {[]byte("not a csr"), "unparsable"},
		"bad signature":  {badSig, "bad signature"},
		"P-384 key":      {csr(t, p384), "P-256"},
		"Ed25519 key":    {csr(t, ed), "P-256"},
		"mismatched SAN": {csr(t, p256(t), idGit), "SANs"},
		"two URI SANs":   {csr(t, p256(t), idAPI, idGit), "SANs"},
		"DNS SAN":        {withDNS, "SANs"},
		"too large":      {make([]byte, maxCSR+1), "too large"},
		"RSA key":        {rsaBadSig, "P-256"},
		"otherName SAN":  {rawSAN(t, uri, otherName), "SANs"},
		"directoryName":  {rawSAN(t, dirName, uri), "SANs"},
		"registeredID":   {rawSAN(t, regID), "SANs"},
		"same URI twice": {rawSAN(t, uri, uri), "SANs"},
	} {
		_, err := c.sign(local, tc.req, idAPI)
		if err == nil || errors.Is(err, errDenied) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// rawSAN builds a CSR whose subjectAltName holds exactly names. (A repeated extension is
// refused by Go's parser itself.)
func rawSAN(t *testing.T, names ...asn1.RawValue) []byte {
	t.Helper()
	ext := func(ns ...asn1.RawValue) pkix.Extension {
		var b []byte
		for _, n := range ns {
			d, err := asn1.Marshal(n)
			if err != nil {
				t.Fatal(err)
			}
			b = append(b, d...)
		}
		v, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: b})
		return pkix.Extension{Id: oidSAN, Value: v}
	}
	exts := []pkix.Extension{ext(names...)}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{ExtraExtensions: exts}, p256(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificateRequest(der); err != nil {
		t.Fatalf("Go must parse it, or the test proves nothing: %v", err)
	}
	return der
}

func TestCAValidity(t *testing.T) {
	cfg, _ := ParseConfig([]byte(example))
	key := p256(t)
	for name, edit := range map[string]func(*x509.Certificate){
		"expired":             func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) },
		"not yet valid":       func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
		"no keyCertSign":      func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
		"no key usage at all": func(c *x509.Certificate) { c.KeyUsage = 0 },
	} {
		if _, err := New(cfg, keyPEM(t, key), caCert(t, key, "ca", edit), nil); err == nil || !strings.Contains(err.Error(), "signing CA") {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	// The SVID ends with the CA; past the CA's end, signing is refused.
	c := newCA(t, &bytes.Buffer{}, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(time.Hour) })
	der, err := c.sign(local, csr(t, p256(t)), idAPI)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	if !leaf.NotAfter.Equal(c.cert.NotAfter) {
		t.Errorf("NotAfter %v, want the CA's %v", leaf.NotAfter, c.cert.NotAfter)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("clamped SVID: %v", err)
	}
	c.now = func() time.Time { return c.cert.NotAfter.Add(time.Second) }
	if _, err := c.sign(local, csr(t, p256(t)), idAPI); !errors.Is(err, errExpired) {
		t.Errorf("after the CA's end: err = %v", err)
	}
}

func TestBundle(t *testing.T) {
	cfg, _ := ParseConfig([]byte(example))
	oldKey, newKey := p256(t), p256(t)
	oldPEM, newPEM := caCert(t, oldKey, "old"), caCert(t, newKey, "new")
	// The signing CA comes first in the bundle whatever its place in the file.
	c, err := New(cfg, keyPEM(t, newKey), append(oldPEM, newPEM...), logging.New(&bytes.Buffer{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(newPEM)
	o, _ := pem.Decode(oldPEM)
	if len(c.bundle) != 2 || !bytes.Equal(c.bundle[0], b.Bytes) || !bytes.Equal(c.bundle[1], o.Bytes) {
		t.Fatal("bundle must be signing CA then the other")
	}
	if _, err := New(cfg, keyPEM(t, p256(t)), newPEM, nil); err == nil || !strings.Contains(err.Error(), "no CA certificate matches") {
		t.Errorf("unmatched key: err = %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := New(cfg, keyPEM(t, p384), newPEM, nil); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Errorf("P-384 CA key: err = %v", err)
	}
}

// TestGRPC runs the service over a loopback listener: the peer address, not the request,
// decides which IDs the caller may get.
func TestGRPC(t *testing.T) {
	var log bytes.Buffer
	c := newCA(t, &log)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(c)
	go srv.Serve(limitListener(lis, maxConns))
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client := cav1.NewCAServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Sign(ctx, &cav1.SignRequest{Csr: csr(t, p256(t), idAPI), SpiffeId: idAPI})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(resp.Svid)
	if err != nil || leaf.URIs[0].String() != idAPI || len(resp.Bundle) != 1 || !bytes.Equal(resp.Bundle[0], c.cert.Raw) {
		t.Fatalf("sign response: %v", err)
	}
	if !strings.Contains(log.String(), `"event":"svid-signed","peer":"127.0.0.1","spiffe_id":"`+idAPI+`"`) {
		t.Errorf("no svid-signed line: %s", log.String())
	}

	// idDB is allowed, but for fd12:3456:789a::3, not for this caller.
	_, err = client.Sign(ctx, &cav1.SignRequest{Csr: csr(t, p256(t)), SpiffeId: idDB})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other host's id: %v", err)
	}
	if !strings.Contains(log.String(), `"level":"warn","v":1,"event":"sign-refused","peer":"127.0.0.1","spiffe_id":"`+idDB+`"`) {
		t.Errorf("no sign-refused line: %s", log.String())
	}
	_, err = client.Sign(ctx, &cav1.SignRequest{Csr: csr(t, p256(t), idGit), SpiffeId: idAPI})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("mismatched SAN: %v", err)
	}

	// A message above maxRecvMsg never reaches the handler.
	_, err = client.Sign(ctx, &cav1.SignRequest{Csr: make([]byte, maxRecvMsg+1), SpiffeId: idAPI})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized request: %v", err)
	}

	b, err := client.Bundle(ctx, &cav1.BundleRequest{})
	if err != nil || len(b.Bundle) != 1 || !bytes.Equal(b.Bundle[0], c.cert.Raw) {
		t.Fatalf("bundle: %v", err)
	}

	// Bundle answers configured hosts only (the peer is set directly: loopback is configured).
	other := peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: 4000}})
	if _, err := c.Bundle(other, &cav1.BundleRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("bundle from an unknown address: %v", err)
	}
	if !strings.Contains(log.String(), `"level":"warn","v":1,"event":"bundle-refused","peer":"127.0.0.2"`) {
		t.Errorf("no bundle-refused line: %s", log.String())
	}
}

func TestLimitListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lis := limitListener(inner, 1)
	defer lis.Close()
	for range 2 {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	first, err := lis.Accept()
	if err != nil {
		t.Fatal(err)
	}
	second := make(chan net.Conn, 1)
	go func() {
		c, _ := lis.Accept()
		second <- c
	}()
	select {
	case <-second:
		t.Fatal("a second connection was accepted while the only slot is taken")
	case <-time.After(100 * time.Millisecond):
	}
	first.Close()
	first.Close() // a double close frees the slot once
	select {
	case c := <-second:
		if c == nil {
			t.Fatal("accept failed")
		}
		c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("closing the first connection did not free its slot")
	}
	lis.Close()
	if _, err := lis.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accept after close: %v", err)
	}
}

// keygen -> hanko-ca's loader -> an SVID for a CSR -> it verifies against the generated cert.
func TestGenerateRoundTrip(t *testing.T) {
	now := time.Now()
	keyPEM, certPEM, err := Generate("hanko CA", 3650, now)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig([]byte(strings.Replace(example, `address = "fd12:3456:789a::2"`, `address = "127.0.0.1"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(cfg, keyPEM, certPEM, logging.New(&bytes.Buffer{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	root := c.cert
	if root.Subject.CommonName != "hanko CA" || !root.IsCA || root.MaxPathLen != 0 || !root.MaxPathLenZero ||
		root.KeyUsage != x509.KeyUsageCertSign || len(root.SubjectKeyId) == 0 ||
		!root.NotBefore.Equal(now.Add(-backdate).Truncate(time.Second)) ||
		!root.NotAfter.Equal(now.UTC().AddDate(0, 0, 3650).Truncate(time.Second)) {
		t.Fatalf("CA fields: %+v", root)
	}
	for _, e := range root.Extensions {
		if (e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) || e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15})) && !e.Critical {
			t.Fatalf("extension %v not critical", e.Id)
		}
	}
	der, err := c.sign(local, csr(t, p256(t), idAPI), idAPI)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatal(err)
	}
	other, _, _ := Generate("hanko CA", 1, now)
	if _, _, _, err := parseCA(other, certPEM, now); err == nil {
		t.Fatal("a foreign key matched the generated certificate")
	}
}

func TestGenerateRefused(t *testing.T) {
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	last := int((maxNotAfter.Unix() - now.Unix()) / 86400) // ends 9999-12-31 00:00:00
	if _, _, err := Generate("ca", last, now); err != nil {
		t.Fatalf("last valid day refused: %v", err)
	}
	for _, days := range []int{0, -1, last + 1, 3_000_001, math.MaxInt} {
		if _, _, err := Generate("ca", days, now); err == nil {
			t.Errorf("days %d accepted", days)
		}
	}
	if _, _, err := Generate("", 1, now); err == nil {
		t.Error("empty name accepted")
	}
}
