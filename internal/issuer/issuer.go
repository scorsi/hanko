// Package issuer obtains certificates from an ACME CA with DNS-01 challenges placed through
// RFC 2136, and decides when one is due (ADR 0003).
package issuer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/rfc2136"
	"github.com/scorsi/hanko/internal/state"
)

// DNS places challenge records; *rfc2136.Client in production.
type DNS interface {
	Add(ctx context.Context, name, value string) error
	Delete(ctx context.Context, name, value string) error
	Wait(ctx context.Context, records map[string][]string, timeout time.Duration) error
}

// Issuer talks to the CA and the nameservers only when a certificate is due, so a run with
// nothing to renew needs neither.
type Issuer struct {
	ACME config.ACME
	DNS  DNS // built from DNSConfig on first use unless set
	// DNSConfig is read only when DNS is nil.
	DNSConfig config.DNS
	Log       *slog.Logger

	client     *acme.Client
	retryUntil time.Time
	// lastRetryAfter is the Retry-After of the latest CA response: the library drops the headers
	// of problems embedded in an invalid order or authorization (ADR 0010).
	lastRetryAfter string
}

type captureRetryAfter struct {
	base http.RoundTripper
	last *string
}

func (t captureRetryAfter) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	*t.last = ""
	if err == nil {
		*t.last = resp.Header.Get("Retry-After")
	}
	return resp, err
}

// Due returns why the certificate in chain (PEM, leaf first) must be renewed for hosts, or ""
// when it need not be. ARI is not used: x/crypto/acme does not expose it.
func Due(chain []byte, hosts []string, now time.Time) string {
	if len(chain) == 0 {
		return "absent"
	}
	leaf, err := parseLeaf(chain)
	switch {
	case err != nil:
		return "unreadable"
	case !sameHosts(leaf.DNSNames, hosts):
		return "hosts changed"
	case leaf.NotAfter.Sub(now) < leaf.NotAfter.Sub(leaf.NotBefore)/3:
		return "less than a third of its lifetime left"
	}
	return ""
}

// NotAfter returns the expiry of chain's leaf certificate.
func NotAfter(chain []byte) (time.Time, error) {
	leaf, err := parseLeaf(chain)
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

func parseLeaf(chain []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(chain)
	if b == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(b.Bytes)
}

func sameHosts(a, b []string) bool {
	norm := func(s []string) []string {
		s = slices.Clone(s)
		for i := range s {
			s[i] = strings.ToLower(s[i])
		}
		slices.Sort(s)
		return slices.Compact(s)
	}
	return slices.Equal(norm(a), norm(b))
}

func (i *Issuer) setup(ctx context.Context, root *os.Root) error {
	if i.DNS == nil {
		d, err := rfc2136.New(i.DNSConfig.Nameservers, i.DNSConfig.TSIGKeyFile)
		if err != nil {
			return err
		}
		i.DNS = d
	}
	if i.client != nil {
		return nil
	}
	key, err := accountKey(root, filepath.Base(i.ACME.AccountKeyFile), i.ACME.CreateAccount)
	if errors.Is(err, ErrAccountKeyMissing) {
		i.Log.Error("", "event", "account-key-missing", "path", i.ACME.AccountKeyFile, "err", err)
	}
	if err != nil {
		return err
	}
	c := &acme.Client{Key: key, DirectoryURL: i.ACME.Directory, UserAgent: "hanko", RetryBackoff: func(n int, _ *http.Request, resp *http.Response) time.Duration {
		// Only bad-nonce recovery is retried here; CA backoff survives the oneshot in .retry-after.
		if resp.StatusCode == http.StatusBadRequest && n <= 3 {
			return 100 * time.Millisecond
		}
		return 0
	}}
	base := http.DefaultClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.HTTPClient = &http.Client{Transport: captureRetryAfter{base, &i.lastRetryAfter}}
	acct, err := c.GetReg(ctx, "")
	if errors.Is(err, acme.ErrNoAccount) {
		if !i.ACME.AcceptTerms {
			return errors.New("acme: no account for this key yet; set accept_terms = true to accept the CA's terms of service")
		}
		i.Log.Info("", "event", "acme-account-register", "directory", i.ACME.Directory)
		acct, err = c.Register(ctx, &acme.Account{}, acme.AcceptTOS)
		if errors.Is(err, acme.ErrAccountAlreadyExists) {
			// Register caches the existing account's URL as the client's KID.
			acct, err = &acme.Account{URI: string(c.KID)}, nil
		}
	}
	if err != nil {
		return i.failure(root, "account", err)
	}
	if acct.URI == "" {
		return errors.New("acme account: the CA returned no account URL")
	}
	// Without a cached KID the library looks the account up again before each order and
	// discards that request's error, a rate limit included (review R2).
	c.KID = acme.KeyID(acct.URI)
	// Logged by every run that contacts the CA, for RFC 8657 accounturi= in CAA (ADR 0007).
	i.Log.Info("", "event", "acme-account", "directory", i.ACME.Directory, "uri", acct.URI)
	i.client = c
	return nil
}

// ErrAccountKeyMissing: the account key file is absent and create_account is not set.
var ErrAccountKeyMissing = errors.New("account key absent; set acme.create_account = true only to create a new account (ADR 0008)")

// accountKey loads the account key. An absent key is created, mode 0600, only when create is set:
// otherwise a lost or hidden key would silently become a new account, which the CAA accounturi
// pin rejects (ADR 0008).
func accountKey(root *os.Root, name string, create bool) (*ecdsa.PrivateKey, error) {
	data, err := state.ReadOptional(root, name, 0o600, os.Getegid())
	if err != nil {
		return nil, err
	}
	if data == nil {
		if !create {
			return nil, ErrAccountKeyMissing
		}
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		// Synced, directory included, before the CA ever sees the key.
		if err := state.WriteFiles(root, 0o600, state.File{Name: name, Data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}); err != nil {
			return nil, err
		}
		return k, nil
	}
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("account key %s: no PEM block", name)
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if ec, ok := k.(*ecdsa.PrivateKey); err == nil && ok {
		return ec, nil
	}
	return nil, fmt.Errorf("account key %s: want a PKCS#8 ECDSA key", name)
}

type record struct{ name, value string }

// Issue runs one order for hosts and returns the chain (leaf first) and a fresh P-256 key, both
// PEM. Challenge records are removed on return, whatever happened.
func (i *Issuer) Issue(ctx context.Context, root *os.Root, hosts []string) (chain, key []byte, err error) {
	if filepath.Dir(i.ACME.AccountKeyFile) != root.Name() {
		return nil, nil, errors.New("account key must be directly in the state directory")
	}
	if err := i.checkRetry(root); err != nil {
		return nil, nil, err
	}
	if err := i.setup(ctx, root); err != nil {
		return nil, nil, err
	}
	c := i.client
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(hosts...))
	if err != nil {
		return nil, nil, i.failure(root, "new order", err)
	}

	var recs []record
	var chals []*acme.Challenge
	var pending []string
	for _, u := range order.AuthzURLs {
		z, err := c.GetAuthorization(ctx, u)
		if err != nil {
			return nil, nil, i.failure(root, "authorization", err)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		n := slices.IndexFunc(z.Challenges, func(ch *acme.Challenge) bool { return ch.Type == "dns-01" })
		if n < 0 {
			return nil, nil, errors.New("authorization offers no dns-01 challenge")
		}
		v, err := c.DNS01ChallengeRecord(z.Challenges[n].Token)
		if err != nil {
			return nil, nil, err
		}
		// The identifier of a wildcard is its base domain, so both share one name.
		recs = append(recs, record{"_acme-challenge." + z.Identifier.Value + ".", v})
		chals = append(chals, z.Challenges[n])
		pending = append(pending, u)
	}

	var placed []record
	defer func() {
		// Detached from ctx so that a timed-out order still cleans up.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		for _, r := range placed {
			if err := i.DNS.Delete(ctx, r.name, r.value); err != nil {
				i.Log.Warn("the nameserver expires it", "event", "challenge-delete-failed", "name", r.name, "err", err)
			}
		}
	}()
	want := map[string][]string{}
	for _, r := range recs {
		placed = append(placed, r) // before Add: a partial fan-out is cleaned up too
		if err := i.DNS.Add(ctx, r.name, r.value); err != nil {
			return nil, nil, err
		}
		want[r.name] = append(want[r.name], r.value)
	}
	if len(recs) > 0 {
		if err := i.DNS.Wait(ctx, want, i.DNSConfig.Timeout()); err != nil {
			return nil, nil, err
		}
	}
	for _, ch := range chals {
		if _, err := c.Accept(ctx, ch); err != nil {
			return nil, nil, i.failure(root, "accept challenge", err)
		}
	}
	for _, u := range pending {
		if _, err := c.WaitAuthorization(ctx, u); err != nil {
			return nil, nil, i.failure(root, "validation", err)
		}
	}
	if order, err = c.WaitOrder(ctx, order.URI); err != nil {
		return nil, nil, i.failure(root, "order", err)
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: hosts}, k)
	if err != nil {
		return nil, nil, err
	}
	der, _, err := c.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return nil, nil, i.failure(root, "finalize", err)
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return nil, nil, errors.New("issued certificate: invalid encoding")
	}
	if !k.PublicKey.Equal(leaf.PublicKey) || !sameHosts(leaf.DNSNames, hosts) {
		return nil, nil, errors.New("issued certificate does not match the request")
	}
	var buf bytes.Buffer
	for _, d := range der {
		pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return buf.Bytes(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), nil
}
