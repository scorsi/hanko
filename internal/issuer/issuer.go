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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/scorsi/hanko/internal/config"
	"github.com/scorsi/hanko/internal/rfc2136"
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

	client *acme.Client
}

// Due returns why the certificate in chain (PEM, leaf first) must be renewed for hosts, or ""
// when it need not be. ARI is not used: x/crypto/acme does not expose it.
func Due(chain []byte, hosts []string, now time.Time) string {
	if len(chain) == 0 {
		return "absent"
	}
	b, _ := pem.Decode(chain)
	if b == nil {
		return "unreadable"
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
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

func (i *Issuer) setup(ctx context.Context) error {
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
	key, err := accountKey(i.ACME.AccountKeyFile)
	if err != nil {
		return err
	}
	c := &acme.Client{Key: key, DirectoryURL: i.ACME.Directory, UserAgent: "hanko"}
	_, err = c.GetReg(ctx, "")
	if errors.Is(err, acme.ErrNoAccount) {
		if !i.ACME.AcceptTerms {
			return errors.New("acme: no account for this key yet; set accept_terms = true to accept the CA's terms of service")
		}
		i.Log.Info("creating ACME account", "directory", i.ACME.Directory)
		_, err = c.Register(ctx, &acme.Account{}, acme.AcceptTOS)
		if errors.Is(err, acme.ErrAccountAlreadyExists) {
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("acme account: %w", err)
	}
	i.client = c
	return nil
}

// accountKey loads the account key, creating it mode 0600 on first run (ADR 0003, ADR 0005).
func accountKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		if err := WriteFile(filepath.Dir(path), filepath.Base(path), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("account key %s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if ec, ok := k.(*ecdsa.PrivateKey); err == nil && ok {
		return ec, nil
	}
	return nil, fmt.Errorf("account key %s: want a PKCS#8 ECDSA key", path)
}

type record struct{ name, value string }

// Issue runs one order for hosts and returns the chain (leaf first) and a fresh P-256 key, both
// PEM. Challenge records are removed on return, whatever happened.
func (i *Issuer) Issue(ctx context.Context, hosts []string) (chain, key []byte, err error) {
	if err := i.setup(ctx); err != nil {
		return nil, nil, err
	}
	c := i.client
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(hosts...))
	if err != nil {
		return nil, nil, fmt.Errorf("new order: %w", err)
	}

	var recs []record
	var chals []*acme.Challenge
	var pending []string
	for _, u := range order.AuthzURLs {
		z, err := c.GetAuthorization(ctx, u)
		if err != nil {
			return nil, nil, fmt.Errorf("authorization: %w", err)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		n := slices.IndexFunc(z.Challenges, func(ch *acme.Challenge) bool { return ch.Type == "dns-01" })
		if n < 0 {
			return nil, nil, fmt.Errorf("authorization for %s offers no dns-01 challenge", z.Identifier.Value)
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
				i.Log.Warn("challenge record not deleted; the nameserver expires it", "name", r.name, "err", err)
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
			return nil, nil, fmt.Errorf("accept challenge: %w", err)
		}
	}
	for _, u := range pending {
		if _, err := c.WaitAuthorization(ctx, u); err != nil {
			return nil, nil, fmt.Errorf("validation: %w", err)
		}
	}
	if order, err = c.WaitOrder(ctx, order.URI); err != nil {
		return nil, nil, fmt.Errorf("order: %w", err)
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
		return nil, nil, fmt.Errorf("finalize: %w", err)
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return nil, nil, fmt.Errorf("issued certificate: %w", err)
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

// WriteFile replaces dir/name atomically: a temporary file next to it, synced, then renamed.
func WriteFile(dir, name string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op once renamed
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(dir, name))
	}
	return err
}
