package issuer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scorsi/hanko/internal/config"
)

var b64 = base64.RawURLEncoding

// fakeCA is the part of an RFC 8555 directory x/crypto/acme uses, with dns-01 validated
// against the fake DNS below. Signatures are not checked; the account is the key thumbprint.
type fakeCA struct {
	srv    *httptest.Server
	dns    *fakeDNS
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate

	mu       sync.Mutex
	nonce    int
	accounts map[string]bool // thumbprint
	kids     map[string]string
	authzs   []*fakeAuthz
	orders   []*fakeOrder
}

type fakeAuthz struct {
	value, token, status string
	wildcard             bool
	thumb                string
}

type fakeOrder struct {
	ids   []string
	authz []int
	cert  []byte
}

func newCA(t *testing.T, d *fakeDNS) *fakeCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	cert, _ := x509.ParseCertificate(der)
	ca := &fakeCA{dns: d, caKey: k, caCert: cert, accounts: map[string]bool{}, kids: map[string]string{}}
	ca.srv = httptest.NewServer(ca)
	t.Cleanup(ca.srv.Close)
	return ca
}

func (ca *fakeCA) url(p string, a ...any) string { return ca.srv.URL + fmt.Sprintf(p, a...) }

func (ca *fakeCA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.nonce++
	w.Header().Set("Replay-Nonce", fmt.Sprint("n", ca.nonce))
	if r.URL.Path == "/dir" {
		ca.json(w, 200, map[string]any{"newNonce": ca.url("/nonce"), "newAccount": ca.url("/acct"), "newOrder": ca.url("/order"),
			"revokeCert": ca.url("/revoke"), "keyChange": ca.url("/kc"), "meta": map[string]any{"termsOfService": ca.url("/tos")}})
		return
	}
	if r.URL.Path == "/nonce" {
		return
	}

	var jws struct{ Protected, Payload string }
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &jws)
	var prot struct {
		JWK struct{ Crv, Kty, X, Y string }
		KID string
	}
	ph, _ := b64.DecodeString(jws.Protected)
	json.Unmarshal(ph, &prot)
	payload, _ := b64.DecodeString(jws.Payload)
	thumb := ca.kids[prot.KID]
	if prot.KID == "" {
		h := sha256.Sum256(fmt.Appendf(nil, `{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, prot.JWK.Crv, prot.JWK.Kty, prot.JWK.X, prot.JWK.Y))
		thumb = b64.EncodeToString(h[:])
	}
	var n int
	var kind string
	fmt.Sscanf(strings.ReplaceAll(r.URL.Path, "/", " "), "%s %d", &kind, &n)

	switch kind {
	case "acct":
		var req struct {
			OnlyReturnExisting   bool
			TermsOfServiceAgreed bool
		}
		json.Unmarshal(payload, &req)
		kid := ca.url("/account/%s", thumb)
		ca.kids[kid] = thumb
		w.Header().Set("Location", kid)
		switch {
		case ca.accounts[thumb]:
			ca.json(w, 200, map[string]any{"status": "valid"})
		case req.OnlyReturnExisting:
			ca.problem(w, 400, "accountDoesNotExist")
		case !req.TermsOfServiceAgreed:
			ca.problem(w, 403, "userActionRequired")
		default:
			ca.accounts[thumb] = true
			ca.json(w, 201, map[string]any{"status": "valid"})
		}
	case "order":
		if !ca.accounts[thumb] {
			ca.problem(w, 403, "unauthorized")
			return
		}
		var req struct{ Identifiers []struct{ Value string } }
		json.Unmarshal(payload, &req)
		o := &fakeOrder{}
		for _, id := range req.Identifiers {
			o.ids = append(o.ids, id.Value)
			o.authz = append(o.authz, len(ca.authzs))
			ca.authzs = append(ca.authzs, &fakeAuthz{value: strings.TrimPrefix(id.Value, "*."), wildcard: strings.HasPrefix(id.Value, "*."),
				token: fmt.Sprint("token-", len(ca.authzs)), status: "pending", thumb: thumb})
		}
		ca.orders = append(ca.orders, o)
		w.Header().Set("Location", ca.url("/o/%d", len(ca.orders)-1))
		ca.json(w, 201, ca.orderJSON(len(ca.orders)-1))
	case "o":
		w.Header().Set("Location", ca.url("/o/%d", n))
		ca.json(w, 200, ca.orderJSON(n))
	case "authz":
		ca.json(w, 200, ca.authzJSON(n))
	case "chal":
		z := ca.authzs[n]
		ka := sha256.Sum256([]byte(z.token + "." + z.thumb))
		if slices.Contains(ca.dns.lookup("_acme-challenge."+z.value+"."), b64.EncodeToString(ka[:])) {
			z.status = "valid"
		} else {
			z.status = "invalid"
		}
		ca.json(w, 200, ca.authzJSON(n)["challenges"].([]any)[0])
	case "final":
		var req struct{ CSR string }
		json.Unmarshal(payload, &req)
		der, _ := b64.DecodeString(req.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		o := ca.orders[n]
		if err != nil || !sameHosts(csr.DNSNames, o.ids) {
			ca.problem(w, 400, "badCSR")
			return
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(n + 2)), DNSNames: csr.DNSNames,
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
		leaf, _ := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, csr.PublicKey, ca.caKey)
		o.cert = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw})...)
		w.Header().Set("Location", ca.url("/o/%d", n))
		ca.json(w, 200, ca.orderJSON(n))
	case "cert":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(ca.orders[n].cert)
	default:
		ca.problem(w, 404, "malformed")
	}
}

func (ca *fakeCA) orderJSON(n int) map[string]any {
	o := ca.orders[n]
	status, urls := "ready", []string{}
	for _, a := range o.authz {
		urls = append(urls, ca.url("/authz/%d", a))
		switch ca.authzs[a].status {
		case "invalid":
			status = "invalid"
		case "pending":
			if status == "ready" {
				status = "pending"
			}
		}
	}
	ids := []any{}
	for _, v := range o.ids {
		ids = append(ids, map[string]any{"type": "dns", "value": v})
	}
	m := map[string]any{"identifiers": ids, "authorizations": urls, "finalize": ca.url("/final/%d", n)}
	if o.cert != nil {
		status, m["certificate"] = "valid", ca.url("/cert/%d", n)
	}
	m["status"] = status
	return m
}

func (ca *fakeCA) authzJSON(n int) map[string]any {
	z := ca.authzs[n]
	return map[string]any{"status": z.status, "wildcard": z.wildcard, "identifier": map[string]any{"type": "dns", "value": z.value},
		"challenges": []any{map[string]any{"type": "dns-01", "url": ca.url("/chal/%d", n), "token": z.token, "status": z.status}}}
}

func (ca *fakeCA) json(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (ca *fakeCA) problem(w http.ResponseWriter, code int, typ string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": typ})
}

// fakeDNS records what the issuer placed, and in which order.
type fakeDNS struct {
	mu      sync.Mutex
	txt     map[string][]string
	log     []string
	failAdd int // the nth Add fails (1-based), 0 never
}

func (d *fakeDNS) Add(_ context.Context, name, value string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.log = append(d.log, "add "+name)
	if d.failAdd == len(d.log) {
		return errors.New("REFUSED")
	}
	d.txt[name] = append(d.txt[name], value)
	return nil
}

func (d *fakeDNS) Delete(_ context.Context, name, value string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.log = append(d.log, "delete "+name)
	d.txt[name] = slices.DeleteFunc(d.txt[name], func(s string) bool { return s == value })
	return nil
}

func (d *fakeDNS) Wait(_ context.Context, records map[string][]string, _ time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.log = append(d.log, fmt.Sprint("wait ", len(records)))
	return nil
}

func (d *fakeDNS) lookup(name string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.txt[name])
}

func setup(t *testing.T, accept bool) (*Issuer, *fakeCA, *fakeDNS) {
	d := &fakeDNS{txt: map[string][]string{}}
	ca := newCA(t, d)
	i := &Issuer{
		ACME:      config.ACME{Directory: ca.url("/dir"), AccountKeyFile: filepath.Join(t.TempDir(), "account.key"), AcceptTerms: accept},
		DNS:       d,
		DNSConfig: config.DNS{PropagationTimeout: "1s"},
		Log:       slog.New(slog.DiscardHandler),
	}
	return i, ca, d
}

var hosts = []string{"*.uchi.example.org", "uchi.example.org", "cv.example.org"}

// accountURIs returns the uri of every acme-account event in a JSON log, and whether an
// acme-account-register event came first.
func accountURIs(t *testing.T, log *bytes.Buffer) (uris []string, registered bool) {
	for line := range strings.Lines(log.String()) {
		var e struct{ Event, Directory, URI string }
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		switch e.Event {
		case "acme-account-register":
			registered = len(uris) == 0
		case "acme-account":
			uris = append(uris, e.URI)
		}
	}
	return uris, registered
}

func TestIssue(t *testing.T) {
	i, ca, d := setup(t, true)
	var log1, log2 bytes.Buffer
	i.Log = slog.New(slog.NewJSONHandler(&log1, nil))
	chain, key, err := i.Issue(context.Background(), hosts)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Certificate) != 2 {
		t.Fatalf("want leaf and intermediate, got %d certificates", len(pair.Certificate))
	}
	if k, ok := pair.PrivateKey.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P256() {
		t.Fatalf("want a P-256 key, got %T", pair.PrivateKey)
	}
	if Due(chain, hosts, time.Now()) != "" {
		t.Fatal("fresh certificate reported due")
	}
	// Every record placed, then all checked once, then all removed.
	want := []string{"add _acme-challenge.uchi.example.org.", "add _acme-challenge.uchi.example.org.", "add _acme-challenge.cv.example.org.", "wait 2",
		"delete _acme-challenge.uchi.example.org.", "delete _acme-challenge.uchi.example.org.", "delete _acme-challenge.cv.example.org."}
	if !slices.Equal(d.log, want) {
		t.Fatalf("dns operations\n got %q\nwant %q", d.log, want)
	}
	if len(ca.orders) != 1 {
		t.Fatalf("want one order, got %d", len(ca.orders))
	}
	info, err := os.Stat(i.ACME.AccountKeyFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("account key: %v %v", info.Mode(), err)
	}

	// A second process reuses the account and a fresh certificate key.
	j, _, _ := setup(t, false)
	j.ACME, j.DNS = i.ACME, d
	j.ACME.AcceptTerms = false
	j.Log = slog.New(slog.NewJSONHandler(&log2, nil))
	_, key2, err := j.Issue(context.Background(), hosts[:1])
	if err != nil || slices.Equal(key, key2) || len(ca.accounts) != 1 {
		t.Fatalf("second issue: %v, accounts %d", err, len(ca.accounts))
	}

	// Both runs log the account URL (RFC 8657 accounturi=); only the first registers.
	var thumb string
	for k := range ca.accounts {
		thumb = k
	}
	uri := ca.url("/account/%s", thumb)
	if uris, reg := accountURIs(t, &log1); !reg || !slices.Equal(uris, []string{uri}) {
		t.Fatalf("first run: registered %v, uris %q, want %q\n%s", reg, uris, uri, log1.String())
	}
	if uris, reg := accountURIs(t, &log2); reg || !slices.Equal(uris, []string{uri}) {
		t.Fatalf("second run: registered %v, uris %q, want %q\n%s", reg, uris, uri, log2.String())
	}
}

func TestTermsNotAccepted(t *testing.T) {
	i, ca, _ := setup(t, false)
	if _, _, err := i.Issue(context.Background(), hosts); err == nil || !strings.Contains(err.Error(), "accept_terms") {
		t.Fatalf("want an accept_terms error, got %v", err)
	}
	if len(ca.accounts) != 0 {
		t.Fatal("account created without accepted terms")
	}
}

func TestFailedUpdateAbortsAndCleansUp(t *testing.T) {
	i, ca, d := setup(t, true)
	d.failAdd = 2
	if _, _, err := i.Issue(context.Background(), hosts); err == nil {
		t.Fatal("want an error")
	}
	want := []string{"add _acme-challenge.uchi.example.org.", "add _acme-challenge.uchi.example.org.",
		"delete _acme-challenge.uchi.example.org.", "delete _acme-challenge.uchi.example.org."}
	if !slices.Equal(d.log, want) {
		t.Fatalf("dns operations\n got %q\nwant %q", d.log, want)
	}
	for _, z := range ca.authzs {
		if z.status != "pending" {
			t.Fatal("challenge accepted after a failed UPDATE")
		}
	}
}

func TestDue(t *testing.T) {
	now := time.Now()
	cert := func(notBefore, notAfter time.Time, names ...string) []byte {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: notBefore, NotAfter: notAfter}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	day := 24 * time.Hour
	cases := map[string]struct {
		chain []byte
		want  string
	}{
		"absent":        {nil, "absent"},
		"garbage":       {[]byte("x"), "unreadable"},
		"fresh":         {cert(now.Add(-day), now.Add(89*day), "b.example.org", "A.example.org"), ""},
		"hosts changed": {cert(now.Add(-day), now.Add(89*day), "a.example.org"), "hosts changed"},
		"at 31 days":    {cert(now.Add(-59*day), now.Add(31*day), "a.example.org", "b.example.org"), ""},
		"at 29 days":    {cert(now.Add(-61*day), now.Add(29*day), "a.example.org", "b.example.org"), "less than a third of its lifetime left"},
	}
	for name, tc := range cases {
		if got := Due(tc.chain, []string{"a.example.org", "b.example.org"}, now); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}
