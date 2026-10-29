package config

import (
	"bytes"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/scorsi/hanko/internal/logging"
)

func TestExample(t *testing.T) {
	data, err := os.ReadFile("../../testdata/example.toml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Certificates) != 2 || c.Certificates[0].Name != "home" || c.DNS.Nameservers[1] != "[2001:db8::10]:53" {
		t.Fatalf("unexpected decode: %+v", c)
	}
}

const head = `
[acme]
directory = "https://x.example.org/dir"
account_key_file = "/var/lib/hanko/account.key"
[dns]
nameservers = ["203.0.113.10:53"]
tsig_key_file = "/run/secrets/k"
propagation_timeout = "30s"
`

const home = `
[[certificates]]
name = "home"
issuer = "acme"
group = "genkan"
hosts = ["uchi.example.org"]
`

const internalTable = `
[internal]
ca = "[fd12:3456:789a::1]:4900"
`

const apiCert = `
[[certificates]]
name = "api"
issuer = "internal"
group = "api"
spiffe_id = "spiffe://uchi.example.org/vm/api"
`

// TestInternal: the v1 example of ADR 0002, alone and next to ACME certificates.
func TestInternal(t *testing.T) {
	for _, data := range []string{internalTable + apiCert, head + home + internalTable + apiCert} {
		c, err := Parse([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		if c.Internal.CA != "[fd12:3456:789a::1]:4900" || c.Certificates[len(c.Certificates)-1].SpiffeID != "spiffe://uchi.example.org/vm/api" {
			t.Fatalf("unexpected decode: %+v", c)
		}
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]struct{ toml, want string }{
		"unknown top key":    {head + home + "bogus = 1\n", "bogus"},
		"unknown table key":  {strings.Replace(head, "directory", "directry", 1) + home, "directry"},
		"unknown cert key":   {head + home + "hsots = []\n", "hsots"},
		"spiffe_id on acme":  {head + home + `spiffe_id = "spiffe://uchi.example.org/vm/a"` + "\n", "spiffe_id"},
		"unused acme":        {head, "acme: table unused"},
		"missing acme":       {home, "acme: table required"},
		"duplicate name":     {head + home + home, "duplicate name"},
		"bad name":           {head + strings.Replace(home, `"home"`, `"Home_1"`, 1), "name must match"},
		"unknown issuer":     {head + strings.Replace(home, `"acme"`, `"foo"`, 1), "unknown issuer"},
		"unused internal":    {head + home + internalTable, "internal: table unused"},
		"missing internal":   {apiCert, "internal: table required"},
		"bad internal ca":    {strings.Replace(internalTable, ":4900", "", 1) + apiCert, "internal: ca"},
		"bad spiffe_id":      {internalTable + strings.Replace(apiCert, "/vm/api", "/api", 1), "spiffe_id"},
		"hosts on internal":  {internalTable + apiCert + "hosts = [\"a.example.org\"]\n", "hosts belong"},
		"reload on internal": {internalTable + apiCert + "reload = [\"api.service\"]\n", "reload belongs"},
		"no hosts":           {head + "[[certificates]]\nname = \"a\"\nissuer = \"acme\"\n", "needs hosts"},
		"bad nameserver":     {strings.Replace(head, "203.0.113.10:53", "203.0.113.10", 1) + home, "nameserver"},
		"bad timeout":        {strings.Replace(head, "30s", "soon", 1) + home, "propagation_timeout"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.toml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestUnsafeConfiguration(t *testing.T) {
	for _, tc := range []struct{ field, old, bad string }{
		{"hosts", "uchi.example.org", ""},
		{"hosts", "uchi.example.org", "a..example.org"},
		{"hosts", "uchi.example.org", "a.*.example.org"},
		{"hosts", "uchi.example.org", "*example.org"},
		{"hosts", "uchi.example.org", "-a.example.org"},
		{"hosts", "uchi.example.org", "a_.example.org"},
		{"hosts", "uchi.example.org", "example.org."},
		{"hosts", "uchi.example.org", "192.0.2.1"},
		{"hosts", "uchi.example.org", strings.Repeat("a", 64) + ".org"},
		{"hosts", "uchi.example.org", "*." + strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 60)},
		{"hosts", "uchi.example.org", strings.Repeat("aaaa.", 60) + "example.org"},
		{"nameserver", "203.0.113.10:53", ":not-a-port"},
		{"nameserver", "203.0.113.10:53", "ns.example.org:53"},
		{"nameserver", "203.0.113.10:53", "203.0.113.10:0"},
		{"nameserver", "203.0.113.10:53", "203.0.113.10:65536"},
		{"nameserver", "203.0.113.10:53", "203.0.113.10:domain"},
		{"directory", "https://x.example.org/dir", "not-a-url"},
		{"directory", "https://x.example.org/dir", "http://example.org/dir"},
		{"directory", "https://x.example.org/dir", "https://user:secret@example.org/dir"},
		{"directory", "https://x.example.org/dir", "https://example.org:65536/dir"},
		{"directory", "https://x.example.org/dir", "https://example.org/dir?secret=token"},
		{"account_key_file", "/var/lib/hanko/account.key", "account.key"},
		{"account_key_file", "/var/lib/hanko/account.key", "/var/lib/hanko/home/key.pem"},
		{"account_key_file", "/var/lib/hanko/account.key", "/var/lib/hanko/home"},
		{"account_key_file", "/var/lib/hanko/account.key", "/var/lib/hanko/.lock"},
		{"account_key_file", "/var/lib/hanko/account.key", "/var/lib/hanko/.retry-after"},
		{"account_key_file", "/var/lib/hanko/account.key", "/var/lib/hanko/a/../account.key"},
		{"tsig_key_file", "/run/secrets/k", "relative"},
		{"tsig_key_file", "/run/secrets/k", "/var/lib/hanko/account.key"},
		{"group", "genkan", ""},
	} {
		t.Run(tc.field+"/"+tc.bad, func(t *testing.T) {
			_, err := Parse([]byte(strings.Replace(head+home, tc.old, tc.bad, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("want %s error, got %v", tc.field, err)
			}
		})
	}
	for _, unit := range []string{"--help", "*.service", "foo?.service", "a b.service", "foo", "a@.service", "a@b@c.service", "foo.service\nbar.service"} {
		t.Run("reload/"+unit, func(t *testing.T) {
			_, err := Parse([]byte(head + home + "reload = [" + strconv.Quote(unit) + "]\n"))
			if err == nil {
				t.Fatal("invalid unit accepted")
			}
		})
	}
	t.Run("state path", func(t *testing.T) {
		t.Setenv("STATE_DIRECTORY", "relative")
		if _, err := Parse([]byte(head + home)); err == nil {
			t.Fatal("relative state accepted")
		}
	})
}

func TestConfigurationCanonicalHostsAndLocalHTTP(t *testing.T) {
	for _, url := range []string{"https://example.org/dir", "http://127.0.0.1:14000/dir", "http://[::1]:14000/dir"} {
		data := strings.Replace(head+home, "https://x.example.org/dir", url, 1)
		data = strings.Replace(data, "uchi.example.org", "*.UCHI.example.org", 1)
		c, err := Parse([]byte(data))
		if err != nil || c.Certificates[0].Hosts[0] != "*.uchi.example.org" {
			t.Fatalf("config %+v: %v", c, err)
		}
	}
}

func TestParserErrorsDoNotLogValues(t *testing.T) {
	const secret = "SECRET_CHALLENGE_MARKER"
	for _, data := range []string{
		head + home + `tsig_secret = "` + secret + `"`,
		head + home + `unknown = { value = "` + secret + `" }`,
		strings.Replace(head+home, `accept_terms = true`, `accept_terms = "`+secret+`"`, 1) + "\ninvalid = '" + secret,
		strings.Replace(head+home, `hosts = ["uchi.example.org"]`, `hosts = "`+secret+`"`, 1),
		strings.Replace(head+home, "30s", secret, 1),
	} {
		_, err := Parse([]byte(data))
		if err == nil {
			t.Fatal("want an error")
		}
		var out bytes.Buffer
		logging.New(&out, slog.LevelInfo).Error("", "event", "config-invalid", "err", err)
		if strings.Contains(out.String(), secret) {
			t.Fatalf("secret leaked: %s", &out)
		}
	}
}
