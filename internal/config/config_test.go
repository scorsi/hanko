package config

import (
	"os"
	"strings"
	"testing"
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
hosts = ["uchi.example.org"]
`

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
		"internal issuer v1": {head + home + "[[certificates]]\nname = \"api\"\nissuer = \"internal\"\nspiffe_id = \"spiffe://uchi.example.org/vm/api\"\n", "v1"},
		"internal table v1":  {head + home + "[internal]\nca = \"[fd12::1]:4900\"\n", "internal"},
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
