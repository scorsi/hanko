// Package config parses and validates hanko's TOML file (ADR 0002).
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	ACME         *ACME         `toml:"acme"`
	DNS          *DNS          `toml:"dns"`
	Certificates []Certificate `toml:"certificates"`
}

type ACME struct {
	Directory      string `toml:"directory"`
	AccountKeyFile string `toml:"account_key_file"`
	// AcceptTerms is the explicit acceptance of the CA's terms of service, needed only to
	// create the account (ADR 0003); an existing account works without it.
	AcceptTerms bool `toml:"accept_terms"`
}

type DNS struct {
	Nameservers        []string `toml:"nameservers"`
	TSIGKeyFile        string   `toml:"tsig_key_file"`
	PropagationTimeout string   `toml:"propagation_timeout"`
}

// Certificate holds the keys of every issuer so that a mismatch is reported by name; the
// internal issuer's spiffe_id is parsed only to be rejected (v1, ADR 0004).
type Certificate struct {
	Name     string   `toml:"name"`
	Issuer   string   `toml:"issuer"`
	Hosts    []string `toml:"hosts"`
	SpiffeID string   `toml:"spiffe_id"`
	Reload   []string `toml:"reload"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9-]+$`)

// Timeout is dns.propagation_timeout, already validated by Parse.
func (d *DNS) Timeout() time.Duration {
	t, _ := time.ParseDuration(d.PropagationTimeout)
	return t
}

// Load reads and validates a file; the error lists every problem, one per line.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes TOML (unknown keys are errors, which also rejects the v1 [internal] table) and validates it.
func Parse(data []byte) (*Config, error) {
	c := &Config{}
	dec := toml.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			return nil, errors.New(strict.String())
		}
		return nil, err
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	seen := map[string]bool{}
	acmeUsed := false
	for i, cert := range c.Certificates {
		at := fmt.Sprintf("certificates[%d]", i)
		if cert.Name != "" {
			at += " " + cert.Name
		}
		switch {
		case !nameRE.MatchString(cert.Name):
			add("%s: name must match [a-z0-9-]+", at)
		case seen[cert.Name]:
			add("%s: duplicate name", at)
		}
		seen[cert.Name] = true
		for _, u := range cert.Reload {
			if u == "" {
				add("%s: empty unit in reload", at)
			}
		}
		switch cert.Issuer {
		case "acme":
			acmeUsed = true
			if len(cert.Hosts) == 0 {
				add("%s: issuer acme needs hosts", at)
			}
			if cert.SpiffeID != "" {
				add("%s: spiffe_id belongs to the internal issuer, not acme", at)
			}
		case "internal":
			add("%s: issuer internal is v1 and not supported by this version", at)
		default:
			add("%s: unknown issuer %q (want acme)", at, cert.Issuer)
		}
	}

	if acmeUsed {
		if c.ACME == nil {
			add("acme: table required by acme certificates")
		} else if c.ACME.Directory == "" || c.ACME.AccountKeyFile == "" {
			add("acme: directory and account_key_file are required")
		}
		c.validateDNS(add)
	} else {
		if c.ACME != nil {
			add("acme: table unused, no certificate has issuer acme")
		}
		if c.DNS != nil {
			add("dns: table unused, no certificate has issuer acme")
		}
	}
	return errors.Join(errs...)
}

func (c *Config) validateDNS(add func(string, ...any)) {
	if c.DNS == nil {
		add("dns: table required by acme certificates")
		return
	}
	if len(c.DNS.Nameservers) == 0 {
		add("dns: nameservers must not be empty")
	}
	for _, ns := range c.DNS.Nameservers {
		if _, _, err := net.SplitHostPort(ns); err != nil {
			add("dns: nameserver %q: %v", ns, err)
		}
	}
	if c.DNS.TSIGKeyFile == "" {
		add("dns: tsig_key_file is required")
	}
	if d, err := time.ParseDuration(c.DNS.PropagationTimeout); err != nil || d <= 0 {
		add("dns: propagation_timeout %q must be a positive duration such as \"120s\"", c.DNS.PropagationTimeout)
	}
}
