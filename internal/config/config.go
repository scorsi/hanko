// Package config parses and validates hanko's TOML file (ADR 0002).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/scorsi/hanko/internal/ca"
)

type Config struct {
	ACME         *ACME         `toml:"acme"`
	DNS          *DNS          `toml:"dns"`
	Internal     *Internal     `toml:"internal"`
	Certificates []Certificate `toml:"certificates"`
}

type ACME struct {
	Directory      string `toml:"directory"`
	AccountKeyFile string `toml:"account_key_file"`
	// AcceptTerms is the explicit acceptance of the CA's terms of service, needed only to
	// create the account (ADR 0003); an existing account works without it.
	AcceptTerms bool `toml:"accept_terms"`
	// CreateAccount lets a run create the account key when it is absent; without it an absent
	// key is an error, never a new account (ADR 0008).
	CreateAccount bool `toml:"create_account"`
}

type DNS struct {
	Nameservers        []string `toml:"nameservers"`
	TSIGKeyFile        string   `toml:"tsig_key_file"`
	PropagationTimeout string   `toml:"propagation_timeout"`
}

// Internal is the internal issuer's table (ADR 0002, ADR 0004).
type Internal struct {
	// CA is hanko-ca's overlay address, host:port.
	CA string `toml:"ca"`
}

// Certificate holds the keys of every issuer so that a mismatch is reported by name.
type Certificate struct {
	Name     string   `toml:"name"`
	Issuer   string   `toml:"issuer"`
	Hosts    []string `toml:"hosts"`
	SpiffeID string   `toml:"spiffe_id"`
	Reload   []string `toml:"reload"`
	Group    string   `toml:"group"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9-]+$`)
var groupRE = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_-]*$`)
var unitRE = regexp.MustCompile(`^[a-zA-Z0-9:_.@-]+\.(service|socket|target|mount|automount|swap|timer|path|slice|scope)$`)

// StateDir is systemd's state directory, or the module's default outside a unit.
func StateDir() string {
	if s := os.Getenv("STATE_DIRECTORY"); s != "" {
		return s
	}
	return "/var/lib/hanko"
}

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

// Parse decodes TOML (unknown keys are errors) and validates it.
func Parse(data []byte) (*Config, error) {
	c := &Config{}
	dec := toml.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			var errs []error
			for _, e := range strict.Errors {
				line, col := e.Position()
				errs = append(errs, fmt.Errorf("unknown key %q at %d:%d", strings.Join(e.Key(), "."), line, col))
			}
			return nil, errors.Join(errs...)
		}
		var decode *toml.DecodeError
		if errors.As(err, &decode) {
			line, col := decode.Position()
			return nil, fmt.Errorf("invalid TOML at %d:%d", line, col)
		}
		return nil, errors.New("invalid TOML")
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	seen := map[string]bool{}
	acmeUsed, internalUsed := false, false
	for i, cert := range c.Certificates {
		at := fmt.Sprintf("certificates[%d]", i)
		if nameRE.MatchString(cert.Name) {
			at += " " + cert.Name
		}
		switch {
		case len(cert.Name) > 255 || !nameRE.MatchString(cert.Name):
			add("%s: name must match [a-z0-9-]+ and fit in 255 bytes", at)
		case seen[cert.Name]:
			add("%s: duplicate name", at)
		}
		seen[cert.Name] = true
		if !groupRE.MatchString(cert.Group) {
			add("%s: group must be a group name or numeric gid", at)
		}
		for _, u := range cert.Reload {
			if len(u) > 255 || !unitRE.MatchString(u) || strings.HasPrefix(u, "-") || strings.Contains(u, "@.") || strings.Count(u, "@") > 1 {
				add("%s: reload must contain literal unit names", at)
			}
		}
		switch cert.Issuer {
		case "acme":
			acmeUsed = true
			if len(cert.Hosts) == 0 {
				add("%s: issuer acme needs hosts", at)
			}
			for j, h := range cert.Hosts {
				if !validHost(h) {
					add("%s: hosts[%d] must be a DNS hostname or leftmost wildcard", at, j)
				} else {
					c.Certificates[i].Hosts[j] = strings.ToLower(h)
				}
			}
			if cert.SpiffeID != "" {
				add("%s: spiffe_id belongs to the internal issuer, not acme", at)
			}
		case "internal":
			internalUsed = true
			if _, err := ca.ParseID(cert.SpiffeID); err != nil {
				add("%s: spiffe_id: %v", at, err)
			}
			if len(cert.Hosts) != 0 {
				add("%s: hosts belong to the acme issuer, not internal", at)
			}
			if len(cert.Reload) != 0 {
				add("%s: reload belongs to the acme issuer: consumers of internal certificates reload their files themselves (ADR 0013)", at)
			}
		default:
			add("%s: unknown issuer (want acme or internal)", at)
		}
	}

	if acmeUsed {
		if c.ACME == nil {
			add("acme: table required by acme certificates")
		} else {
			u, err := url.Parse(c.ACME.Directory)
			if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
				(u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback())) {
				add("acme: directory must be an HTTPS URL without credentials, query or fragment (HTTP only on loopback)")
			} else if p := u.Port(); p != "" && !validPort(p) {
				add("acme: directory has an invalid port")
			}
			state := StateDir()
			if !cleanAbsolute(state) || state == "/" {
				add("state directory must be a clean absolute directory path")
			}
			key := c.ACME.AccountKeyFile
			base := filepath.Base(key)
			if !cleanAbsolute(key) || filepath.Dir(key) != state || base == ".lock" || base == ".retry-after" || seen[base] {
				add("acme: account_key_file must be directly in the state directory, distinct from internal state files and certificate directories")
			}
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
	switch {
	case internalUsed && c.Internal == nil:
		add("internal: table required by internal certificates")
	case internalUsed:
		if ap, err := netip.ParseAddrPort(c.Internal.CA); err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" {
			add("internal: ca must be a numeric IP address with port 1..65535")
		}
	case c.Internal != nil:
		add("internal: table unused, no certificate has issuer internal")
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
		addr, err := netip.ParseAddrPort(ns)
		if err != nil || addr.Port() == 0 || addr.Addr().Zone() != "" {
			add("dns: nameserver must be a numeric IP address with port 1..65535")
		}
	}
	if !cleanAbsolute(c.DNS.TSIGKeyFile) {
		add("dns: tsig_key_file must be a clean absolute path")
	} else if rel, err := filepath.Rel(StateDir(), c.DNS.TSIGKeyFile); err == nil && filepath.IsLocal(rel) {
		add("dns: tsig_key_file must be outside the state directory")
	}
	if d, err := time.ParseDuration(c.DNS.PropagationTimeout); err != nil || d <= 0 {
		add("dns: propagation_timeout must be a positive duration such as \"120s\"")
	}
}

func cleanAbsolute(s string) bool {
	return filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsAny(s, "\x00\n\r")
}

func validPort(s string) bool {
	n, err := strconv.ParseUint(s, 10, 16)
	return err == nil && n > 0
}

func validHost(s string) bool {
	if len(s) > 253 {
		return false
	}
	s = strings.TrimPrefix(s, "*.")
	if !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
