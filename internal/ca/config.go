// Package ca is hanko-ca, the internal signer of ADR 0004: its configuration, the X.509-SVID
// signer and the gRPC service.
package ca

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config is hanko-ca's own file (ADR 0004).
type Config struct {
	CA    Settings `toml:"ca"`
	Hosts []Host   `toml:"hosts"`
}

type Settings struct {
	KeyFile      string `toml:"key_file"`
	CertFile     string `toml:"cert_file"`
	Listen       string `toml:"listen"`
	SVIDLifetime string `toml:"svid_lifetime"`
}

// Host is one overlay address and the SPIFFE IDs a caller from it may request.
type Host struct {
	Address string   `toml:"address"`
	IDs     []string `toml:"ids"`
}

// Lifetime is svid_lifetime, already validated by Parse.
func (s Settings) Lifetime() time.Duration {
	d, _ := time.ParseDuration(s.SVIDLifetime)
	return d
}

// Allowed maps each (unmapped) host address to its set of IDs.
func (c *Config) Allowed() map[netip.Addr]map[string]bool {
	m := map[netip.Addr]map[string]bool{}
	for _, h := range c.Hosts {
		a := netip.MustParseAddr(h.Address).Unmap()
		m[a] = map[string]bool{}
		for _, id := range h.IDs {
			m[a][id] = true
		}
	}
	return m
}

// ParseConfig decodes TOML (unknown keys are errors) and validates it without reading the
// key or certificate, so the module can run it at build time (ADR 0002).
func ParseConfig(data []byte) (*Config, error) {
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

	for _, f := range []struct{ key, v string }{{"key_file", c.CA.KeyFile}, {"cert_file", c.CA.CertFile}} {
		if !filepath.IsAbs(f.v) || filepath.Clean(f.v) != f.v {
			add("ca: %s must be a clean absolute path", f.key)
		}
	}
	// ADR 0005: the overlay address only, above 1024.
	if ap, err := netip.ParseAddrPort(c.CA.Listen); err != nil || !specific(ap.Addr()) || ap.Port() <= 1024 {
		add("ca: listen must be a specific IP address (an IPv4 one in IPv4 form) with a port above 1024")
	}
	if d, err := time.ParseDuration(c.CA.SVIDLifetime); err != nil || d <= 0 {
		add("ca: svid_lifetime must be a positive duration such as \"24h\"")
	}
	if len(c.Hosts) == 0 {
		add("hosts: at least one host is required")
	}
	seen := map[netip.Addr]bool{}
	trust := ""
	for i, h := range c.Hosts {
		at := fmt.Sprintf("hosts[%d]", i)
		a, err := netip.ParseAddr(h.Address)
		switch {
		case err != nil || !specific(a):
			add("%s: address must be a specific IP address, an IPv4 one in IPv4 form", at)
		case seen[a.Unmap()]:
			add("%s: duplicate address", at)
		default:
			seen[a.Unmap()] = true
		}
		if len(h.IDs) == 0 {
			add("%s: ids must not be empty", at)
		}
		for j, id := range h.IDs {
			td, err := ParseID(id)
			switch {
			case err != nil:
				add("%s: ids[%d]: %v", at, j, err)
			case trust == "":
				trust = td
			case td != trust:
				// Federation is out of scope (ADR 0004): one trust domain per CA.
				add("%s: ids[%d]: trust domain %q differs from %q", at, j, td, trust)
			}
		}
	}
	return errors.Join(errs...)
}

// specific refuses the wildcard, zones and IPv4-mapped IPv6 forms ([::ffff:0.0.0.0] would
// otherwise pass IsUnspecified); peers are compared unmapped, so IPv4 is written as IPv4.
func specific(a netip.Addr) bool {
	return !a.Is4In6() && !a.Unmap().IsUnspecified() && a.Zone() == ""
}

// ParseID checks a SPIFFE ID of the form spiffe://<trust domain>/<host>/<service> (ADR 0004)
// with the character rules of the SPIFFE ID standard, and returns its trust domain.
func ParseID(id string) (string, error) {
	bad := errors.New("must be spiffe://<trust domain>/<host>/<service>")
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "spiffe" || u.Opaque != "" || u.User != nil || u.Port() != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.String() != id {
		return "", bad
	}
	if u.Host == "" || strings.Trim(u.Host, "abcdefghijklmnopqrstuvwxyz0123456789.-_") != "" {
		return "", errors.New("trust domain must be lowercase letters, digits, '.', '-' or '_'")
	}
	segs := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if !strings.HasPrefix(u.Path, "/") || len(segs) != 2 {
		return "", bad
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." ||
			strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_") != "" {
			return "", errors.New("path segments must be letters, digits, '.', '-' or '_', not '.' or '..'")
		}
	}
	return u.Host, nil
}
