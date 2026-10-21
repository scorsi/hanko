// Package rfc2136 places and removes DNS-01 challenge records with TSIG-signed RFC 2136 UPDATEs
// on every nameserver, and checks their propagation by asking each one by address (ADR 0003).
package rfc2136

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// TTL of the challenge records; annai caps dynamic records at 120 s anyway.
const ttl = 60

type Client struct {
	Nameservers []string // host:port, every one written to and checked
	KeyName     string   // TSIG key name
	Secret      string   // TSIG secret, base64
	Interval    time.Duration
}

// New reads the TSIG key file, one line "<name>:<base64 secret>" (ADR 0002).
func New(nameservers []string, keyFile string) (*Client, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	line := strings.TrimSuffix(strings.TrimSuffix(string(data), "\r\n"), "\n")
	name, secret, ok := strings.Cut(line, ":")
	_, validName := dns.IsDomainName(name)
	if _, err := base64.StdEncoding.DecodeString(secret); !ok || !validName || name == "" || name == "." || strings.ContainsAny(line, "\r\n \t\\") || secret == "" || err != nil {
		// Never print the content: it is a secret (ADR 0005).
		return nil, fmt.Errorf("tsig key %s: want one line <name>:<base64 secret>", keyFile)
	}
	return &Client{Nameservers: nameservers, KeyName: dns.CanonicalName(name), Secret: secret, Interval: 2 * time.Second}, nil
}

// Add places the TXT record on every nameserver; the first refused or failed UPDATE aborts,
// since the CA may query precisely that nameserver.
func (c *Client) Add(ctx context.Context, name, value string) error {
	for _, ns := range c.Nameservers {
		if err := c.update(ctx, ns, name, value, (*dns.Msg).Insert); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes the TXT record from every nameserver and returns every failure; callers log
// it, since annai expires dynamic records by itself.
func (c *Client) Delete(ctx context.Context, name, value string) error {
	var errs []error
	for _, ns := range c.Nameservers {
		errs = append(errs, c.update(ctx, ns, name, value, (*dns.Msg).Remove))
	}
	return errors.Join(errs...)
}

func (c *Client) update(ctx context.Context, ns, name, value string, op func(*dns.Msg, []dns.RR)) error {
	name = dns.Fqdn(name)
	zone, err := c.zone(ctx, ns, name)
	if err != nil {
		return err
	}
	m := new(dns.Msg).SetUpdate(zone)
	op(m, []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
		Txt: []string{value},
	}})
	m.SetTsig(c.KeyName, dns.HmacSHA256, 300, time.Now().Unix())
	r, err := c.exchange(ctx, m, ns)
	if err == nil {
		err = c.signed(m, r)
	}
	if err != nil {
		return fmt.Errorf("update %s on %s: %w", name, ns, err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("update %s on %s: %s", name, ns, dns.RcodeToString[r.Rcode])
	}
	return nil
}

// signed checks that r answers the signed UPDATE m under the same key. The library verifies a
// response's MAC, time and request MAC only when it carries a TSIG, so an unsigned reply, success
// or error, would otherwise be taken at its word (RFC 8945 5.3, ADR 0003).
func (c *Client) signed(m, r *dns.Msg) error {
	t := r.IsTsig()
	switch {
	case t == nil:
		return fmt.Errorf("unsigned %s response", dns.RcodeToString[r.Rcode])
	case !strings.EqualFold(t.Hdr.Name, c.KeyName) || !strings.EqualFold(t.Algorithm, dns.HmacSHA256):
		return fmt.Errorf("response signed with key %s %s", t.Hdr.Name, t.Algorithm)
	case t.Error != dns.RcodeSuccess:
		return fmt.Errorf("response tsig error %s", dns.RcodeToString[int(t.Error)])
	case !r.Response || r.Opcode != dns.OpcodeUpdate || r.Id != m.Id:
		return errors.New("response does not answer the update")
	}
	return nil
}

// zone finds the zone holding name from the SOA the nameserver returns, in the answer for an
// apex, in the authority section otherwise (RFC 2308).
func (c *Client) zone(ctx context.Context, ns, name string) (string, error) {
	m := new(dns.Msg).SetQuestion(name, dns.TypeSOA)
	m.RecursionDesired = false
	r, err := c.exchange(ctx, m, ns)
	if err != nil {
		return "", fmt.Errorf("zone of %s on %s: %w", name, ns, err)
	}
	if !answerTo(m, r) || !r.Authoritative || (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) {
		return "", fmt.Errorf("zone of %s on %s: not an authoritative SOA response", name, ns)
	}
	for _, rr := range append(r.Answer, r.Ns...) {
		if soa, ok := rr.(*dns.SOA); ok && soa.Hdr.Class == dns.ClassINET && dns.IsSubDomain(soa.Hdr.Name, name) {
			return soa.Hdr.Name, nil
		}
	}
	return "", fmt.Errorf("zone of %s on %s: no SOA in the answer (%s)", name, ns, dns.RcodeToString[r.Rcode])
}

// exchange sends m over UDP, then over TCP if the reply is truncated. Each attempt gets its own
// copy: signing removes the TSIG stub from the message it is given, so a reused m would go
// unsigned over TCP.
func (c *Client) exchange(ctx context.Context, m *dns.Msg, ns string) (*dns.Msg, error) {
	cl := &dns.Client{Net: "udp", TsigSecret: map[string]string{c.KeyName: c.Secret}}
	r, _, err := cl.ExchangeContext(ctx, m.Copy(), ns)
	if err == nil && r.Truncated {
		cl.Net = "tcp"
		r, _, err = cl.ExchangeContext(ctx, m.Copy(), ns)
	}
	return r, err
}

// Wait asks every nameserver by address, never a resolver, until each one returns every value
// of every name, or timeout elapses.
func (c *Client) Wait(ctx context.Context, records map[string][]string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		var pending []string
		for _, ns := range c.Nameservers {
			if !c.has(ctx, ns, records) {
				pending = append(pending, ns)
			}
		}
		if len(pending) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("challenge records not visible after %s on %s", timeout, strings.Join(pending, ", "))
		case <-time.After(c.Interval):
		}
	}
}

func (c *Client) has(ctx context.Context, ns string, records map[string][]string) bool {
	for name, values := range records {
		m := new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeTXT)
		m.RecursionDesired = false
		r, err := c.exchange(ctx, m, ns)
		if err != nil || !answerTo(m, r) || !r.Authoritative || r.Rcode != dns.RcodeSuccess {
			return false
		}
		var got []string
		for _, rr := range r.Answer {
			if txt, ok := rr.(*dns.TXT); ok && txt.Hdr.Class == dns.ClassINET && strings.EqualFold(txt.Hdr.Name, m.Question[0].Name) {
				got = append(got, strings.Join(txt.Txt, ""))
			}
		}
		for _, v := range values {
			if !slices.Contains(got, v) {
				return false
			}
		}
	}
	return true
}

// The transport checks IDs, but a successful exchange alone says nothing about DNS semantics.
func answerTo(q, r *dns.Msg) bool {
	if r == nil || !r.Response || r.Truncated || r.Id != q.Id || r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 {
		return false
	}
	a, b := q.Question[0], r.Question[0]
	return a.Qtype == b.Qtype && a.Qclass == b.Qclass && strings.EqualFold(a.Name, b.Name)
}
