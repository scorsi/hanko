package rfc2136

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTMyYg=="

// fakeNS is an authoritative server for example.org applying TSIG-signed UPDATEs to TXT records,
// in the manner of an annai soto instance, over UDP and TCP on one port.
type fakeNS struct {
	addr string

	mu       sync.Mutex
	txt      map[string][]string
	refuse   bool     // answer a signed REFUSED to every UPDATE
	lag      int      // TXT queries answered empty before the records show
	truncate bool     // answer UPDATEs over UDP with a signed, truncated, unapplied reply
	forge    string   // answer UPDATEs with this kind of bad reply, see forged
	updates  []string // transport of every UPDATE received
}

func startNS(t *testing.T) *fakeNS {
	t.Helper()
	// TCP fallback dials the same host:port: find a port free for both.
	var l net.Listener
	var pc net.PacketConn
	for i := 0; pc == nil; i++ {
		var err error
		if l, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if pc, err = net.ListenPacket("udp", l.Addr().String()); err != nil {
			l.Close()
			if i == 10 {
				t.Fatal(err)
			}
		}
	}
	f := &fakeNS{addr: l.Addr().String(), txt: map[string][]string{}}
	for _, srv := range []*dns.Server{{PacketConn: pc}, {Listener: l}} {
		started := make(chan struct{})
		srv.Handler, srv.TsigSecret, srv.NotifyStartedFunc = f, map[string]string{"hanko.": secret}, func() { close(started) }
		srv.MsgAcceptFunc = func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }
		go srv.ActivateAndServe()
		<-started
		t.Cleanup(func() { srv.Shutdown() })
	}
	return f
}

func (f *fakeNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := new(dns.Msg).SetReply(r)
	q := r.Question[0]
	switch {
	case r.Opcode == dns.OpcodeUpdate:
		udp := w.RemoteAddr().Network() == "udp"
		f.updates = append(f.updates, w.RemoteAddr().Network())
		if r.IsTsig() == nil || w.TsigStatus() != nil {
			m.Rcode = dns.RcodeRefused // unsigned, as for BADKEY/BADSIG
			break
		}
		if f.forge != "" {
			w.Write(f.forged(r, m))
			return
		}
		switch {
		case f.refuse || q.Name != "example.org.":
			m.Rcode = dns.RcodeRefused
		case f.truncate && udp:
			m.Truncated = true
		default:
			f.apply(r)
		}
		m.SetTsig(r.IsTsig().Hdr.Name, dns.HmacSHA256, 300, time.Now().Unix())
	case q.Qtype == dns.TypeSOA:
		soa, _ := dns.NewRR("example.org. 60 IN SOA ns.example.org. admin.example.org. 1 60 60 60 60")
		m.Ns = []dns.RR{soa}
	case q.Qtype == dns.TypeTXT && f.lag > 0:
		f.lag--
	case q.Qtype == dns.TypeTXT:
		for _, v := range f.txt[q.Name] {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{v}})
		}
	}
	w.WriteMsg(m)
}

func (f *fakeNS) apply(r *dns.Msg) {
	for _, rr := range r.Ns {
		v := rr.(*dns.TXT).Txt[0]
		name := rr.Header().Name
		switch rr.Header().Class {
		case dns.ClassINET:
			f.txt[name] = append(f.txt[name], v)
		case dns.ClassNONE:
			f.txt[name] = slices.DeleteFunc(f.txt[name], func(s string) bool { return s == v })
		}
	}
}

// forged builds the wire form of the reply m to r that f.forge names; every one must be rejected.
func (f *fakeNS) forged(r, m *dns.Msg) []byte {
	key, sec, signedAt := r.IsTsig().Hdr.Name, secret, time.Now().Unix()
	switch f.forge {
	case "unsigned success", "unsigned refusal":
		if f.forge == "unsigned refusal" {
			m.Rcode = dns.RcodeRefused
		}
		b, _ := m.Pack()
		return b
	case "empty mac": // a TSIG stub never signed
		m.SetTsig(key, dns.HmacSHA256, 300, signedAt)
		b, _ := m.Pack()
		return b
	case "wrong mac":
		sec = "d3Jvbmctd3Jvbmctd3Jvbmctd3Jvbmctd3Jvbmc="
	case "expired":
		signedAt -= 3600
	case "wrong key name":
		key = "other."
	case "signed refusal":
		m.Rcode = dns.RcodeRefused
	case "query opcode":
		m.Opcode = dns.OpcodeQuery
	}
	m.SetTsig(key, dns.HmacSHA256, 300, signedAt)
	if f.forge == "tsig error" {
		m.IsTsig().Error = dns.RcodeBadTime // still signed (RFC 8945 5.2.3)
	}
	b, _, err := dns.TsigGenerate(m, sec, r.IsTsig().MAC, false)
	if err != nil {
		panic(err)
	}
	return b
}

func (f *fakeNS) values(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.txt[name])
}

func client(t *testing.T, ns ...*fakeNS) *Client {
	t.Helper()
	key := filepath.Join(t.TempDir(), "tsig")
	if err := os.WriteFile(key, []byte("hanko:"+secret+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	var addrs []string
	for _, n := range ns {
		addrs = append(addrs, n.addr)
	}
	c, err := New(addrs, key)
	if err != nil {
		t.Fatal(err)
	}
	c.Interval = 10 * time.Millisecond
	return c
}

const name = "_acme-challenge.uchi.example.org."

func TestAddDeleteFanOut(t *testing.T) {
	a, b := startNS(t), startNS(t)
	c := client(t, a, b)
	ctx := context.Background()
	if err := c.Add(ctx, name, "v1"); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(ctx, name, "v2"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*fakeNS{a, b} {
		if got := n.values(name); !slices.Equal(got, []string{"v1", "v2"}) {
			t.Fatalf("%s holds %v", n.addr, got)
		}
	}
	if err := c.Delete(ctx, name, "v1"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*fakeNS{a, b} {
		if got := n.values(name); !slices.Equal(got, []string{"v2"}) {
			t.Fatalf("%s holds %v after delete", n.addr, got)
		}
	}
}

func TestAddAbortsOnRefusal(t *testing.T) {
	a, b := startNS(t), startNS(t)
	a.refuse = true
	err := client(t, a, b).Add(context.Background(), name, "v")
	if err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("want REFUSED, got %v", err)
	}
	if len(b.values(name)) != 0 {
		t.Fatal("UPDATE sent to the next nameserver after a refusal")
	}
}

func TestDeleteReportsEveryFailure(t *testing.T) {
	a, b := startNS(t), startNS(t)
	c := client(t, a, b)
	if err := c.Add(context.Background(), name, "v"); err != nil {
		t.Fatal(err)
	}
	a.refuse = true
	if err := c.Delete(context.Background(), name, "v"); err == nil {
		t.Fatal("want an error from the refusing nameserver")
	}
	if len(b.values(name)) != 0 {
		t.Fatal("delete not sent to the second nameserver")
	}
}

func TestWrongKeyRefused(t *testing.T) {
	a := startNS(t)
	c := client(t, a)
	c.Secret = "d3Jvbmc="
	if err := c.Add(context.Background(), name, "v"); err == nil || len(a.values(name)) != 0 {
		t.Fatalf("want a failed UPDATE, got %v", err)
	}
}

// H1 of the 6959360 review: the UPDATE was signed, so only a reply signed by the same key,
// valid, in time and answering it, is an acknowledgement.
func TestUpdateRejectsUnauthenticatedReplies(t *testing.T) {
	for _, forge := range []string{"unsigned success", "unsigned refusal", "empty mac", "wrong mac", "expired", "wrong key name", "tsig error", "signed refusal", "query opcode"} {
		t.Run(forge, func(t *testing.T) {
			a := startNS(t)
			a.forge = forge
			if err := client(t, a).Add(context.Background(), name, "v"); err == nil {
				t.Fatal("reply accepted")
			}
		})
	}
}

// H2 of the 6959360 review: a truncated UDP reply makes the client retry over TCP, signed again.
func TestTruncatedUpdateRetriesSignedOverTCP(t *testing.T) {
	a := startNS(t)
	a.truncate = true
	c := client(t, a)
	if err := c.Add(context.Background(), name, "v"); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(context.Background(), name, "v"); err != nil {
		t.Fatal(err)
	}
	// The fake refuses an unsigned TCP UPDATE, so the record coming and going proves the signature.
	a.mu.Lock()
	defer a.mu.Unlock()
	if !slices.Equal(a.updates, []string{"udp", "tcp", "udp", "tcp"}) || len(a.txt[name]) != 0 {
		t.Fatalf("updates %v, records %v", a.updates, a.txt[name])
	}
}

func TestWaitLaggingNameserver(t *testing.T) {
	a, b := startNS(t), startNS(t)
	c := client(t, a, b)
	if err := c.Add(context.Background(), name, "v"); err != nil {
		t.Fatal(err)
	}
	b.lag = 3
	if err := c.Wait(context.Background(), map[string][]string{name: {"v"}}, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	b.lag = 1 << 30
	err := c.Wait(context.Background(), map[string][]string{name: {"v"}}, 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), b.addr) || strings.Contains(err.Error(), a.addr) {
		t.Fatalf("want a timeout naming only %s, got %v", b.addr, err)
	}
}

func TestKeyFile(t *testing.T) {
	key := filepath.Join(t.TempDir(), "tsig")
	os.WriteFile(key, []byte("hanko-not-base64:%%%"), 0o400)
	_, err := New(nil, key)
	if err == nil || strings.Contains(err.Error(), "%%%") {
		t.Fatalf("want an error without the secret, got %v", err)
	}
}
