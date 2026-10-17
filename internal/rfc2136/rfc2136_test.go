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
// in the manner of an annai soto instance.
type fakeNS struct {
	addr string

	mu     sync.Mutex
	txt    map[string][]string
	refuse bool // answer REFUSED to every UPDATE
	lag    int  // TXT queries answered empty before the records show
}

func startNS(t *testing.T) *fakeNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeNS{addr: pc.LocalAddr().String(), txt: map[string][]string{}}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: f, TsigSecret: map[string]string{"hanko.": secret}, NotifyStartedFunc: func() { close(started) },
		MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }}
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })
	return f
}

func (f *fakeNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := new(dns.Msg).SetReply(r)
	q := r.Question[0]
	switch {
	case r.Opcode == dns.OpcodeUpdate:
		if r.IsTsig() == nil || w.TsigStatus() != nil || f.refuse || q.Name != "example.org." {
			m.Rcode = dns.RcodeRefused
			break
		}
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
