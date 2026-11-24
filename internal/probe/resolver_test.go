package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsServer is a tiny authoritative server for tests, over UDP and TCP on
// one port.
type dnsServer struct {
	addr  string
	mu    sync.Mutex
	asked []string
	// truncate makes UDP answers for this name truncated (empty, TC set).
	truncate string
}

func mustName(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

func (s *dnsServer) answer(q dnsmessage.Message, udp bool) []byte {
	qq := q.Questions[0]
	name := strings.ToLower(qq.Name.String())
	s.mu.Lock()
	s.asked = append(s.asked, qq.Name.String()+"/"+qq.Type.String())
	truncate := s.truncate
	s.mu.Unlock()
	h := dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true}
	var ans []dnsmessage.Resource
	rh := func(n string, t dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: mustName(n), Type: t, Class: dnsmessage.ClassINET, TTL: 30}
	}
	switch name {
	case "api.example.test.":
		switch qq.Type {
		case dnsmessage.TypeA:
			ans = append(ans, dnsmessage.Resource{Header: rh(name, dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 10}}})
		case dnsmessage.TypeAAAA:
			ans = append(ans, dnsmessage.Resource{Header: rh(name, dnsmessage.TypeAAAA), Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::10").As16()}})
		case dnsmessage.TypeTXT:
			ans = append(ans, dnsmessage.Resource{Header: rh(name, dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: []string{"v=spf1 ", "-all"}}})
		}
	case "alias.example.test.":
		ans = append(ans, dnsmessage.Resource{Header: rh(name, dnsmessage.TypeCNAME), Body: &dnsmessage.CNAMEResource{CNAME: mustName("api.example.test.")}})
		if qq.Type == dnsmessage.TypeA {
			ans = append(ans,
				// A record for another name in the answer: must be ignored.
				dnsmessage.Resource{Header: rh("evil.example.org.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{169, 254, 169, 254}}},
				dnsmessage.Resource{Header: rh("api.example.test.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 10}}})
		}
	case "big.example.test.":
		if udp && truncate == name {
			h.Truncated = true
			break
		}
		if qq.Type == dnsmessage.TypeA {
			ans = append(ans, dnsmessage.Resource{Header: rh(name, dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 77}}})
		}
	default:
		h.RCode = dnsmessage.RCodeNameError
	}
	m := dnsmessage.Message{Header: h, Questions: q.Questions, Answers: ans}
	b, _ := m.Pack()
	return b
}

func newDNSServer(t *testing.T) *dnsServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &dnsServer{addr: pc.LocalAddr().String()}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			// A spoofed answer with the wrong id comes first.
			bogus := q
			bogus.ID++
			bogus.Response = true
			bogus.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.AResource{A: [4]byte{169, 254, 169, 254}},
			}}
			if b, err := bogus.Pack(); err == nil {
				_, _ = pc.WriteTo(b, from)
			}
			_, _ = pc.WriteTo(s.answer(q, true), from)
		}
	}()
	ln, err := net.Listen("tcp", s.addr)
	if err == nil {
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					var lb [2]byte
					if _, err := io.ReadFull(c, lb[:]); err != nil {
						return
					}
					b := make([]byte, binary.BigEndian.Uint16(lb[:]))
					if _, err := io.ReadFull(c, b); err != nil {
						return
					}
					var q dnsmessage.Message
					if q.Unpack(b) != nil || len(q.Questions) != 1 {
						return
					}
					resp := s.answer(q, false)
					out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
					_, _ = c.Write(append(out, resp...))
				}()
			}
		}()
	}
	return s
}

func TestDNSResolver(t *testing.T) {
	srv := newDNSServer(t)
	r := &DNSResolver{Servers: []string{"127.0.0.1:1", srv.addr}, Timeout: 500 * time.Millisecond}
	ctx := context.Background()

	got, err := r.LookupNetIP(ctx, "ip", "api.example.test.")
	if err != nil || !slices.Equal(got, ips("203.0.113.10", "2001:db8::10")) {
		t.Fatalf("api: %v %v", got, err)
	}
	// A name without the trailing dot is still absolute: no search list.
	srv.mu.Lock()
	srv.asked = nil
	srv.mu.Unlock()
	if got, err := r.LookupNetIP(ctx, "ip4", "API.example.test"); err != nil || len(got) != 1 {
		t.Fatalf("no dot: %v %v", got, err)
	}
	srv.mu.Lock()
	asked := slices.Clone(srv.asked)
	srv.mu.Unlock()
	if !slices.Equal(asked, []string{"API.example.test./TypeA"}) {
		t.Fatalf("asked %v", asked)
	}

	// CNAMEs are followed inside the answer; records of other names are
	// ignored; the spoofed answer (wrong id) is ignored.
	if got, err := r.LookupNetIP(ctx, "ip4", "alias.example.test."); err != nil || !slices.Equal(got, ips("203.0.113.10")) {
		t.Fatalf("alias: %v %v", got, err)
	}

	var de *net.DNSError
	if _, err := r.LookupNetIP(ctx, "ip", "missing.example.test."); !errors.As(err, &de) || !de.IsNotFound {
		t.Fatalf("missing: %v", err)
	}

	if rs, err := r.LookupRecords(ctx, "api.example.test.", "TXT"); err != nil || !slices.Equal(rs, []string{"v=spf1 -all"}) {
		t.Fatalf("TXT: %v %v", rs, err)
	}
	if rs, err := r.LookupRecords(ctx, "alias.example.test.", "CNAME"); err != nil || !slices.Equal(rs, []string{"api.example.test"}) {
		t.Fatalf("CNAME: %v %v", rs, err)
	}
	if rs, err := r.LookupRecords(ctx, "missing.example.test.", "A"); err != nil || len(rs) != 0 {
		t.Fatalf("missing records: %v %v", rs, err)
	}

	// A truncated UDP answer is asked again over TCP.
	srv.mu.Lock()
	srv.truncate = "big.example.test."
	srv.mu.Unlock()
	if got, err := r.LookupNetIP(ctx, "ip4", "big.example.test."); err != nil || !slices.Equal(got, ips("203.0.113.77")) {
		t.Fatalf("truncated: %v %v", got, err)
	}

	// Through the Dialer, the CNAME target's address is checked like any
	// answer.
	d := &Dialer{Allow: newEnv(t).dialer.Allow, Resolver: r}
	if a, err := d.Resolve(ctx, "alias.example.test"); err != nil || !slices.Equal(a, ips("203.0.113.10")) {
		t.Fatalf("Resolve: %v %v", a, err)
	}
}

func TestParseResolvConf(t *testing.T) {
	r, err := parseResolvConf(strings.NewReader("search ns.svc.cluster.local svc.cluster.local cluster.local\nnameserver 10.96.0.10\nnameserver fd00::a\nnameserver bogus\noptions ndots:5\n"))
	if err != nil || !slices.Equal(r.Servers, []string{"10.96.0.10:53", "[fd00::a]:53"}) {
		t.Fatalf("%v %v", r, err)
	}
	if _, err := parseResolvConf(strings.NewReader("search x\n")); err == nil {
		t.Fatal("no nameserver accepted")
	}
}
