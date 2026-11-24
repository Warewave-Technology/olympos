package probe

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// RecordResolver is implemented by resolvers that serve the DNS step's
// record types. A Resolver without it only serves A and AAAA steps.
type RecordResolver interface {
	// LookupRecords returns the records of one type (A, AAAA, CNAME or
	// TXT) for an absolute name. A name that does not exist, or has no
	// record of the type, returns no records and no error.
	LookupRecords(ctx context.Context, name, rtype string) ([]string, error)
}

// DNSResolver is a DNS-only stub resolver: it sends queries to its servers
// and nothing else. Unlike the system resolver (cgo getaddrinfo, or Go's
// own), it never reads /etc/hosts (which maps the pod's host name to the
// pod IP), never applies a search list or ndots (decision 4: names are
// absolute), and never parses inet_aton forms such as "127.1".
type DNSResolver struct {
	// Servers are "ip:port" addresses, tried in order.
	Servers []string
	// Timeout is the deadline of one query to one server; 0 means 3 s.
	Timeout time.Duration
}

// maxCNAMEs is how many CNAMEs an answer may chain.
const maxCNAMEs = 8

// SystemResolver returns a DNSResolver for the nameservers in
// /etc/resolv.conf (the cluster DNS in a pod). Only the nameserver lines
// are used: search, domain and options are ignored.
func SystemResolver() (*DNSResolver, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseResolvConf(f)
}

func parseResolvConf(r io.Reader) (*DNSResolver, error) {
	var servers []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		servers = append(servers, netip.AddrPortFrom(a, 53).String())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, errors.New("probe: no nameserver in resolv.conf")
	}
	return &DNSResolver{Servers: servers}, nil
}

var errNoServers = errors.New("no DNS servers")

// LookupNetIP returns the A (network "ip4"), AAAA ("ip6") or both ("ip")
// records of host, which is taken as an absolute name whether or not it
// ends with a dot.
func (r *DNSResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var types []dnsmessage.Type
	switch network {
	case "ip":
		types = []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	case "ip4":
		types = []dnsmessage.Type{dnsmessage.TypeA}
	case "ip6":
		types = []dnsmessage.Type{dnsmessage.TypeAAAA}
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
	var out []netip.Addr
	var firstErr error
	for _, t := range types {
		rs, err := r.query(ctx, host, t)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, rr := range rs {
			switch b := rr.Body.(type) {
			case *dnsmessage.AResource:
				out = append(out, netip.AddrFrom4(b.A))
			case *dnsmessage.AAAAResource:
				out = append(out, netip.AddrFrom16(b.AAAA))
			}
		}
	}
	if len(out) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

// LookupRecords implements RecordResolver.
func (r *DNSResolver) LookupRecords(ctx context.Context, name, rtype string) ([]string, error) {
	var t dnsmessage.Type
	switch rtype {
	case "A":
		t = dnsmessage.TypeA
	case "AAAA":
		t = dnsmessage.TypeAAAA
	case "CNAME":
		t = dnsmessage.TypeCNAME
	case "TXT":
		t = dnsmessage.TypeTXT
	default:
		return nil, fmt.Errorf("unsupported record type %q", rtype)
	}
	rs, err := r.query(ctx, name, t)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range rs {
		switch b := rr.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(b.A).String())
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(b.AAAA).String())
		case *dnsmessage.CNAMEResource:
			out = append(out, strings.TrimSuffix(b.CNAME.String(), "."))
		case *dnsmessage.TXTResource:
			out = append(out, strings.Join(b.TXT, ""))
		}
	}
	return out, nil
}

// query asks the servers in turn for name's records of type t and returns
// those of the answer section that belong to name or, through CNAMEs in
// the answer, to its canonical name. NXDOMAIN and an empty answer give no
// records and no error.
func (r *DNSResolver) query(ctx context.Context, host string, t dnsmessage.Type) ([]dnsmessage.Resource, error) {
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, &net.DNSError{Err: "invalid name", Name: host}
	}
	if len(r.Servers) == 0 {
		return nil, errNoServers
	}
	var last error
	for _, srv := range r.Servers {
		msg, err := r.exchange(ctx, srv, name, t)
		if err != nil {
			last = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		switch msg.RCode {
		case dnsmessage.RCodeSuccess:
		case dnsmessage.RCodeNameError:
			return nil, nil
		default:
			last = &net.DNSError{Err: "server answered " + msg.RCode.String(), Name: host, IsTemporary: true}
			continue
		}
		return answers(msg, name, t), nil
	}
	return nil, last
}

// answers follows CNAMEs from name within the answer section and returns
// the records of type t for the final name (for TypeCNAME, the CNAME
// records of name itself).
func answers(msg *dnsmessage.Message, name dnsmessage.Name, t dnsmessage.Type) []dnsmessage.Resource {
	cur := strings.ToLower(name.String())
	if t == dnsmessage.TypeCNAME {
		var out []dnsmessage.Resource
		for _, rr := range msg.Answers {
			if rr.Header.Type == t && strings.ToLower(rr.Header.Name.String()) == cur {
				out = append(out, rr)
			}
		}
		return out
	}
	for range maxCNAMEs {
		var out []dnsmessage.Resource
		next := ""
		for _, rr := range msg.Answers {
			if strings.ToLower(rr.Header.Name.String()) != cur {
				continue
			}
			switch rr.Header.Type {
			case t:
				out = append(out, rr)
			case dnsmessage.TypeCNAME:
				next = strings.ToLower(rr.Body.(*dnsmessage.CNAMEResource).CNAME.String())
			}
		}
		if len(out) > 0 || next == "" {
			return out
		}
		cur = next
	}
	return nil
}

// exchange sends one query to one server over UDP, and again over TCP when
// the answer is truncated.
func (r *DNSResolver) exchange(ctx context.Context, server string, name dnsmessage.Name, t dnsmessage.Type) (*dnsmessage.Message, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: t, Class: dnsmessage.ClassINET}},
	}
	packed, err := q.Pack()
	if err != nil {
		return nil, err
	}

	msg, err := exchangeOnce(ctx, "udp", server, packed, id, q.Questions[0])
	if err == nil && msg.Truncated {
		msg, err = exchangeOnce(ctx, "tcp", server, packed, id, q.Questions[0])
	}
	return msg, err
}

const maxDNSMessage = 65535

func exchangeOnce(ctx context.Context, network, server string, packed []byte, id uint16, q dnsmessage.Question) (*dnsmessage.Message, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if network == "tcp" {
		buf := make([]byte, 2+len(packed))
		binary.BigEndian.PutUint16(buf, uint16(len(packed)))
		copy(buf[2:], packed)
		if _, err := c.Write(buf); err != nil {
			return nil, err
		}
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, resp); err != nil {
			return nil, err
		}
		return checkResponse(resp, id, q)
	}

	if _, err := c.Write(packed); err != nil {
		return nil, err
	}
	buf := make([]byte, maxDNSMessage)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// A connected UDP socket only receives from the server; an answer
		// that is not ours (wrong id or question) is ignored, as a
		// spoofing attempt or a late answer would be.
		if msg, err := checkResponse(buf[:n], id, q); err == nil {
			return msg, nil
		}
	}
}

func checkResponse(b []byte, id uint16, q dnsmessage.Question) (*dnsmessage.Message, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(b); err != nil {
		return nil, err
	}
	if !msg.Response || msg.ID != id || len(msg.Questions) != 1 ||
		msg.Questions[0].Type != q.Type || msg.Questions[0].Class != q.Class ||
		!strings.EqualFold(msg.Questions[0].Name.String(), q.Name.String()) {
		return nil, errors.New("not the answer to the query")
	}
	return &msg, nil
}
