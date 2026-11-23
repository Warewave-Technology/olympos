package probe

import (
	"context"
	"errors"
	"net"
	"time"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// dnsStep looks a name up through the cluster's resolver. The name must be
// on the allowlist (a lookup reveals it to resolvers) and is looked up as
// an absolute name. The answers are not connected to, so they are not
// checked against the always-denied addresses.
func (r *Runner) dnsStep(ctx context.Context, rs *runState, st *spec.Step) *outcome {
	name, err := r.Dialer.checkHost(st.DNS.Name)
	if err != nil {
		return failOutcome(classify(ctx, err))
	}
	start := time.Now()
	records, err := r.lookupRecords(ctx, name+".", st.DNS.RecordType)
	elapsed := time.Since(start)
	o := &outcome{timings: &pb.StepTimings{DnsUs: elapsed.Microseconds(), TotalUs: elapsed.Microseconds()}}
	if err != nil {
		o.status = StatusError
		if ctxCode(ctx, err) == CodeTimeout {
			o.err = errorf(CodeTimeout, "resolving %s", name)
		} else {
			o.err = errorf(CodeDNSError, "resolving %s: %s", name, dnsMessage(err))
		}
		return o
	}
	f := &facts{kind: spec.KindDNS, latencyMS: elapsed.Milliseconds(), records: records, redact: r.Redactor}
	o.assertions, o.actualCut = r.evaluate(st, f)
	o.finish()
	return o
}

// lookupRecords asks the Dialer's resolver for name's records of rtype.
// A name that does not exist has no records.
func (r *Runner) lookupRecords(ctx context.Context, name, rtype string) ([]string, error) {
	if r.Dialer.Resolver == nil {
		return nil, errors.New("no resolver")
	}
	if rr, ok := r.Dialer.Resolver.(RecordResolver); ok {
		return rr.LookupRecords(ctx, name, rtype)
	}
	var network string
	switch rtype {
	case "A":
		network = "ip4"
	case "AAAA":
		network = "ip6"
	default:
		return nil, errors.New("the resolver does not serve " + rtype + " records")
	}
	addrs, err := r.Dialer.Resolver.LookupNetIP(ctx, network, name)
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap().String())
	}
	return out, nil
}
