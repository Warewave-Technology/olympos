package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"net/netip"
	"time"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/sensitive"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// Step and run statuses.
const (
	StatusPassed  = "passed"
	StatusFailed  = "failed"
	StatusError   = "error"
	StatusSkipped = "skipped"
)

// maxActual is the longest assertion actual value reported, in bytes.
const maxActual = 200

// userAgent is sent unless a step sets its own.
const userAgent = "olympos-probe"

// Runner runs scenarios. Dialer carries the run's allowlist snapshot, so a
// Runner is made per run (or its Dialer.Allow set before each run).
type Runner struct {
	Dialer   *Dialer
	Redactor *sensitive.Redactor
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	// rootCAs replaces the system roots in tests. Nil means the system
	// roots of the probe image.
	rootCAs *x509.CertPool
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// runState is what the steps of one run share.
type runState struct {
	s     *spec.Scenario
	vars  map[string]string
	taint map[string]spec.Taint // per variable (P11)
	creds *credSet
	local netip.Addr
}

// noteSession copies a session's timings and addresses into o, and keeps
// the first local address of the run as the probe's address.
func (rs *runState) noteSession(sess *session, o *outcome, start time.Time) {
	if o.timings == nil {
		o.timings = &pb.StepTimings{}
	}
	dns, conn := sess.timings()
	o.timings.DnsUs = dns.Microseconds()
	o.timings.ConnectUs = conn.Microseconds()
	o.timings.TotalUs = time.Since(start).Microseconds()
	remote, local := sess.addrs()
	o.remote = remote
	if !rs.local.IsValid() && local.IsValid() {
		rs.local = local
	}
}

// outcome is the result of one step attempt before it is scrubbed and cut.
type outcome struct {
	status     string
	err        *Error
	timings    *pb.StepTimings
	assertions []*pb.AssertionResult
	extracted  map[string]string
	names      []string // extract names, in step order
	excerpt    []byte   // redacted, not yet scrubbed or cut
	excerptCut bool     // the excerpt's body was cut before it was scrubbed
	actualCut  []bool   // per assertion, likewise
	statusCode int
	remote     netip.Addr
	// taint is that of the step's extracts: the taint of the variables
	// its request used, plus its own credential (P11).
	taint spec.Taint
}

// Run runs s with creds and returns its result. The run stops at the first
// step that does not pass; the steps after it are skipped. The deadline is
// the scenario's TimeoutSeconds (and ctx's, if earlier).
//
// RunId and ProbeVersion are left for the caller. Run does not keep or
// zero creds: the caller zeroes them (spec.ZeroCredentials) after Run.
// Everything Run derives from them (OAuth2 tokens, encoded forms) is
// zeroed before it returns.
func (r *Runner) Run(ctx context.Context, s *spec.Scenario, creds []spec.RunCredential) *pb.RunResult {
	start := r.now()
	res := &pb.RunResult{StartedUnixMs: start.UnixMilli()}
	if s == nil || r.Dialer == nil {
		res.Status = StatusError
		res.FailureReason = CodeInvalidRequest + ": no scenario or no dialer"
		res.FinishedUnixMs = r.now().UnixMilli()
		return res
	}
	if s.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	cs := newCredSet(creds)
	defer cs.close()
	rs := &runState{s: s, vars: map[string]string{}, taint: map[string]spec.Taint{}, creds: cs}

	failed := -1
	var failErr *Error
	var cuts []*stepCuts
	for i := range s.Steps {
		st := &s.Steps[i]
		if failed >= 0 {
			res.Steps = append(res.Steps, &pb.StepResult{Position: int32(st.Position), Status: StatusSkipped})
			cuts = append(cuts, &stepCuts{})
			continue
		}
		o := r.runStep(ctx, rs, st)
		for _, n := range o.names {
			v, ok := o.extracted[n]
			switch {
			case !ok:
			case len(o.taint) > 0:
				// A tainted value may be a piece of a credential:
				// scrubbed whatever its length (P11).
				cs.lits.addSecret([]byte(v))
			default:
				cs.lits.addExtracted(v)
			}
		}
		if o.status == StatusPassed {
			for n, v := range o.extracted {
				rs.vars[n] = v
				if len(o.taint) > 0 {
					t := spec.Taint{}
					t.Add(o.taint)
					rs.taint[n] = t
				}
			}
		}
		sr, c := r.stepResult(st, o, cs.lits.all())
		res.Steps = append(res.Steps, sr)
		cuts = append(cuts, c)
		if o.status != StatusPassed {
			failed = i
			failErr = o.err
			res.Status = o.status
			res.FailedStep = int32(st.Position)
		}
	}

	// A value extracted by a later step may also be in an earlier step's
	// excerpt: scrub everything again with the run's final literals.
	lits := cs.lits.all()
	for i, sr := range res.Steps {
		rescrub(sr, cuts[i], lits)
	}
	if failed < 0 {
		res.Status = StatusPassed
	} else if failErr != nil {
		res.FailureReason = string(refinalize([]byte(failErr.Code+": "+r.redactMsg(failErr.Msg)), false, lits, maxMessage))
	}
	if rs.local.IsValid() {
		res.ProbeIp = rs.local.String()
	}
	res.FinishedUnixMs = r.now().UnixMilli()
	return res
}

// runStep runs one step, trying it again up to StepRetries times while it
// fails for a reason a retry can change.
func (r *Runner) runStep(ctx context.Context, rs *runState, st *spec.Step) *outcome {
	attempts := 1 + min(max(rs.s.StepRetries, 0), spec.MaxStepRetries)
	var o *outcome
	for a := 0; a < attempts; a++ {
		o = r.attempt(ctx, rs, st)
		if o.status == StatusPassed || ctx.Err() != nil || !retryable(o.err) {
			break
		}
	}
	return o
}

// retryable reports whether a retry can change the outcome: policy and
// request errors cannot.
func retryable(e *Error) bool {
	if e == nil {
		return true
	}
	switch e.Code {
	case CodeHostNotAllowed, CodeIPDenied, CodeRedirectBlocked, CodeInvalidRequest, CodeTimeout:
		return false
	}
	return true
}

func (r *Runner) attempt(ctx context.Context, rs *runState, st *spec.Step) *outcome {
	var o *outcome
	switch {
	case st.Kind == spec.KindHTTP && st.HTTP != nil:
		o = r.httpStep(ctx, rs, st)
	case st.Kind == spec.KindDNS && st.DNS != nil:
		o = r.dnsStep(ctx, rs, st)
	case st.Kind == spec.KindTCP && st.TCP != nil:
		o = r.tcpStep(ctx, rs, st)
	case st.Kind == spec.KindTLS && st.TLS != nil:
		o = r.tlsStep(ctx, rs, st)
	default:
		o = failOutcome(errorf(CodeInvalidRequest, "step %d has no %q settings", st.Position, st.Kind))
	}
	if o.timings == nil {
		o.timings = &pb.StepTimings{}
	}
	return o
}

// failOutcome is an attempt that could not run.
func failOutcome(e *Error) *outcome {
	status := StatusError
	if e.Code == CodeAssertionFailed {
		status = StatusFailed
	}
	return &outcome{status: status, err: e}
}

// finish sets the status from the assertions: passed when all hold.
func (o *outcome) finish() {
	for _, a := range o.assertions {
		if !a.Passed {
			o.status = StatusFailed
			o.err = errorf(CodeAssertionFailed, "%s %s %s", a.Subject, a.Operator, a.Expected)
			return
		}
	}
	o.status = StatusPassed
}

// maxMessage is the longest error message reported, in bytes.
const maxMessage = 1024

// stepCuts records which fields of a StepResult were cut by finalize.
type stepCuts struct {
	expected, actual []bool
	err, excerpt     bool
}

// stepResult turns an outcome into a StepResult, scrubbed with lits and
// cut to its limits.
func (r *Runner) stepResult(st *spec.Step, o *outcome, lits [][]byte) (*pb.StepResult, *stepCuts) {
	sr := &pb.StepResult{
		Position:   int32(st.Position),
		Status:     o.status,
		Timings:    o.timings,
		StatusCode: int32(o.statusCode),
	}
	c := &stepCuts{}
	for _, n := range o.names {
		if _, ok := o.extracted[n]; ok {
			sr.ExtractedNames = append(sr.ExtractedNames, n)
		}
	}
	if o.remote.IsValid() {
		sr.RemoteIp = o.remote.String()
	}
	for i, a := range o.assertions {
		e, ec := finalize([]byte(a.Expected), lits, spec.MaxBody)
		v, vc := finalizeCut([]byte(a.Actual), i < len(o.actualCut) && o.actualCut[i], lits, maxActual)
		a.Expected, a.Actual = string(e), string(v)
		c.expected = append(c.expected, ec)
		c.actual = append(c.actual, vc)
		sr.Assertions = append(sr.Assertions, a)
	}
	if o.err != nil {
		e, ec := finalize([]byte(o.err.Code+": "+r.redactMsg(o.err.Msg)), lits, maxMessage)
		sr.Error, c.err = string(e), ec
	}
	if len(o.excerpt) > 0 {
		sr.ResponseExcerpt, c.excerpt = finalizeCut(o.excerpt, o.excerptCut, lits, spec.MaxExcerpt)
	}
	return sr, c
}

// redactMsg runs an error message through the redactor: a message can
// quote a URL or a header value from the server.
func (r *Runner) redactMsg(msg string) string {
	return r.Redactor.RedactValue("error", msg)
}

// rescrub scrubs a finished StepResult again with the run's final
// literals.
func rescrub(sr *pb.StepResult, c *stepCuts, lits [][]byte) {
	for i, a := range sr.Assertions {
		a.Expected = string(refinalize([]byte(a.Expected), c.expected[i], lits, spec.MaxBody))
		a.Actual = string(refinalize([]byte(a.Actual), c.actual[i], lits, maxActual))
	}
	if sr.Error != "" {
		sr.Error = string(refinalize([]byte(sr.Error), c.err, lits, maxMessage))
	}
	if len(sr.ResponseExcerpt) > 0 {
		sr.ResponseExcerpt = refinalize(sr.ResponseExcerpt, c.excerpt, lits, spec.MaxExcerpt)
	}
}

// classify maps an error from a connection or a request to a step error.
func classify(ctx context.Context, err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	if ctxCode(ctx, err) == CodeTimeout {
		return errorf(CodeTimeout, "the run's deadline passed")
	}
	if isTLSError(err) {
		return errorf(CodeTLSError, "%s", innerMessage(err))
	}
	return errorf(CodeConnectError, "%s", innerMessage(err))
}
