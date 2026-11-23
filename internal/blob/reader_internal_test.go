package blob

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
)

// failingBody fails mid-read with the transport error the Azure SDK's
// retrying reader produces: a *url.Error carrying the full request URL.
type failingBody struct{ err error }

func (b failingBody) Read([]byte) (int, error) { return 3, b.err }
func (b failingBody) Close() error             { return nil }

func TestRangeObjectScrubsBodyErrors(t *testing.T) {
	const sig = "SECRETSIGNATURE%2Bvalue"
	cause := context.DeadlineExceeded
	uerr := &url.Error{Op: "Get", URL: "https://acct.blob.core.windows.net/c/b.zip?sv=2022-11-02&se=2030-01-01&sig=" + sig, Err: cause}
	o := &rangeObject{ctx: context.Background(), size: 100, scrub: scrubAzure,
		fetch: func(context.Context, int64, int64) (io.ReadCloser, error) { return failingBody{uerr}, nil }}
	_, err := o.ReadAt(make([]byte, 10), 0)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "sig=") || strings.Contains(err.Error(), sig) {
		t.Fatalf("error leaks the SAS: %q", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error chain lost: %v", err)
	}
}

func TestRangeObjectScrubsFetchErrors(t *testing.T) {
	uerr := &url.Error{Op: "Get", URL: "https://acct.blob.core.windows.net/c/b.zip?sig=SECRETSIG", Err: context.Canceled}
	o := &rangeObject{ctx: context.Background(), size: 100, scrub: scrubAzure,
		fetch: func(context.Context, int64, int64) (io.ReadCloser, error) { return nil, uerr }}
	_, err := o.ReadAt(make([]byte, 10), 0)
	if err == nil || strings.Contains(err.Error(), "SECRETSIG") || !errors.Is(err, context.Canceled) {
		t.Fatalf("fetch error: %v", err)
	}
}
