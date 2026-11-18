package blob_test

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/Warewave-Technology/olympos/internal/blob"
)

func TestNormalizeSASAndExpiry(t *testing.T) {
	for in, want := range map[string]string{
		"sv=1&sp=rcwt&sig=x": "sv=1&sp=rcwt&sig=x",
		" ?sv=1&sig=x ":      "sv=1&sig=x",
		"https://a.blob.core.windows.net/c?sv=1&sig=x": "sv=1&sig=x",
	} {
		if got := blob.NormalizeSAS(in); got != want {
			t.Errorf("NormalizeSAS(%q) = %q", in, got)
		}
	}
	exp, ok := blob.SASExpiry("sp=r&se=2027-03-01T10:00:00Z&sig=x")
	if !ok || !exp.Equal(time.Date(2027, 3, 1, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("expiry %v %v", exp, ok)
	}
	if _, ok := blob.SASExpiry("sp=r&sig=x"); ok {
		t.Fatal("no se")
	}
	for _, v := range []string{"2027-03-01", "2027-03-01T10:00Z", "2027-03-01T10:00:00Z", "2027-03-01T10:00:00.1234567Z"} {
		if _, err := blob.ParseSASTime(v); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
}

func TestOpenFailsFast(t *testing.T) {
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	_, err := blob.Open(blob.Target{Name: "d1", Account: "acct", Container: "c1", Auth: blob.AuthSAS,
		SAS: "sp=rcwt&sr=c&se=2026-11-17T00:00:00Z&sig=SECRETSIG"}, nil, now)
	if !errors.Is(err, blob.ErrSASExpired) || strings.Contains(err.Error(), "SECRETSIG") || !strings.Contains(err.Error(), "d1") {
		t.Fatalf("expired: %v", err)
	}
	if _, err := blob.Open(blob.Target{Account: "acct", Container: "c1", Auth: blob.AuthManagedIdentity}, nil, now); err == nil ||
		!strings.Contains(err.Error(), "managed identity") {
		t.Fatalf("MI without credential: %v", err)
	}
	if _, err := blob.Open(blob.Target{Account: "acct", Container: "c1", Auth: "shared_key"}, nil, now); err == nil {
		t.Fatal("only two auth options are supported")
	}
	if _, err := blob.Open(blob.Target{Account: "acct", Container: "c1", Auth: blob.AuthSAS, SAS: "  "}, nil, now); err == nil {
		t.Fatal("empty SAS")
	}
}

func TestContainerURLAndPaths(t *testing.T) {
	if u := (blob.Target{Account: "acct", Container: "c"}).ContainerURL(); u != "https://acct.blob.core.windows.net/c" {
		t.Fatal(u)
	}
	if u := (blob.Target{Account: "devstoreaccount1", Container: "c", EndpointOverride: "http://127.0.0.1:10000/devstoreaccount1/"}).ContainerURL(); u != "http://127.0.0.1:10000/devstoreaccount1/c" {
		t.Fatal(u)
	}
	if p := blob.Join("/pfx/", "a", "", "/b/"); p != "pfx/a/b" {
		t.Fatal(p)
	}
	if p := blob.Join("", "a"); p != "a" {
		t.Fatal(p)
	}
	if !blob.IsProbePath("pfx/.olympos-probe/123") || !blob.IsProbePath(".olympos-probe/123") || blob.IsProbePath("pfx/prod/run.dump") ||
		blob.IsProbePath(".olympos-probe/x/y") {
		t.Fatal("probe path detection")
	}
}

func TestDescribeStripsQuery(t *testing.T) {
	err := &url.Error{Op: "Put", URL: "https://acct.blob.core.windows.net/c/x?sv=1&se=2027&sig=SECRETSIG", Err: errors.New("dial tcp: refused")}
	got := blob.Describe(fmt.Errorf("upload: %w", err))
	if strings.Contains(got, "SECRETSIG") || strings.Contains(got, "se=2027") || !strings.Contains(got, "acct.blob.core.windows.net/c/x") {
		t.Fatalf("describe: %s", got)
	}
	re := &azcore.ResponseError{ErrorCode: "AuthorizationPermissionMismatch", StatusCode: 403}
	if got := blob.Describe(re); got != "AuthorizationPermissionMismatch (HTTP 403)" {
		t.Fatalf("describe response error: %s", got)
	}
}
