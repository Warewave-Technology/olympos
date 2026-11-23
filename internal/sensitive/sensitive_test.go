package sensitive

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	canaryAWS = "AKIAQ3VZ7RMXK2JWDTPL"
	canaryGH  = "ghp_R4nd0mCanaryT0kenV4lue0123456789abXy"
)

var (
	detOnce sync.Once
	det     *Detector
	detErr  error
)

func testDetector(t testing.TB) *Detector {
	t.Helper()
	detOnce.Do(func() { det, detErr = NewDetector() })
	if detErr != nil {
		t.Fatal(detErr)
	}
	return det
}

func TestFindPrefersSpecificRule(t *testing.T) {
	d := testDetector(t)
	id, desc, ok := d.Find("AWS_ACCESS_KEY_ID", canaryAWS)
	if !ok || !strings.Contains(id, "aws") || desc == "" {
		t.Fatalf("Find = %q %q %v", id, desc, ok)
	}
	if strings.Contains(id+desc, canaryAWS) {
		t.Fatal("Find returned the value")
	}
	if _, _, ok := d.Find("LOG_LEVEL", "debug"); ok {
		t.Fatal("debug matched")
	}
}

func TestSensitiveName(t *testing.T) {
	for name, want := range map[string]bool{
		"Authorization": true, "X-Api-Key": true, "Set-Cookie": true, "access_token": true, "refresh-token": true,
		"client_secret": true, "secret_key": true, "tokenPath": true, "password": true, "X-Session-Id": true,
		"id_token": true, "X-Signature": true, "jwt": true,
		"Content-Type": false, "status": false, "name": false, "items": false, "": false, "Location": false,
	} {
		if got := SensitiveName(name); got != want {
			t.Errorf("SensitiveName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestRedactHeaders(t *testing.T) {
	r := &Redactor{D: testDetector(t)}
	h := http.Header{
		"Authorization":  {"Bearer abc"},
		"Set-Cookie":     {"sid=1", "other=2"},
		"X-Custom-Cred":  {"v"},
		"X-Api-Key":      {"k"},
		"X-Echo":         {"github " + canaryGH},
		"Content-Type":   {"application/json"},
		"Location":       {"https://a.example.com/cb?access_token=zzz&state=ok"},
		"Www-Authorized": {"x"},
	}
	got := r.RedactHeaders(h, []string{"x-custom-cred"})
	for _, n := range []string{"Authorization", "X-Custom-Cred", "X-Api-Key", "Www-Authorized"} {
		if got.Get(n) != Redacted {
			t.Errorf("%s = %q", n, got.Get(n))
		}
	}
	if v := got.Values("Set-Cookie"); len(v) != 2 || v[0] != Redacted || v[1] != Redacted {
		t.Errorf("Set-Cookie = %q", v)
	}
	if got.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", got.Get("Content-Type"))
	}
	if strings.Contains(got.Get("X-Echo"), canaryGH) {
		t.Errorf("X-Echo = %q", got.Get("X-Echo"))
	}
	if loc := got.Get("Location"); strings.Contains(loc, "zzz") || !strings.Contains(loc, "state=ok") {
		t.Errorf("Location = %q", loc)
	}
	if h.Get("Authorization") != "Bearer abc" {
		t.Fatal("RedactHeaders changed its input")
	}
}

func TestRedactBodyJSON(t *testing.T) {
	r := &Redactor{}
	in := `{"z":1,"access_token":"tok-1","nested":{"password":{"a":[1,2]},"ok":"<b>&"},"list":[{"secret":true},null],"a":"x"}`
	got := string(r.RedactBody([]byte(in)))
	want := `{"z":1,"access_token":"[redacted]","nested":{"password":"[redacted]","ok":"<b>&"},"list":[{"secret":"[redacted]"},null],"a":"x"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if !json.Valid([]byte(got)) {
		t.Fatal("not valid JSON")
	}
}

func TestRedactBodyText(t *testing.T) {
	r := &Redactor{D: testDetector(t)}
	cases := map[string]string{
		"form":      "grant_type=client_credentials&client_secret=s3cr3t-value&scope=read",
		"cut JSON":  `{"items":[1,2],"refresh_token": "rt-123456", "more": [`,
		"header":    "Authorization: Bearer abc.def.ghi\nX: y",
		"yaml":      "password: hunter2\nuser: bob",
		"gitleaks":  "the key is " + canaryAWS + " ok",
		"github":    "token " + canaryGH,
		"long JSON": `{"data":"` + strings.Repeat("x", 100) + `","api_key":"` + canaryAWS + `"}`,
	}
	for name, in := range cases {
		got := string(r.RedactBody([]byte(in)))
		for _, leak := range []string{"s3cr3t-value", "rt-123456", "abc.def.ghi", "hunter2", canaryAWS, canaryGH} {
			if strings.Contains(got, leak) {
				t.Errorf("%s: %q leaks %q", name, got, leak)
			}
		}
		if !strings.Contains(got, Redacted) {
			t.Errorf("%s: nothing redacted in %q", name, got)
		}
	}
	if got := string(r.RedactBody([]byte("scope=read&state=ok"))); got != "scope=read&state=ok" {
		t.Errorf("plain text changed: %q", got)
	}
}

func TestRedactBodyDoesNotAlias(t *testing.T) {
	in := []byte("nothing to see")
	out := (&Redactor{}).RedactBody(in)
	out[0] = 'X'
	if in[0] != 'n' {
		t.Fatal("RedactBody returned its input")
	}
}

func TestRedactValue(t *testing.T) {
	r := &Redactor{D: testDetector(t)}
	if got := r.RedactValue("access_token", "abc"); got != Redacted {
		t.Errorf("by name: %q", got)
	}
	if got := r.RedactValue("x", canaryAWS); got != Redacted {
		t.Errorf("by rule: %q", got)
	}
	if got := r.RedactValue("Content-Type", "text/plain"); got != "text/plain" {
		t.Errorf("plain: %q", got)
	}
	var nilR *Redactor
	if got := nilR.RedactValue("token", "abc"); got != Redacted {
		t.Errorf("nil redactor: %q", got)
	}
}

func TestScrub(t *testing.T) {
	in := []byte("a=abcdef b=abc c=zzz")
	got := string(Scrub(in, [][]byte{[]byte("abc"), nil, []byte("abcdef")}))
	if got != "a=[redacted] b=[redacted] c=zzz" {
		t.Fatalf("got %q", got)
	}
	if string(in) != "a=abcdef b=abc c=zzz" {
		t.Fatal("Scrub changed its input")
	}
	if Scrub(nil, nil) == nil {
		t.Fatal("Scrub(nil) is nil")
	}
}

// RedactPrefix returns what RedactBody would, cut to n, while scanning
// only a window of a large body.
func TestRedactPrefix(t *testing.T) {
	r := &Redactor{D: testDetector(t)}
	var b bytes.Buffer
	b.WriteString(`{"items":[`)
	for b.Len() < 1<<20 {
		b.WriteString(`{"id":12345,"name":"item name here","token":"abc","url":"https://example.com/x?api_key=zz"},`)
	}
	b.WriteString(`{}]}`)
	full := r.RedactBody(b.Bytes())
	start := time.Now()
	got, cut := r.RedactPrefix(b.Bytes(), 4096)
	t.Logf("1 MiB JSON: prefix redacted in %s", time.Since(start))
	if !cut || !bytes.Equal(got, full[:4096]) {
		t.Fatalf("prefix differs (cut %v):\n%s\n%s", cut, got[:200], full[:200])
	}
	if bytes.Contains(full, []byte(`"token":"abc"`)) || bytes.Contains(full, []byte("api_key=zz")) {
		t.Fatal("not redacted")
	}

	// Cut JSON (not valid) and plain text.
	text := bytes.Repeat([]byte("line password=hunter2 ok\n"), 10000)
	got, cut = r.RedactPrefix(text, 1000)
	if !cut || len(got) != 1000 || bytes.Contains(got, []byte("hunter2")) {
		t.Fatalf("text: %v %q", cut, got[:100])
	}
	small := []byte("token=abc")
	if got, cut := r.RedactPrefix(small, 1000); cut || string(got) != "token=[redacted]" {
		t.Fatalf("small: %v %q", cut, got)
	}

	// A body that the rules shrink a lot never returns the end of the
	// window, where a match may have been cut.
	shrink := bytes.Repeat([]byte("token="+strings.Repeat("x", 1000)+"&"), 200)
	got, cut = r.RedactPrefix(shrink, 100000)
	if !cut || len(got) > max(0, len(r.RedactBody(shrink[:100000+prefixMargin]))-prefixGuard) {
		t.Fatalf("shrunk: %v %d", cut, len(got))
	}
}
