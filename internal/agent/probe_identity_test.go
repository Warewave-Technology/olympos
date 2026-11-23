package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	testProbeCluster = "6f1c2a52-3b0e-4d57-9a53-0d9f9c7a1e11"
	testNS           = "olympos-system"
	testProbeSecret  = "olympos-probe-identity"
	testAgentSecret  = "olympos-agent-identity"
)

var probeEpoch = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// probeCert makes a self-signed probe certificate and its key.
func probeCert(t *testing.T, serial int64, notBefore, notAfter time.Time) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: testProbeCluster + "/probe"},
		NotBefore:    notBefore, NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func certData(t *testing.T, der []byte, key *ecdsa.PrivateKey) map[string][]byte {
	t.Helper()
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		keyCert:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyKey:       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}),
		keyClusterID: []byte(testProbeCluster),
	}
}

type fakeEnroller struct {
	mu          sync.Mutex
	enrollToks  []string
	renewCerts  [][]byte // DER of the certificate each Renew was dialled with
	enrollCert  func() ([]byte, error)
	renewScript []func() ([]byte, error)
}

func (f *fakeEnroller) Enroll(_ context.Context, token string, csr []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrollToks = append(f.enrollToks, token)
	if _, err := x509.ParseCertificateRequest(csr); err != nil {
		return nil, err
	}
	return f.enrollCert()
}

func (f *fakeEnroller) Renew(_ context.Context, cur tls.Certificate, csr []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewCerts = append(f.renewCerts, cur.Certificate[0])
	if _, err := x509.ParseCertificateRequest(csr); err != nil {
		return nil, err
	}
	n := len(f.renewCerts) - 1
	if n >= len(f.renewScript) {
		return nil, errors.New("unscripted renew")
	}
	return f.renewScript[n]()
}

func (f *fakeEnroller) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.enrollToks) + len(f.renewCerts)
}

type probeHarness struct {
	a     *Agent
	kube  *fake.Clientset
	logs  *bytes.Buffer
	now   time.Time
	waits []time.Duration
}

func newProbeHarness(t *testing.T, probeData map[string][]byte) *probeHarness {
	t.Helper()
	agentData := map[string][]byte{keyCert: []byte("agent-cert"), keyKey: []byte("agent-key"), keyClusterID: []byte("agent")}
	kube := fake.NewClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testProbeSecret}, Data: probeData},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testAgentSecret}, Data: agentData},
	)
	logs := &bytes.Buffer{}
	return &probeHarness{
		a: &Agent{
			cfg:  Config{Namespace: testNS, IdentitySecret: testAgentSecret, ProbeEnabled: true, ProbeIdentitySecret: testProbeSecret},
			log:  slog.New(slog.NewTextHandler(logs, nil)),
			kube: kube,
		},
		kube: kube, logs: logs, now: probeEpoch,
	}
}

// run drives the loop on a fake clock until stop reports true after a sleep
// (or the clock has slept max times). Each sleep advances the clock.
func (h *probeHarness) run(t *testing.T, e probeEnroller, max int, stop func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.a.probeIdentityLoop(ctx, e, probeClock{
		now: func() time.Time { return h.now },
		sleep: func(_ context.Context, d time.Duration) bool {
			h.waits = append(h.waits, d)
			h.now = h.now.Add(d)
			return len(h.waits) < max && !stop()
		},
	})
}

// seed replaces the probe Secret's data without it counting as a write.
func (h *probeHarness) seed(t *testing.T, data map[string][]byte) {
	t.Helper()
	s := h.secret(t, testProbeSecret)
	s.Data = data
	if _, err := h.kube.CoreV1().Secrets(testNS).Update(context.Background(), s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.kube.ClearActions()
}

func (h *probeHarness) secret(t *testing.T, name string) *corev1.Secret {
	t.Helper()
	s, err := h.kube.CoreV1().Secrets(testNS).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (h *probeHarness) updates() int {
	n := 0
	for _, a := range h.kube.Actions() {
		if a.GetVerb() == "update" || a.GetVerb() == "create" || a.GetVerb() == "delete" || a.GetVerb() == "patch" {
			n++
		}
	}
	return n
}

func (h *probeHarness) storedSerial(t *testing.T) int64 {
	t.Helper()
	der, _, err := parseStored(h.secret(t, testProbeSecret).Data)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c.SerialNumber.Int64()
}

func (h *probeHarness) agentSecretIntact(t *testing.T) {
	t.Helper()
	want := map[string][]byte{keyCert: []byte("agent-cert"), keyKey: []byte("agent-key"), keyClusterID: []byte("agent")}
	if got := h.secret(t, testAgentSecret).Data; !reflect.DeepEqual(got, want) {
		t.Fatalf("agent Secret changed: %v", got)
	}
	for _, a := range h.kube.Actions() {
		if n, ok := a.(k8stesting.UpdateAction); ok && n.GetObject().(metav1.Object).GetName() == testAgentSecret {
			t.Fatalf("agent Secret was written: %v", a)
		}
	}
}

func TestProbeIdentityEnrollsFromTokenAndDropsIt(t *testing.T) {
	h := newProbeHarness(t, map[string][]byte{keyBootstrap: []byte("tok-1")})
	der, _ := probeCert(t, 10, h.now.Add(-time.Minute), h.now.Add(30*24*time.Hour))
	e := &fakeEnroller{enrollCert: func() ([]byte, error) { return der, nil }}

	h.run(t, e, 1, func() bool { return true })

	if !reflect.DeepEqual(e.enrollToks, []string{"tok-1"}) || len(e.renewCerts) != 0 {
		t.Fatalf("enroll tokens %v, renews %d", e.enrollToks, len(e.renewCerts))
	}
	data := h.secret(t, testProbeSecret).Data
	if _, ok := data[keyBootstrap]; ok {
		t.Fatal("bootstrap token kept")
	}
	if string(data[keyClusterID]) != testProbeCluster {
		t.Fatalf("cluster-id %q", data[keyClusterID])
	}
	stored, key, err := parseStored(data)
	if err != nil || !bytes.Equal(stored, der) {
		t.Fatalf("stored cert mismatch: %v", err)
	}
	if key == nil {
		t.Fatal("no key stored")
	}
	h.agentSecretIntact(t)
}

func TestProbeIdentityKeepsValidCertificate(t *testing.T) {
	h := newProbeHarness(t, nil)
	der, key := probeCert(t, 11, h.now.Add(-time.Hour), h.now.Add(30*24*time.Hour))
	h.seed(t, certData(t, der, key))
	e := &fakeEnroller{}

	h.run(t, e, 3, func() bool { return false })

	if e.calls() != 0 {
		t.Fatalf("enroller called %d times", e.calls())
	}
	if h.updates() != 0 {
		t.Fatalf("Secret written: %v", h.kube.Actions())
	}
	for _, w := range h.waits {
		if w != probeRetry {
			t.Fatalf("long wait must be capped at %v, got %v", probeRetry, w)
		}
	}
}

func TestProbeIdentityRenewsAtTwoThirds(t *testing.T) {
	h := newProbeHarness(t, nil)
	nb := h.now.Add(-time.Hour)
	na := nb.Add(30 * 24 * time.Hour)
	oldDER, oldKey := probeCert(t, 12, nb, na)
	h.seed(t, certData(t, oldDER, oldKey))
	newDER, _ := probeCert(t, 13, nb.Add(20*24*time.Hour), nb.Add(50*24*time.Hour))
	e := &fakeEnroller{renewScript: []func() ([]byte, error){func() ([]byte, error) { return newDER, nil }}}
	renewAt := nb.Add(20 * 24 * time.Hour)

	var renewedAt time.Time
	h.run(t, e, 10000, func() bool {
		if renewedAt.IsZero() && len(e.renewCerts) > 0 {
			renewedAt = h.now
		}
		return len(e.renewCerts) > 0 && h.storedSerial(t) == 13
	})

	if len(e.renewCerts) != 1 || !bytes.Equal(e.renewCerts[0], oldDER) {
		t.Fatalf("renew must be dialled with the old certificate once; calls %d", len(e.renewCerts))
	}
	// No renewal before 2/3 of the life: the clock is within one retry step.
	if renewedAt.Before(renewAt) || renewedAt.After(renewAt.Add(probeRetry)) {
		t.Fatalf("renewed at %v, 2/3 of life is %v", renewedAt, renewAt)
	}
	h.agentSecretIntact(t)
}

func TestProbeIdentityRetriesLostRenewalWithSameCertificate(t *testing.T) {
	h := newProbeHarness(t, nil)
	nb := h.now.Add(-21 * 24 * time.Hour) // past 2/3 of a 30-day life
	oldDER, oldKey := probeCert(t, 20, nb, nb.Add(30*24*time.Hour))
	h.seed(t, certData(t, oldDER, oldKey))
	newDER, _ := probeCert(t, 21, h.now, h.now.Add(30*24*time.Hour))
	e := &fakeEnroller{renewScript: []func() ([]byte, error){
		func() ([]byte, error) { return nil, status.Error(codes.DeadlineExceeded, "response lost") },
		func() ([]byte, error) { return nil, status.Error(codes.Unavailable, "gateway restarting") },
		func() ([]byte, error) { return newDER, nil },
	}}

	h.run(t, e, 20, func() bool { return h.storedSerial(t) == 21 })

	if len(e.renewCerts) != 3 {
		t.Fatalf("renew calls = %d, want 3", len(e.renewCerts))
	}
	for i, c := range e.renewCerts {
		if !bytes.Equal(c, oldDER) {
			t.Fatalf("attempt %d was not made with the old certificate", i)
		}
	}
	// The old certificate stayed in the Secret until the answer arrived: the
	// only write is the renewed certificate.
	if h.updates() != 1 {
		t.Fatalf("Secret writes = %d, want 1", h.updates())
	}
	if got, _, _ := parseStored(h.secret(t, testProbeSecret).Data); !bytes.Equal(got, newDER) {
		t.Fatal("renewed certificate is not in the Secret")
	}
	if h.waits[0] != probeRetry || h.waits[1] != probeRetry {
		t.Fatalf("retry waits %v", h.waits)
	}
	h.agentSecretIntact(t)
}

func TestProbeIdentityPermissionDeniedNeedsReinstall(t *testing.T) {
	h := newProbeHarness(t, nil)
	nb := h.now.Add(-21 * 24 * time.Hour)
	oldDER, oldKey := probeCert(t, 30, nb, nb.Add(30*24*time.Hour))
	h.seed(t, certData(t, oldDER, oldKey))
	denied := func() ([]byte, error) {
		return nil, status.Error(codes.PermissionDenied, "probe revoked or certificate superseded")
	}
	e := &fakeEnroller{renewScript: []func() ([]byte, error){denied, denied, denied}}

	h.run(t, e, 3, func() bool { return false }) // keeps checking: runs all 3 rounds

	if len(e.renewCerts) != 3 {
		t.Fatalf("renew calls = %d, want a check every 10m", len(e.renewCerts))
	}
	if h.updates() != 0 {
		t.Fatalf("Secret written on PermissionDenied: %v", h.kube.Actions())
	}
	if got, _, _ := parseStored(h.secret(t, testProbeSecret).Data); !bytes.Equal(got, oldDER) {
		t.Fatal("probe certificate changed")
	}
	if !strings.Contains(h.logs.String(), "Install probe") || !strings.Contains(h.logs.String(), "level=ERROR") {
		t.Fatalf("lock-out not logged as an error asking for a reinstall:\n%s", h.logs)
	}
	for _, w := range h.waits {
		if w != probeRetry {
			t.Fatalf("waits %v, want 10m", h.waits)
		}
	}
	h.agentSecretIntact(t)
}

func TestProbeIdentityLockedOutThenReinstalled(t *testing.T) {
	h := newProbeHarness(t, nil)
	nb := h.now.Add(-21 * 24 * time.Hour)
	oldDER, oldKey := probeCert(t, 40, nb, nb.Add(30*24*time.Hour))
	h.seed(t, certData(t, oldDER, oldKey))
	freshDER, _ := probeCert(t, 41, h.now, h.now.Add(30*24*time.Hour))
	e := &fakeEnroller{
		enrollCert: func() ([]byte, error) { return freshDER, nil },
		renewScript: []func() ([]byte, error){
			func() ([]byte, error) { return nil, status.Error(codes.PermissionDenied, "revoked") },
		},
	}
	// The user generates an Install probe command: the Secret gets a token
	// while the old certificate is still in it.
	round := 0
	ctx := context.Background()
	h.a.probeIdentityLoop(ctx, e, probeClock{
		now: func() time.Time { return h.now },
		sleep: func(_ context.Context, d time.Duration) bool {
			round++
			if round == 1 {
				s := h.secret(t, testProbeSecret)
				s.Data[keyBootstrap] = []byte("tok-new")
				if _, err := h.kube.CoreV1().Secrets(testNS).Update(ctx, s, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			h.now = h.now.Add(d)
			return round < 3
		},
	})

	if !reflect.DeepEqual(e.enrollToks, []string{"tok-new"}) {
		t.Fatalf("enroll tokens %v", e.enrollToks)
	}
	if h.storedSerial(t) != 41 {
		t.Fatal("fresh certificate not stored")
	}
	if _, ok := h.secret(t, testProbeSecret).Data[keyBootstrap]; ok {
		t.Fatal("token kept")
	}
}

func TestProbeIdentityExpiredWithoutTokenWritesNothing(t *testing.T) {
	h := newProbeHarness(t, nil)
	oldDER, oldKey := probeCert(t, 50, h.now.Add(-60*24*time.Hour), h.now.Add(-30*24*time.Hour))
	h.seed(t, certData(t, oldDER, oldKey))
	e := &fakeEnroller{}

	h.run(t, e, 3, func() bool { return false })

	if e.calls() != 0 {
		t.Fatal("enroller called without a token")
	}
	if h.updates() != 0 {
		t.Fatalf("Secret written: %v", h.kube.Actions())
	}
	if n := strings.Count(h.logs.String(), "generate an Install probe command in Olympos"); n != 3 {
		t.Fatalf("logged %d times, want 3:\n%s", n, h.logs)
	}
	if len(h.waits) != 3 || h.waits[0] != probeRetry {
		t.Fatalf("waits %v", h.waits)
	}
	h.agentSecretIntact(t)
}

func TestProbeIdentityEmptySecretLogsAndWritesNothing(t *testing.T) {
	h := newProbeHarness(t, nil)
	h.kube.ClearActions()
	h.run(t, &fakeEnroller{}, 1, func() bool { return false })
	if h.updates() != 0 || !strings.Contains(h.logs.String(), "Install probe") {
		t.Fatalf("updates %d logs %s", h.updates(), h.logs)
	}
}

func TestProbeIdentityKeepsNewIdentityUntilItIsWritten(t *testing.T) {
	h := newProbeHarness(t, map[string][]byte{keyBootstrap: []byte("tok-1")})
	der, _ := probeCert(t, 60, h.now.Add(-time.Minute), h.now.Add(30*24*time.Hour))
	e := &fakeEnroller{enrollCert: func() ([]byte, error) { return der, nil }}
	fails := 1
	h.kube.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		if fails > 0 {
			fails--
			return true, nil, errors.New("conflict")
		}
		return false, nil, nil
	})

	h.run(t, e, 5, func() bool { _, ok := h.secret(t, testProbeSecret).Data[keyCert]; return ok })

	if len(e.enrollToks) != 1 {
		t.Fatalf("the spent token was used %d times", len(e.enrollToks))
	}
	if h.storedSerial(t) != 60 {
		t.Fatal("identity not written after the retry")
	}
}

func TestProbeIdentityDisabledMakesNoCalls(t *testing.T) {
	h := newProbeHarness(t, map[string][]byte{keyBootstrap: []byte("tok-1")})
	h.a.cfg.ProbeEnabled = false
	h.kube.ClearActions()
	e := &fakeEnroller{}
	if h.a.startProbeIdentity(context.Background(), e) {
		t.Fatal("started although disabled")
	}
	if e.calls() != 0 || len(h.kube.Actions()) != 0 {
		t.Fatalf("calls %d actions %v", e.calls(), h.kube.Actions())
	}
}

func TestProbeConfigFromEnv(t *testing.T) {
	t.Setenv("OLYMPOS_SERVER", "olympos.example:8443")
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.ProbeEnabled || c.ProbeIdentitySecret != "olympos-probe-identity" {
		t.Fatalf("defaults: %+v", c)
	}
	t.Setenv("OLYMPOS_PROBE_ENABLED", "true")
	t.Setenv("OLYMPOS_PROBE_IDENTITY_SECRET", "other")
	if c, err = ConfigFromEnv(); err != nil || !c.ProbeEnabled || c.ProbeIdentitySecret != "other" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestProbeIdentityTokenReplacesValidCertificate(t *testing.T) {
	h := newProbeHarness(t, nil)
	oldDER, oldKey := probeCert(t, 70, h.now.Add(-time.Hour), h.now.Add(30*24*time.Hour))
	data := certData(t, oldDER, oldKey)
	data[keyBootstrap] = []byte("tok-reinstall")
	h.seed(t, data)
	newDER, _ := probeCert(t, 71, h.now, h.now.Add(30*24*time.Hour))
	e := &fakeEnroller{enrollCert: func() ([]byte, error) { return newDER, nil }}

	h.run(t, e, 1, func() bool { return true })

	if !reflect.DeepEqual(e.enrollToks, []string{"tok-reinstall"}) || len(e.renewCerts) != 0 {
		t.Fatalf("enroll tokens %v, renews %d", e.enrollToks, len(e.renewCerts))
	}
	got := h.secret(t, testProbeSecret).Data
	if _, ok := got[keyBootstrap]; ok {
		t.Fatal("token kept")
	}
	if h.storedSerial(t) != 71 {
		t.Fatal("the valid certificate was not replaced")
	}
	h.agentSecretIntact(t)
}

func TestProbeIdentityBadTokenIsDroppedAndCertificateKept(t *testing.T) {
	for _, code := range []codes.Code{codes.PermissionDenied, codes.NotFound} {
		t.Run(code.String(), func(t *testing.T) {
			h := newProbeHarness(t, nil)
			oldDER, oldKey := probeCert(t, 80, h.now.Add(-time.Hour), h.now.Add(30*24*time.Hour))
			data := certData(t, oldDER, oldKey)
			data[keyBootstrap] = []byte("tok-bad")
			h.seed(t, data)
			e := &fakeEnroller{enrollCert: func() ([]byte, error) { return nil, status.Error(code, "token invalid, expired or used") }}

			h.run(t, e, 3, func() bool { return false })

			if len(e.enrollToks) != 1 {
				t.Fatalf("the bad token was tried %d times", len(e.enrollToks))
			}
			got := h.secret(t, testProbeSecret).Data
			if _, ok := got[keyBootstrap]; ok {
				t.Fatal("bad token kept")
			}
			if h.storedSerial(t) != 80 || !bytes.Equal(got[keyClusterID], []byte(testProbeCluster)) {
				t.Fatal("current certificate not kept")
			}
			if !strings.Contains(h.logs.String(), "bootstrap token was refused") || !strings.Contains(h.logs.String(), "level=ERROR") {
				t.Fatalf("refusal not logged:\n%s", h.logs)
			}
			if len(e.renewCerts) != 0 {
				t.Fatal("renewed before 2/3 of the life")
			}
			h.agentSecretIntact(t)
		})
	}
}

func TestProbeIdentityUnreachableServerKeepsToken(t *testing.T) {
	h := newProbeHarness(t, nil)
	oldDER, oldKey := probeCert(t, 90, h.now.Add(-time.Hour), h.now.Add(30*24*time.Hour))
	data := certData(t, oldDER, oldKey)
	data[keyBootstrap] = []byte("tok-1")
	h.seed(t, data)
	e := &fakeEnroller{enrollCert: func() ([]byte, error) { return nil, status.Error(codes.Unavailable, "down") }}

	h.run(t, e, 2, func() bool { return false })

	if len(e.enrollToks) != 2 || h.updates() != 0 {
		t.Fatalf("enroll tries %d, writes %d: the token must stay for the next try", len(e.enrollToks), h.updates())
	}
}
