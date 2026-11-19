package agent

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

const (
	canaryAWS = "AKIAQ3VZ7RMXK2JWDTPL"
	canaryPW  = "hunter2-Canary-Pw-91x"
	canaryPEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM2BxeLmKgcXQBpZ4u5RD9Zx1Zc0m8Qx2vCanaryPemBody4t0H8\n-----END RSA PRIVATE KEY-----\n"
)

func cm(ns, name string, uid types.UID, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: uid}, Data: data}
}

// F2: an AWS key, a private key and a DB_PASSWORD give three items; the
// report never carries a value; references, placeholders, kube-root-ca.crt
// and excluded namespaces give none; removing the keys empties the report.
func TestSensitiveDataReporter(t *testing.T) {
	kube := fake.NewClientset(
		cm("shop", "app-config", "u1", map[string]string{
			"AWS_ACCESS_KEY_ID": canaryAWS,
			"tls.key":           canaryPEM,
			"DB_PASSWORD":       canaryPW,
			"DB_HOST":           "orders-pg.shop.svc",
			"API_TOKEN":         "${API_TOKEN}",
			"secretName":        "orders-db-credentials",
			"LOG_LEVEL":         "debug",
		}),
		cm("shop", "kube-root-ca.crt", "u2", map[string]string{"ca.crt": canaryPEM}),
		cm("kube-system", "leaky", "u3", map[string]string{"PASSWORD": canaryPW}),
	)
	r, err := newSensitiveReporter(kube, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reports := make(chan *pb.SensitiveDataReport, 8)
	go func() {
		_ = r.Run(ctx, func(rep *pb.ResourceReport) { reports <- rep.GetSensitiveData() })
	}()
	rep := <-reports
	got := map[string]*pb.SensitiveDataItem{}
	for _, it := range rep.Items {
		got[it.Namespace+"/"+it.ConfigMap+":"+it.Key] = it
	}
	if len(got) != 3 || rep.RulesVersion != SensitiveRulesVersion {
		t.Fatalf("items: %v", rep.Items)
	}
	aws, pem, pw := got["shop/app-config:AWS_ACCESS_KEY_ID"], got["shop/app-config:tls.key"], got["shop/app-config:DB_PASSWORD"]
	if aws == nil || aws.Confidence != ConfidenceHigh || !strings.Contains(aws.RuleId, "aws") {
		t.Fatalf("aws: %v", aws)
	}
	if pem == nil || pem.Confidence != ConfidenceHigh || pem.RuleId != "private-key" {
		t.Fatalf("private key: %v", pem)
	}
	if pw == nil || pw.ValueLength != lengthBucket(len(canaryPW)) || pw.ValueLength < int64(len(canaryPW)) || pw.ValueLength&(pw.ValueLength-1) != 0 {
		t.Fatalf("password: %v", pw)
	}
	b, _ := proto.Marshal(rep)
	for _, c := range []string{canaryAWS, canaryPW, "CanaryPemBody", "MIIEpAIBAAKCAQEA"} {
		if strings.Contains(string(b), c) {
			t.Fatalf("report carries a value: %q", c)
		}
	}
	// The informer cache holds no data.
	for _, o := range r.inf.GetStore().List() {
		if c := o.(*corev1.ConfigMap); c.Data != nil || c.BinaryData != nil {
			t.Fatalf("cached ConfigMap %s keeps its data", c.Name)
		}
	}

	// The keys are removed: the next report is empty.
	_, err = kube.CoreV1().ConfigMaps("shop").Update(ctx, cm("shop", "app-config", "u1", map[string]string{"DB_HOST": "orders-pg.shop.svc"}), metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case rep = <-reports:
		if len(rep.Items) != 0 {
			t.Fatalf("after removal: %v", rep.Items)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no report after the update")
	}
}

func TestKeyNameHeuristics(t *testing.T) {
	for key, want := range map[string]string{
		"DB_PASSWORD": "password", "redis-passwd": "passwd", "client.secret": "secret", "API_KEY": "apikey",
		"connection_string": "connectionstring", "DATABASE_DSN": "dsn",
		"secretName": "", "tokenPath": "", "passwordFile": "", "LOG_LEVEL": "", "SECRET_REF": "",
	} {
		if got, _ := keyNameMatch(key); got != want {
			t.Errorf("%s: %q, want %q", key, got, want)
		}
	}
	for v, want := range map[string]bool{"${X}": false, "{{ .Values.pw }}": false, "changeme": false, "true": false, "abc": false, "s3cr3t-value": true} {
		if got := meaningful(v); got != want {
			t.Errorf("meaningful(%q) = %v", v, got)
		}
	}
}
