package destinations_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// Azurite in Docker for blob tests. Skipped when Docker is unavailable
// unless OLYMPOS_REQUIRE_DOCKER=1.
const (
	azuriteName  = "olympos-m2a-azurite"
	azuriteImage = "mcr.microsoft.com/azure-storage/azurite"
	devAccount   = "devstoreaccount1"
	devKey       = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)

var (
	azOnce     sync.Once
	azEndpoint string
	azErr      error
	azStarted  bool
)

func TestMain(m *testing.M) {
	code := m.Run()
	if azStarted {
		_ = exec.Command("docker", "rm", "-f", "-v", azuriteName).Run()
	}
	testutil.StopMinIO()
	os.Exit(code)
}

func startAzurite() (string, error) {
	if err := exec.Command("docker", "info").Run(); err != nil {
		return "", fmt.Errorf("docker not available: %w", err)
	}
	_ = exec.Command("docker", "rm", "-f", "-v", azuriteName).Run()
	out, err := exec.Command("docker", "run", "-d", "--name", azuriteName, "-p", "127.0.0.1::10000", azuriteImage,
		"azurite-blob", "--blobHost", "0.0.0.0", "--skipApiVersionCheck", "--loose").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker run: %v: %s", err, out)
	}
	azStarted = true
	out, err = exec.Command("docker", "port", azuriteName, "10000/tcp").Output()
	if err != nil {
		return "", fmt.Errorf("docker port: %w", err)
	}
	hostPort := strings.TrimSpace(strings.Split(strings.TrimSpace(string(out)), "\n")[0])
	ep := "http://" + hostPort + "/" + devAccount
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(ep + "?comp=list")
		if err == nil {
			resp.Body.Close()
			return ep, nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return "", fmt.Errorf("azurite did not become ready at %s", ep)
}

func azurite(t *testing.T) string {
	t.Helper()
	azOnce.Do(func() { azEndpoint, azErr = startAzurite() })
	if azErr != nil {
		if os.Getenv("OLYMPOS_REQUIRE_DOCKER") == "1" {
			t.Fatalf("azurite: %v", azErr)
		}
		t.Skipf("azurite unavailable: %v", azErr)
	}
	return azEndpoint
}

func sharedKey(t *testing.T) *container.SharedKeyCredential {
	cred, err := container.NewSharedKeyCredential(devAccount, devKey)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// newContainer creates a fresh container with the account key (test setup
// only; the server never uses shared keys).
func newContainer(t *testing.T, ep string) string {
	t.Helper()
	name := "c" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	cc, err := container.NewClientWithSharedKeyCredential(ep+"/"+name, sharedKey(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Create(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	return name
}

// containerSAS signs a container-scoped service SAS with the account key.
func containerSAS(t *testing.T, containerName string, perms sas.ContainerPermissions, expiry time.Time) string {
	t.Helper()
	qp, err := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPSandHTTP,
		StartTime:     time.Now().Add(-5 * time.Minute).UTC(),
		ExpiryTime:    expiry.UTC(),
		Permissions:   perms.String(),
		ContainerName: containerName,
	}.SignWithSharedKey(sharedKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return qp.Encode()
}

var (
	permsRCWT  = sas.ContainerPermissions{Read: true, Create: true, Write: true, Tag: true}
	permsRCWTD = sas.ContainerPermissions{Read: true, Create: true, Write: true, Tag: true, Delete: true}
	permsRW    = sas.ContainerPermissions{Read: true, Write: true}
)

// sigOf returns the sig value of a SAS (the canary that must never leak).
func sigOf(token string) string {
	for _, kv := range strings.Split(token, "&") {
		if v, ok := strings.CutPrefix(kv, "sig="); ok {
			return v
		}
	}
	return ""
}
