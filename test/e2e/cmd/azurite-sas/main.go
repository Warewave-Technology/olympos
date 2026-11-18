// Command azurite-sas creates a container in the lab Azurite and prints a
// container SAS with r c w t (no delete) for Settings > Destinations.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
)

// Azurite's public, well-known development account key.
const key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

func main() {
	url := flag.String("url", "http://127.0.0.1:31000/devstoreaccount1", "Azurite account URL")
	container := flag.String("container", "backups", "container")
	flag.Parse()
	cred, _ := azblob.NewSharedKeyCredential("devstoreaccount1", key)
	c, err := azblob.NewClientWithSharedKeyCredential(*url, cred, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := c.CreateContainer(context.Background(), *container, nil); err != nil && !strings.Contains(err.Error(), "ContainerAlreadyExists") {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	q, err := sas.BlobSignatureValues{Protocol: sas.ProtocolHTTPSandHTTP, ExpiryTime: time.Now().Add(30 * 24 * time.Hour),
		ContainerName: *container, Permissions: (&sas.ContainerPermissions{Read: true, Create: true, Write: true, Tag: true}).String(),
	}.SignWithSharedKey(cred)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(q.Encode())
}
