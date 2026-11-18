package app

import (
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/config"
)

// storageOptions maps config backup.* to the S3/NFS storage options shared
// by every blob.Resolver and the destinations API. It fails when the
// storage CA bundle cannot be read, so a broken bundle stops the server at
// start instead of failing every S3 run.
func storageOptions(c *config.Server) (blob.StorageOptions, error) {
	o := blob.StorageOptions{
		NFSRoot:      c.Backup.NFSRoot,
		CABundleFile: c.Backup.StorageCABundleFile,
		S3PartSize:   uint64(c.Backup.S3PartSizeMiB) << 20,
	}
	if _, err := o.S3Transport(); err != nil {
		return blob.StorageOptions{}, err
	}
	return o, nil
}
