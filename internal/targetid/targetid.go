// Package targetid computes stable discovery target IDs (SPEC §5).
package targetid

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// Compute returns hex(sha256(cluster_uuid|namespace|service|port)[:16]).
func Compute(clusterID, namespace, service string, port int32) string {
	h := sha256.Sum256([]byte(clusterID + "|" + namespace + "|" + service + "|" + strconv.Itoa(int(port))))
	return hex.EncodeToString(h[:16])
}
