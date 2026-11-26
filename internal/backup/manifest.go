package backup

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ManifestFormat identifies the manifest schema.
const ManifestFormat = "olympos.backup.manifest/v1"

// TierTag is the blob index tag lifecycle rules match on (SPEC §10.3).
const TierTag = "olympos-tier"

// Manifest is written next to every backup as {run_id}.manifest.json and
// holds everything needed to verify and restore it (SPEC §10.4).
type Manifest struct {
	Format        string          `json:"format"`
	RunID         uuid.UUID       `json:"run_id"`
	JobID         uuid.UUID       `json:"job_id"`
	Trigger       string          `json:"trigger"`
	Tier          string          `json:"tier"`
	ScheduledFor  *time.Time      `json:"scheduled_for,omitempty"`
	StartedAt     time.Time       `json:"started_at"`
	FinishedAt    time.Time       `json:"finished_at"`
	Cluster       ManifestCluster `json:"cluster"`
	Target        ManifestTarget  `json:"target"`
	Engine        string          `json:"engine"`
	EngineOptions json.RawMessage `json:"engine_options"`
	Blob          ManifestBlob    `json:"blob"`
	WireBytes     int64           `json:"wire_bytes"`
	TransferMode  string          `json:"transfer_mode"`
	TLS           *bool           `json:"tls,omitempty"`
	ServerVersion string          `json:"server_version"`
	ToolVersion   string          `json:"tool_version,omitempty"`
	Details       map[string]any  `json:"details,omitempty"`
	Test          bool            `json:"test,omitempty"`
	// Destination is where this copy was written; Group is set when the
	// job writes to a destination group (every member has its own copy).
	Destination *ManifestDestination `json:"destination,omitempty"`
	Group       *ManifestGroup       `json:"group,omitempty"`
}

// ManifestDestination identifies the destination holding this copy.
type ManifestDestination struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// ManifestGroup names the destination group and its members, in order.
type ManifestGroup struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// ManifestCluster identifies the source cluster.
type ManifestCluster struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// ManifestTarget identifies the source service.
type ManifestTarget struct {
	ID            string `json:"id"`
	Namespace     string `json:"namespace"`
	Service       string `json:"service"`
	Port          int    `json:"port"`
	TLSServerName string `json:"tls_server_name"`
}

// ManifestBlob describes the backup blob itself.
type ManifestBlob struct {
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	Ext         string `json:"ext"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

// pathSegment keeps a name usable as one blob path segment.
func pathSegment(s string) string {
	s = strings.NewReplacer("/", "_", "\\", "_").Replace(s)
	if s == "" || s == "." || s == ".." {
		return "_"
	}
	return s
}

// BlobPath is {prefix}/{cluster}/{namespace}/{service}/{engine}/{YYYY}/{MM}/{DD}/{run_id}.{ext}.
func BlobPath(prefix, cluster, namespace, service, engine string, at time.Time, runID uuid.UUID, ext string) string {
	return RunDir(prefix, cluster, namespace, service, engine, at, runID) + "." + ext
}

// RunDir is {prefix}/{cluster}/{namespace}/{service}/{engine}/{YYYY}/{MM}/{DD}/{run_id}:
// the directory of a native run's objects, and BlobPath without its
// extension. The run's manifest is next to it (ManifestPath).
func RunDir(prefix, cluster, namespace, service, engine string, at time.Time, runID uuid.UUID) string {
	var parts []string
	if p := strings.Trim(prefix, "/"); p != "" {
		parts = append(parts, p)
	}
	at = at.UTC()
	parts = append(parts, pathSegment(cluster), pathSegment(namespace), pathSegment(service), pathSegment(engine),
		at.Format("2006"), at.Format("01"), at.Format("02"), runID.String())
	return strings.Join(parts, "/")
}

// ManifestPath returns the manifest path for a backup blob path, or for a
// native run's directory.
func ManifestPath(blobPath string, runID uuid.UUID) string {
	dir := ""
	if i := strings.LastIndexByte(blobPath, '/'); i >= 0 {
		dir = blobPath[:i+1]
	}
	return dir + runID.String() + ".manifest.json"
}
