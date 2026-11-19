package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// RestoreGuide is the ready-to-copy restore procedure of one successful run
// (F19). v0.1 has no restore button; a UI restore to a NEW target (maker/
// checker) is planned for v0.2. Commands contain placeholders in <angle
// brackets> for what Olympos cannot know (new host, credentials).
type RestoreGuide struct {
	Doc   string        `json:"doc"` // docs/restore.md anchor
	Steps []RestoreStep `json:"steps"`
}

// RestoreStep is one titled block of shell commands.
type RestoreStep struct {
	Title    string `json:"title"`
	Commands string `json:"commands"`
	Note     string `json:"note,omitempty"`
}

type guideInput struct {
	engine, vaultProvider, ns, svc                              string
	kind, account, container, endpoint, bucket, region, nfsPath string
	blobPath, sha256                                            string
	runID                                                       uuid.UUID
	options                                                     map[string]any
}

// LoadRestoreGuide builds the guide of a succeeded, non-test run; nil for
// other runs.
func LoadRestoreGuide(ctx context.Context, q store.Querier, runID uuid.UUID) (*RestoreGuide, error) {
	var in guideInput
	var status, trigger string
	var opts []byte
	err := q.QueryRow(ctx, `SELECT r.status, r.trigger, r.blob_path, r.sha256, COALESCE(t.engine, 'postgresql'), COALESCE(t.vault_provider, ''),
		COALESCE(t.namespace, 'olympos'), COALESCE(t.service, 'olympos-db'), j.engine_options,
		d.kind, d.account, d.container, d.endpoint_override, d.bucket, d.region, d.path
		FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id JOIN destinations d ON d.id = j.destination_id
		LEFT JOIN targets t ON t.id = j.target_id WHERE r.id = $1`, runID).
		Scan(&status, &trigger, &in.blobPath, &in.sha256, &in.engine, &in.vaultProvider, &in.ns, &in.svc, &opts,
			&in.kind, &in.account, &in.container, &in.endpoint, &in.bucket, &in.region, &in.nfsPath)
	if err != nil {
		return nil, store.NotFound(err)
	}
	if status != "succeeded" || trigger == "test" || in.blobPath == "" {
		return nil, nil
	}
	in.runID = runID
	_ = json.Unmarshal(opts, &in.options)
	return buildRestoreGuide(in), nil
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func buildRestoreGuide(in guideInput) *RestoreGuide {
	ext := path.Ext(in.blobPath)
	file := "backup" + ext
	manifest := ManifestPath(in.blobPath, in.runID)
	g := &RestoreGuide{}

	var dl string
	switch in.kind {
	case "s3":
		extra := ""
		if in.region != "" {
			extra += " --region " + shq(in.region)
		}
		if in.endpoint != "" {
			extra += " --endpoint-url " + shq(in.endpoint)
		}
		dl = fmt.Sprintf("aws s3 cp %s %s%s\naws s3 cp %s manifest.json%s",
			shq("s3://"+in.bucket+"/"+in.blobPath), file, extra, shq("s3://"+in.bucket+"/"+manifest), extra)
	case "nfs":
		dl = fmt.Sprintf("# on the Olympos server, or any host that mounts the same export\ncp %s %s\ncp %s manifest.json",
			shq(path.Join(in.nfsPath, in.blobPath)), file, shq(path.Join(in.nfsPath, manifest)))
	default: // azure_blob
		ep := ""
		if in.endpoint != "" {
			ep = " --blob-endpoint " + shq(in.endpoint)
		}
		dl = fmt.Sprintf("az storage blob download --auth-mode login --account-name %s --container-name %s%s \\\n  --name %s --file %s\n"+
			"az storage blob download --auth-mode login --account-name %s --container-name %s%s \\\n  --name %s --file manifest.json",
			shq(in.account), shq(in.container), ep, shq(in.blobPath), file, shq(in.account), shq(in.container), ep, shq(manifest))
	}
	g.Steps = append(g.Steps, RestoreStep{Title: "Download the backup and its manifest", Commands: dl,
		Note: "Human access to backup storage is break-glass (PIM); see docs/install.md §4."})
	g.Steps = append(g.Steps, RestoreStep{Title: "Verify it",
		Commands: fmt.Sprintf("echo %s | sha256sum -c -\njq '{engine, server_version, tool_version, blob}' manifest.json", shq(in.sha256+"  "+file))})

	switch in.engine {
	case "clickhouse":
		g.Doc = "docs/restore.md#clickhouse"
		g.Steps = append(g.Steps, RestoreStep{Title: "Restore into a new ClickHouse",
			Commands: "unzip -l " + file + " | head\nunzip -p " + file + " manifest.json | jq -r '.databases[].name'\n" +
				"# connection settings for the target (host, port 9440, secure, user, password):\n" +
				"$EDITOR restore-client.xml\n" +
				"# the script from docs/restore.md \"Everything at once\" (target databases must not exist):\n" +
				"./restore-clickhouse.sh " + file,
			Note: "Review the schema first ([HIDDEN] secrets in engine definitions, replicated tables)."})
	case "vault":
		cli := "vault"
		if in.vaultProvider == "openbao" {
			cli = "bao"
		}
		g.Doc = "docs/restore.md#vault--openbao-raft"
		g.Steps = append(g.Steps, RestoreStep{Title: "Restore the raft snapshot",
			Commands: fmt.Sprintf("export VAULT_ADDR=https://<new-%s-host>:8200\n# a token with sys/storage/raft/snapshot-force (break-glass root token)\n"+
				"%s operator raft snapshot restore -force %s\n%s operator unseal   # if it seals after the restore\n%s token revoke -self", in.svc, cli, file, cli, cli),
			Note: "Only a cluster that unseals with the SAME unseal/recovery keys can read the snapshot. Run Vaults › Configure again if the AppRole secret_id was rotated since."})
	default: // postgresql (incl. olympos-self)
		g.Doc = "docs/restore.md#postgresql"
		if in.svc == selfService && in.ns == selfNamespace {
			g.Doc = "docs/restore-olympos.md"
		}
		var dbs []string
		if v, ok := in.options["databases"].([]any); ok {
			for _, x := range v {
				if s, ok := x.(string); ok {
					dbs = append(dbs, s)
				}
			}
		}
		var b strings.Builder
		b.WriteString("unzip " + file + " -d restore/\n")
		if glb, _ := in.options["globals"].(bool); glb || in.options["globals"] == nil {
			b.WriteString("# roles and tablespaces (review first)\npsql \"host=<new-host> user=postgres dbname=postgres sslmode=verify-full\" -f restore/globals.sql\n")
		}
		if len(dbs) > 0 {
			for _, db := range dbs {
				fmt.Fprintf(&b, "createdb -h <new-host> -U postgres %s\npg_restore -h <new-host> -U postgres -d %s --no-owner -j 4 %s\n", shq(db), shq(db), shq("restore/"+pgDumpEntry(db)))
			}
		} else {
			b.WriteString("for f in restore/*.dump; do\n  db=$(basename \"$f\" .dump)\n  createdb -h <new-host> -U postgres \"$db\"\n  pg_restore -h <new-host> -U postgres -d \"$db\" --no-owner -j 4 \"$f\"\ndone\n")
		}
		g.Steps = append(g.Steps, RestoreStep{Title: "Restore into a new PostgreSQL", Commands: strings.TrimRight(b.String(), "\n"),
			Note: "Use pg_restore with a major version ≥ tool_version in the manifest. Into the original server: --clean --if-exists, ideally into a new database first."})
	}
	return g
}

// pgDumpEntry is the zip entry of one database (postgres engine entryName).
func pgDumpEntry(db string) string {
	n := strings.NewReplacer("/", "_", "\\", "_", "\x00", "_").Replace(db)
	if strings.HasPrefix(n, ".") || n == "globals.sql" {
		n = "_" + n
	}
	return n + ".dump"
}
