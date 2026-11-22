package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// RestoreGuide is the ready-to-copy restore procedure of one successful run
// (F19). v0.1 has no restore button; a UI restore to a NEW target (maker/
// checker) is planned for v0.2. Commands contain placeholders in <angle
// brackets> for what Olympos cannot know (new host, credentials).
type RestoreGuide struct {
	Doc   string        `json:"doc"` // docs/restore.md anchor
	Steps []RestoreStep `json:"steps"`
	// Copies: the destinations the run can be restored from, in member
	// order, with the one the steps are built from selected.
	Copies []RestoreCopy `json:"copies"`
}

// RestoreCopy is one succeeded copy of a run that a guide can be built from.
// RunID is the run that wrote it: the guide's run, or one of its repairs
// (the copy was completed later); TakenAt is when that run started.
type RestoreCopy struct {
	DestinationID uuid.UUID  `json:"destination_id"`
	Name          string     `json:"name"`
	Kind          string     `json:"kind"`
	Selected      bool       `json:"selected"`
	RunID         uuid.UUID  `json:"run_id"`
	TakenAt       *time.Time `json:"taken_at"`
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

// ErrNoSuccessfulCopy is returned when a restore guide is asked for a
// destination in which the run has no successful copy.
var ErrNoSuccessfulCopy = errors.New("this run has no successful copy in that destination")

// guideSource is one destination a run can be restored from.
type guideSource struct {
	copy      RestoreCopy
	dest      guideInput // destination fields only
	blob, sum string
	repair    bool // written by a repair of the guide's run
}

const guideDestCols = `d.id, d.name, d.kind, d.account, d.container, d.endpoint_override, d.bucket, d.region, d.path`

func (s *guideSource) dests() []any {
	d := &s.dest
	return []any{&s.copy.DestinationID, &s.copy.Name, &d.kind, &d.account, &d.container, &d.endpoint, &d.bucket, &d.region, &d.nfsPath}
}

// LoadRestoreGuide builds the guide of a succeeded or partial, non-test run;
// nil for other runs. A run with copy rows restores from one of its
// succeeded copies and that copy's destination. An original run also offers
// the succeeded copies its repairs wrote (for that destination they are the
// only copy of this activation), after its own copies, by repair start. The
// copy used is the run's own on destID, else the newest repair copy there,
// else (destID nil) the first one; the commands use that copy's blob and the
// manifest of the run that wrote it. A failed copy is never a source, even
// when its data blob landed (its manifest did not). A repair run's guide
// offers its own copies only. Runs from before destination groups have no
// copy rows; they use the job's destination. With destID set and no
// succeeded copy there, the error is ErrNoSuccessfulCopy.
func LoadRestoreGuide(ctx context.Context, q store.Querier, runID uuid.UUID, destID *uuid.UUID) (*RestoreGuide, error) {
	var in guideInput
	var status, trigger, runBlob, runSum string
	var jobID uuid.UUID
	var order []uuid.UUID
	var repairOf *uuid.UUID
	var started *time.Time
	var opts []byte
	err := q.QueryRow(ctx, `SELECT r.job_id, r.status, r.trigger, r.blob_path, r.sha256, r.destination_ids, r.repair_of, r.started_at,
		COALESCE(t.engine, 'postgresql'), COALESCE(t.vault_provider, ''), COALESCE(t.namespace, 'olympos'), COALESCE(t.service, 'olympos-db'),
		j.engine_options
		FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id LEFT JOIN targets t ON t.id = j.target_id WHERE r.id = $1`, runID).
		Scan(&jobID, &status, &trigger, &runBlob, &runSum, &order, &repairOf, &started, &in.engine, &in.vaultProvider, &in.ns, &in.svc, &opts)
	if err != nil {
		return nil, store.NotFound(err)
	}

	// The run's own copies in destination_ids order, then (original runs
	// only) the succeeded copies of its repairs by repair start.
	rows, err := q.Query(ctx, `SELECT `+guideDestCols+`, c.status, c.blob_path, c.sha256, c.run_id, x.started_at
		FROM backup_run_copies c JOIN backup_runs x ON x.id = c.run_id JOIN destinations d ON d.id = c.destination_id
		WHERE c.run_id = $1 OR $3 AND x.repair_of = $1 AND c.status = 'succeeded'
		ORDER BY c.run_id <> $1, CASE WHEN c.run_id = $1 THEN COALESCE(array_position($2::uuid[], c.destination_id), 1000) ELSE 0 END,
		  x.started_at, COALESCE(array_position($2::uuid[], c.destination_id), 1000), d.name`, runID, order, repairOf == nil)
	if err != nil {
		return nil, err
	}
	hasCopies := false
	var sources []guideSource
	for rows.Next() {
		var s guideSource
		var cs string
		if err := rows.Scan(append(s.dests(), &cs, &s.blob, &s.sum, &s.copy.RunID, &s.copy.TakenAt)...); err != nil {
			rows.Close()
			return nil, err
		}
		s.repair = s.copy.RunID != runID
		hasCopies = hasCopies || !s.repair
		if cs == "succeeded" && s.blob != "" {
			s.copy.Kind = s.dest.kind
			sources = append(sources, s)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !hasCopies && status == "succeeded" && runBlob != "" {
		// From before destination groups: the job's destination.
		s := guideSource{blob: runBlob, sum: runSum, copy: RestoreCopy{RunID: runID, TakenAt: started}}
		err := q.QueryRow(ctx, `SELECT `+guideDestCols+` FROM backup_jobs j JOIN destinations d ON d.id = j.destination_id WHERE j.id = $1`, jobID).
			Scan(s.dests()...)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			s.copy.Kind = s.dest.kind
			sources = append(sources, s)
		}
	}
	if status != "succeeded" && status != "partial" || trigger == "test" {
		sources = nil
	}

	pick := -1
	switch {
	case destID == nil && len(sources) > 0:
		pick = 0
	case destID != nil:
		for i, s := range sources {
			if s.copy.DestinationID != *destID {
				continue
			}
			pick = i
			if !s.repair {
				break // the run's own copy there
			}
			// Repairs come last, oldest first: the last match is the newest.
		}
	}
	if pick < 0 {
		if destID != nil {
			return nil, ErrNoSuccessfulCopy
		}
		return nil, nil
	}
	s := sources[pick]
	in.kind, in.account, in.container, in.endpoint, in.bucket, in.region, in.nfsPath =
		s.dest.kind, s.dest.account, s.dest.container, s.dest.endpoint, s.dest.bucket, s.dest.region, s.dest.nfsPath
	in.blobPath, in.sha256, in.runID = s.blob, s.sum, s.copy.RunID
	_ = json.Unmarshal(opts, &in.options)
	g := buildRestoreGuide(in)
	for i, c := range sources {
		c.copy.Selected = i == pick
		g.Copies = append(g.Copies, c.copy)
	}
	return g, nil
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
