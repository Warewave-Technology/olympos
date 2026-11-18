# Restoring backups

Restore is manual in v1 (SPEC §10.4). Every backup blob comes with a `{run_id}.manifest.json` written by the
server (sha256, size, engine, versions, timestamps). Blob data-plane access for humans is break-glass only
(PIM, SPEC §10.3.1). Download the backup and check it before restoring:

```bash
az storage blob download --auth-mode login --account-name <account> --container-name <container> \
  --name "<prefix>/<cluster>/<namespace>/<service>/<engine>/YYYY/MM/DD/<run_id>.<ext>" --file backup.<ext>
sha256sum backup.<ext>   # must match "sha256" in <run_id>.manifest.json
```

## ClickHouse

### What a backup contains

A ClickHouse backup is a zip (`<run_id>.zip`) written front to back by the server over the native protocol.
Entries:

| Entry | Content |
|---|---|
| `schema/<db>.sql` | `CREATE DATABASE` (`SHOW CREATE DATABASE`) |
| `schema/<db>/<object>.sql` | `CREATE TABLE / VIEW / MATERIALIZED VIEW / DICTIONARY` (`SHOW CREATE ...`) |
| `data/<db>/<table>/<partition_id>.native` | rows of one partition (`all` = whole table), ClickHouse **Native** format |
| `data/<db>/<table>/<partition_id>.rowbinary` | same, **RowBinaryWithNamesAndTypes**. Used for tables with a column type the Native block codec cannot stream (for example `AggregateFunction`, `Tuple`, `Variant`/`Dynamic`/`JSON`, `LowCardinality(Nullable(...))`). The table's `fallback_reason` in the manifest says which column. |
| `manifest.json` | written last: objects, kinds, columns, partitions, row counts, sha256 per data entry, `restore_order` |

Names in entry paths are escaped (anything outside `[A-Za-z0-9_.-]` becomes `%XX`). Always read the real
database and table names, and the entry paths, from `manifest.json`.

Useful manifest fields (`.databases[].tables[]`):

- `kind`: `table`, `dictionary`, `view`, `materialized_view`, `materialized_view_inner` (the `.inner_id.<uuid>`
  table of a materialized view without `TO`; it is created by its view, see `inner_of`), `other`.
- `has_data`, `data_format` (`Native` or `RowBinaryWithNamesAndTypes`), `data_note` (why there is no data:
  views, engines without local data such as `Distributed`, `Merge`, `Buffer`, `Kafka`, `S3`, `MySQL`, ...).
- `partitions[]`: `id`, `entry` (empty when the partition had no rows), `rows` (streamed), `rows_expected`
  (from `system.parts` at backup start, or from `count()`: see `rows_source`), `sha256` of the entry content.
- `restore_order`: `db.object` in creation order: tables, then dictionaries, then views and materialized views.

A dry run (`"dry_run": true`) contains schema and manifest only.

Things the backup does **not** contain, by design:

- **Secrets in DDL.** `SHOW CREATE` masks credentials of external sources (dictionary `SOURCE(... PASSWORD ...)`,
  `MySQL`/`PostgreSQL`/`S3`/`URL` engines, named collections) as `'[HIDDEN]'`. Put them back before running the
  statement.
- **UUIDs.** Statements are portable (no `UUID '...'`); the original UUIDs are in the manifest for reference.
- **Users, roles, quotas, settings profiles, named collections.** Recreate them separately.
- **A point-in-time snapshot.** Each data entry is one `SELECT` (one partition, or the whole table). Writes during
  the backup can make partitions disagree by a few rows; the manifest lists them under `warnings`.

Each ClickHouse target is backed up through one service. On a sharded cluster, back up each shard (each
shard's service) separately; for replicated tables one replica per shard is enough.

### Restore, step by step

You need `unzip`, `jq` and a `clickhouse-client` matching the target server. Keep the connection settings in a
client config file rather than on the command line:

```bash
ZIP=backup.zip
CH=(clickhouse-client --config-file ./restore-client.xml)   # host, port 9440, secure, user, password
manifest() { unzip -p "$ZIP" manifest.json; }

manifest | jq '{server_version, started_at, dry_run, rows_source, warnings, totals}'
manifest | jq -r '.databases[].tables[] | [.kind, .name, .data_format // "-", .rows] | @tsv'
```

1. **Optional: verify entries** against the manifest:

   ```bash
   manifest | jq -r '.databases[].tables[].partitions[]? | select((.entry // "") != "") | [.sha256, .entry] | @tsv' |
   while IFS=$'\t' read -r sum entry; do
     [ "$(unzip -p "$ZIP" "$entry" | sha256sum | cut -d' ' -f1)" = "$sum" ] || echo "MISMATCH $entry"
   done
   ```

2. **Create the databases** (edit the statement to restore under another name or engine):

   ```bash
   unzip -p "$ZIP" schema/shop.sql | "${CH[@]}" --multiquery
   ```

3. **Create the tables** (`kind == "table"`), in `restore_order`:

   ```bash
   unzip -p "$ZIP" schema/shop/events.sql | "${CH[@]}" --multiquery
   ```

   For `Replicated*MergeTree` tables, make sure the ZooKeeper/Keeper path and replica name do not collide
   with live tables (edit the statement), create the table on every replica, and load data on **one** replica.

4. **Load the data** of each table, one entry per partition:

   ```bash
   unzip -p "$ZIP" data/shop/events/202401.native   | "${CH[@]}" --query "INSERT INTO shop.events FORMAT Native"
   unzip -p "$ZIP" data/shop/agg/all.rowbinary      | "${CH[@]}" --query "INSERT INTO shop.agg FORMAT RowBinaryWithNamesAndTypes"
   ```

   The files hold the columns `SELECT *` returns; `MATERIALIZED` columns are recomputed on insert, `ALIAS`
   columns are not stored. Columns are matched by name.

5. **Create dictionaries, views and materialized views** (the remaining objects of `restore_order`). Create
   materialized views **after** loading the tables so they do not re-ingest the restored rows.

6. **Load materialized view data.** For a view without `TO` (its data is the `materialized_view_inner` table),
   insert into the view itself; this writes straight into its new inner table without running the view's query:

   ```bash
   unzip -p "$ZIP" "data/shop/.inner_id.<uuid>/all.native" | "${CH[@]}" --query "INSERT INTO shop.mv_daily FORMAT Native"
   ```

   Views with `TO db.target` need nothing extra: the target is an ordinary table restored in step 4.

7. **Check row counts** against `rows` in the manifest:

   ```bash
   "${CH[@]}" --query "SELECT count() FROM shop.events"
   ```

### Everything at once

Restores every database of the backup under its original name (the target databases must not exist).
Review it first, in particular for `[HIDDEN]` secrets and replicated tables.

```bash
#!/usr/bin/env bash
set -euo pipefail
ZIP=${1:?backup.zip}
CH=(clickhouse-client --config-file ./restore-client.xml)
manifest() { unzip -p "$ZIP" manifest.json; }

# objects of the given kinds, in restore_order: db <TAB> name <TAB> schema entry
objects() {
  manifest | jq -r --arg kinds "$1" '
    ([.databases[] | .name as $db | .tables[] | {key: ($db + "." + .name), value: (. + {db: $db})}] | from_entries) as $t
    | .restore_order[] | $t[.] | select(.kind as $k | $kinds | split(",") | index($k))
    | [.db, .name, .schema_entry] | @tsv'
}
# data entries of the given kinds: db <TAB> insert target <TAB> format <TAB> entry
entries() {
  manifest | jq -r --arg kinds "$1" '
    .databases[] | .name as $db | .tables[] | select(.has_data) | select(.kind as $k | $kinds | split(",") | index($k))
    | . as $t | .partitions[] | select((.entry // "") != "")
    | [$db, ($t.inner_of // $t.name), $t.data_format, .entry] | @tsv'
}
q() { local s=${1//\\/\\\\}; s=${s//\`/\\\`}; printf '`%s`' "$s"; }   # quote an identifier

for e in $(manifest | jq -r '.databases[].schema_entry'); do unzip -p "$ZIP" "$e" | "${CH[@]}" --multiquery; done
objects table | while IFS=$'\t' read -r db name entry; do unzip -p "$ZIP" "$entry" | "${CH[@]}" --multiquery; done
entries table | while IFS=$'\t' read -r db table fmt entry; do
  unzip -p "$ZIP" "$entry" | "${CH[@]}" --query "INSERT INTO $(q "$db").$(q "$table") FORMAT $fmt"
done
objects dictionary,view,materialized_view,other | while IFS=$'\t' read -r db name entry; do
  unzip -p "$ZIP" "$entry" | "${CH[@]}" --multiquery
done
entries materialized_view_inner | while IFS=$'\t' read -r db table fmt entry; do
  unzip -p "$ZIP" "$entry" | "${CH[@]}" --query "INSERT INTO $(q "$db").$(q "$table") FORMAT $fmt"
done
```

Views that select from other views may need to be created in a different order than `restore_order` (which
sorts views by name); re-run the failed statements once the others exist.

To restore into **another database name**, create the new database yourself and rewrite the qualified names
(`old_db.` → `new_db.`) in the statements, including inside view and materialized view queries, then insert
into `new_db.<table>`.

### Large datasets (v2)

This logical backup (`SELECT ... FORMAT Native` per partition) is slower than ClickHouse's native `BACKUP` for
very large datasets, and restore re-inserts every row. A later version may add an S3-compatible ingest
endpoint on the Olympos server so that ClickHouse can run `BACKUP DATABASE ... TO S3('https://olympos/...')`
against Olympos itself (and `RESTORE ... FROM S3(...)` through it), while the server stays the only writer to
Blob storage and ClickHouse still never receives a Blob credential.
