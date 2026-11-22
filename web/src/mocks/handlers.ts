// DEV-ONLY request handlers for the VITE_MOCK fixture layer.
import type { BackupJob, BackupJobInput, BackupRun, BackupRunCopy, DestinationGroup, DestinationGroupInput, RestoreGuide, SelfBackup, ChangeRequestInput, Cluster, Dashboard, Destination, DestinationInput, DestinationTest, Grant, RegistryInput, Role, Vault } from '../api/types';
import { describeCron, nextRuns, runsPerMonth } from '../lib/cron';
import { parseSas } from '../lib/sas';
import * as db from './db';
import { fleetRoutes } from './fleet';

export interface MockReq {
  method: string;
  path: string; // below /api/v1, without query
  query: URLSearchParams;
  body: any; // eslint-disable-line @typescript-eslint/no-explicit-any
}
export type MockRes = { status: number; body?: unknown };
type Handler = (req: MockReq, params: Record<string, string>) => MockRes | Promise<MockRes>;

const ok = (body: unknown, status = 200): MockRes => ({ status, body });
const items = (list: unknown[]) => ok({ items: list });
const notFound = (): MockRes => ({ status: 404, body: { error: 'not found' } });
const invalid = (error: string, fields: Record<string, string>): MockRes => ({ status: 422, body: { error, fields } });
const forbidden = (): MockRes => ({ status: 403, body: { error: 'your role does not allow this action' } });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const perms = () => db.me().permissions;

function fingerprint(value: string): string {
  // Fake, NOT a real HMAC: the mock never keeps the value, only this derived string.
  let h = 0x811c9dc5;
  for (let i = 0; i < value.length; i++) h = Math.imul(h ^ value.charCodeAt(i), 0x01000193) >>> 0;
  const hex = (h.toString(16).padStart(8, '0') + ((h * 2654435761) >>> 0).toString(16).padStart(8, '0')).slice(0, 12);
  return `hm:${hex.slice(0, 4)}·${hex.slice(4, 8)}·${hex.slice(8, 12)}`;
}

function minor(v: string) {
  const m = /^v?1\.(\d+)/.exec(v);
  return m ? Number(m[1]) : 0;
}

function liveClusters(): Cluster[] {
  const now = Date.now();
  for (const c of db.clusters) {
    const t = db.enrolling.get(c.id);
    if (t && c.status === 'pending' && now - t > 9000) {
      Object.assign(c, {
        status: 'online',
        last_seen_at: new Date().toISOString(),
        api_version: 'v1.32.2',
        min_kubelet: 'v1.32.2',
        nodes: 4,
        nodes_ready: 4,
        provider: 'oracle',
        provider_label: 'Oracle Cloud',
        region: 'eu-frankfurt-1',
        agent_version: '0.4.2',
        inventory_at: new Date().toISOString(),
      });
    }
  }
  return db.clusters;
}

function dashboard(): Dashboard {
  const cs = liveClusters().filter((c) => c.status !== 'revoked');
  const minors = new Map<number, number>();
  for (const c of cs) if (minor(c.api_version)) minors.set(minor(c.api_version), (minors.get(minor(c.api_version)) ?? 0) + 1);
  const keys = [...minors.keys()].sort((a, b) => a - b);
  const provs = new Map<string, { provider: string; label: string; clusters: number; nodes: number }>();
  for (const c of cs) {
    const p = provs.get(c.provider) ?? { provider: c.provider, label: c.provider_label, clusters: 0, nodes: 0 };
    p.clusters++;
    p.nodes += c.nodes;
    provs.set(c.provider, p);
  }
  const offline = cs.filter((c) => c.status === 'offline');
  const waiting = db.changeRequests.filter((r) => r.status === 'pending' && r.maker.object_id !== db.people.yigit.object_id);
  const attention: Dashboard['attention'] = [
    ...offline.map((c) => ({ kind: 'agent_offline' as const, severity: 'crit' as const, label: 'Agent offline', detail: `${c.name} · 2 h`, link: `/settings/clusters?cluster=${c.id}` })),
    { kind: 'backup_failed', severity: 'crit', label: 'Backup failed', detail: 'metrics-ch · SAS expired', link: '/backups?tab=runs' },
  ];
  for (const t of db.targets.filter((x) => x.tls_server_name_pending != null))
    attention.push({
      kind: 'target_tls_changed',
      severity: 'crit',
      label: 'TLS name changed',
      detail: `${t.namespace}/${t.service} asks for ${t.tls_server_name_pending || 'the default name'}; still verifying ${t.tls_server_name || `${t.service}.${t.namespace}.svc`}`,
      link: '/backups?tls=1',
    });
  // partial runs no repair has completed since (latest original run per job)
  for (const j of db.jobs) {
    const last = db.runs.find((r) => r.job_id === j.id && r.trigger !== 'test' && !r.repair_of);
    if (last?.status !== 'partial' || db.runs.some((r) => r.repair_of === last.id && r.status === 'succeeded')) continue;
    const missing = (last.copies ?? []).filter((c) => c.status === 'failed').map((c) => c.destination_name);
    attention.push({ kind: 'backup_partial', severity: 'warn', label: 'Backup incomplete', detail: `${j.target.service} · missing ${missing.join(', ')}`, link: '/backups?tab=runs' });
  }
  const selfLast = selfBackup.runs.find((r) => !r.repair_of);
  if (selfLast?.status === 'partial')
    attention.push({ kind: 'self_backup_partial', severity: 'warn', label: 'Olympos backup incomplete', detail: `missing ${(selfLast.copies ?? []).filter((c) => c.status === 'failed').map((c) => c.destination_name).join(', ')}`, link: '/backups?self=1' });
  if (!selfBackup.configured) attention.push({ kind: 'self_backup_unset', severity: 'warn', label: 'Olympos backup', detail: 'choose where the Olympos database is backed up', link: '/backups?self=1' });
  if (perms().vault_approve && waiting.length) attention.push({ kind: 'approvals', severity: 'warn', label: `${waiting.length} approvals`, detail: 'waiting for you · oldest 51 h left', link: '/approvals' });
  const eol = cs.filter((c) => c.eol);
  if (eol.length) attention.push({ kind: 'eol', severity: 'warn', label: 'End of life', detail: `${eol.length} cluster${eol.length > 1 ? 's' : ''} on v1.29`, link: '/?filter=eol' });
  return {
    attention,
    totals: {
      clusters: cs.length,
      agents_online: cs.filter((c) => c.status === 'online').length,
      nodes: cs.reduce((s, c) => s + c.nodes, 0),
      cpu_milli: cs.reduce((s, c) => s + c.cpu_milli, 0),
      mem_bytes: cs.reduce((s, c) => s + c.mem_bytes, 0),
      versions: keys.length,
      version_min: keys.length ? `1.${keys[0]}` : '',
      version_max: keys.length ? `1.${keys[keys.length - 1]}` : '',
      skew_clusters: cs.filter((c) => c.version_skew).length,
      offline_agents: offline.length,
      offline_detail: offline[0] ? `${offline[0].name} · 2 h ago` : '',
    },
    version_matrix: keys.map((k) => ({ minor: `1.${k}`, clusters: minors.get(k)!, eol: k <= 29 })),
    providers: [...provs.values()],
    clusters: cs,
    refreshed_at: new Date(Date.now() - 40_000).toISOString(),
  };
}

function runFor(id: string): BackupRun | undefined {
  const r = db.runs.find((x) => x.id === id);
  if (!r || r.trigger !== 'test') return r;
  const started = new Date(r.started_at ?? r.scheduled_for ?? Date.now()).getTime();
  const el = Date.now() - started;
  const steps = [
    { name: 'tunnel', ok: true, detail: 'Tunnel opened through agent (target allowlisted)' },
    { name: 'tls', ok: true, detail: 'TLS verified end to end' },
    { name: 'dump', ok: true, detail: 'pg_dump 16 schema-only: 2.1 MB, 0.4 MB on the wire' },
    { name: 'blob', ok: true, detail: 'Written to Blob with manifest and olympos-tier=daily' },
    { name: 'notify', ok: true, detail: 'Slack test message delivered to #infra-backups' },
  ];
  if (el < 1500) Object.assign(r, { status: 'queued', steps: [] });
  else if (el < 6000) Object.assign(r, { status: 'running', steps: steps.slice(0, Math.min(4, Math.floor((el - 1500) / 1000) + 1)) });
  else {
    // A group job writes one copy per member. localStorage olympos.mock.failCopy = <destination name> fails that copy.
    const g = groupOf(db.jobs.find((j) => j.id === r.job_id));
    const fail = localStorage.getItem('olympos.mock.failCopy') ?? '';
    const copies = g ? db.groupCopies(g, 2.1e6, fail ? { [fail]: 'dial tcp: i/o timeout' } : {}, 'test') : undefined;
    const bad = copies?.filter((c) => c.status === 'failed') ?? [];
    const status = !copies || bad.length === 0 ? 'succeeded' : bad.length === copies.length ? 'failed' : 'partial';
    // A group run: an upload step per copy, a manifest step per uploaded copy (as the server's checklist).
    const groupSteps = copies && [
      ...steps.slice(0, 3),
      ...copies.map((c) => (c.status === 'succeeded' ? { name: 'upload', ok: true, detail: `Wrote 2.0 MiB to ${c.destination_name} (390.6 KiB on the wire)` } : { name: 'upload', ok: false, detail: `${c.destination_name}: ${c.error}` })),
      ...copies.filter((c) => c.status === 'succeeded').map((c) => ({ name: 'manifest', ok: true, detail: `Manifest with checksum written to ${c.destination_name}` })),
    ];
    Object.assign(r, { status, finished_at: new Date(started + 6000).toISOString(), bytes: 2.1e6, wire_bytes: 0.4e6, steps: groupSteps ?? steps, copies, error: bad.map((c) => `${c.destination_name}: ${c.error}`).join('; ') });
  }
  return r;
}

function groupOf(j: Pick<BackupJob, 'destination_group'> | undefined): DestinationGroup | undefined {
  return j?.destination_group ? db.destinationGroups.find((g) => g.id === j.destination_group!.id) : undefined;
}

/** Each destination's groups count follows the group list. */
function syncGroupCounts() {
  for (const d of db.destinations) d.groups = db.destinationGroups.filter((g) => g.members.some((m) => m.id === d.id)).length;
}

function validateGroup(b: DestinationGroupInput, self?: DestinationGroup): MockRes | null {
  const fields: Record<string, string> = {};
  const name = (b.name ?? self?.name ?? '').trim();
  if (!name) fields.name = 'Enter a name.';
  else if (db.destinationGroups.some((g) => g.name === name && g.id !== self?.id) || db.destinations.some((d) => d.name === name)) fields.name = `the name ${name} is already used by a destination or group`;
  const ids = b.member_ids ?? self?.members.map((m) => m.id) ?? [];
  if (ids.length < 2 || ids.length > 4) fields.member_ids = 'a group needs 2 to 4 destinations';
  else if (new Set(ids).size !== ids.length) fields.member_ids = 'a destination can be in a group only once';
  else if (ids.some((id) => !db.destinations.some((d) => d.id === id))) fields.member_ids = 'unknown destination';
  return Object.keys(fields).length ? invalid('invalid destination group', fields) : null;
}

/** Restore guide of a run: built from the selected succeeded copy (its own, then those its repairs completed). */
function runRestore(x: BackupRun, doc: string, copyId: string | null): RestoreGuide | null | MockRes {
  type C = BackupRunCopy & { run_id: string; taken_at: string | null };
  const own: C[] = (x.copies ?? []).filter((c) => c.status === 'succeeded').map((c) => ({ ...c, run_id: x.id, taken_at: x.started_at }));
  const later: C[] = x.repair_of ? [] : db.runs.filter((r) => r.repair_of === x.id).flatMap((r) => (r.copies ?? []).filter((c) => c.status === 'succeeded').map((c) => ({ ...c, run_id: r.id, taken_at: r.started_at })));
  const all = [...own, ...later];
  const fallback = x.blob_path || `olympos/${x.cluster_name}/${x.target_service}/${x.engine}/${x.id}.zip`;
  if (!all.length) return restoreGuide(fallback, doc);
  const sel = copyId ? (own.find((c) => c.destination_id === copyId) ?? [...later].reverse().find((c) => c.destination_id === copyId)) : all[0];
  if (!sel) return invalid('no successful copy of this run in that destination', { copy: 'no successful copy of this run in that destination' });
  const d = db.destinations.find((v) => v.id === sel.destination_id);
  return {
    ...restoreGuide(`${x.cluster_name}/${x.target_service}/${sel.run_id.slice(0, 8)}/${x.engine}.zip`, doc, d),
    copies: all.map((c) => ({ destination_id: c.destination_id, name: c.destination_name, kind: c.destination_kind, selected: c === sel, run_id: c.run_id, taken_at: c.taken_at })),
  };
}

function restoreGuide(blob: string, doc: string, d?: Pick<Destination, 'kind' | 'account' | 'container' | 'bucket' | 'endpoint_override' | 'path' | 'prefix'>) {
  const download =
    d?.kind === 's3'
      ? `aws s3 cp${d.endpoint_override ? ` --endpoint-url '${d.endpoint_override}'` : ''} 's3://${d.bucket}/${d.prefix}${blob}' backup.zip`
      : d?.kind === 'nfs'
        ? `cp '${d.path}/${blob}' backup.zip`
        : `az storage blob download --auth-mode login --account-name '${d?.account || 'stolympos'}' --container-name '${d?.container || 'backups'}' \\\n  --name '${d ? d.prefix + blob : blob}' --file backup.zip`;
  return {
    doc,
    steps: [
      {
        title: 'Download the backup and its manifest',
        commands: download,
        note: 'Human access to backup storage is break-glass (PIM).',
      },
      { title: 'Verify it', commands: "echo '<sha256>  backup.zip' | sha256sum -c -" },
      {
        title: 'Restore into a new PostgreSQL',
        commands:
          'unzip backup.zip -d restore/\nfor f in restore/*.dump; do\n  db=$(basename "$f" .dump)\n  createdb -h <new-host> -U postgres "$db"\n  pg_restore -h <new-host> -U postgres -d "$db" --no-owner -j 4 "$f"\ndone',
      },
    ],
  };
}

// The built-in olympos-self job starts unconfigured (Dashboard: Needs attention).
const selfBackup: SelfBackup = { configured: false, job: null, runs: [] };

const routes: [string, string, Handler][] = [
  ...fleetRoutes,
  ['GET', '/me', () => ok(db.me())],
  ['GET', '/dashboard', () => ok(dashboard())],
  ['GET', '/clusters', () => items(liveClusters())],
  [
    'POST',
    '/clusters',
    (r) => {
      if (!perms().admin_global) return forbidden();
      const name = String(r.body?.name ?? '');
      if (!/^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/.test(name)) return invalid('invalid cluster', { name: 'Use lowercase letters, digits and dashes.' });
      if (db.clusters.some((c) => c.name === name)) return invalid('invalid cluster', { name: 'A cluster with this name already exists.' });
      const c: Cluster = {
        ...db.clusters[0],
        id: db.uuid(),
        name,
        labels: { ...(r.body.labels ?? {}), 'olympos.io/cluster': name },
        bench_enabled: !!r.body.bench_enabled,
        status: 'pending',
        last_seen_at: null,
        api_version: '',
        min_kubelet: '',
        nodes: 0,
        nodes_ready: 0,
        cpu_milli: 0,
        mem_bytes: 0,
        provider: '',
        provider_label: '',
        region: '',
        zones: [],
        instance_types: [],
        agent_version: '',
        inventory_at: null,
        created_at: new Date().toISOString(),
        eol: false,
        version_skew: false,
      };
      db.clusters.push(c);
      db.enrolling.set(c.id, Date.now());
      db.record('cluster.created', 'cluster', name, 'install command issued');
      return ok(
        {
          cluster: c,
          command: `helm install olympos-agent oci://olympos.contoso.internal/charts/olympos-agent \\\n  --namespace olympos-system --create-namespace \\\n  --set server=olympos-gw.contoso.internal:8443 \\\n  --set clusterName=${name} \\\n  --set bootstrapToken=obt_6Qv${Math.random().toString(36).slice(2, 10)}h2Kx${c.bench_enabled ? ' \\\n  --set bench.enabled=true' : ''}`,
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
        },
        201,
      );
    },
  ],
  [
    'GET',
    '/clusters/:id',
    (_r, p) => {
      const c = liveClusters().find((x) => x.id === p.id);
      return c ? ok(c) : notFound();
    },
  ],
  [
    'PATCH',
    '/clusters/:id',
    (r, p) => {
      if (!perms().admin_global) return forbidden();
      const c = db.clusters.find((x) => x.id === p.id);
      if (!c) return notFound();
      const b = r.body ?? {};
      if (b.labels) c.labels = { ...b.labels, 'olympos.io/cluster': c.name };
      if (b.provider_override !== undefined) {
        c.provider_override = b.provider_override;
        if (b.provider_override) {
          c.provider = b.provider_override;
          c.provider_label = { azure: 'Azure', aws: 'AWS', gcp: 'GCP', oracle: 'Oracle Cloud', huawei: 'Huawei Cloud', onprem: 'On-prem' }[b.provider_override as string] ?? b.provider_override;
        }
      }
      if (b.transfer_mode) {
        c.transfer_mode = b.transfer_mode;
        const has = db.findings.find((f) => f.control_id === 'transfer.compressed_mode' && f.cluster_id === c.id);
        if (b.transfer_mode === 'compressed' && !has)
          db.findings.push({ ...db.findings[3], id: db.uuid(), cluster_id: c.id, cluster_name: c.name, resource_ref: `cluster/${c.name}`, first_seen_at: new Date().toISOString() });
        if (b.transfer_mode === 'e2e-tls' && has) has.status = 'resolved';
      }
      if (b.clear_egress_rate) c.egress_rate_per_gb = null;
      else if (typeof b.egress_rate_per_gb === 'number') c.egress_rate_per_gb = b.egress_rate_per_gb;
      db.record('cluster.updated', 'cluster', c.name, 'settings saved');
      return ok(c);
    },
  ],
  [
    'DELETE',
    '/clusters/:id',
    (_r, p) => {
      if (!perms().admin_global) return forbidden();
      const c = db.clusters.find((x) => x.id === p.id);
      if (!c) return notFound();
      c.status = 'revoked';
      db.record('cluster.revoked', 'cluster', c.name, 'certificate denied, streams dropped');
      return { status: 204 };
    },
  ],
  [
    'POST',
    '/clusters/:id/token',
    (_r, p) => {
      const c = db.clusters.find((x) => x.id === p.id);
      if (!c) return notFound();
      db.enrolling.set(c.id, Date.now());
      return ok({
        cluster: c,
        command: `helm upgrade --install olympos-agent oci://olympos.contoso.internal/charts/olympos-agent \\\n  --namespace olympos-system --create-namespace \\\n  --set server=olympos-gw.contoso.internal:8443 \\\n  --set clusterName=${c.name} \\\n  --set bootstrapToken=obt_${Math.random().toString(36).slice(2, 12)}`,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      });
    },
  ],
  ['GET', '/clusters/:id/nodes', () => items([])],
  [
    'GET',
    '/targets',
    (r) => {
      const st = r.query.get('status');
      const en = r.query.get('engine');
      const tls = r.query.get('tls_pending') === '1';
      return items(db.targets.filter((t) => (!st || t.status === st) && (!en || t.engine === en) && (!tls || t.tls_server_name_pending != null) && t.engine !== ''));
    },
  ],
  [
    'POST',
    '/targets/:id/accept-tls-name',
    (r, p) => {
      const t = db.targets.find((x) => x.id === p.id);
      if (!t) return notFound();
      const b = r.body as { name?: string };
      if (t.tls_server_name_pending == null || t.tls_server_name_pending !== b.name) return { status: 409, body: { error: 'the TLS name changed again; reload and review it' } };
      t.tls_server_name = t.tls_server_name_pending;
      t.tls_server_name_pending = null;
      t.tls_server_name_changed_at = null;
      return { status: 204 };
    },
  ],

  // -------------------------------------------------------- access
  ['GET', '/grants', () => items(db.grants)],
  [
    'POST',
    '/grants',
    (r) => {
      if (!perms().admin_global) return forbidden();
      const u = db.directory.find((d) => d.object_id === r.body?.object_id);
      if (!u) return invalid('invalid grant', { object_id: 'Pick a person from the directory search.' });
      const roles = (r.body.roles ?? []) as Role[];
      if (!roles.length) return invalid('invalid grant', { roles: 'Select at least one role.' });
      if (u.is_guest && roles.some((x) => x === 'vault-approver' || x === 'admin')) return invalid('invalid grant', { roles: 'vault-approver and admin cannot be granted to guest accounts' });
      const p = { id: db.uuid(), tenant_id: db.people.yigit.tenant_id, object_id: u.object_id, upn: u.upn, display_name: u.display_name, user_type: u.user_type, account_enabled: true };
      const ids: string[] = [];
      for (const role of roles) {
        const g: Grant = {
          id: db.uuid(),
          principal: p,
          is_guest: u.is_guest,
          role,
          scope: r.body.scope || 'all',
          granted_by: db.people.yigit.id,
          granted_by_name: 'yigit@contoso.com',
          granted_at: new Date().toISOString(),
          stale: false,
        };
        db.grants.push(g);
        ids.push(g.id);
      }
      db.record('grant.created', 'grant', u.upn, `+ ${roles.join(', ')} · scope ${r.body.scope || 'all'}`);
      return ok({ ids }, 201);
    },
  ],
  [
    'DELETE',
    '/grants/:id',
    (_r, p) => {
      const i = db.grants.findIndex((g) => g.id === p.id);
      if (i < 0) return notFound();
      const g = db.grants[i];
      if (g.role === 'admin' && db.grants.filter((x) => x.role === 'admin' && x.scope === 'all' && !x.stale).length <= 1)
        return { status: 409, body: { error: 'this is the last admin grant with scope all; grant admin to someone else first' } };
      db.grants.splice(i, 1);
      db.record('grant.revoked', 'grant', g.principal.upn, `− ${g.role}`);
      return { status: 204 };
    },
  ],
  [
    'GET',
    '/principals/search',
    async (r) => {
      await sleep(250);
      const q = (r.query.get('q') ?? '').toLowerCase();
      if (q.length < 2) return items([]);
      return items(db.directory.filter((d) => d.display_name.toLowerCase().includes(q) || d.upn.toLowerCase().includes(q)));
    },
  ],
  [
    'GET',
    '/activity',
    (r) => {
      const before = r.query.get('before');
      const action = r.query.get('action');
      const q = (r.query.get('q') ?? '').toLowerCase();
      const objectType = r.query.get('object_type');
      const limit = Number(r.query.get('limit') ?? 100);
      const list = db.activity.filter(
        (e) =>
          (!before || e.at < before) &&
          (!action || action.split(',').some((a) => e.action.startsWith(a))) &&
          (!objectType || e.object_type === objectType) &&
          (!q || `${e.actor_name} ${e.action} ${e.object_id} ${JSON.stringify(e.details)}`.toLowerCase().includes(q)),
      );
      return items(list.slice(0, limit));
    },
  ],

  // -------------------------------------------------------- notifications
  ['GET', '/notifications/channels', () => items(db.channels)],
  [
    'POST',
    '/notifications/channels',
    (r) => {
      const name = String(r.body?.name ?? '').trim();
      const sid = String(r.body?.slack_channel_id ?? '').trim();
      const fields: Record<string, string> = {};
      if (!name.startsWith('#')) fields.name = 'Use the Slack channel name, starting with #.';
      if (!/^[CG][A-Z0-9]{6,}$/.test(sid)) fields.slack_channel_id = 'Slack channel IDs look like C0123ABCD (channel details › About).';
      if (Object.keys(fields).length) return invalid('invalid channel', fields);
      const c = { id: db.uuid(), kind: 'slack' as const, name, slack_channel_id: sid, routes: [], created_at: new Date().toISOString() };
      db.channels.push(c);
      return ok(c, 201);
    },
  ],
  [
    'DELETE',
    '/notifications/channels/:id',
    (_r, p) => {
      const i = db.channels.findIndex((c) => c.id === p.id);
      if (i >= 0) db.channels.splice(i, 1);
      return { status: 204 };
    },
  ],
  ['POST', '/notifications/channels/:id/test', async () => (await sleep(600), ok({ ok: true }))],
  [
    'GET',
    '/notifications/routes',
    () => ok({ catalog: db.catalog, routes: db.catalog.map((e) => ({ event_type: e.event_type, channel_ids: db.channels.filter((c) => c.routes.includes(e.event_type)).map((c) => c.id) })) }),
  ],
  [
    'PUT',
    '/notifications/routes',
    (r) => {
      for (const c of db.channels) c.routes = [];
      for (const rt of r.body?.routes ?? []) for (const id of rt.channel_ids) db.channels.find((c) => c.id === id)?.routes.push(rt.event_type);
      db.record('notifications.routes_updated', 'notification_routes', '', 'routing saved');
      return ok({ catalog: db.catalog, routes: r.body.routes });
    },
  ],

  // -------------------------------------------------------- destinations
  ['GET', '/destinations', () => items(db.destinations)],
  ['GET', '/destinations/mounts', () => items(localStorage.getItem('olympos.mock.noMounts') === '1' ? [] : db.destinationMounts)],
  [
    'POST',
    '/destinations/test',
    async (r) => {
      await sleep(900);
      return ok(destTest(r.body));
    },
  ],
  [
    'POST',
    '/destinations/:id/test',
    async (_r, p) => {
      await sleep(900);
      const d = db.destinations.find((x) => x.id === p.id);
      if (!d) return notFound();
      const t = destTest({
        ...d,
        sas:
          d.auth === 'sas_token'
            ? d.sas_source === 'keyvault_ref'
              ? { source: 'keyvault_ref', ref: d.sas_ref }
              : { source: 'stored', value: `sv=2025-01-05&sr=c&sp=${d.sas_permissions}&se=${d.sas_expires_at}&sig=x` }
            : undefined,
        secret_key: d.kind === 's3' ? { source: d.secret_key_source === 'stored' ? 'stored' : 'keyvault_ref', ref: d.secret_key_ref, value: d.secret_key_source === 'stored' ? 'stored-secret' : undefined } : undefined,
      });
      d.last_test = t;
      d.last_test_at = new Date().toISOString();
      d.last_test_ok = t.ok;
      return ok(t);
    },
  ],
  [
    'POST',
    '/destinations',
    async (r) => {
      if (!perms().admin_global) return forbidden();
      const b: DestinationInput = { kind: 'azure_blob', ...r.body };
      const v = validateDest(b);
      if (v) return v;
      if (db.destinations.some((x) => x.name === b.name)) return { status: 409, body: { error: `a destination named ${b.name} already exists` } };
      await sleep(700);
      const t = destTest(b);
      if (!t.ok) return { status: 422, body: { error: `destination test failed: ${t.error}`, fields: {}, test: t } };
      const d = { id: db.uuid(), jobs: 0, created_at: new Date().toISOString(), ...storeDest(b, emptyDest(b.kind!)), last_test_at: new Date().toISOString(), last_test_ok: true, last_test: t } as Destination;
      db.destinations.push(d);
      db.record('destination.created', 'destination', d.name, t.can_delete ? 'saved with warning: credential can delete' : 'test passed');
      return ok({ ...d, warnings: destWarnings(d, t) }, 201);
    },
  ],
  [
    'PATCH',
    '/destinations/:id',
    async (r, p) => {
      if (!perms().admin_global) return forbidden();
      const d = db.destinations.find((x) => x.id === p.id);
      if (!d) return notFound();
      if (r.body.kind && r.body.kind !== d.kind) return invalid('invalid destination', { kind: 'The kind of a destination cannot change.' });
      // Partial: absent fields keep their value; an absent secret keeps the stored one.
      const merged: DestinationInput = {
        ...d,
        ...r.body,
        kind: d.kind,
        sas:
          r.body.sas ??
          (d.auth === 'sas_token'
            ? d.sas_source === 'keyvault_ref'
              ? { source: 'keyvault_ref', ref: d.sas_ref }
              : { source: 'stored', value: `sv=2025-01-05&sr=c&sp=${d.sas_permissions}&se=${d.sas_expires_at}&sig=x` }
            : undefined),
        secret_key:
          r.body.secret_key ??
          (d.kind === 's3' ? { source: d.secret_key_source === 'stored' ? 'stored' : 'keyvault_ref', ref: d.secret_key_ref, value: d.secret_key_source === 'stored' ? 'stored-secret' : undefined } : undefined),
      };
      const v = validateDest(merged);
      if (v) return v;
      await sleep(700);
      const t = destTest(merged);
      if (!t.ok) return { status: 422, body: { error: `destination test failed: ${t.error}`, fields: {}, test: t } };
      Object.assign(d, storeDest(merged, d), { last_test: t, last_test_at: new Date().toISOString(), last_test_ok: true });
      db.record('destination.updated', 'destination', d.name, 'saved');
      return ok({ ...d, warnings: destWarnings(d, t) });
    },
  ],
  [
    'DELETE',
    '/destinations/:id',
    (_r, p) => {
      const d = db.destinations.find((x) => x.id === p.id);
      if (d && d.jobs > 0) return { status: 409, body: { error: `used by ${d.jobs} backup jobs; move them to another destination first` } };
      if (d && d.groups) return { status: 409, body: { error: `member of ${d.groups} destination group${d.groups === 1 ? '' : 's'}; remove it from the group first` } };
      if (d) db.destinations.splice(db.destinations.indexOf(d), 1);
      return { status: 204 };
    },
  ],

  // -------------------------------------------------------- destination groups
  ['GET', '/destination-groups', () => items(db.destinationGroups)],
  [
    'GET',
    '/destination-groups/:id',
    (_r, p) => {
      const g = db.destinationGroups.find((x) => x.id === p.id);
      return g ? ok(g) : notFound();
    },
  ],
  [
    'POST',
    '/destination-groups',
    (r) => {
      if (!perms().admin_global) return forbidden();
      const b = (r.body ?? {}) as DestinationGroupInput;
      const v = validateGroup(b);
      if (v) return v;
      const now = new Date().toISOString();
      const g: DestinationGroup = {
        id: db.uuid(),
        name: b.name!.trim(),
        description: (b.description ?? '').trim(),
        members: b.member_ids!.map((id) => db.destinations.find((d) => d.id === id)!).map((d) => ({ id: d.id, name: d.name, kind: d.kind })),
        jobs: 0,
        created_at: now,
        updated_at: now,
      };
      db.destinationGroups.push(g);
      syncGroupCounts();
      db.record('destination_group.created', 'destination_group', g.name, g.members.map((m) => m.name).join(' → '));
      return ok(g, 201);
    },
  ],
  [
    'PATCH',
    '/destination-groups/:id',
    (r, p) => {
      if (!perms().admin_global) return forbidden();
      const g = db.destinationGroups.find((x) => x.id === p.id);
      if (!g) return notFound();
      const b = (r.body ?? {}) as DestinationGroupInput;
      const v = validateGroup(b, g);
      if (v) return v;
      if (b.name !== undefined) g.name = b.name.trim();
      if (b.description !== undefined) g.description = b.description.trim();
      if (b.member_ids) g.members = b.member_ids.map((id) => db.destinations.find((d) => d.id === id)!).map((d) => ({ id: d.id, name: d.name, kind: d.kind }));
      g.updated_at = new Date().toISOString();
      for (const j of db.jobs) if (j.destination_group?.id === g.id) j.destination_group = { id: g.id, name: g.name, members: g.members.map((m) => m.name) };
      syncGroupCounts();
      db.record('destination_group.updated', 'destination_group', g.name, g.members.map((m) => m.name).join(' → '));
      return ok(g);
    },
  ],
  [
    'DELETE',
    '/destination-groups/:id',
    (_r, p) => {
      if (!perms().admin_global) return forbidden();
      const g = db.destinationGroups.find((x) => x.id === p.id);
      if (g && g.jobs > 0) return { status: 409, body: { error: `used by ${g.jobs} backup job${g.jobs === 1 ? '' : 's'}; move ${g.jobs === 1 ? 'it' : 'them'} to another destination or group first` } };
      if (g) {
        db.destinationGroups.splice(db.destinationGroups.indexOf(g), 1);
        syncGroupCounts();
        db.record('destination_group.deleted', 'destination_group', g.name, '');
      }
      return { status: 204 };
    },
  ],

  // -------------------------------------------------------- backups
  ['GET', '/backup/jobs', () => items(db.jobs)],
  [
    'GET',
    '/backup/jobs/:id',
    (_r, p) => {
      const j = db.jobs.find((x) => x.id === p.id);
      return j ? ok(j) : notFound();
    },
  ],
  [
    'POST',
    '/backup/jobs',
    (r) => {
      if (!perms().operate) return forbidden();
      const b = r.body as BackupJobInput;
      const t = db.targets.find((x) => x.id === b.target_id);
      if (!t) return invalid('invalid job', { target_id: 'Target not found.' });
      if (t.engine === 'vault') {
        const v = db.vaults.find((x) => x.target.id === t.id);
        if (!v || v.status !== 'configured') return invalid('vault not configured', { target_id: 'Configure this vault in Olympos first (Vaults > Configure): backups use its Olympos AppRole.' });
      } else if (!b.credential?.username) return invalid('invalid job', { username: 'Username is required.' });
      if (!!b.destination_id === !!b.destination_group_id) return invalid('invalid job', { destination_id: 'Pick a destination or a destination group (exactly one).' });
      const dest = db.destinations.find((d) => d.id === b.destination_id);
      const group = db.destinationGroups.find((g) => g.id === b.destination_group_id);
      if (b.destination_id && !dest) return invalid('invalid job', { destination_id: 'Pick a destination.' });
      if (b.destination_group_id && !group) return invalid('invalid job', { destination_group_id: 'Unknown destination group.' });
      if (group) group.jobs++;
      const job: BackupJob = {
        id: db.uuid(),
        target: t,
        engine: t.engine,
        credential: b.credential ? { id: db.uuid(), source: b.credential.source, ref: b.credential.ref ?? '', username: b.credential.username } : { id: '', source: 'approle', ref: '', username: 'approle' },
        destination: dest ? { id: dest.id, name: dest.name } : null,
        destination_group: group ? { id: group.id, name: group.name, members: group.members.map((m) => m.name) } : null,
        engine_options: b.engine_options ?? {},
        cron: b.cron ?? '0 2 * * *',
        timezone: b.timezone ?? 'UTC',
        retention: b.retention ?? { daily: 7, weekly: 4, monthly: 12 },
        enabled: !!b.enabled,
        paused_reason: '',
        notify_channel_id: b.notify_channel_id ?? null,
        notify_on_success: !!b.notify_on_success,
        next_run_at: null,
        last_run: null,
        estimated_monthly_bytes: 3.1e9 * runsPerMonth(b.cron ?? '0 2 * * *'),
        estimated_monthly_cost: null,
        created_at: new Date().toISOString(),
      };
      db.jobs.push(job);
      t.status = 'configured';
      db.record('backup.job_created', 'backup_job', t.service, 'created disabled');
      return ok(job, 201);
    },
  ],
  [
    'PATCH',
    '/backup/jobs/:id',
    (r, p) => {
      const j = db.jobs.find((x) => x.id === p.id);
      if (!j) return notFound();
      const b = r.body as BackupJobInput;
      if (b.enabled !== undefined) {
        j.enabled = b.enabled;
        j.next_run_at = b.enabled ? (nextRuns(j.cron, 1, new Date(), j.timezone)[0] ?? null) : null;
      }
      if (b.cron) j.cron = b.cron;
      if (b.timezone) j.timezone = b.timezone;
      if (b.retention) j.retention = b.retention;
      if (b.destination_id && b.destination_group_id) return invalid('invalid job', { destination_id: 'Pick a destination or a destination group (exactly one).' });
      if (b.destination_id) {
        const d = db.destinations.find((x) => x.id === b.destination_id);
        if (!d) return invalid('invalid job', { destination_id: 'Pick a destination.' });
        const old = groupOf(j);
        if (old) old.jobs--;
        j.destination = { id: d.id, name: d.name };
        j.destination_group = null;
      }
      if (b.destination_group_id) {
        const g = db.destinationGroups.find((x) => x.id === b.destination_group_id);
        if (!g) return invalid('invalid job', { destination_group_id: 'Unknown destination group.' });
        const old = groupOf(j);
        if (old !== g) {
          if (old) old.jobs--;
          g.jobs++;
        }
        j.destination = null;
        j.destination_group = { id: g.id, name: g.name, members: g.members.map((m) => m.name) };
      }
      if (b.notify_channel_id !== undefined) j.notify_channel_id = b.notify_channel_id;
      if (b.notify_on_success !== undefined) j.notify_on_success = b.notify_on_success;
      if (b.engine_options) j.engine_options = b.engine_options;
      if (b.credential) j.credential = { ...j.credential, source: b.credential.source, ref: b.credential.ref ?? '', username: b.credential.username };
      db.record(b.enabled ? 'backup.job_enabled' : 'backup.job_updated', 'backup_job', j.target.service, '');
      return ok(j);
    },
  ],
  [
    'POST',
    '/backup/jobs/:id/run',
    (r, p) => {
      const j = db.jobs.find((x) => x.id === p.id);
      if (!j) return notFound();
      const trigger = r.body?.trigger === 'test' ? 'test' : 'manual';
      const run: BackupRun = {
        id: db.uuid(),
        job_id: j.id,
        target_service: j.target.service,
        cluster_name: j.target.cluster_name,
        engine: j.engine,
        trigger,
        status: 'queued',
        scheduled_for: null,
        tier: trigger === 'test' ? '' : 'daily',
        started_at: new Date().toISOString(),
        finished_at: null,
        bytes: 0,
        wire_bytes: 0,
        blob_path: '',
        sha256: '',
        error: '',
        destination_name: j.destination_group?.name ?? j.destination?.name,
        steps: [],
      };
      db.runs.unshift(run);
      return ok(run, 202);
    },
  ],
  ['GET', '/audit/settings', () => ok(db.auditSettings)],
  [
    'PUT',
    '/audit/settings',
    (r) => {
      const id = r.body?.raw_destination_id ?? null;
      if (id === null) {
        db.auditSettings.raw_destination = null;
        return ok(db.auditSettings);
      }
      const d = db.destinations.find((x) => x.id === id);
      if (!d) return invalid('unknown destination', { raw_destination_id: 'no destination with this id' });
      db.auditSettings.raw_destination = { id: d.id, name: d.name, kind: d.kind };
      return ok(db.auditSettings);
    },
  ],
  [
    'GET',
    '/backup/self',
    (r) => {
      const copy = r.query.get('copy');
      const last = selfBackup.runs.find((x) => !x.repair_of && (x.status === 'succeeded' || x.status === 'partial'));
      if (!copy || !last) return ok(selfBackup);
      const g = runRestore(last, 'docs/restore-olympos.md', copy);
      if (g && 'status' in g) return g;
      return ok({ ...selfBackup, restore: g });
    },
  ],
  [
    'PUT',
    '/backup/self',
    (r) => {
      if (r.body?.destination_id && r.body?.destination_group_id) return invalid('invalid self-backup', { destination_id: 'Choose a destination or a destination group, not both.' });
      const groupId = r.body?.destination_group_id ?? (r.body?.destination_id ? null : selfBackup.job?.destination_group_id);
      const g = groupId ? db.destinationGroups.find((x) => x.id === groupId) : undefined;
      if (groupId && !g) return invalid('invalid self-backup', { destination_group_id: 'Unknown destination group.' });
      const d = g ? undefined : db.destinations.find((x) => x.id === (r.body?.destination_id ?? selfBackup.job?.destination_id));
      if (!g && !d) return invalid('invalid self-backup', { destination_id: 'Choose where the Olympos database is backed up.' });
      selfBackup.configured = true;
      selfBackup.job = {
        id: selfBackup.job?.id ?? db.uuid(),
        destination_id: d?.id ?? null,
        destination_group_id: g?.id ?? null,
        destination_name: (g ?? d)!.name,
        cron: r.body?.cron ?? selfBackup.job?.cron ?? '30 2 * * *',
        timezone: r.body?.timezone ?? selfBackup.job?.timezone ?? 'UTC',
        retention: r.body?.retention ?? selfBackup.job?.retention ?? { daily: 7, weekly: 4, monthly: 12 },
        enabled: r.body?.enabled ?? true,
        notify_channel_id: null,
        created_at: selfBackup.job?.created_at ?? new Date().toISOString(),
      };
      return ok(selfBackup);
    },
  ],
  [
    'POST',
    '/backup/self/run',
    () => {
      if (!selfBackup.job) return { status: 409, body: { error: 'choose a destination for the Olympos self-backup first' } };
      const now = new Date().toISOString();
      const g = selfBackup.job.destination_group_id ? db.destinationGroups.find((x) => x.id === selfBackup.job!.destination_group_id) : undefined;
      selfBackup.runs.unshift({
        id: db.uuid(),
        job_id: selfBackup.job.id,
        target_service: 'olympos-db',
        cluster_name: 'olympos',
        engine: 'postgresql',
        trigger: 'manual',
        status: 'succeeded',
        scheduled_for: null,
        tier: 'daily',
        started_at: now,
        finished_at: now,
        bytes: 4_812_331,
        wire_bytes: 4_812_331,
        blob_path: 'olympos/olympos/olympos/olympos-db/postgresql/x.zip',
        sha256: '',
        error: '',
        destination_name: selfBackup.job.destination_name,
        copies: g ? db.groupCopies(g, 4_812_331) : undefined,
        repair_of: null,
      });
      const guide = runRestore(selfBackup.runs[0], 'docs/restore-olympos.md', null);
      selfBackup.restore = guide && !('status' in guide) ? guide : null;
      return ok({ run_id: selfBackup.runs[0].id }, 202);
    },
  ],
  [
    'GET',
    '/backup/runs',
    (r) => {
      const job = r.query.get('job_id');
      const st = r.query.get('status');
      return items(
        db.runs
          .filter((x) => (!job || x.job_id === job) && (!st || x.status === st))
          .map((x) => runFor(x.id)!)
          .slice(0, Number(r.query.get('limit') ?? 50)),
      );
    },
  ],
  [
    'GET',
    '/backup/runs/:id',
    (r, p) => {
      const x = runFor(p.id);
      if (!x) return notFound();
      const restorable = (x.status === 'succeeded' || x.status === 'partial') && x.trigger !== 'test';
      const restore = restorable ? runRestore(x, 'docs/restore.md#postgresql', r.query.get('copy')) : null;
      if (restore && 'status' in restore) return restore;
      // a partial run with a repair queued: when it starts
      const waiting = x.status === 'partial' ? db.runs.filter((y) => y.repair_of === x.id && y.status === 'queued' && y.not_before).map((y) => y.not_before!) : [];
      return ok({ ...x, restore, next_repair_at: waiting.sort()[0] ?? null });
    },
  ],
  [
    'POST',
    '/backup/test-connection',
    async (r) => {
      await sleep(1100);
      const c = r.body?.credential ?? {};
      if (!c.username) return invalid('invalid credential', { username: 'Username is required.' });
      if (c.source === 'keyvault_ref' && !/^kv:\/\/[^/]+\/[^/]+$/.test(c.ref ?? '')) return invalid('invalid credential', { ref: 'Use kv://<vault>/<secret>.' });
      if (c.source === 'stored' && !c.password) return invalid('invalid credential', { password: 'Enter the password.' });
      const t = db.targets.find((x) => x.id === r.body?.target_id);
      if (c.username === 'nobody') return ok({ ok: false, server_version: '', tls: !!t?.tls_ok, privileges: [], databases: [], error: 'password authentication failed for user "nobody"' });
      return ok({
        ok: true,
        server_version: t?.detected_version ?? '16.4',
        tls: !!t?.tls_ok,
        privileges: [
          { name: 'connect', ok: true, detail: 'SELECT 1 ok in 84 ms' },
          { name: 'pg_read_all_data', ok: true, detail: 'role has pg_read_all_data' },
          { name: 'globals', ok: true, detail: 'can read pg_roles for pg_dumpall --globals-only' },
        ],
        databases: ['orders', 'orders_archive', 'postgres'],
        error: '',
      });
    },
  ],
  [
    'GET',
    '/backup/schedule-preview',
    (r) => {
      const cron = r.query.get('cron') ?? '';
      try {
        return ok({ next: nextRuns(cron, Number(r.query.get('count') ?? 5), new Date(), r.query.get('timezone') ?? 'UTC'), description: describeCron(cron) });
      } catch (e) {
        return invalid('invalid cron', { cron: (e as Error).message });
      }
    },
  ],

  // -------------------------------------------------------- vaults
  ['GET', '/vaults', () => items(db.vaults)],
  [
    'GET',
    '/vaults/search',
    async (r) => {
      await sleep(150);
      const q = (r.query.get('q') ?? '').trim().toLowerCase();
      if (q.length < 2) return invalid('invalid query', { q: 'Type at least 2 characters.' });
      const hits: unknown[] = [];
      const base = (v: Vault) => ({ vault_id: v.id, vault_name: v.target.service, provider: v.provider, cluster_id: v.target.cluster_id, cluster_name: v.target.cluster_name, namespace: v.target.namespace });
      for (const v of db.vaults) {
        const labels = Object.entries(v.cluster_labels ?? {})
          .map(([k, x]) => `${k}=${x}`)
          .join(' ');
        const hay = `${v.target.service} ${v.target.cluster_name} ${v.target.namespace} ${v.provider === 'openbao' ? 'openbao' : 'hashicorp vault'} ${labels}`.toLowerCase();
        if (hay.includes(q)) hits.push({ match: 'vault', ...base(v) });
      }
      for (const v of db.vaults) {
        for (const sm of db.summaries(v.id)) {
          if (`${sm.mount}${sm.path}`.toLowerCase().includes(q)) hits.push({ match: 'path', ...base(v), mount: sm.mount, path: sm.path, keys: sm.keys });
        }
      }
      return items(hits.slice(0, 50));
    },
  ],
  [
    'GET',
    '/vaults/:id',
    (_r, p) => {
      const v = db.vaults.find((x) => x.id === p.id);
      return v ? ok(v) : notFound();
    },
  ],
  [
    'POST',
    '/vaults/:id/inspect',
    async (r, p) => {
      await sleep(800);
      const tok = String(r.body?.root_token ?? '');
      const vi = db.vaults.find((x) => x.id === p.id);
      if (vi && vi.target.tls_ok === false) {
        const c = db.clusters.find((x) => x.id === vi.target.cluster_id);
        return {
          status: 502,
          body: {
            error: `could not reach ${vi.provider === 'openbao' ? 'OpenBao' : 'Vault'} at ${vi.target.service}.${vi.target.namespace}.svc:${vi.target.port}: the listener answered plain HTTP to an HTTPS request.\nTLS is required for vaults: the root token and secret values would otherwise cross the agent in clear.\nTo fix it, either:\n  - enable TLS on the listener (listener "tcp" { tls_cert_file / tls_key_file }) and set olympos.io/tls-server-name on the Service, or\n  - switch the transfer mode of cluster ${c?.name ?? vi.target.cluster_name} to compressed (Settings > Clusters).`,
          },
        };
      }
      if (!/^(hvs\.|s\.)/.test(tok) || tok.length < 10) return invalid('token rejected', { root_token: 'Vault rejected this token (permission denied). Paste a root token or one with sys and auth admin rights.' });
      return ok({
        version: '1.17.6',
        sealed: false,
        mounts: [
          { path: 'kv/', version: 2, managed: false, description: 'apps' },
          { path: 'apps/', version: 2, managed: false, description: '' },
          { path: 'legacy/', version: 1, managed: false, description: 'old integrations' },
        ],
      });
    },
  ],
  [
    'POST',
    '/vaults/:id/configure',
    async (r, p) => {
      await sleep(1200);
      if (!perms().admin) return forbidden();
      const v = db.vaults.find((x) => x.id === p.id);
      if (!v) return notFound();
      if (!r.body?.mounts?.length) return invalid('invalid configure', { mounts: 'Select at least one KV v2 mount.' });
      Object.assign(v, {
        status: 'configured',
        configured_at: new Date().toISOString(),
        configured_by_name: 'yigit@contoso.com',
        last_index_at: new Date().toISOString(),
        kv_mounts: [...(r.body.mounts as string[]).map((m) => ({ path: m, version: 2, managed: true, description: '' })), { path: 'legacy/', version: 1, managed: false, description: '' }],
      });
      db.secrets[v.id] = [];
      db.record('vault.configured', 'vault', v.target.service, `AppRole olympos created · mounts ${(r.body.mounts as string[]).join(', ')}`);
      return ok(v);
    },
  ],
  ['POST', '/vaults/:id/refresh', () => ({ status: 202 })],
  [
    'GET',
    '/vaults/:id/tree',
    (r, p) => {
      const m = r.query.get('mount');
      return items(db.summaries(p.id).filter((s) => !m || s.mount === m));
    },
  ],
  [
    'GET',
    '/vaults/:id/secrets/*',
    (r, p) => {
      const s = (db.secrets[p.id] ?? []).find((x) => x.path === p['*'] && x.mount === r.query.get('mount'));
      return s ? ok(s) : notFound();
    },
  ],
  [
    'GET',
    '/change-requests',
    (r) => {
      const meOid = db.people.yigit.object_id;
      const status = r.query.get('status');
      let list = db.changeRequests;
      if (r.query.get('mine') === 'true') list = list.filter((c) => c.maker.object_id === meOid);
      if (r.query.get('waiting_for_me') === 'true') list = perms().vault_approve ? list.filter((c) => c.maker.object_id !== meOid && c.status === 'pending') : [];
      if (status) list = list.filter((c) => c.status === status);
      const vid = r.query.get('vault_id');
      if (vid) list = list.filter((c) => c.vault.id === vid);
      return items(list.map(withPerms));
    },
  ],
  [
    'GET',
    '/change-requests/:id',
    (_r, p) => {
      const c = db.changeRequests.find((x) => x.id === p.id);
      return c ? ok(withPerms(c)) : notFound();
    },
  ],
  [
    'POST',
    '/change-requests',
    (r) => {
      if (!perms().vault_make) return forbidden();
      const b = r.body as ChangeRequestInput;
      if (!b.justification || b.justification.trim().length < 10) return invalid('invalid change request', { justification: 'Explain why in at least 10 characters (ticket numbers help the approver).' });
      const v = db.vaults.find((x) => x.id === b.vault_id);
      if (!v) return notFound();
      const c = {
        id: db.uuid(),
        number: db.nextCrNumber(),
        vault: { id: v.id, name: `${v.target.namespace}/${v.target.service}`, cluster_name: v.target.cluster_name, provider: v.provider, version: v.version },
        maker: db.people.yigit,
        checker: null,
        justification: b.justification,
        status: 'pending' as const,
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 72 * 3600_000).toISOString(),
        decided_at: null,
        decision_comment: '',
        applied_at: null,
        failure: '',
        can_approve: false,
        approve_disabled_reason: 'You opened this request. Another approver must decide.',
        can_cancel: true,
        // Values are reduced to a fingerprint immediately and never stored by the mock.
        items: b.items.map((it) => ({
          id: db.uuid(),
          mount: it.mount,
          path: it.path,
          key: it.key ?? null,
          op: it.op,
          base_version: it.base_version ?? 0,
          versions: it.versions ?? [],
          fingerprint: it.value ? fingerprint(it.value) : '',
        })),
        events: [{ at: new Date().toISOString(), kind: 'opened', actor_name: 'yigit@contoso.com', details: {} }],
        eligible_approvers: 2,
      };
      db.changeRequests.unshift(c);
      const sd = (db.secrets[v.id] ?? []).find((s) => s.path === b.items[0]?.path);
      for (const it of b.items) {
        const ki = sd?.key_info?.find((k) => k.key === it.key);
        if (ki) {
          ki.pending_cr_id = c.id;
          ki.pending_cr_label = c.number;
        }
      }
      if (sd) sd.pending_change_requests++;
      db.record('cr.opened', 'change_request', c.number, b.items.map((i) => `${i.op} ${i.key ?? i.path}`).join(', '));
      return ok(c, 201);
    },
  ],
  ['POST', '/change-requests/:id/approve', (r, p) => decide(p.id, 'approve', r.body?.comment ?? '')],
  ['POST', '/change-requests/:id/reject', (r, p) => decide(p.id, 'reject', r.body?.comment ?? '')],
  [
    'POST',
    '/change-requests/:id/cancel',
    (_r, p) => {
      const c = db.changeRequests.find((x) => x.id === p.id);
      if (!c) return notFound();
      c.status = 'cancelled';
      c.events.push({ at: new Date().toISOString(), kind: 'cancelled', actor_name: 'yigit@contoso.com', details: {} });
      return ok(withPerms(c));
    },
  ],

  // -------------------------------------------------------- audit
  ['GET', '/audit/schedules', () => items(db.auditSchedules)],
  [
    'POST',
    '/audit/schedules',
    (r) => {
      if (!perms().operate) return forbidden();
      const s = {
        id: db.uuid(),
        tool: r.body.tool,
        frameworks: r.body.frameworks ?? [],
        scope_selector: r.body.scope_selector || 'all',
        cron: r.body.cron,
        timezone: r.body.timezone ?? 'UTC',
        enabled: r.body.enabled ?? true,
        notify_channel_id: r.body.notify_channel_id ?? null,
        next_run_at: nextRuns(r.body.cron, 1)[0] ?? null,
        clusters: 7,
        last_run: null,
      };
      db.auditSchedules.push(s);
      return ok(s, 201);
    },
  ],
  [
    'PATCH',
    '/audit/schedules/:id',
    (r, p) => {
      const s = db.auditSchedules.find((x) => x.id === p.id);
      if (!s) return notFound();
      Object.assign(s, r.body);
      return ok(s);
    },
  ],
  [
    'DELETE',
    '/audit/schedules/:id',
    (_r, p) => {
      if (!perms().operate) return forbidden();
      const i = db.auditSchedules.findIndex((x) => x.id === p.id);
      if (i < 0) return notFound();
      db.auditSchedules.splice(i, 1);
      return { status: 204 };
    },
  ],
  [
    'POST',
    '/audit/schedules/:id/run',
    (_r, p) => {
      const s = db.auditSchedules.find((x) => x.id === p.id);
      if (!s) return notFound();
      const run = {
        id: db.uuid(),
        schedule_id: s.id,
        tool: s.tool,
        cluster_id: '',
        cluster_name: 'all clusters',
        status: 'queued' as const,
        started_at: null,
        finished_at: null,
        score: null,
        new_findings: 0,
        resolved_findings: 0,
        error: '',
      };
      db.auditRuns.unshift(run);
      return ok({ items: [run] }, 202);
    },
  ],
  [
    'GET',
    '/audit/runs/:id',
    (_r, p) => {
      const x = db.auditRuns.find((y) => y.id === p.id);
      return x ? ok(x) : notFound();
    },
  ],
  // -------------------------------------------------------- security
  ['POST', '/images/scan', () => (noImages() ? { status: 409, body: { error: 'No running images to scan yet. Add a cluster first; its agent reports running images within a minute.' } } : { status: 202 })],
  [
    'POST',
    '/images/:digest/scan',
    (_r, p) => {
      if (!perms().operate) return forbidden();
      const i = db.images.find((x) => x.digest === decodeURIComponent(p.digest));
      if (!i) return notFound();
      const before = i.scan_status;
      Object.assign(i, { scan_status: 'scanning', next_retry_at: null });
      setTimeout(() => {
        if (before === 'unavailable') Object.assign(i, { scan_status: 'unavailable', scan_attempts: (i.scan_attempts ?? 0) + 1 });
        else if (before === 'missing_credential') Object.assign(i, { scan_status: 'missing_credential' });
        else Object.assign(i, { scan_status: 'scanned', scan_error: '', scan_attempts: 0, next_retry_at: null, last_scanned_at: new Date().toISOString() });
      }, 2500);
      return { status: 202 };
    },
  ],
  ['GET', '/registries', () => ok({ items: db.registries, unmatched: db.unmatched })],
  [
    'POST',
    '/registries',
    (r) => {
      if (!perms().admin_global) return forbidden();
      const b = r.body as RegistryInput;
      if (!b.host_pattern) return invalid('invalid registry', { host_pattern: 'Enter a host or host/path pattern, e.g. harbor.example.com/team/*' });
      if (b.password?.source === 'keyvault_ref' && !/^kv:\/\/[^/]+\/[^/]+$/.test(b.password.ref ?? '')) return invalid('invalid registry', { ref: 'Use kv://<vault>/<secret>.' });
      const reg = {
        id: db.uuid(),
        host_pattern: b.host_pattern,
        username: b.username ?? '',
        credential_source: (b.password?.source ?? '') as never,
        credential_ref: b.password?.ref ?? '',
        images: 4,
        created_at: new Date().toISOString(),
      };
      db.registries.push(reg);
      db.unmatched.splice(0, db.unmatched.length, ...db.unmatched.filter((u) => !b.host_pattern.startsWith(u.host)));
      db.record('registry.created', 'registry', reg.host_pattern, '');
      return ok(reg, 201);
    },
  ],
  [
    'DELETE',
    '/registries/:id',
    (_r, p) => {
      const i = db.registries.findIndex((x) => x.id === p.id);
      if (i >= 0) db.registries.splice(i, 1);
      return { status: 204 };
    },
  ],
  [
    'POST',
    '/registries/test',
    async (r) => {
      await sleep(700);
      return ok(r.body?.username ? { ok: true, error: '' } : { ok: false, error: 'registry answered 401 Unauthorized for anonymous pull' });
    },
  ],
];

function withPerms(c: (typeof db.changeRequests)[number]) {
  const mine = c.maker.object_id === db.people.yigit.object_id;
  const p = perms();
  return {
    ...c,
    can_approve: c.status === 'pending' && !mine && p.vault_approve,
    approve_disabled_reason: mine ? 'You opened this request. Another approver must decide.' : '',
    can_cancel: mine && c.status === 'pending',
  };
}

function decide(id: string, kind: 'approve' | 'reject', comment: string): MockRes {
  const c = db.changeRequests.find((x) => x.id === id);
  if (!c) return notFound();
  if (c.maker.object_id === db.people.yigit.object_id) return { status: 403, body: { error: 'You opened this request. Maker and checker must be different people.' } };
  if (!perms().vault_approve) return forbidden();
  if (kind === 'reject' && !comment.trim()) return invalid('comment required', { comment: 'Explain why you reject the request.' });
  const at = new Date().toISOString();
  c.checker = db.people.yigit;
  c.decided_at = at;
  c.decision_comment = comment;
  if (kind === 'approve') {
    c.status = 'applied';
    c.applied_at = at;
    c.events.push({ at, kind: 'approved', actor_name: 'yigit@contoso.com', details: { comment } }, { at, kind: 'applied', actor_name: 'system', details: { version: (c.items[0]?.base_version ?? 0) + 1 } });
  } else {
    c.status = 'rejected';
    c.events.push({ at, kind: 'rejected', actor_name: 'yigit@contoso.com', details: { comment } });
  }
  db.record(kind === 'approve' ? 'cr.applied' : 'cr.rejected', 'change_request', c.number ?? c.id, comment);
  return ok(withPerms(c));
}

/** Empty images list + 409 on Scan now: localStorage.setItem('olympos.mock.noImages', '1'). */
function noImages() {
  return localStorage.getItem('olympos.mock.noImages') === '1';
}

function validUrl(u: string | undefined): boolean {
  if (!u) return true;
  try {
    const x = new URL(u);
    return x.protocol === 'http:' || x.protocol === 'https:';
  } catch {
    return false;
  }
}

function validateDest(b: DestinationInput): MockRes | null {
  const f: Record<string, string> = {};
  if (!b.name?.trim()) f.name = 'Name is required.';
  if (!validUrl(b.endpoint_override)) f.endpoint_override = 'Use an http:// or https:// URL.';
  if (b.kind === 's3') {
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(b.bucket ?? '')) f.bucket = 'Bucket names are 3–63 lowercase letters, digits, dots and dashes.';
    if (!b.access_key_id?.trim()) f.access_key_id = 'Access key ID is required.';
    if (!b.secret_key || (b.secret_key.source === 'keyvault_ref' ? !b.secret_key.ref : !b.secret_key.value))
      f.secret_key = b.secret_key?.source === 'keyvault_ref' ? 'Enter the Key Vault reference (kv://vault/secret).' : 'Paste the secret key.';
  } else if (b.kind === 'nfs') {
    const m = db.destinationMounts.find((x) => b.path === x.path || (b.path ?? '').startsWith(x.path + '/'));
    if (!m) f.path = 'The path must be below one of the server mounts.';
    else if (!m.writable) f.path = `Mount ${m.name} is read-only.`;
    else if ((b.path ?? '').split('/').includes('..')) f.path = 'The path must stay below the mount.';
  } else {
    if (!/^[a-z0-9]{3,24}$/.test(b.account ?? '')) f.account = 'Storage account names are 3–24 lowercase letters and digits.';
    if (!b.container) f.container = 'Container is required.';
    if (b.auth === 'sas_token' && (!b.sas || (b.sas.source === 'keyvault_ref' ? !b.sas.ref : !b.sas.value)))
      f.sas = b.sas?.source === 'keyvault_ref' ? 'Enter the Key Vault reference (kv://vault/secret).' : 'Paste the SAS token.';
  }
  return Object.keys(f).length ? invalid('invalid destination', f) : null;
}

function emptyDest(kind: Destination['kind']): Destination {
  return {
    id: '',
    name: '',
    kind,
    prefix: '',
    endpoint_override: '',
    auth: 'none',
    account: '',
    container: '',
    sas_source: '',
    sas_ref: '',
    sas_expires_at: null,
    sas_permissions: '',
    last_test_at: null,
    last_test_ok: null,
    jobs: 0,
  };
}

/** What the server would persist: non-secret fields plus secret metadata, never the secret. */
function storeDest(b: DestinationInput, base: Destination): Omit<Destination, 'id' | 'jobs' | 'last_test_at' | 'last_test_ok'> {
  const out = { ...base, name: b.name ?? base.name, prefix: b.prefix ?? base.prefix, endpoint_override: b.endpoint_override ?? base.endpoint_override };
  if (base.kind === 's3') {
    return {
      ...out,
      auth: 'access_key',
      bucket: b.bucket,
      region: b.region || 'us-east-1',
      path_style: !!b.path_style,
      access_key_id: b.access_key_id,
      secret_key_source: b.secret_key?.source ?? base.secret_key_source ?? '',
      secret_key_ref: b.secret_key?.source === 'keyvault_ref' ? b.secret_key.ref : '',
    };
  }
  if (base.kind === 'nfs') return { ...out, auth: 'none', path: b.path };
  const sas = b.auth === 'sas_token' && b.sas?.source === 'stored' && b.sas.value ? parseSas(b.sas.value) : null;
  return {
    ...out,
    account: b.account ?? base.account,
    container: b.container ?? base.container,
    auth: b.auth === 'sas_token' ? 'sas_token' : 'managed_identity',
    sas_source: b.auth === 'sas_token' ? (b.sas?.source ?? 'stored') : '',
    sas_ref: b.auth === 'sas_token' && b.sas?.source === 'keyvault_ref' ? (b.sas.ref ?? '') : '',
    sas_expires_at: b.auth !== 'sas_token' ? null : sas ? sas.expiresAt : b.sas?.source === 'keyvault_ref' ? new Date(Date.now() + 120 * 86400_000).toISOString() : base.sas_expires_at,
    sas_permissions: b.auth !== 'sas_token' ? '' : sas ? sas.permissions.join('') : b.sas?.source === 'keyvault_ref' ? 'rcwt' : base.sas_permissions,
  };
}

function destWarnings(d: Destination, t: DestinationTest): string[] {
  const w: string[] = [];
  if (d.kind === 'nfs') w.push('Olympos can delete files on this NFS path. Protect backups with storage-side snapshots or WORM; retention cannot be enforced by Olympos.');
  else if (t.can_delete) w.push('This credential can delete backups. Remove the delete permission; the destination stays flagged until then.');
  if (t.sas?.scope === 'account') w.push('This is an account SAS: it needs shared key access on the storage account.');
  const days = d.sas_expires_at ? Math.floor((new Date(d.sas_expires_at).getTime() - Date.now()) / 86400_000) : null;
  if (d.kind === 'azure_blob' && d.auth === 'sas_token' && days !== null && days < 14) w.push(`The SAS token expires in ${days} days.`);
  return w;
}

function destTest(b: DestinationInput): DestinationTest {
  const probe = `${b.prefix ?? ''}.olympos-probe/${db.uuid()}`;
  if (b.kind === 's3') {
    const host = b.endpoint_override ? new URL(b.endpoint_override).host : `s3.${b.region || 'us-east-1'}.amazonaws.com`;
    if (/unreachable|invalid/.test(host)) {
      return { ok: false, can_delete: false, error: `could not reach ${host}: connection refused`, steps: [{ name: 'endpoint', ok: false, detail: `dial tcp ${host}: connection refused` }], sas: null, probe_path: probe };
    }
    const canDelete = /admin|root/i.test(b.access_key_id ?? '');
    return {
      ok: true,
      can_delete: canDelete,
      probe_path: probe,
      steps: [
        { name: 'endpoint', ok: true, detail: `${host}${b.path_style ? ' · path-style' : ''}` },
        { name: 'write', ok: true, detail: 'PutObject ok' },
        { name: 'read', ok: true, detail: 'GetObject ok, sha256 matches' },
        { name: 'tag', ok: true, detail: 'PutObjectTagging ok' },
        { name: 'delete_refused', ok: !canDelete, detail: canDelete ? 'DeleteObject SUCCEEDED: this key can delete backups' : 'DeleteObject returned 403 AccessDenied' },
      ],
      sas: null,
    };
  }
  if (b.kind === 'nfs') {
    return {
      ok: true,
      can_delete: true,
      probe_path: `${b.path}/${probe}`,
      steps: [
        { name: 'path', ok: true, detail: `${b.path} exists, writable` },
        { name: 'write', ok: true, detail: 'probe file written' },
        { name: 'read', ok: true, detail: 'read back, sha256 matches' },
        { name: 'delete_refused', ok: false, detail: 'the server process can delete files here' },
      ],
      sas: null,
    };
  }
  const endpointStep = b.endpoint_override ? [{ name: 'endpoint' as const, ok: true, detail: new URL(b.endpoint_override).host }] : [];
  if (b.auth !== 'sas_token') {
    return {
      ok: true,
      can_delete: false,
      probe_path: probe,
      steps: [
        ...endpointStep,
        { name: 'write', ok: true, detail: 'probe blob written' },
        { name: 'read', ok: true, detail: 'read back, sha256 matches' },
        { name: 'tag', ok: true, detail: 'olympos-tier tag set' },
        { name: 'delete_refused', ok: true, detail: 'delete returned 403 AuthorizationPermissionMismatch' },
      ],
      sas: null,
    };
  }
  if (b.sas?.source === 'keyvault_ref') {
    return {
      ok: true,
      can_delete: false,
      steps: [
        { name: 'sas_permissions', ok: true, detail: 'r c w t' },
        { name: 'sas_expiry', ok: true, detail: 'expires in 120 days' },
        { name: 'write', ok: true, detail: '' },
        { name: 'read', ok: true, detail: '' },
        { name: 'tag', ok: true, detail: '' },
        { name: 'delete_refused', ok: true, detail: '' },
      ],
      sas: { permissions: 'rcwt', expires_at: new Date(Date.now() + 120 * 86400_000).toISOString(), missing: [], extra: [], scope: 'container' },
    };
  }
  const s = parseSas(b.sas?.value ?? '');
  const canDelete = s.extra.includes('d');
  const okAll = s.missing.length === 0 && !s.expired;
  return {
    ok: okAll,
    can_delete: canDelete,
    error: okAll ? '' : s.expired ? 'The SAS token has expired.' : `The SAS token lacks required permissions: ${s.missing.join(', ')}`,
    steps: [
      { name: 'sas_permissions', ok: s.missing.length === 0, detail: s.permissions.join(' ') },
      { name: 'sas_expiry', ok: !s.expired, detail: s.expiresAt ?? 'no expiry' },
      { name: 'write', ok: okAll, detail: '' },
      { name: 'read', ok: okAll, detail: '' },
      { name: 'tag', ok: okAll && s.permissions.includes('t'), detail: '' },
      { name: 'delete_refused', ok: !canDelete, detail: canDelete ? 'delete SUCCEEDED: this credential can delete backups' : 'delete returned 403' },
    ],
    sas: { permissions: s.permissions.join(''), expires_at: s.expiresAt, missing: s.missing, extra: s.extra, scope: s.scope },
  };
}

export function match(method: string, path: string): { h: Handler; params: Record<string, string> } | null {
  for (const [m, pattern, h] of routes) {
    if (m !== method) continue;
    const pp = pattern.split('/');
    const sp = path.split('/');
    const params: Record<string, string> = {};
    let okm = true;
    for (let i = 0; i < pp.length; i++) {
      if (pp[i] === '*') {
        params['*'] = sp.slice(i).map(decodeURIComponent).join('/');
        okm = sp.length > i;
        break;
      }
      if (i >= sp.length) {
        okm = false;
        break;
      }
      if (pp[i].startsWith(':')) params[pp[i].slice(1)] = decodeURIComponent(sp[i]);
      else if (pp[i] !== sp[i]) {
        okm = false;
        break;
      }
      if (i === pp.length - 1 && sp.length !== pp.length) okm = false;
    }
    if (okm) return { h, params };
  }
  return null;
}
