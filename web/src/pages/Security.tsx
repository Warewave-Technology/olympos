import { useMemo, useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, api, errorMessage } from '../api/client';
import type { Image, ImageDetail, ItemList, KyvernoPolicy, NetpolNamespace, ScanStatus, SecurityClusterSummary } from '../api/types';
import { useCan } from '../auth/me';
import { age, clockTime, plural, shortDigest, shortText } from '../lib/format';
import { securityRoute } from '../router';
import { SensitiveDataTab, useSensitiveData } from '../ui/SensitiveDataTab';
import { SecretsTab, useSecretInventory } from '../ui/SecretsTab';
import { ClusterOverview, ScopeCrumbs, ClusterOfflineNote, findCluster, resolveScope, scopeParam, useClusterList, type ClusterInfo, type OverviewRow, type Scope } from '../ui/clusterScope';
import { DataTable, type Column } from '../ui/DataTable';
import { Badge, EmptyState, Modal, QueryView, Tabs, sentence, useToast } from '../ui/kit';
import { Select } from '../ui/Select';
import { PageHead, SeverityBadge } from '../ui/status';

type Tab = 'images' | 'kyverno' | 'netpol' | 'sensitive' | 'secrets';
type Sev = '' | 'critical' | 'high';
type StatusFilter = '' | 'attention' | 'scanned' | 'waiting';
type KyFilter = 'failing' | 'not_ready' | 'all';
type NpFilter = 'missing' | 'all';

/** The server retries a failed scan automatically up to this many times. */
export const MAX_SCAN_ATTEMPTS = 5;
const RETRYABLE: ScanStatus[] = ['failed', 'unavailable', 'missing_credential'];
const STATUS_RANK: Record<ScanStatus, number> = { failed: 0, unavailable: 1, missing_credential: 2, pending: 3, scanning: 4, scanned: 5 };

export function imageName(i: Pick<Image, 'repo' | 'tags'>) {
  return i.tags.length ? `${i.repo}:${i.tags[0]}` : i.repo;
}

/** Scanned through the registry's image with the same tag (the running digest is not in the registry). */
export const scannedByTag = (i: Pick<Image, 'scanned_by'>) => i.scanned_by === 'tag';
/** Has CVE results to show (by digest, or by tag). */
export const hasResults = (i: Pick<Image, 'scan_status' | 'scanned_by'>) => i.scan_status === 'scanned' || scannedByTag(i);
/** "Not scanned · needs attention": nothing usable yet. Tag-scanned images have results, so they do not count. */
export const needsAttention = (i: Pick<Image, 'scan_status' | 'scanned_by'>) => RETRYABLE.includes(i.scan_status) && !scannedByTag(i);
/** Retry is offered whenever the running digest itself has no scan (incl. tag scans: the digest may appear later). */
const canRetry = (i: Pick<Image, 'scan_status' | 'scanned_by'>) => RETRYABLE.includes(i.scan_status) || scannedByTag(i);

function credentialCell(i: Image) {
  if (i.scan_status === 'missing_credential') return <span className="muted">none</span>;
  if (i.registry && i.registry !== 'public') return <span className="mono">{i.registry}</span>;
  return <span className="muted">public</span>;
}

function fixCell(i: Image) {
  if (!hasResults(i)) return <span className="muted">—</span>;
  if (i.critical + i.high === 0) return <span className="muted">—</span>;
  return (i.fixable ?? 0) > 0 ? <Badge tone="ok">Yes · {i.fixable}</Badge> : <Badge tone="mute">No</Badge>;
}

const UNAVAILABLE_WHY =
  'This digest is not in any registry Olympos can reach: the image was built locally or retagged on the node (for example kind node images loaded with "kind load"). Olympos scans by digest so the results match exactly what runs; push the image to a registry to have it scanned.';

export function tagScanWhy(i: Pick<Image, 'repo' | 'tags'>): string {
  return `The running digest is not in the registry (built locally or retagged on the node), so Olympos scanned the registry's image with the same tag, ${imageName(i)}, instead. The results describe that registry image and may differ from what actually runs. Retry checks for the digest again.`;
}

/** Short badge + reason for an image's scan state. Never a dead end: says why and what happens next. */
export function ScanStatusCell({ i, now = new Date() }: { i: Image; now?: Date }) {
  if (scannedByTag(i)) {
    const why = tagScanWhy(i);
    return (
      <span className="scan-cell">
        <Badge tone="info" title={why}>
          Scanned by tag
        </Badge>
        <span className="scan-why" title={why}>
          Registry image {i.tags[0] ? `:${i.tags[0]}` : ''} · may differ from the running image
          {i.last_scanned_at ? ` · ${age(i.last_scanned_at, now.getTime())} ago` : ''}
        </span>
      </span>
    );
  }
  switch (i.scan_status) {
    case 'scanned':
      return <span className="muted small">{i.last_scanned_at ? `${age(i.last_scanned_at, now.getTime())} ago` : 'scanned'}</span>;
    case 'scanning':
      return <Badge tone="info">Scanning</Badge>;
    case 'pending':
      return <Badge tone="mute">Waiting to scan</Badge>;
    case 'failed': {
      const n = i.scan_attempts ?? 0;
      const next = i.next_retry_at;
      const label = next ? `Scan failed · retry ${Math.max(1, Math.min(n, MAX_SCAN_ATTEMPTS))}/${MAX_SCAN_ATTEMPTS} at ${clockTime(next, now)}` : n >= MAX_SCAN_ATTEMPTS ? `Scan failed · gave up after ${n} attempts` : 'Scan failed';
      return (
        <span className="scan-cell">
          <Badge tone="crit">{label}</Badge>
          {i.scan_error && (
            <span className="scan-why" title={i.scan_error}>
              {shortText(i.scan_error, 60)}
            </span>
          )}
        </span>
      );
    }
    case 'unavailable':
      return (
        <span className="scan-cell">
          <Badge tone="warn" title={UNAVAILABLE_WHY}>
            Not in registry
          </Badge>
          <span className="scan-why" title={i.scan_error ? `${i.scan_error}\n\n${UNAVAILABLE_WHY}` : UNAVAILABLE_WHY}>
            Locally built or retagged image
          </span>
        </span>
      );
    case 'missing_credential':
      return (
        <span className="scan-cell">
          <Badge tone="warn">Missing credential</Badge>
          <span className="scan-why">
            Add one in <Link to="/settings/registries">Settings › Registries</Link>
          </span>
        </span>
      );
    default:
      return <Badge>{String(i.scan_status)}</Badge>;
  }
}

function useImageScan() {
  const qc = useQueryClient();
  const toast = useToast();
  const [queued, setQueued] = useState<Set<string>>(new Set());
  const m = useMutation({
    mutationFn: (i: Image) => api.post(`/images/${encodeURIComponent(i.digest)}/scan`),
    onSuccess: (_r, i) => {
      setQueued((s) => new Set(s).add(i.digest));
      toast(`${canRetry(i) ? 'Retry' : 'Scan'} queued for ${imageName(i)}.`);
      setTimeout(() => {
        void qc.invalidateQueries({ queryKey: ['images'] });
        setQueued((s) => {
          const n = new Set(s);
          n.delete(i.digest);
          return n;
        });
      }, 1500);
    },
    onError: (e, i) => toast(`Could not queue the scan of ${imageName(i)}: ${errorMessage(e)}`, 'crit'),
  });
  return { scan: (i: Image) => m.mutate(i), busy: (i: Image) => (m.isPending && m.variables?.digest === i.digest) || queued.has(i.digest) };
}

/** Scan now for every running image; a 409 (nothing runs yet) becomes a warning, not an error. */
function useScanAll() {
  const qc = useQueryClient();
  const toast = useToast();
  const [warning, setWarning] = useState<string | null>(null);
  const m = useMutation({
    mutationFn: () => api.post('/images/scan'),
    onMutate: () => setWarning(null),
    onSuccess: () => {
      toast('Scan queued for all running images.');
      setTimeout(() => void qc.invalidateQueries({ queryKey: ['images'] }), 2000);
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) {
        setWarning(sentence(e.message));
        void qc.invalidateQueries({ queryKey: ['images'] });
        void qc.invalidateQueries({ queryKey: ['security-clusters'] });
      } else toast(`Could not queue the scan: ${errorMessage(e)}`, 'crit');
    },
  });
  return { m, warning, dismiss: () => setWarning(null) };
}

function ScanActions({ scanAll, nothingToScan }: { scanAll: ReturnType<typeof useScanAll>; nothingToScan: boolean }) {
  return (
    <>
      {nothingToScan && (
        <span className="muted small" id="scan-why">
          No running images yet · add a cluster first
        </span>
      )}
      <button type="button" className="btn" onClick={() => scanAll.m.mutate()} disabled={scanAll.m.isPending || nothingToScan} aria-describedby={nothingToScan ? 'scan-why' : undefined}>
        {scanAll.m.isPending ? 'Queueing…' : 'Scan now'}
      </button>
    </>
  );
}

function ScanWarning({ scanAll }: { scanAll: ReturnType<typeof useScanAll> }) {
  const canAddCluster = useCan('admin_global');
  if (!scanAll.warning) return null;
  return (
    <div className="note warn spread" role="alert">
      <span>
        <b>Nothing was scanned.</b> {scanAll.warning}
        {canAddCluster && (
          <>
            {' '}
            <Link to="/" search={{ add: true }}>
              Add a cluster
            </Link>
          </>
        )}
      </span>
      <button type="button" className="btn sm" onClick={scanAll.dismiss}>
        Dismiss
      </button>
    </div>
  );
}

export function SecurityPage() {
  const search = securityRoute.useSearch();
  const scope = resolveScope(search.cluster, !!(search.tab || search.digest));
  const { q: clustersQ, list: clusters } = useClusterList();
  const navigate = useNavigate({ from: '/security' });
  const canOperate = useCan('operate');
  const closeDigest = () => navigate({ search: (s) => ({ ...s, digest: undefined }) });
  return (
    <>
      {scope.mode === 'overview' ? <SecurityOverview clusters={clusters} clustersLoading={clustersQ.isPending} /> : <SecurityDetail scope={scope} clusters={clusters} />}
      {search.digest && <ImageDialog digest={search.digest} onClose={closeDigest} canOperate={canOperate} />}
    </>
  );
}

// ------------------------------------------------------------ cluster overview

function SecurityOverview({ clusters, clustersLoading }: { clusters: ClusterInfo[]; clustersLoading: boolean }) {
  const navigate = useNavigate({ from: '/security' });
  const canOperate = useCan('operate');
  const scanAll = useScanAll();
  const q = useQuery({ queryKey: ['security-clusters'], queryFn: () => api.get<ItemList<SecurityClusterSummary>>('/security/clusters') });
  const rows = q.data?.items ?? [];
  const sum = (f: (r: SecurityClusterSummary) => number) => rows.reduce((s, r) => s + f(r), 0);
  const open = (cluster: string, tab?: Tab) => navigate({ search: { cluster, tab } });
  const columns: Column<OverviewRow<SecurityClusterSummary>>[] = [
    { id: 'images', header: 'Images', align: 'num', sortValue: (r) => r.images, defaultDir: 'desc', cell: (r) => (
        <>
          <span className="n">{r.images}</span>
          <div className="muted small">{plural(r.workloads, 'workload')}</div>
        </>
      ) },
    { id: 'critical', header: 'Critical CVEs', align: 'num', sortValue: (r) => r.critical, defaultDir: 'desc', cell: (r) => (
        <>
          <span className={`n${r.critical ? ' crit' : ''}`}>{r.critical}</span>
          <div className="muted small">{r.images_with_critical > 0 ? `in ${plural(r.images_with_critical, 'image')} · ` : ''}{r.high} high</div>
        </>
      ) },
    { id: 'notscanned', header: 'Not scanned', align: 'num', sortValue: (r) => r.not_scanned, defaultDir: 'desc', cell: (r) => (r.not_scanned ? <Badge tone="warn">{r.not_scanned}</Badge> : <span className="muted">0</span>) },
    {
      id: 'kyverno',
      header: 'Kyverno failures',
      align: 'num',
      sortValue: (r) => (r.kyverno_installed ? r.kyverno_failures : -1),
      defaultDir: 'desc',
      cell: (r) =>
        r.kyverno_installed ? (
          <>
            <span className={`n${r.kyverno_failures ? ' warn' : ''}`}>{r.kyverno_failures}</span>
            <div className="muted small">{plural(r.kyverno_policies, 'policy', 'policies')}</div>
          </>
        ) : (
          <Badge tone="mute">Not installed</Badge>
        ),
    },
    {
      id: 'sensitive',
      header: 'Sensitive data',
      align: 'num',
      sortValue: (r) => (r.sensitive_data_high ?? 0) * 1000 + (r.sensitive_data ?? 0),
      defaultDir: 'desc',
      cell: (r) =>
        r.sensitive_data ? (
          <>
            <span className={`n ${r.sensitive_data_high ? 'crit' : 'warn'}`}>{r.sensitive_data}</span>
            <div className="muted small">{r.sensitive_data_high ? `${r.sensitive_data_high} high` : 'key names'}</div>
          </>
        ) : (
          <span className="muted">0</span>
        ),
    },
    {
      id: 'netpol',
      header: 'No default-deny',
      align: 'num',
      sortValue: (r) => r.namespaces_without_default_deny,
      defaultDir: 'desc',
      cell: (r) => (
        <>
          <span className={`n${r.namespaces_without_default_deny ? ' warn' : ''}`}>{r.namespaces_without_default_deny}</span>
          <div className="muted small">of {plural(r.namespaces, 'namespace')}</div>
        </>
      ),
    },
  ];
  return (
    <>
      <PageHead title="Security" sub="Images by digest, Kyverno policies and NetworkPolicies, per cluster." actions={canOperate && <ScanActions scanAll={scanAll} nothingToScan={!!q.data && sum((r) => r.images) === 0} />} />
      <ScanWarning scanAll={scanAll} />
      <section className="stats four" aria-label="Security totals">
        <button type="button" className="card stat" onClick={() => open('all')}>
          <div className="k">Clusters</div>
          <div className="v">{q.data ? rows.length : '—'}</div>
          <div className="d">{q.data ? `${plural(sum((r) => r.not_scanned), 'image')} not scanned` : ' '}</div>
        </button>
        <button type="button" className="card stat" onClick={() => open('all')}>
          <div className="k">Critical CVEs</div>
          <div className={`v${sum((r) => r.critical) ? ' crit' : ''}`}>{q.data ? sum((r) => r.critical) : '—'}</div>
          <div className="d">in running images, summed per cluster</div>
        </button>
        <button type="button" className="card stat" onClick={() => open('all', 'kyverno')}>
          <div className="k">Kyverno violations</div>
          <div className={`v${sum((r) => r.kyverno_failures) ? ' warn' : ''}`}>{q.data ? sum((r) => r.kyverno_failures) : '—'}</div>
          <div className="d">{q.data ? `${plural(rows.filter((r) => !r.kyverno_installed).length, 'cluster')} without Kyverno` : ' '}</div>
        </button>
        <button type="button" className="card stat" onClick={() => open('all', 'netpol')}>
          <div className="k">No default-deny</div>
          <div className={`v${sum((r) => r.namespaces_without_default_deny) ? ' warn' : ''}`}>{q.data ? sum((r) => r.namespaces_without_default_deny) : '—'}</div>
          <div className="d">namespaces without a default-deny policy</div>
        </button>
      </section>
      <ClusterOverview<SecurityClusterSummary>
        label="Security by cluster"
        what="clusters"
        rows={q.data ? rows : undefined}
        clusters={clusters}
        loading={q.isPending || clustersLoading}
        error={q.isError ? q.error : undefined}
        onRetry={() => q.refetch()}
        columns={columns}
        onOpen={(id) => open(id)}
        onAll={() => open('all')}
        initialSort={{ id: 'critical', dir: 'desc' }}
      />
    </>
  );
}

// ------------------------------------------------------------ one cluster / all clusters

function SecurityDetail({ scope, clusters }: { scope: Exclude<Scope, { mode: 'overview' }>; clusters: ClusterInfo[] }) {
  const { tab = 'images' } = securityRoute.useSearch();
  const navigate = useNavigate({ from: '/security' });
  const canOperate = useCan('operate');
  const scanAll = useScanAll();
  const cluster = scope.mode === 'cluster' ? findCluster(clusters, scope.id) : undefined;
  const cq = scope.mode === 'cluster' ? scope.id : undefined;
  const one = scope.mode === 'cluster';
  const [q, setQ] = useState('');
  const [sev, setSev] = useState<Sev>('');
  const [status, setStatus] = useState<StatusFilter>('');
  const [kyFilter, setKyFilter] = useState<KyFilter>('failing');
  const [npFilter, setNpFilter] = useState<NpFilter>('missing');
  const imagesQ = useQuery({ queryKey: ['images', { cluster: cq }], queryFn: () => api.get<ItemList<Image>>('/images', { cluster: cq }) });
  const kyQ = useQuery({ queryKey: ['kyverno', { cluster: cq }], queryFn: () => api.get<ItemList<KyvernoPolicy>>('/security/kyverno', { cluster: cq }) });
  const npQ = useQuery({ queryKey: ['netpol', { cluster: cq }], queryFn: () => api.get<ItemList<NetpolNamespace>>('/security/netpol', { cluster: cq }) });
  const sdQ = useSensitiveData(cq);
  const ksQ = useSecretInventory(cq);
  const ksFindings = (ksQ.data?.items ?? []).filter((x) => x.findings.some((f) => f !== 'secret.unmanaged')).length;
  const sdItems = sdQ.data?.items ?? [];

  const all = imagesQ.data?.items ?? [];
  const lastScan = all.map((i) => i.last_scanned_at).filter(Boolean).sort().pop() ?? null;
  const critImages = all.filter((i) => hasResults(i) && i.critical > 0);
  const critTotal = critImages.reduce((s, i) => s + i.critical, 0);
  const critFix = critImages.filter((i) => (i.fixable ?? 0) > 0).length;
  const workloads = all.reduce((s, i) => s + i.workloads, 0);
  const attention = all.filter(needsAttention);
  const kyItems = kyQ.data?.items ?? [];
  const kyFail = kyItems.reduce((s, p) => s + p.fail_count, 0);
  const npItems = npQ.data?.items ?? [];
  const noDeny = npItems.filter((n) => !n.default_deny && !n.excluded);
  // Permission-independent state: nothing runs yet, so the button is disabled with the reason shown.
  const nothingToScan = !!imagesQ.data && all.length === 0 && !one;
  const from = scopeParam(scope);

  const goTab = (t: Tab) => navigate({ search: (s) => ({ ...s, tab: t === 'images' ? undefined : t }), replace: true });

  return (
    <>
      <PageHead
        crumbs={<ScopeCrumbs area="Security" to="/security" scope={scope} cluster={cluster} />}
        title={one ? <span className="mono">{cluster?.name ?? scope.id}</span> : 'All clusters'}
        sub={`Images are deduplicated by digest${one ? '' : ' across clusters'}${lastScan ? ` · last scan ${age(lastScan)} ago` : ''}`}
        actions={canOperate && <ScanActions scanAll={scanAll} nothingToScan={nothingToScan} />}
      />
      <ClusterOfflineNote cluster={one ? cluster : undefined} />
      <ScanWarning scanAll={scanAll} />
      <section className="stats four" aria-label="Security totals">
        <button
          type="button"
          className="card stat"
          onClick={() => {
            setSev('');
            setStatus('');
            goTab('images');
          }}
        >
          <div className="k">Unique images</div>
          <div className="v">{imagesQ.data ? all.length : '—'}</div>
          <div className="d">
            across {plural(workloads, 'running workload')}
            {attention.length > 0 && ` · ${attention.length} not scanned`}
          </div>
        </button>
        <button
          type="button"
          className="card stat"
          onClick={() => {
            setSev('critical');
            setStatus('');
            goTab('images');
          }}
        >
          <div className="k">Critical CVEs</div>
          <div className={`v${critTotal ? ' crit' : ''}`}>{imagesQ.data ? critTotal : '—'}</div>
          <div className="d">
            in {plural(critImages.length, 'image')} · {critFix} with a fix
          </div>
        </button>
        <button
          type="button"
          className="card stat"
          onClick={() => {
            setKyFilter('failing');
            goTab('kyverno');
          }}
        >
          <div className="k">Kyverno violations</div>
          <div className={`v${kyFail ? ' warn' : ''}`}>{kyQ.data ? kyFail : '—'}</div>
          <div className="d">from PolicyReports</div>
        </button>
        <button
          type="button"
          className="card stat"
          onClick={() => {
            setNpFilter('missing');
            goTab('netpol');
          }}
        >
          <div className="k">No default-deny</div>
          <div className={`v${noDeny.length ? ' warn' : ''}`}>{npQ.data ? noDeny.length : '—'}</div>
          <div className="d">namespaces without a default-deny policy</div>
        </button>
      </section>

      <Tabs<Tab>
        label="Security sections"
        value={tab}
        onChange={goTab}
        tabs={[
          { id: 'images', label: <>Images {imagesQ.data && <span className="muted small">{all.length}</span>}</> },
          { id: 'kyverno', label: <>Kyverno policies {kyFail > 0 && <Badge tone="warn">{kyFail} failing</Badge>}</> },
          { id: 'netpol', label: <>Network policies {noDeny.length > 0 && <Badge tone="warn">{noDeny.length} without default-deny</Badge>}</> },
          { id: 'secrets', label: <>Kubernetes secrets {ksFindings > 0 && <Badge tone="info">{ksFindings} to review</Badge>}</> },
          { id: 'sensitive', label: <>Sensitive data {sdItems.length > 0 && <Badge tone={sdItems.some((f) => f.severity === 'high') ? 'crit' : 'warn'}>{sdItems.length} in ConfigMaps</Badge>}</> },
        ]}
      />

      {tab === 'images' && (
        <ImagesTab q={q} setQ={setQ} sev={sev} setSev={setSev} status={status} setStatus={setStatus} imagesQ={imagesQ} attention={attention.length} canOperate={canOperate} oneCluster={one} onOpen={(d) => navigate({ search: (s) => ({ ...s, digest: d }) })} />
      )}
      {tab === 'kyverno' && (
        <KyvernoTab
          q={kyQ}
          filter={kyFilter}
          setFilter={setKyFilter}
          oneCluster={one}
          onOpen={(p) => navigate({ to: '/security/kyverno', search: { cluster: p.cluster_id, kind: p.kind || (p.namespace ? 'Policy' : 'ClusterPolicy'), namespace: p.namespace || undefined, name: p.name, from } })}
        />
      )}
      {tab === 'sensitive' && <SensitiveDataTab q={sdQ} oneCluster={one} />}
      {tab === 'secrets' && <SecretsTab q={ksQ} oneCluster={one} />}
      {tab === 'netpol' && <NetpolTab q={npQ} filter={npFilter} setFilter={setNpFilter} oneCluster={one} onOpen={(n) => navigate({ to: '/security/netpol', search: { cluster: n.cluster_id, namespace: n.namespace, from } })} />}
    </>
  );
}

// ------------------------------------------------------------ images
function ImagesTab({
  q,
  setQ,
  sev,
  setSev,
  status,
  setStatus,
  imagesQ,
  attention,
  canOperate,
  oneCluster,
  onOpen,
}: {
  q: string;
  setQ: (v: string) => void;
  sev: Sev;
  setSev: (v: Sev) => void;
  status: StatusFilter;
  setStatus: (v: StatusFilter) => void;
  imagesQ: ReturnType<typeof useQuery<ItemList<Image>>>;
  attention: number;
  canOperate: boolean;
  oneCluster: boolean;
  onOpen: (digest: string) => void;
}) {
  const { scan, busy } = useImageScan();
  const all = imagesQ.data?.items ?? [];
  const rows = useMemo(
    () =>
      all.filter((i) => {
        if (sev === 'critical' && !(i.critical > 0)) return false;
        if (sev === 'high' && !(i.high > 0)) return false;
        if (status === 'attention' && !needsAttention(i)) return false;
        if (status === 'scanned' && i.scan_status !== 'scanned') return false;
        if (status === 'waiting' && i.scan_status !== 'pending' && i.scan_status !== 'scanning') return false;
        return true;
      }),
    [all, sev, status],
  );
  const filtered = !!(sev || status);
  const columns: Column<Image>[] = [
    {
      id: 'image',
      header: 'Image · digest',
      sortValue: imageName,
      searchText: (i) => `${imageName(i)} ${i.digest} ${i.registry ?? ''}`,
      className: 'mono wrap break',
      style: { minWidth: 220 },
      cell: (i) => (
        <>
          <button type="button" className="link-btn mono" onClick={() => onOpen(i.digest)} aria-label={`Details for ${imageName(i)}`}>
            {imageName(i)}
          </button>
          <div className="mono muted small">{shortDigest(i.digest)}</div>
        </>
      ),
    },
    {
      id: 'usage',
      header: 'Running in',
      sortValue: (i) => i.workloads,
      defaultDir: 'desc',
      cell: (i) =>
        oneCluster ? (
          plural(i.workloads, 'workload')
        ) : (
          <>
            {plural(i.clusters, 'cluster')}
            <div className="muted small">{plural(i.workloads, 'workload')}</div>
          </>
        ),
    },
    { id: 'critical', header: 'Critical', align: 'num', sortValue: (i) => (hasResults(i) ? i.critical : null), defaultDir: 'desc', cell: (i) => (hasResults(i) ? <span className={`n${i.critical ? ' crit' : ''}`}>{i.critical}</span> : <span className="muted">—</span>) },
    { id: 'high', header: 'High', align: 'num', sortValue: (i) => (hasResults(i) ? i.high : null), defaultDir: 'desc', cell: (i) => (hasResults(i) ? <span className="n">{i.high}</span> : <span className="muted">—</span>) },
    { id: 'fix', header: 'Fix', sortValue: (i) => (hasResults(i) ? (i.fixable ?? 0) : null), defaultDir: 'desc', cell: fixCell },
    { id: 'scan', header: 'Scan', sortValue: (i) => (scannedByTag(i) ? 4.5 : (STATUS_RANK[i.scan_status] ?? 9)), cell: (i) => <ScanStatusCell i={i} />, className: 'wrap' },
    { id: 'cred', header: 'Pull credential', sortValue: (i) => (i.scan_status === 'missing_credential' ? '' : i.registry || 'public'), cell: credentialCell },
    {
      id: 'actions',
      header: 'Actions',
      srOnlyHeader: true,
      align: 'actions',
      hidden: !canOperate,
      cell: (i) => {
        const retry = canRetry(i);
        const b = busy(i) || i.scan_status === 'scanning';
        return (
          <button type="button" className={`btn sm${retry ? ' pri' : ''}`} onClick={() => scan(i)} disabled={b} aria-label={`${retry ? 'Retry scan of' : 'Scan'} ${imageName(i)}`}>
            {b ? 'Queued…' : retry ? 'Retry' : 'Scan now'}
          </button>
        );
      },
    },
  ];
  return (
    <section className="card" aria-label="Images">
      <div className="card-head">
        <div className="inline">
          <label className="sr-only" htmlFor="img-q">
            Search images
          </label>
          <input id="img-q" type="search" className="in search" placeholder="Search repository, tag or digest…" value={q} onChange={(e) => setQ(e.target.value)} />
          <div className="pills" role="group" aria-label="Severity filter">
            {(
              [
                ['', 'All'],
                ['critical', 'With critical'],
                ['high', 'With high'],
              ] as [Sev, string][]
            ).map(([v, l]) => (
              <button key={v} type="button" className="pill" aria-pressed={sev === v} onClick={() => setSev(v)}>
                {l}
              </button>
            ))}
          </div>
          <Select<StatusFilter>
            inline
            size="sm"
            aria-label="Scan status"
            value={status}
            onChange={setStatus}
            options={[
              { value: '', label: 'Any scan status' },
              { value: 'attention', label: `Not scanned · needs attention (${attention})`, text: 'Not scanned needs attention' },
              { value: 'waiting', label: 'Waiting or scanning' },
              { value: 'scanned', label: 'Scanned' },
            ]}
          />
        </div>
      </div>
      {attention > 0 && status !== 'attention' && (
        <div className="note warn spread" style={{ margin: '12px 14px 0' }}>
          <span>
            <b>{plural(attention, 'image')} could not be scanned.</b> Each row says why; failed scans are retried automatically, and operators can retry now.
          </span>
          <button type="button" className="btn sm" onClick={() => setStatus('attention')}>
            Show them
          </button>
        </div>
      )}
      <DataTable
        label="Images"
        what="images"
        rows={imagesQ.data ? rows : undefined}
        loading={imagesQ.isPending}
        error={imagesQ.isError ? imagesQ.error : undefined}
        onRetry={() => imagesQ.refetch()}
        columns={columns}
        rowKey={(i) => i.digest}
        filterText={q}
        resetKey={`${sev}|${status}`}
        initialSort={{ id: 'critical', dir: 'desc' }}
        empty={<EmptyState title={filtered ? 'No images match' : 'No images reported yet'}>{filtered ? 'Try another filter.' : 'Agents report running images (by digest) within a minute of connecting.'}</EmptyState>}
        noMatch={<EmptyState title="No images match">Try another search or filter.</EmptyState>}
      />
      <div className="card-foot">
        Registry credentials are server objects (<Link to="/settings/registries">Settings › Registries</Link>). The agent never reads imagePullSecrets. Images are scanned by digest, so results match exactly what runs; “Scanned by tag” marks the exceptions.
      </div>
    </section>
  );
}

// ------------------------------------------------------------ kyverno

function KyvernoTab({ q, filter, setFilter, oneCluster, onOpen }: { q: ReturnType<typeof useQuery<ItemList<KyvernoPolicy>>>; filter: KyFilter; setFilter: (f: KyFilter) => void; oneCluster: boolean; onOpen: (p: KyvernoPolicy) => void }) {
  const [text, setText] = useState('');
  const all = q.data?.items ?? [];
  const failing = all.filter((p) => p.fail_count > 0);
  const notReady = all.filter((p) => !p.ready);
  const effective: KyFilter = filter === 'failing' && failing.length === 0 && all.length > 0 ? 'all' : filter;
  const rows = effective === 'failing' ? failing : effective === 'not_ready' ? notReady : all;
  const columns: Column<KyvernoPolicy>[] = [
    {
      id: 'name',
      header: 'Policy',
      sortValue: (p) => p.name,
      className: 'mono',
      cell: (p) => (
        <>
          <button type="button" className="link-btn mono" onClick={() => onOpen(p)}>
            {p.name}
          </button>
          {!p.ready && (
            <>
              {' '}
              <Badge tone="warn">Not ready</Badge>
            </>
          )}
        </>
      ),
    },
    { id: 'kind', header: 'Kind', sortValue: (p) => p.kind || (p.namespace ? 'Policy' : 'ClusterPolicy'), className: 'muted', cell: (p) => p.kind || (p.namespace ? 'Policy' : 'ClusterPolicy') },
    { id: 'cluster', header: 'Cluster', hidden: oneCluster, sortValue: (p) => p.cluster_name, className: 'mono', cell: (p) => p.cluster_name },
    { id: 'ns', header: 'Namespace', sortValue: (p) => p.namespace || 'cluster-wide', className: (p) => (p.namespace ? 'mono' : 'muted'), cell: (p) => p.namespace || 'cluster-wide' },
    { id: 'mode', header: 'Mode', sortValue: (p) => p.mode, cell: (p) => (p.mode === 'Enforce' ? <Badge tone="ok">Enforce</Badge> : <Badge tone="info">Audit</Badge>) },
    { id: 'rules', header: 'Rules', align: 'num', sortValue: (p) => p.rules, defaultDir: 'desc', cell: (p) => p.rules },
    { id: 'fail', header: 'Fail', align: 'num', sortValue: (p) => p.fail_count, defaultDir: 'desc', className: (p) => (p.fail_count ? 'up' : undefined), cell: (p) => p.fail_count },
  ];
  return (
    <section className="card" aria-labelledby="ky-t">
      <div className="card-head">
        <div>
          <h2 id="ky-t">{effective === 'failing' ? 'Top Kyverno violations' : effective === 'not_ready' ? 'Kyverno policies not ready' : 'Kyverno policies'}</h2>
          <div className="desc">{effective === 'failing' ? 'Policies with failing resources in the latest PolicyReports, most failures first.' : 'Every validation policy the agents report.'}</div>
        </div>
        <div className="inline">
          <div className="pills" role="group" aria-label="Show policies">
            <button type="button" className="pill" aria-pressed={effective === 'failing'} onClick={() => setFilter('failing')}>
              With violations · {failing.length}
            </button>
            {notReady.length > 0 && (
              <button type="button" className="pill" aria-pressed={effective === 'not_ready'} onClick={() => setFilter('not_ready')}>
                Not ready · {notReady.length}
              </button>
            )}
            <button type="button" className="pill" aria-pressed={effective === 'all'} onClick={() => setFilter('all')}>
              All · {all.length}
            </button>
          </div>
          <label className="sr-only" htmlFor="ky-q">
            Search policies
          </label>
          <input id="ky-q" type="search" className="in search-sm" placeholder="Search policy, cluster, namespace…" value={text} onChange={(e) => setText(e.target.value)} />
        </div>
      </div>
      <DataTable
        label="Kyverno policies"
        what="Kyverno policies"
        rows={q.data ? rows : undefined}
        loading={q.isPending}
        error={q.isError ? q.error : undefined}
        onRetry={() => q.refetch()}
        columns={columns}
        rowKey={(p) => p.cluster_id + (p.kind ?? '') + p.namespace + p.name}
        onRowClick={onOpen}
        rowLabel={(p) => `Open policy ${p.name}${oneCluster ? '' : ` on ${p.cluster_name}`}`}
        filterText={text}
        resetKey={effective}
        initialSort={{ id: 'fail', dir: 'desc' }}
        empty={
          all.length === 0 ? (
            <EmptyState title="No Kyverno policies found">Either Kyverno is not installed on the clusters in your scope, or it has no validation policies yet.</EmptyState>
          ) : (
            <EmptyState title={effective === 'not_ready' ? 'Every policy is ready' : 'No violations'}>Every policy passes in the latest PolicyReports.</EmptyState>
          )
        }
      />
      <div className="card-foot">Read by the agent from ClusterPolicy / Policy (kyverno.io), ValidatingPolicy and ImageValidatingPolicy kinds (policies.kyverno.io) and PolicyReports. Failures are recorded as findings (source kyverno). Open a policy to see its rules explained, its YAML and the resources that fail it.</div>
    </section>
  );
}

// ------------------------------------------------------------ network policies

function NetpolTab({ q, filter, setFilter, oneCluster, onOpen }: { q: ReturnType<typeof useQuery<ItemList<NetpolNamespace>>>; filter: NpFilter; setFilter: (f: NpFilter) => void; oneCluster: boolean; onOpen: (n: NetpolNamespace) => void }) {
  const [text, setText] = useState('');
  const all = q.data?.items ?? [];
  const missing = all.filter((n) => !n.default_deny && !n.excluded);
  const effective: NpFilter = filter === 'missing' && missing.length === 0 && all.length > 0 ? 'all' : filter;
  const rows = effective === 'missing' ? missing : all;
  const columns: Column<NetpolNamespace>[] = [
    { id: 'cluster', header: 'Cluster', hidden: oneCluster, sortValue: (n) => n.cluster_name, className: 'mono', cell: (n) => n.cluster_name },
    {
      id: 'ns',
      header: 'Namespace',
      sortValue: (n) => n.namespace,
      className: 'mono',
      cell: (n) => (
        <button type="button" className="link-btn mono" onClick={() => onOpen(n)}>
          {n.namespace}
        </button>
      ),
    },
    { id: 'policies', header: 'Policies', align: 'num', sortValue: (n) => n.policy_count, defaultDir: 'desc', cell: (n) => (n.policy_count === 0 ? 0 : !n.default_deny ? `${n.policy_count} (allow only)` : n.policy_count) },
    {
      id: 'deny',
      header: 'Default-deny',
      sortValue: (n) => (n.excluded ? 2 : n.default_deny ? 1 : 0),
      cell: (n) => (n.excluded ? <Badge tone="mute">Excluded · system</Badge> : n.default_deny ? <Badge tone="ok">Yes</Badge> : <Badge tone="warn">Missing</Badge>),
    },
  ];
  return (
    <section className="card" aria-labelledby="np-t">
      <div className="card-head">
        <div>
          <h2 id="np-t">{effective === 'missing' ? 'Namespaces without default-deny' : 'All namespaces'}</h2>
          <div className="desc">{effective === 'missing' ? 'Any pod in these namespaces accepts traffic from anywhere in the cluster.' : 'NetworkPolicy coverage per namespace.'}</div>
        </div>
        <div className="inline">
          <div className="pills" role="group" aria-label="Show namespaces">
            <button type="button" className="pill" aria-pressed={effective === 'missing'} onClick={() => setFilter('missing')}>
              Without default-deny · {missing.length}
            </button>
            <button type="button" className="pill" aria-pressed={effective === 'all'} onClick={() => setFilter('all')}>
              All · {all.length}
            </button>
          </div>
          <label className="sr-only" htmlFor="np-q">
            Search namespaces
          </label>
          <input id="np-q" type="search" className="in search-sm" placeholder="Search cluster or namespace…" value={text} onChange={(e) => setText(e.target.value)} />
        </div>
      </div>
      <DataTable
        label="Network policies"
        what="network policies"
        rows={q.data ? rows : undefined}
        loading={q.isPending}
        error={q.isError ? q.error : undefined}
        onRetry={() => q.refetch()}
        columns={columns}
        rowKey={(n) => n.cluster_id + n.namespace}
        onRowClick={onOpen}
        rowLabel={(n) => `Open namespace ${n.namespace}${oneCluster ? '' : ` on ${n.cluster_name}`}`}
        filterText={text}
        resetKey={effective}
        initialSort={{ id: oneCluster ? 'ns' : 'cluster', dir: 'asc' }}
        empty={
          all.length === 0 ? (
            <EmptyState title="No namespaces reported yet">Agents report namespaces and NetworkPolicies after connecting.</EmptyState>
          ) : (
            <EmptyState title="Every namespace has default-deny">Nothing to fix here.</EmptyState>
          )
        }
      />
      <div className="card-foot">A namespace counts as default-deny when a policy selects all pods with policyTypes Ingress and no ingress rules. System namespaces are excluded. Open a namespace for a diagram of its policies and a connection simulator.</div>
    </section>
  );
}

// ------------------------------------------------------------ image detail

function ScanExplain({ d }: { d: ImageDetail }) {
  if (scannedByTag(d)) {
    return (
      <div className="note info" role="note">
        <div className="note-title">Scanned by tag · may differ from the running image</div>
        {tagScanWhy(d)}
      </div>
    );
  }
  if (d.scan_status === 'failed') {
    const n = d.scan_attempts ?? 0;
    return (
      <div className="note crit" role="note">
        <div className="note-title">
          Scan failed{n ? ` after ${plural(n, 'attempt')}` : ''}
          {d.next_retry_at ? ` · next automatic retry at ${clockTime(d.next_retry_at)} (${n} of ${MAX_SCAN_ATTEMPTS} attempts used)` : n >= MAX_SCAN_ATTEMPTS ? ' · no more automatic retries' : ''}
        </div>
        {d.scan_error && <pre className="err-text" style={{ marginTop: 6 }}>{d.scan_error}</pre>}
      </div>
    );
  }
  if (d.scan_status === 'unavailable') {
    return (
      <div className="note warn" role="note">
        <div className="note-title">Not in registry</div>
        {UNAVAILABLE_WHY}
        {d.scan_error && <pre className="err-text muted small" style={{ marginTop: 8 }}>{d.scan_error}</pre>}
      </div>
    );
  }
  if (d.scan_status === 'missing_credential') {
    return (
      <div className="note warn" role="note">
        <div className="note-title">No registry credential matches this image</div>
        {d.scan_error && <pre className="err-text" style={{ marginTop: 6 }}>{d.scan_error}</pre>}
        <div style={{ marginTop: 6 }}>
          Add a read-only credential in <Link to="/settings/registries">Settings › Registries</Link>, then retry.
        </div>
      </div>
    );
  }
  return null;
}

function ImageDialog({ digest, onClose, canOperate }: { digest: string; onClose: () => void; canOperate: boolean }) {
  const q = useQuery({ queryKey: ['images', digest], queryFn: () => api.get<ImageDetail>(`/images/${encodeURIComponent(digest)}`) });
  const { scan, busy } = useImageScan();
  const i = q.data;
  return (
    <Modal open onClose={onClose} size="wide" eyebrow="Image" title={<span className="mono" style={{ fontSize: 16 }}>{i ? imageName(i) : 'Image'}</span>} description={<span className="mono small">{digest}</span>}>
      <QueryView q={q} what="this image" isEmpty={() => false}>
        {(d) => (
          <>
            <ScanExplain d={d} />
            <div>
              <div className="lbl">Vulnerabilities</div>
              {d.vulns.length === 0 ? (
                <p className="muted small" style={{ margin: 0 }}>
                  {hasResults(d) ? 'No known vulnerabilities.' : 'Not scanned yet.'}
                </p>
              ) : (
                <div className="boxed tight">
                  <DataTable
                    label="Vulnerabilities"
                    what="vulnerabilities"
                    rows={d.vulns}
                    rowKey={(v) => v.cve_id + v.package}
                    pageSize={10}
                    pageSizes={[10, 25, 50]}
                    stickyHeader={false}
                    initialSort={{ id: 'sev', dir: 'asc' }}
                    columns={[
                      { id: 'cve', header: 'CVE', sortValue: (v) => v.cve_id, className: 'mono', cell: (v) => <span title={v.title}>{v.cve_id}</span> },
                      { id: 'sev', header: 'Severity', sortValue: (v) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(v.severity), cell: (v) => <SeverityBadge s={v.severity} /> },
                      { id: 'pkg', header: 'Package', sortValue: (v) => v.package, className: 'mono', cell: (v) => v.package },
                      { id: 'inst', header: 'Installed', className: 'mono', cell: (v) => v.installed },
                      { id: 'fix', header: 'Fixed in', className: 'mono', sortValue: (v) => v.fixed_in || null, cell: (v) => v.fixed_in || <span className="muted">no fix</span> },
                    ]}
                  />
                </div>
              )}
            </div>
            <div>
              <div className="lbl">Running in</div>
              <ul className="plain-list">
                {d.usage.map((u, n) => (
                  <li key={n} className="mono small" style={{ padding: '3px 0' }}>
                    {u.cluster_name} / {u.namespace} / {u.workload_kind} {u.workload_name} · {u.container}
                  </li>
                ))}
              </ul>
            </div>
            <div className="end">
              {canOperate && (
                <button type="button" className="btn" onClick={() => scan(d)} disabled={busy(d) || d.scan_status === 'scanning'}>
                  {busy(d) ? 'Queued…' : canRetry(d) ? 'Retry scan' : 'Rescan'}
                </button>
              )}
              <button type="button" className="btn pri" onClick={onClose}>
                Close
              </button>
            </div>
          </>
        )}
      </QueryView>
    </Modal>
  );
}
