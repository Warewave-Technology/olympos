import { useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../api/client';
import type { Image, ImageDetail, ItemList, KyvernoPolicy, NetpolNamespace } from '../api/types';
import { useCan } from '../auth/me';
import { age, plural, shortDigest } from '../lib/format';
import { securityRoute } from '../router';
import { Badge, EmptyState, Modal, QueryView, Tabs, useToast } from '../ui/kit';
import { PageHead, SeverityBadge } from '../ui/status';

type Tab = 'images' | 'kyverno' | 'netpol';

function imageName(i: Image) {
  return i.tags.length ? `${i.repo}:${i.tags[0]}` : i.repo;
}

function credentialCell(i: Image) {
  if (i.scan_status === 'missing_credential') return <Badge tone="warn">Missing credential</Badge>;
  if (i.registry) return <span className="mono">{i.registry}</span>;
  return <span className="muted">public</span>;
}

function fixCell(i: Image) {
  if (i.scan_status !== 'scanned') return <span className="muted">—</span>;
  if (i.critical + i.high === 0) return <span className="muted">—</span>;
  return i.fixed_in ? <Badge tone="ok">Yes · {i.fixed_in}</Badge> : <Badge tone="mute">No</Badge>;
}

export function SecurityPage() {
  const { tab = 'images', digest } = securityRoute.useSearch();
  const navigate = useNavigate({ from: '/security' });
  const canOperate = useCan('operate');
  const qc = useQueryClient();
  const toast = useToast();
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('');
  const imagesQ = useQuery({ queryKey: ['images', { q, sev }], queryFn: () => api.get<ItemList<Image>>('/images', { q, severity: sev }) });
  const allImagesQ = useQuery({ queryKey: ['images', {}], queryFn: () => api.get<ItemList<Image>>('/images') });
  const kyQ = useQuery({ queryKey: ['kyverno'], queryFn: () => api.get<ItemList<KyvernoPolicy>>('/security/kyverno') });
  const npQ = useQuery({ queryKey: ['netpol'], queryFn: () => api.get<ItemList<NetpolNamespace>>('/security/netpol') });
  const scan = useMutation({
    mutationFn: () => api.post('/images/scan'),
    onSuccess: () => {
      toast('Scan queued for all running images.');
      setTimeout(() => void qc.invalidateQueries({ queryKey: ['images'] }), 2000);
    },
    onError: (e) => toast(`Could not queue the scan: ${errorMessage(e)}`, 'crit'),
  });

  const all = allImagesQ.data?.items ?? [];
  const lastScan = all.map((i) => i.last_scanned_at).filter(Boolean).sort().pop() ?? null;
  const critImages = all.filter((i) => i.critical > 0);
  const critTotal = critImages.reduce((s, i) => s + i.critical, 0);
  const critFix = critImages.filter((i) => i.fixed_in).length;
  const workloads = all.reduce((s, i) => s + i.workloads, 0);
  const kyFail = (kyQ.data?.items ?? []).reduce((s, p) => s + p.fail_count, 0);
  const noDeny = (npQ.data?.items ?? []).filter((n) => !n.default_deny && !n.excluded);

  return (
    <>
      <PageHead
        title="Security"
        sub={`Images are deduplicated by digest across clusters${lastScan ? ` · last scan ${age(lastScan)} ago` : ''}`}
        actions={
          canOperate && (
            <button type="button" className="btn" onClick={() => scan.mutate()} disabled={scan.isPending}>
              Scan now
            </button>
          )
        }
      />
      <section className="stats four" aria-label="Security totals">
        <div className="card stat">
          <div className="k">Unique images</div>
          <div className="v">{allImagesQ.data ? all.length : '—'}</div>
          <div className="d">across {plural(workloads, 'running workload')}</div>
        </div>
        <div className="card stat">
          <div className="k">Critical CVEs</div>
          <div className={`v${critTotal ? ' crit' : ''}`}>{allImagesQ.data ? critTotal : '—'}</div>
          <div className="d">
            in {plural(critImages.length, 'image')} · {critFix} with a fix
          </div>
        </div>
        <div className="card stat">
          <div className="k">Kyverno violations</div>
          <div className={`v${kyFail ? ' warn' : ''}`}>{kyQ.data ? kyFail : '—'}</div>
          <div className="d">from PolicyReports</div>
        </div>
        <div className="card stat">
          <div className="k">No default-deny</div>
          <div className={`v${noDeny.length ? ' warn' : ''}`}>{npQ.data ? noDeny.length : '—'}</div>
          <div className="d">namespaces without a default-deny policy</div>
        </div>
      </section>

      <Tabs<Tab>
        label="Security sections"
        value={tab}
        onChange={(t) => navigate({ search: { tab: t === 'images' ? undefined : t }, replace: true })}
        tabs={[
          { id: 'images', label: 'Images' },
          { id: 'kyverno', label: 'Kyverno policies' },
          { id: 'netpol', label: 'Network policies' },
        ]}
      />

      {tab === 'images' && (
        <>
          <section className="card" aria-label="Images">
            <div className="card-head">
              <div className="inline">
                <label className="sr-only" htmlFor="img-q">
                  Search images
                </label>
                <input id="img-q" type="search" className="in search" placeholder="Search repository or digest…" value={q} onChange={(e) => setQ(e.target.value)} />
                <div className="pills" role="group" aria-label="Severity filter">
                  {[
                    ['', 'All'],
                    ['critical', 'With critical'],
                    ['high', 'With high'],
                  ].map(([v, l]) => (
                    <button key={v} type="button" className="pill" aria-pressed={sev === v} onClick={() => setSev(v)}>
                      {l}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <QueryView
              q={imagesQ}
              what="images"
              isEmpty={(d) => d.items.length === 0}
              empty={<EmptyState title={q || sev ? 'No images match' : 'No images reported yet'}>{q || sev ? 'Try another search or filter.' : 'Agents report running images (by digest) within a minute of connecting.'}</EmptyState>}
            >
              {(d) => (
                <div className="table-wrap">
                  <table className="t">
                    <thead>
                      <tr>
                        <th>Image · digest</th>
                        <th>Running in</th>
                        <th className="num">Critical</th>
                        <th className="num">High</th>
                        <th>Fix available</th>
                        <th>Pull credential</th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.items.map((i) => (
                        <tr key={i.digest}>
                          <td className="mono">
                            <button type="button" className="link-btn mono" onClick={() => navigate({ search: (s) => ({ ...s, digest: i.digest }) })} aria-label={`Details for ${imageName(i)}`}>
                              {imageName(i)}
                            </button>
                            <div className="mono muted small">{shortDigest(i.digest)}</div>
                          </td>
                          <td>
                            {plural(i.clusters, 'cluster')} · {plural(i.workloads, 'workload')}
                          </td>
                          {i.scan_status === 'scanned' ? (
                            <>
                              <td className="num">
                                <span className={`n${i.critical ? ' crit' : ''}`}>{i.critical}</span>
                              </td>
                              <td className="num">
                                <span className="n">{i.high}</span>
                              </td>
                            </>
                          ) : (
                            <td className="num" colSpan={2}>
                              {i.scan_status === 'missing_credential' ? <span className="muted">not scanned</span> : <Badge tone={i.scan_status === 'failed' ? 'crit' : 'info'}>{i.scan_status === 'failed' ? 'Scan failed' : i.scan_status === 'scanning' ? 'Scanning' : 'Pending'}</Badge>}
                            </td>
                          )}
                          <td>{fixCell(i)}</td>
                          <td>{credentialCell(i)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </QueryView>
            <div className="card-foot">
              Registry credentials are server objects (<Link to="/settings/registries">Settings › Registries</Link>). The agent never reads imagePullSecrets.
            </div>
          </section>
          <div className="row gap-sm">
            <section className="card half" aria-labelledby="ky-top">
              <div className="card-head">
                <h2 id="ky-top">Top Kyverno violations</h2>
              </div>
              <KyvernoTable q={kyQ} top />
            </section>
            <section className="card half" aria-labelledby="np-top">
              <div className="card-head">
                <h2 id="np-top">Namespaces without default-deny</h2>
              </div>
              <NetpolTable q={npQ} onlyMissing top />
            </section>
          </div>
        </>
      )}
      {tab === 'kyverno' && (
        <section className="card" aria-label="Kyverno policies">
          <KyvernoTable q={kyQ} />
          <div className="card-foot">Read from ClusterPolicy / Policy and PolicyReports by the agent. Failures are recorded as findings (source kyverno).</div>
        </section>
      )}
      {tab === 'netpol' && (
        <section className="card" aria-label="Network policies">
          <NetpolTable q={npQ} />
          <div className="card-foot">A namespace counts as default-deny when a policy selects all pods with policyTypes Ingress and no ingress rules. System namespaces are excluded.</div>
        </section>
      )}

      {digest && <ImageDialog digest={digest} onClose={() => navigate({ search: (s) => ({ ...s, digest: undefined }) })} canOperate={canOperate} />}
    </>
  );
}

function KyvernoTable({ q, top }: { q: ReturnType<typeof useQuery<ItemList<KyvernoPolicy>>>; top?: boolean }) {
  return (
    <QueryView q={q} what="Kyverno policies" isEmpty={(d) => d.items.length === 0} empty={<EmptyState title="No Kyverno policies found">Either Kyverno is not installed on the clusters in your scope, or it has no ClusterPolicy/Policy yet.</EmptyState>}>
      {(d) => {
        const list = top ? [...d.items].filter((p) => p.fail_count > 0).sort((a, b) => b.fail_count - a.fail_count).slice(0, 5) : d.items;
        if (top && list.length === 0) return <EmptyState title="No violations">Every policy passes in the latest PolicyReports.</EmptyState>;
        return (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th>Policy</th>
                  {!top && <th>Cluster</th>}
                  {!top && <th>Namespace</th>}
                  <th>Mode</th>
                  {!top && <th className="num">Rules</th>}
                  <th className="num">Fail</th>
                </tr>
              </thead>
              <tbody>
                {list.map((p) => (
                  <tr key={p.cluster_id + p.namespace + p.name}>
                    <td className="mono">
                      {p.name}
                      {!p.ready && (
                        <>
                          {' '}
                          <Badge tone="warn">Not ready</Badge>
                        </>
                      )}
                    </td>
                    {!top && <td className="mono">{p.cluster_name}</td>}
                    {!top && <td className={p.namespace ? 'mono' : 'muted'}>{p.namespace || 'cluster-wide'}</td>}
                    <td>{p.mode === 'Enforce' ? <Badge tone="ok">Enforce</Badge> : <Badge tone="info">Audit</Badge>}</td>
                    {!top && <td className="num">{p.rules}</td>}
                    <td className={`num${p.fail_count ? ' up' : ''}`}>{p.fail_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      }}
    </QueryView>
  );
}

function NetpolTable({ q, onlyMissing, top }: { q: ReturnType<typeof useQuery<ItemList<NetpolNamespace>>>; onlyMissing?: boolean; top?: boolean }) {
  return (
    <QueryView q={q} what="network policies" isEmpty={(d) => d.items.length === 0} empty={<EmptyState title="No namespaces reported yet">Agents report namespaces and NetworkPolicies after connecting.</EmptyState>}>
      {(d) => {
        let list = onlyMissing ? d.items.filter((n) => !n.default_deny && !n.excluded) : d.items;
        if (top) list = list.slice(0, 6);
        if (list.length === 0) return <EmptyState title="Every namespace has default-deny">Nothing to fix here.</EmptyState>;
        return (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th>Cluster</th>
                  <th>Namespace</th>
                  <th className="num">Policies</th>
                  {!onlyMissing && <th>Default-deny</th>}
                </tr>
              </thead>
              <tbody>
                {list.map((n) => (
                  <tr key={n.cluster_id + n.namespace}>
                    <td className="mono">{n.cluster_name}</td>
                    <td className="mono">{n.namespace}</td>
                    <td className="num">{n.policy_count === 0 ? 0 : !n.default_deny ? `${n.policy_count} (allow only)` : n.policy_count}</td>
                    {!onlyMissing && <td>{n.excluded ? <Badge tone="mute">Excluded · system</Badge> : n.default_deny ? <Badge tone="ok">Yes</Badge> : <Badge tone="warn">Missing</Badge>}</td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      }}
    </QueryView>
  );
}

function ImageDialog({ digest, onClose, canOperate }: { digest: string; onClose: () => void; canOperate: boolean }) {
  const q = useQuery({ queryKey: ['images', digest], queryFn: () => api.get<ImageDetail>(`/images/${encodeURIComponent(digest)}`) });
  const toast = useToast();
  const rescan = useMutation({
    mutationFn: () => api.post(`/images/${encodeURIComponent(digest)}/scan`),
    onSuccess: () => toast('Rescan queued.'),
    onError: (e) => toast(`Could not queue the rescan: ${errorMessage(e)}`, 'crit'),
  });
  const i = q.data;
  return (
    <Modal open onClose={onClose} size="wide" eyebrow="Image" title={<span className="mono" style={{ fontSize: 16 }}>{i ? imageName(i) : 'Image'}</span>} description={<span className="mono small">{digest}</span>}>
      <QueryView q={q} what="this image" isEmpty={() => false}>
        {(d) => (
          <>
            {d.scan_error && <div className="note warn">{d.scan_error}{d.scan_status === 'missing_credential' && <> · add one in <Link to="/settings/registries">Settings › Registries</Link></>}</div>}
            <div>
              <div className="lbl">Vulnerabilities</div>
              {d.vulns.length === 0 ? (
                <p className="muted small" style={{ margin: 0 }}>{d.scan_status === 'scanned' ? 'No known vulnerabilities.' : 'Not scanned yet.'}</p>
              ) : (
                <div className="boxed tight table-wrap">
                  <table className="t">
                    <thead>
                      <tr>
                        <th>CVE</th>
                        <th>Severity</th>
                        <th>Package</th>
                        <th>Installed</th>
                        <th>Fixed in</th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.vulns.map((v) => (
                        <tr key={v.cve_id + v.package}>
                          <td className="mono" title={v.title}>
                            {v.cve_id}
                          </td>
                          <td>
                            <SeverityBadge s={v.severity} />
                          </td>
                          <td className="mono">{v.package}</td>
                          <td className="mono">{v.installed}</td>
                          <td className="mono">{v.fixed_in || <span className="muted">no fix</span>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
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
                <button type="button" className="btn" onClick={() => rescan.mutate()} disabled={rescan.isPending}>
                  Rescan
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
