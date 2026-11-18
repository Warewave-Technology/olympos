import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { Cluster, ItemList, Provider, TransferMode } from '../../api/types';
import { useCan } from '../../auth/me';
import { bytes, money, plural, shortDate } from '../../lib/format';
import { formatLabels } from '../../lib/labels';
import { clustersSettingsRoute } from '../../router';
import { Badge, Chip, EmptyState, Field, FormError, Modal, TypeToConfirm, aria, fieldError, useNow, useToast } from '../../ui/kit';
import { ClusterStatusBadge } from '../../ui/status';
import { Select } from '../../ui/Select';
import { TagInput } from '../../ui/TagInput';
import { AddClusterDialog } from '../AddClusterDialog';
import { SettingsLayout } from './SettingsLayout';
import { DataTable } from '../../ui/DataTable';

const PROVIDERS: { id: Provider; label: string }[] = [
  { id: 'azure', label: 'Azure' },
  { id: 'aws', label: 'AWS' },
  { id: 'gcp', label: 'GCP' },
  { id: 'oracle', label: 'Oracle Cloud' },
  { id: 'huawei', label: 'Huawei Cloud' },
  { id: 'onprem', label: 'On-prem' },
];

export function ClustersSettingsPage() {
  const { cluster: selectedId } = clustersSettingsRoute.useSearch();
  const navigate = useNavigate({ from: '/settings/clusters' });
  const canAdmin = useCan('admin_global');
  const [adding, setAdding] = useState(false);
  const now = useNow(30_000);
  const q = useQuery({ queryKey: ['clusters'], queryFn: () => api.get<ItemList<Cluster>>('/clusters'), refetchInterval: 30_000 });
  const list = q.data?.items ?? [];
  const selected = list.find((c) => c.id === selectedId) ?? list.find((c) => c.status !== 'revoked');
  const [text, setText] = useState('');

  return (
    <SettingsLayout
      current="clusters"
      sub="Clusters & agents · labels drive access scopes and audit scopes"
      actions={
        canAdmin && (
          <button type="button" className="btn pri" onClick={() => setAdding(true)}>
            Add cluster
          </button>
        )
      }
    >
      <section className="card" aria-label="Clusters">
        <div className="card-head">
          <h2>Clusters</h2>
          <span>
            <label className="sr-only" htmlFor="cl-q">
              Search clusters
            </label>
            <input id="cl-q" type="search" className="in search-sm" placeholder="Search name, label, provider…" value={text} onChange={(e) => setText(e.target.value)} />
          </span>
        </div>
        <DataTable
          label="Clusters"
          what="clusters"
          rows={q.data?.items}
          loading={q.isPending}
          error={q.isError ? q.error : undefined}
          onRetry={() => q.refetch()}
          rowKey={(c) => c.id}
          filterText={text}
          rowClassName={(c) => (c.id === selected?.id ? 'sel' : undefined)}
          onRowClick={(c) => navigate({ search: { cluster: c.id }, replace: true })}
          rowLabel={(c) => `Show settings of ${c.name}`}
          initialSort={{ id: 'name', dir: 'asc' }}
          empty={
            <EmptyState
              title="No clusters yet"
              action={
                canAdmin ? (
                  <button type="button" className="btn pri" onClick={() => setAdding(true)}>
                    Add cluster
                  </button>
                ) : undefined
              }
            >
              {canAdmin ? 'Add a cluster to get a one-time Helm command for the agent.' : 'No clusters are in your access scope.'}
            </EmptyState>
          }
          columns={[
            {
              id: 'name',
              header: 'Cluster',
              sortValue: (c) => c.name,
              searchText: (c) => `${c.name} ${formatLabels(c.labels ?? {}, ' ')} ${c.provider_label} ${c.region} ${c.agent_version}`,
              cell: (c) => (
                <button type="button" className="link-btn mono" onClick={() => navigate({ search: { cluster: c.id }, replace: true })} aria-current={c.id === selected?.id}>
                  {c.name}
                </button>
              ),
            },
            { id: 'labels', header: 'Labels', className: 'wrap', cell: (c) => (Object.keys(c.labels ?? {}).length ? Object.entries(c.labels).map(([k, v]) => <Chip key={k}>{`${k}=${v}`}</Chip>) : <span className="muted">none</span>) },
            {
              id: 'provider',
              header: 'Provider',
              sortValue: (c) => c.provider_label || null,
              cell: (c) => (
                <>
                  {c.provider_label || (c.status === 'pending' ? <span className="muted">after enrollment</span> : 'On-prem')}
                  {c.provider_override && <span className="muted"> (override)</span>}
                </>
              ),
            },
            { id: 'agent', header: 'Agent', sortValue: (c) => c.agent_version || null, className: 'mono', cell: (c) => c.agent_version || '—' },
            { id: 'transfer', header: 'Transfer', sortValue: (c) => c.transfer_mode, cell: (c) => (c.transfer_mode === 'compressed' ? <Badge tone="warn">compressed</Badge> : <Badge tone="ok">e2e-tls</Badge>) },
            { id: 'bench', header: 'kube-bench', sortValue: (c) => c.bench_enabled, cell: (c) => (c.bench_enabled ? <Badge tone="ok">On</Badge> : <Badge tone="mute">Off</Badge>) },
            { id: 'status', header: 'Status', sortValue: (c) => c.status, cell: (c) => <ClusterStatusBadge c={c} now={now} /> },
          ]}
        />
        <div className="card-spacer" />
      </section>
      {selected && <ClusterSettings key={selected.id + selected.status} c={selected} canAdmin={canAdmin} />}
      <AddClusterDialog open={adding} onClose={() => setAdding(false)} />
    </SettingsLayout>
  );
}

function ClusterSettings({ c, canAdmin }: { c: Cluster; canAdmin: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [labels, setLabels] = useState<Record<string, string>>({ ...(c.labels ?? {}) });
  const [labelDraftErr, setLabelDraftErr] = useState<string | null>(null);
  const [override, setOverride] = useState(c.provider_override);
  const [mode, setMode] = useState<TransferMode>(c.transfer_mode);
  const [rate, setRate] = useState(c.egress_rate_per_gb != null ? String(c.egress_rate_per_gb) : '');
  const [labelErr, setLabelErr] = useState<string | undefined>();
  const [rateErr, setRateErr] = useState<string | undefined>();
  const [revoking, setRevoking] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [confirmText, setConfirmText] = useState('');

  const save = useMutation({
    mutationFn: (body: object) => api.patch<Cluster>(`/clusters/${c.id}`, body),
    onSuccess: (r) => {
      toast(r.transfer_mode === 'compressed' && c.transfer_mode !== 'compressed' ? `Saved. ${r.name} now uses compressed mode; a finding was added in Security.` : `Saved ${r.name}.`);
      void qc.invalidateQueries({ queryKey: ['clusters'] });
      void qc.invalidateQueries({ queryKey: ['dashboard'] });
      void qc.invalidateQueries({ queryKey: ['findings'] });
    },
  });
  const revoke = useMutation({
    mutationFn: () => api.del(`/clusters/${c.id}`),
    onSuccess: () => {
      setRevoking(false);
      toast(`${c.name} revoked. Its certificate is denied and open streams were dropped.`);
      void qc.invalidateQueries({ queryKey: ['clusters'] });
      void qc.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setLabelErr(labelDraftErr ? 'Fix or remove the label you are typing.' : undefined);
    const n = rate.trim() === '' ? null : Number(rate.replace(/[^0-9.]/g, ''));
    const badRate = n !== null && (Number.isNaN(n) || n < 0);
    setRateErr(badRate ? 'Enter a number such as 0.09, or leave empty.' : undefined);
    if (labelDraftErr || badRate) return;
    save.mutate({
      labels,
      provider_override: override,
      transfer_mode: mode,
      ...(n === null ? { clear_egress_rate: true } : { egress_rate_per_gb: n }),
    });
  };

  const wire = c.backup_wire_bytes_30d;
  const raw = c.backup_bytes_30d;
  const rateNum = Number(rate.replace(/[^0-9.]/g, ''));
  const cost = wire != null && rate.trim() !== '' && !Number.isNaN(rateNum) ? (wire / 1e9) * rateNum : null;
  const detected = PROVIDERS.find((p) => p.id === c.provider)?.label ?? 'none (on-prem)';
  const switchingToCompressed = mode === 'compressed' && c.transfer_mode !== 'compressed';
  const revoked = c.status === 'revoked';

  const desc = [
    c.provider_label && c.region ? `${c.provider_label} ${c.region}` : c.provider_label || null,
    c.nodes ? plural(c.nodes, 'node') : null,
    `enrolled ${shortDate(c.created_at)}`,
    c.cert_expires_at ? `cert renews ${shortDate(new Date(new Date(c.cert_expires_at).getTime() - 10 * 86400000).toISOString())}` : null,
  ]
    .filter(Boolean)
    .join(' · ');

  if (!canAdmin) {
    return (
      <section className="card pad-lg" aria-labelledby="cs-t">
        <div className="card-title">
          <div>
            <div className="eyebrow">Cluster settings</div>
            <h2 id="cs-t" className="mono">
              {c.name}
            </h2>
            <div className="card-desc">{desc}</div>
          </div>
        </div>
        <dl className="dl">
          <dt>Labels</dt>
          <dd className="mono">{formatLabels(c.labels) || '—'}</dd>
          <dt>Provider</dt>
          <dd>{c.provider_label || '—'}{c.provider_override ? ' (override)' : ''}</dd>
          <dt>Transfer mode</dt>
          <dd>{c.transfer_mode}</dd>
          <dt>Egress rate</dt>
          <dd>{c.egress_rate_per_gb != null ? `${c.egress_rate_per_gb} USD/GB` : 'not set'}</dd>
          <dt>kube-bench</dt>
          <dd>{c.bench_enabled ? 'on' : 'off'}</dd>
        </dl>
        <p className="muted small" style={{ margin: 0 }}>Only admins with scope all can change cluster settings.</p>
      </section>
    );
  }

  return (
    <section className="card pad-lg" aria-labelledby="cs-t" style={{ gap: 20 }}>
      <div className="card-title">
        <div>
          <div className="eyebrow">Cluster settings</div>
          <h2 id="cs-t" className="mono">
            {c.name}
          </h2>
          <div className="card-desc">{desc}</div>
        </div>
      </div>
      {revoked ? (
        <div className="note">This cluster was revoked. Its agent certificate is on the deny list; add it again to re-enroll.</div>
      ) : (
        <form onSubmit={submit} className="stack" noValidate>
          <div className="grid-2">
            <Field label="Labels" htmlFor="cs-labels" error={labelErr ?? fieldError(save.error, 'labels')} hint="Type key=value and press Enter; Backspace removes the last one. olympos.io/cluster is set by Olympos.">
              <TagInput {...aria('cs-labels', labelErr ?? fieldError(save.error, 'labels'), true)} value={labels} onChange={setLabels} onDraftError={setLabelDraftErr} lockedPrefix="olympos.io/" />
            </Field>
            <Field label="Provider" htmlFor="cs-prov" error={fieldError(save.error, 'provider_override')}>
              <Select
                id="cs-prov"
                value={override}
                onChange={setOverride}
                options={[{ value: '', label: `Detected: ${detected}`, hint: 'from the nodes’ providerID' }, ...PROVIDERS.map((p) => ({ value: p.id as string, label: `Override: ${p.label}` }))]}
              />
            </Field>
          </div>
          <fieldset className="opts">
            <legend className="lbl">Transfer mode for backups</legend>
            <label className="opt">
              <input type="radio" name="tm" checked={mode === 'e2e-tls'} onChange={() => setMode('e2e-tls')} />
              <span>
                <span className="t1">e2e-tls</span> <Badge tone="ok">Default</Badge>
                <span className="t2">TLS from the server to the database. The agent only sees ciphertext. Data crosses the network uncompressed.</span>
              </span>
            </label>
            <label className="opt">
              <input type="radio" name="tm" checked={mode === 'compressed'} onChange={() => setMode('compressed')} aria-describedby="tm-tradeoff" />
              <span>
                <span className="t1">compressed</span>
                <span className="t2" id="tm-tradeoff">
                  zstd on the agent tunnel, typically 5–10× less egress. The database connection inside the cluster is not TLS, so the agent can see backup data.
                </span>
              </span>
            </label>
          </fieldset>
          {switchingToCompressed && (
            <div className="note warn" role="alert">
              <b>Before you save:</b> in compressed mode the server connects to the database without TLS, and the agent can see backup data in plaintext inside the cluster. Saving adds the finding <span className="mono">transfer.compressed_mode</span> on this cluster; it stays in Security until you switch back to e2e-tls.
            </div>
          )}
          {c.transfer_mode === 'compressed' && mode === 'compressed' && <div className="note warn">This cluster runs in compressed mode. A finding is shown in Security until you switch back.</div>}
          {c.transfer_mode === 'compressed' && mode === 'e2e-tls' && <div className="note">Switching back to e2e-tls resolves the compressed-mode finding after saving.</div>}
          <div className="grid-3">
            <Field label="Egress rate (USD per GB)" htmlFor="cs-rate" error={rateErr ?? fieldError(save.error, 'egress_rate_per_gb')} hint="Leave empty when transfer is free.">
              <input className="in mono" inputMode="decimal" {...aria('cs-rate', rateErr, true)} value={rate} onChange={(e) => setRate(e.target.value)} placeholder="0.09" />
            </Field>
            <div>
              <div className="lbl">Backup transfer, last 30 days</div>
              <div className="big-num">
                {wire != null ? bytes(wire) : '—'}
                {raw != null && wire != null && raw > wire && <span className="muted" style={{ fontSize: 13, fontWeight: 400 }}> · was ~{bytes(raw)} raw</span>}
              </div>
            </div>
            <div>
              <div className="lbl">Estimated monthly cost</div>
              <div className="big-num">{cost != null ? `≈ ${money(cost)}` : '—'}</div>
            </div>
          </div>
          <div className="note">
            kube-bench is <b>{c.bench_enabled ? 'on' : 'off'}</b> for this cluster. It is set by the agent Helm value <span className="mono">bench.enabled</span>, so the agent only has Job permissions where you allowed them. Change it with a Helm upgrade.
          </div>
          <FormError error={save.error} />
          <div className="foot-actions">
            <button type="button" className="btn danger" onClick={() => setRevoking(true)}>
              Revoke agent
            </button>
            <div className="inline">
              <button type="button" className="btn" onClick={() => setInstalling(true)}>
                Show install command
              </button>
              <button type="submit" className="btn pri" disabled={save.isPending}>
                Save
              </button>
            </div>
          </div>
        </form>
      )}
      {revoking && (
        <Modal open onClose={() => setRevoking(false)} danger eyebrow="Irreversible" eyebrowTone="crit" title={`Revoke the agent of ${c.name}?`} description="The agent certificate is added to the deny list and open streams are dropped. Backups, audits and vault access through this cluster stop. Re-adding the cluster needs a new install.">
          <form
            className="stack-sm"
            style={{ gap: 18 }}
            onSubmit={(e) => {
              e.preventDefault();
              if (confirmText === c.name) revoke.mutate();
            }}
          >
            <TypeToConfirm id="rv-confirm" expected={c.name} value={confirmText} onChange={setConfirmText} />
            <FormError error={revoke.error} />
            <div className="end">
              <button type="button" className="btn" onClick={() => setRevoking(false)}>
                Cancel
              </button>
              <button type="submit" className="btn danger" disabled={confirmText !== c.name || revoke.isPending}>
                Revoke agent
              </button>
            </div>
          </form>
        </Modal>
      )}
      <AddClusterDialog open={installing} onClose={() => setInstalling(false)} existing={c} />
    </section>
  );
}
