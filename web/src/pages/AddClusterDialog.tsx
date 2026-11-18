import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { Cluster, InstallResponse } from '../api/types';
import { CheckIcon } from '../ui/icons';
import { Badge, CopyButton, Field, FormError, Modal, Spinner, aria, fieldError, useNow } from '../ui/kit';
import { TagInput } from '../ui/TagInput';

const NAME_RE = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;

function countdown(expiresAt: string, now: number): { text: string; expired: boolean } {
  const s = Math.round((new Date(expiresAt).getTime() - now) / 1000);
  if (s <= 0) return { text: 'Token expired', expired: true };
  const m = Math.floor(s / 60);
  return { text: m >= 1 ? `Token expires in ${m} min · single use` : `Token expires in ${s} s · single use`, expired: false };
}

/**
 * Add cluster (SPEC §2.2, §4.4): name + labels + bench opt-in → one-time Helm command,
 * then wait for the agent by polling /clusters/{id} until it is online.
 * `existing` re-issues a fresh command for a pending cluster (Settings › Clusters).
 */
export function AddClusterDialog({ open, onClose, existing }: { open: boolean; onClose: () => void; existing?: Cluster }) {
  const qc = useQueryClient();
  const [name, setName] = useState('');
  const [labels, setLabels] = useState<Record<string, string>>({});
  const [labelDraftErr, setLabelDraftErr] = useState<string | null>(null);
  const [bench, setBench] = useState(false);
  const [localErr, setLocalErr] = useState<Record<string, string>>({});
  const [install, setInstall] = useState<InstallResponse | null>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const now = useNow(1000);

  useEffect(() => {
    if (!open) {
      // The command contains a one-time token: drop it as soon as the dialog closes.
      setInstall(null);
      setName('');
      setLabels({});
      setLabelDraftErr(null);
      setBench(false);
      setLocalErr({});
    } else if (existing) {
      setName(existing.name);
      setLabels({ ...(existing.labels ?? {}) });
      setBench(existing.bench_enabled);
    }
  }, [open, existing]);

  const create = useMutation({
    mutationFn: (body: { name: string; labels: Record<string, string>; bench_enabled: boolean }) => api.post<InstallResponse>('/clusters', body),
    onSuccess: (r) => {
      setInstall(r);
      void qc.invalidateQueries({ queryKey: ['dashboard'] });
      void qc.invalidateQueries({ queryKey: ['clusters'] });
    },
  });
  const reissue = useMutation({
    mutationFn: (id: string) => api.post<InstallResponse>(`/clusters/${id}/token`),
    onSuccess: (r) => setInstall(r),
  });

  const clusterId = install?.cluster.id;
  const statusQ = useQuery({
    queryKey: ['clusters', clusterId, 'enroll'],
    queryFn: () => api.get<Cluster>(`/clusters/${clusterId}`),
    enabled: open && !!clusterId,
    refetchInterval: (q) => (q.state.data?.status === 'online' ? false : 3000),
  });
  const online = statusQ.data?.status === 'online';
  useEffect(() => {
    if (online) {
      void qc.invalidateQueries({ queryKey: ['dashboard'] });
      void qc.invalidateQueries({ queryKey: ['clusters'] });
    }
  }, [online, qc]);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (existing) {
      reissue.mutate(existing.id);
      return;
    }
    const errs: Record<string, string> = {};
    if (!NAME_RE.test(name)) errs.name = 'Use lowercase letters, digits and dashes (max 63), starting and ending with a letter or digit.';
    if (labelDraftErr) errs.labels = 'Fix or remove the label you are typing, then try again.';
    setLocalErr(errs);
    if (Object.keys(errs).length) {
      nameRef.current?.focus();
      return;
    }
    create.mutate({ name, labels, bench_enabled: bench });
  };

  const err = create.error ?? reissue.error;
  const nameErr = localErr.name ?? fieldError(err, 'name');
  const labelsErr = localErr.labels ?? fieldError(err, 'labels');
  const cd = install ? countdown(install.expires_at, now) : null;
  const locked = !!install || !!existing;

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="wide"
      eyebrow="Add cluster"
      title={existing ? `Install command for ${existing.name}` : 'Connect a cluster to Olympos'}
      description="The agent dials out to Olympos. No inbound port is needed on the cluster."
      initialFocus={locked ? undefined : nameRef}
    >
      <form onSubmit={submit} className="stack-sm" style={{ gap: 18 }} noValidate>
        <div className="grid-2">
          <Field label="Cluster name" htmlFor="ac-name" error={nameErr}>
            <input
              ref={nameRef}
              className="in mono"
              {...aria('ac-name', nameErr)}
              value={name}
              onChange={(e) => setName(e.target.value.trim())}
              placeholder="prod-aks-weu-01"
              readOnly={locked}
              autoComplete="off"
              spellCheck={false}
              required
            />
          </Field>
          <Field label="Labels" htmlFor="ac-labels" error={labelsErr} hint={!locked ? 'Type key=value and press Enter. Used for access and audit scopes. olympos.io/cluster=<name> is added automatically.' : undefined}>
            <TagInput {...aria('ac-labels', labelsErr, !locked)} value={labels} onChange={setLabels} placeholder="env=prod" readOnly={locked} onDraftError={setLabelDraftErr} lockedPrefix="olympos.io/" />
          </Field>
        </div>
        <label className="opt">
          <input type="checkbox" checked={bench} onChange={(e) => setBench(e.target.checked)} disabled={locked} />
          <span>
            <span className="t1">Enable kube-bench on this cluster</span>
            <span className="t2">
              Adds a privileged, read-only Job per node in namespace <span className="mono">olympos-bench</span>. You can enable it later with a Helm upgrade.
            </span>
          </span>
        </label>

        <FormError error={err && !nameErr && !labelsErr ? err : null} />

        {install && cd && (
          <>
            <div>
              <div className="spread" style={{ marginBottom: 6 }}>
                <span className="lbl" style={{ margin: 0 }}>
                  Run on the cluster
                </span>
                <span aria-live="polite">
                  <Badge tone={cd.expired ? 'crit' : 'warn'}>{cd.text}</Badge>
                </span>
              </div>
              <pre className="code scroll" aria-label="Helm install command" tabIndex={0}>
                {install.command}
              </pre>
            </div>
            {online ? (
              <div className="panel" role="status">
                <CheckIcon ok label="Connected" />
                <span>
                  Agent connected. <span className="mono">{statusQ.data?.name}</span> is online
                  {statusQ.data?.api_version ? (
                    <>
                      {' '}
                      · Kubernetes <span className="mono">{statusQ.data.api_version}</span>
                    </>
                  ) : null}
                  .
                </span>
              </div>
            ) : cd.expired ? (
              <div className="panel" role="status">
                <Badge tone="crit">Expired</Badge>
                <span>The token expired before the agent connected. Issue a new command and run it again.</span>
                <button type="button" className="btn sm" onClick={() => reissue.mutate(install.cluster.id)} disabled={reissue.isPending}>
                  Issue new command
                </button>
              </div>
            ) : (
              <div className="panel dashed" role="status" aria-live="polite">
                <Spinner label="Waiting" />
                <span>Waiting for the agent to connect…</span>
                {statusQ.isError && <span className="muted small">Could not check status; retrying.</span>}
              </div>
            )}
          </>
        )}

        <div className="end">
          {install ? (
            <>
              <CopyButton text={install.command} label="Copy command" />
              <button type="button" className="btn pri" onClick={onClose}>
                Done
              </button>
            </>
          ) : (
            <>
              <button type="button" className="btn" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className="btn pri" disabled={create.isPending || reissue.isPending}>
                {create.isPending || reissue.isPending ? 'Creating…' : existing ? 'Issue install command' : 'Create install command'}
              </button>
            </>
          )}
        </div>
      </form>
    </Modal>
  );
}
