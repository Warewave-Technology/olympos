// Vault identity: shown wherever a change could go to the wrong vault (detail header,
// change-request drawer, confirmations, approvals).
import type { ReactNode } from 'react';
import type { Vault } from '../api/types';
import { Badge, Chip } from './kit';

export function providerName(p: string | undefined): string {
  return p === 'openbao' ? 'OpenBao' : 'HashiCorp Vault';
}

export function VaultStatusBadge({ v }: { v: Pick<Vault, 'status'> }) {
  switch (v.status) {
    case 'configured':
      return <Badge tone="ok">Configured</Badge>;
    case 'discovered':
      return <Badge tone="info">Discovered</Badge>;
    case 'error':
      return <Badge tone="crit">Error</Badge>;
    default:
      return <Badge tone="mute">Gone</Badge>;
  }
}

/** "cluster / namespace / service" as plain text (aria labels, confirmations). */
export function vaultPath(x: { cluster: string; namespace?: string; service: string }): string {
  return [x.cluster, x.namespace, x.service].filter(Boolean).join(' / ');
}

export function VaultIdentity({
  cluster,
  namespace,
  service,
  provider,
  version,
  status,
  labels,
  compact,
  extra,
}: {
  cluster: string;
  namespace?: string;
  service: string;
  provider?: string;
  version?: string;
  status?: Vault['status'];
  labels?: Record<string, string>;
  compact?: boolean;
  extra?: ReactNode;
}) {
  const parts = [cluster, namespace, service].filter(Boolean) as string[];
  return (
    <div className={`vault-id${compact ? ' compact' : ''}`}>
      <div className="path" aria-label={`Vault ${vaultPath({ cluster, namespace, service })}`}>
        {parts.map((p, i) => (
          <span key={i}>
            {i > 0 && (
              <span className="sep" aria-hidden="true">
                /
              </span>
            )}
            {p}
          </span>
        ))}
      </div>
      <div className="inline-sm small">
        {provider && (
          <Badge tone="mute">
            {providerName(provider)}
            {version ? ` ${version}` : ''}
          </Badge>
        )}
        {status && <VaultStatusBadge v={{ status }} />}
        {labels &&
          Object.entries(labels).map(([k, v]) => (
            <Chip key={k}>
              {k}={v}
            </Chip>
          ))}
        {extra}
      </div>
    </div>
  );
}

export function vaultIdentityProps(v: Vault) {
  return { cluster: v.target.cluster_name, namespace: v.target.namespace, service: v.target.service, provider: v.provider, version: v.version };
}
