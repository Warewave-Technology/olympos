import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Vault } from '../api/types';
import { groupByCluster, matchesVault } from '../pages/Vaults';
import { renderApp } from './renderApp';

afterEach(cleanup);
const T = { timeout: 5000 };

function v(id: string, cluster: string, service: string, ns: string, provider: Vault['provider'], labels: Record<string, string>): Vault {
  return {
    id,
    target: { id: 't' + id, cluster_id: 'c-' + cluster, cluster_name: cluster, namespace: ns, service, port: 8200, port_name: '', engine: '', vault_provider: provider, tls_server_name: '', detected_version: '', tls_ok: true, status: 'configured', first_seen_at: '', last_seen_at: '' },
    cluster_labels: labels,
    provider,
    version: provider === 'openbao' ? '2.1.0' : '1.18.2',
    status: 'configured',
    kv_mounts: [],
    configured_by_name: '',
    configured_at: null,
    secret_id_rotated_at: null,
    last_index_at: null,
    secrets: 0,
    drift: 0,
    last_error: '',
  };
}

describe('vault grouping and matching', () => {
  const list = [v('1', 'prod-b', 'vault', 'vault', 'hashicorp', { env: 'prod' }), v('2', 'prod-a', 'openbao', 'security', 'openbao', { env: 'prod', team: 'core' }), v('3', 'prod-b', 'bao-ci', 'ci', 'openbao', { env: 'prod' }), v('4', 'lab', 'vault', 'vault', 'hashicorp', { env: 'lab' })];

  it('groups by cluster, sorted, with vaults sorted inside', () => {
    const g = groupByCluster(list);
    expect(g.map((x) => x.clusterName)).toEqual(['lab', 'prod-a', 'prod-b']);
    expect(g[2].vaults.map((x) => x.target.service)).toEqual(['bao-ci', 'vault']);
    expect(g[1].labels).toEqual({ env: 'prod', team: 'core' });
  });

  it('matches name, cluster, namespace, provider and cluster labels (all words)', () => {
    expect(list.filter((x) => matchesVault(x, 'openbao')).map((x) => x.id)).toEqual(['2', '3']);
    expect(list.filter((x) => matchesVault(x, 'team=core')).map((x) => x.id)).toEqual(['2']);
    expect(list.filter((x) => matchesVault(x, 'prod-b openbao')).map((x) => x.id)).toEqual(['3']);
    expect(list.filter((x) => matchesVault(x, 'env=lab')).map((x) => x.id)).toEqual(['4']);
    expect(list.filter((x) => matchesVault(x, 'security')).map((x) => x.id)).toEqual(['2']);
  });
});

describe('Vaults page search', () => {
  it('filters the grouped list and finds secret paths across vaults; choosing a path opens it', async () => {
    const user = userEvent.setup();
    await renderApp('/vaults');
    const box = await screen.findByLabelText('Search vaults and secret paths', {}, T);
    // grouped by cluster: a group header per cluster, with counts
    expect(await screen.findByRole('button', { name: /oke-fra-erp/, expanded: true }, T)).toBeInTheDocument();

    await user.type(box, 'billing');
    // vaults whose cluster carries team=billing
    expect(await screen.findByText('Vaults · 2', {}, T)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /prod-aks-weu-02/, expanded: true })).toBeInTheDocument();
    // paths from GET /vaults/search, grouped separately
    const paths = await screen.findByRole('region', { name: 'Matching secret paths' }, T);
    await waitFor(() => expect(within(paths).getAllByRole('button').length).toBeGreaterThan(0), T);
    const hit = within(paths).getAllByRole('button').find((b) => /apps\/billing\/(stripe|db)/.test(b.textContent ?? ''))!;
    const where = hit.querySelector('.w')!.textContent!; // "cluster / namespace / vault · n keys"
    const [cluster, ns, rest] = where.split(' / ');
    await user.click(hit);

    // the detail header names the selected vault in full
    const header = await screen.findByRole('region', { name: 'Selected vault' }, T);
    await waitFor(() => expect(header).toHaveTextContent(`${cluster}/${ns}/${rest.split(' · ')[0]}`), T);
    await waitFor(() => expect(window.location.search).toContain('path=apps%2Fbilling'), T);
  });
});
