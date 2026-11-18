import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import * as db from '../mocks/db';
import { matchesCluster, resolveScope, scopeParam } from '../ui/clusterScope';
import { renderApp } from './renderApp';

afterEach(cleanup);
const T = { timeout: 5000 };

const c = (name: string, provider: string, labels: Record<string, string>) => ({ id: name, name, provider: provider as 'azure', provider_label: '', region: '', labels, status: 'online' as const, last_seen_at: null });

describe('cluster scope', () => {
  it('lands on the overview, deep links fall back to all clusters', () => {
    expect(resolveScope(undefined)).toEqual({ mode: 'overview' });
    expect(resolveScope(undefined, true)).toEqual({ mode: 'all' });
    expect(resolveScope('all')).toEqual({ mode: 'all' });
    expect(resolveScope('abc')).toEqual({ mode: 'cluster', id: 'abc' });
    expect(scopeParam({ mode: 'overview' })).toBeUndefined();
    expect(scopeParam({ mode: 'all' })).toBe('all');
    expect(scopeParam({ mode: 'cluster', id: 'x' })).toBe('x');
  });

  it('finds clusters by name, provider and labels (all words must match)', () => {
    const list = [c('prod-aks-weu-01', 'azure', { env: 'prod', team: 'core' }), c('eks-fra-data', 'aws', { env: 'prod', team: 'data' }), c('onprem-lab', 'onprem', { env: 'lab' })];
    const names = (q: string) => list.filter((x) => matchesCluster(x, q)).map((x) => x.name);
    expect(names('')).toHaveLength(3);
    expect(names('aks')).toEqual(['prod-aks-weu-01']);
    expect(names('Azure')).toEqual(['prod-aks-weu-01']); // provider label
    expect(names('aws')).toEqual(['eks-fra-data']);
    expect(names('team=data')).toEqual(['eks-fra-data']);
    expect(names('env:prod')).toHaveLength(2);
    expect(names('prod on-prem')).toEqual([]);
    expect(names('lab on-prem')).toEqual(['onprem-lab']);
  });
});

describe('cluster overview pages', () => {
  it('Security: overview → search → open a cluster → breadcrumb and switcher', async () => {
    const user = userEvent.setup();
    await renderApp('/security');
    const table = await screen.findByRole('table', { name: 'Security by cluster' }, T);
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(5), T);
    await user.type(screen.getByLabelText('Search clusters'), 'team=data');
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(2));
    await user.click(within(table).getByRole('row', { name: 'Open eks-fra-data' }));
    await waitFor(() => expect(window.location.search).toBe(`?cluster=${db.byName('eks-fra-data').id}`));
    const crumbs = await screen.findByRole('navigation', { name: 'Breadcrumb' }, T);
    expect(crumbs).toHaveTextContent('Security / eks-fra-data');
    expect(within(crumbs).getByRole('link', { name: 'Security' })).toHaveAttribute('href', '/security');
    expect(await screen.findByRole('combobox', { name: 'Cluster' }, T)).toHaveTextContent('eks-fra-data');
    await screen.findByRole('table', { name: 'Images' }, T);
  });

  it('Audit: a failed last run is a short badge that opens the pretty-printed log', async () => {
    const user = userEvent.setup();
    await renderApp('/audit?cluster=all');
    const sched = await screen.findByRole('heading', { name: 'Schedules' }, T);
    const card = sched.closest('section')!;
    const btn = await within(card).findByRole('button', { name: /^Failed: framework 'cis-v1\.23-t1\.0\.1' not found/ }, T);
    expect(card).not.toHaveTextContent('"level"');
    await user.click(btn);
    const dlg = await screen.findByRole('dialog', {}, T);
    await within(dlg).findByText('Run failed', {}, T);
    const log = await within(dlg).findByRole('list', { name: 'Log' }, T);
    expect(within(log).getAllByRole('listitem').length).toBeGreaterThan(3);
    expect(log).toHaveTextContent("Error: framework 'cis-v1.23-t1.0.1' not found");
    await user.click(within(dlg).getByRole('button', { name: 'Raw' }));
    expect(within(dlg).getByLabelText('Raw log').textContent).toContain('"level":"info"');
    expect(window.location.search).toContain('run=');
  });

  it('Backups: overview lists clusters with their jobs and opens one', async () => {
    const user = userEvent.setup();
    await renderApp('/backups');
    const table = await screen.findByRole('table', { name: 'Backups by cluster' }, T);
    const row = await within(table).findByRole('row', { name: 'Open prod-aks-weu-02' }, T);
    await user.click(row);
    await waitFor(() => expect(window.location.search).toBe(`?cluster=${db.byName('prod-aks-weu-02').id}`));
    expect(await screen.findByRole('navigation', { name: 'Breadcrumb' }, T)).toHaveTextContent('Backups / prod-aks-weu-02');
    await screen.findAllByText('billing-pg', {}, T);
    expect(screen.queryByText('orders-pg')).toBeNull(); // another cluster's candidate
  });
});
