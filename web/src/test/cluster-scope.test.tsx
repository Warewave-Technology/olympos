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
  it('Security: overview → search → open a cluster → breadcrumb, no switcher', async () => {
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
    await screen.findByRole('table', { name: 'Images' }, T);
    // Changing cluster goes back through the overview: no switcher on the page.
    expect(screen.queryByRole('combobox', { name: 'Cluster' })).toBeNull();
  });

  it('Audit: a schedule created from a cluster page is pinned to that cluster', async () => {
    const user = userEvent.setup();
    const c = db.byName('eks-fra-data');
    await renderApp(`/audit?cluster=${c.id}`);
    await user.click(await screen.findByRole('button', { name: 'New schedule' }, T));
    const dlg = await screen.findByRole('dialog', { name: 'New audit schedule' }, T);
    const chips = within(dlg).getByRole('list', { name: 'Required labels' });
    expect(chips).toHaveTextContent('olympos.io/cluster=eks-fra-data');
    expect(within(chips).queryByRole('button')).toBeNull(); // no remove button
    expect(dlg).toHaveTextContent('Only eks-fra-data.');
    expect(within(dlg).queryByRole('button', { name: 'Advanced selector' })).toBeNull();
  });

  it('Audit: schedules can be edited (scope stays pinned) and deleted', async () => {
    const user = userEvent.setup();
    const c = db.byName('eks-fra-data');
    const pin = `olympos.io/cluster=${c.name}`;
    db.auditSchedules.push({ id: 'pinned-1', tool: 'polaris', frameworks: [], scope_selector: pin, cron: '0 4 * * *', timezone: 'UTC', enabled: true, notify_channel_id: null, next_run_at: null, clusters: 1, last_run: null });
    await renderApp(`/audit?cluster=${c.id}`);
    const card = (await screen.findByRole('heading', { name: 'Schedules' }, T)).closest('section')!;
    const row = (await within(card).findByText(pin, {}, T)).closest('tr')!;
    await user.click(within(row).getByRole('button', { name: 'Edit Polaris schedule' }));
    const dlg = await screen.findByRole('dialog', { name: 'Edit Polaris schedule' }, T);
    expect(within(dlg).getByRole('radio', { name: /Kubescape/ })).toBeDisabled(); // the tool is fixed
    expect(within(within(dlg).getByRole('list', { name: 'Required labels' })).queryByRole('button')).toBeNull();
    await user.click(within(dlg).getByRole('checkbox', { name: /^Enabled/ }));
    await user.click(within(dlg).getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(db.auditSchedules.find((x) => x.id === 'pinned-1')?.enabled).toBe(false));
    expect(db.auditSchedules.find((x) => x.id === 'pinned-1')?.scope_selector).toBe(pin);
    await user.click(within(row).getByRole('button', { name: 'Delete Polaris schedule' }));
    const confirm = await screen.findByRole('dialog', { name: 'Delete the Polaris schedule?' }, T);
    await user.click(within(confirm).getByRole('button', { name: 'Delete schedule' }));
    await waitFor(() => expect(db.auditSchedules.some((x) => x.id === 'pinned-1')).toBe(false));
  });

  it('Audit: an empty schedule list has no second New schedule button', async () => {
    const saved = db.auditSchedules.splice(0);
    try {
      await renderApp(`/audit?cluster=${db.byName('eks-fra-data').id}`);
      await screen.findByText('No schedule covers this cluster', {}, T);
      expect(screen.getAllByRole('button', { name: 'New schedule' })).toHaveLength(1);
    } finally {
      db.auditSchedules.push(...saved);
    }
  });

  it('Audit: a kube-bench node opens its checks, failed first', async () => {
    const user = userEvent.setup();
    await renderApp(`/audit?cluster=${db.byName('eks-fra-data').id}`);
    const rows = await screen.findAllByRole('row', { name: /^Show kube-bench checks of / }, T);
    await user.click(rows[0]); // sorted by Fail, most first
    const dlg = await screen.findByRole('dialog', {}, T);
    const filter = within(dlg).getByRole('group', { name: 'Show checks' });
    const fail = within(filter).getByRole('button', { name: /^Fail · \d+/ });
    expect(fail).toHaveAttribute('aria-pressed', 'true');
    expect(within(dlg).getAllByText('Fail').length).toBeGreaterThan(0);
    expect(within(dlg).queryByText('Pass')).toBeNull();
    await user.click(within(filter).getByRole('button', { name: /^Pass · / }));
    expect(within(dlg).getAllByText('Pass').length).toBeGreaterThan(0);
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
