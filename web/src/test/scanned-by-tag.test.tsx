import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Image } from '../api/types';
import * as db from '../mocks/db';
import { ScanStatusCell, hasResults, needsAttention } from '../pages/Security';
import { renderApp } from './renderApp';

afterEach(cleanup);
const T = { timeout: 5000 };
const base: Image = { digest: 'sha256:bb', repo: 'registry.k8s.io/etcd', tags: ['3.5.15-0'], clusters: 1, workloads: 1, critical: 1, high: 6, medium: 0, low: 0, scan_status: 'scanned', scanned_by: 'tag', last_scanned_at: new Date(Date.now() - 3 * 3600_000).toISOString() };

describe('scanned_by: tag', () => {
  it('shows a "Scanned by tag" badge whose tooltip explains the registry image was scanned', () => {
    render(<ScanStatusCell i={base} />);
    const badge = screen.getByText('Scanned by tag');
    expect(badge).toHaveAttribute('title', expect.stringMatching(/running digest is not in the registry.*registry.k8s.io\/etcd:3\.5\.15-0/));
    expect(screen.getByText(/Registry image :3\.5\.15-0 · may differ from the running image · 3 h ago/)).toBeInTheDocument();
  });

  it('counts as having results, never as "needs attention" (also when the status says unavailable)', () => {
    expect(hasResults(base)).toBe(true);
    expect(needsAttention(base)).toBe(false);
    expect(needsAttention({ ...base, scan_status: 'unavailable' })).toBe(false);
    expect(needsAttention({ ...base, scan_status: 'unavailable', scanned_by: '' })).toBe(true);
    expect(hasResults({ ...base, scan_status: 'failed', scanned_by: 'digest' })).toBe(false);
  });

  it('keeps Retry and leaves tag-scanned images out of the "Not scanned · needs attention" filter', async () => {
    const user = userEvent.setup();
    const cluster = db.byName('onprem-factory-01');
    await renderApp(`/security?cluster=${cluster.id}`);
    const table = await screen.findByRole('table', { name: 'Images' }, T);
    await user.type(screen.getByLabelText('Search images'), 'kube-apiserver:v1.30.9');
    const row = (await within(table).findAllByText('Scanned by tag', {}, T))[0].closest('tr')!;
    expect(within(row).getByRole('button', { name: /^Retry scan of registry\.k8s\.io\/kube-apiserver/ })).toBeInTheDocument();
    expect(within(row).getByText('3')).toBeInTheDocument(); // high CVEs are shown
    await user.clear(screen.getByLabelText('Search images'));
    await user.click(screen.getByRole('combobox', { name: 'Scan status' }));
    await user.click(screen.getByRole('option', { name: /Not scanned/ }));
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(1));
    expect(within(table).queryByText('Scanned by tag')).toBeNull();
  });
});
