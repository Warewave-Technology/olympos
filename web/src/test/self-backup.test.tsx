import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import * as db from '../mocks/db';
import { renderApp } from './renderApp';

afterEach(cleanup);
const T = { timeout: 5000 };

describe('olympos-self backup', () => {
  it('needs attention until an admin picks a destination, then shows the job and runs it', async () => {
    const user = userEvent.setup();
    renderApp('/');
    const strip = await screen.findByRole('region', { name: 'Needs attention' }, T);
    expect(within(strip).getByText('choose where the Olympos database is backed up')).toBeTruthy();

    cleanup();
    renderApp('/backups?self=1');
    const card = await screen.findByRole('region', { name: /Olympos database/ }, T);
    expect(within(card).getByText(/Not backed up yet/)).toBeTruthy();
    expect(within(card).getByRole('img', { name: 'Built-in job, cannot be deleted' })).toBeTruthy();
    const picker = within(card).getByRole('combobox', { name: 'Destination' });
    await waitFor(() => expect((picker as HTMLButtonElement).disabled).toBe(false), T); // destinations loaded
    await user.click(picker);
    const first = (await screen.findAllByRole('option', {}, T))[0];
    await user.click(first);
    await user.click(within(card).getByRole('button', { name: 'Back up Olympos here' }));
    expect(await within(card).findByText('Last success', {}, T)).toBeTruthy();
    expect(within(card).queryByText(/Not backed up yet/)).toBeNull();
    expect(within(card).queryByRole('button', { name: /delete/i })).toBeNull();
    await user.click(within(card).getByRole('button', { name: 'Run now' }));
    expect(await within(card).findByText(/ago ·/, {}, T)).toBeTruthy();
  });
});

describe('restore commands (F19)', () => {
  it('a successful run shows ready-to-copy restore commands', async () => {
    const user = userEvent.setup();
    renderApp('/backups?cluster=all&tab=runs');
    const table = await screen.findByRole('table', { name: 'Backup runs' }, T);
    const row = (await within(table).findAllByRole('row', { name: /^Restore commands and details of/ }, T))[0];
    await user.click(row);
    const dialog = await screen.findByRole('dialog', {}, T);
    expect(await within(dialog).findByText('Download the backup and its manifest', {}, T)).toBeTruthy();
    expect(within(dialog).getAllByText(/pg_restore -h <new-host>/).length).toBeGreaterThan(0);
    expect(within(dialog).getAllByRole('button', { name: /Copy/ }).length).toBeGreaterThan(0);
  });
});

describe('olympos-self to a destination group', () => {
  it('the picker offers groups next to destinations and sends destination_group_id', async () => {
    const user = userEvent.setup();
    const sent: { method: string; body: unknown }[] = [];
    renderApp('/backups?self=1');
    const card = await screen.findByRole('region', { name: /Olympos database/ }, T);
    const change = within(card).queryByRole('button', { name: 'Change' });
    if (change) await user.click(change);
    const picker = within(card).getByRole('combobox', { name: 'Destination' });
    await waitFor(() => expect((picker as HTMLButtonElement).disabled).toBe(false), T);
    await user.click(picker);
    const option = await screen.findByRole('option', { name: /eu-offsite/ }, T);
    expect(option).toHaveTextContent(/Group · blob-weu-backups → minio-factory/);
    await user.click(option);
    const orig = window.fetch;
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'PUT') sent.push({ method: 'PUT', body: JSON.parse(String(init.body)) });
      return orig(input, init);
    };
    try {
      await user.click(within(card).getByRole('button', { name: change ? 'Save' : 'Back up Olympos here' }));
      await waitFor(() => expect(sent).toHaveLength(1), T);
    } finally {
      window.fetch = orig;
    }
    const group = db.destinationGroups.find((g) => g.name === 'eu-offsite')!;
    expect(sent[0].body).toEqual({ destination_group_id: group.id });
    const dd = (await within(card).findByText('eu-offsite', {}, T)).closest('dd')!;
    expect(within(dd).getByRole('img', { name: 'Destination group' })).toBeInTheDocument();
  });

  // Runs after the test above: the job writes to the eu-offsite group.
  it('never shows the raw g:/d: value while destinations load or when groups fail', async () => {
    const user = userEvent.setup();
    const orig = window.fetch;
    let release: () => void = () => {};
    const held = new Promise<void>((r) => (release = r));
    let failGroups = false;
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.startsWith('/api/v1/destination-groups')) {
        if (failGroups) return new Response(JSON.stringify({ error: 'boom' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
        await held;
      }
      return orig(input, init);
    };
    try {
      renderApp('/backups?self=1');
      const card = await screen.findByRole('region', { name: /Olympos database/ }, T);
      await user.click(await within(card).findByRole('button', { name: 'Change' }, T));
      const picker = within(card).getByRole('combobox', { name: 'Destination' });
      expect(picker).toHaveTextContent('Loading destinations…');
      expect(picker).not.toHaveTextContent(/[gd]:[0-9a-f-]{8}/);
      expect(picker).toBeDisabled();
      release();
      await waitFor(() => expect(picker).toHaveTextContent('eu-offsite'), T);

      cleanup();
      failGroups = true;
      renderApp('/backups?self=1');
      const card2 = await screen.findByRole('region', { name: /Olympos database/ }, T);
      await user.click(await within(card2).findByRole('button', { name: 'Change' }, T));
      expect(await within(card2).findByText(/Destination groups could not be loaded/, {}, T)).toBeInTheDocument();
      const picker2 = within(card2).getByRole('combobox', { name: 'Destination' });
      expect(picker2).not.toHaveTextContent(/[gd]:[0-9a-f-]{8}/);
    } finally {
      window.fetch = orig;
    }
  });

  it('a repair waiting for its start does not make the job busy', async () => {
    const orig = window.fetch;
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const res = await orig(input, init);
      if (String(input) !== '/api/v1/backup/self' || (init?.method ?? 'GET') !== 'GET') return res;
      const v = await res.json();
      const at = new Date(Date.now() - 60_000).toISOString();
      const partial = { ...v.runs[0], id: 'p1', status: 'partial', error: 'minio-factory: dial tcp: i/o timeout', started_at: at, finished_at: at, repair_of: null };
      const repair = { ...partial, id: 'r1', status: 'queued', error: '', started_at: null, finished_at: null, repair_of: 'p1', not_before: new Date(Date.now() + 4 * 60_000).toISOString() };
      return new Response(JSON.stringify({ ...v, runs: [repair, partial, ...v.runs] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    try {
      renderApp('/backups?self=1');
      const card = await screen.findByRole('region', { name: /Olympos database/ }, T);
      const runNow = await within(card).findByRole('button', { name: 'Run now' }, T);
      expect(runNow).toBeEnabled();
      const last = within(card).getByText('Last run', { selector: 'dt' }).nextElementSibling!;
      expect(last).toHaveTextContent(/^Partial/);
    } finally {
      window.fetch = orig;
    }
  });
});

describe('destinations of a group job', () => {
  it('a group job row says when each member last got a copy', async () => {
    renderApp('/backups?cluster=all&tab=jobs');
    const list = await screen.findByRole('list', { name: 'Last copy per destination of billing-pg' }, T);
    const items = within(list).getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent(/^blob-weu-backups · last copy \d+ h ago$/);
    expect(items[1]).toHaveTextContent(/^minio-factory · last copy 2 days ago$/);
    // a single-destination job has no such list
    expect(screen.queryByRole('list', { name: 'Last copy per destination of openbao' })).toBeNull();
  });

  // Runs after the olympos-self group tests above: the self job writes to eu-offsite.
  it('the Olympos database card shows each copy of the last run and the last copy per destination', async () => {
    const user = userEvent.setup();
    renderApp('/backups?self=1');
    const card = await screen.findByRole('region', { name: /Olympos database/ }, T);
    await user.click(await within(card).findByRole('button', { name: 'Run now' }, T));
    const table = await within(card).findByRole('table', { name: 'Copies of the last run' }, T);
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('blob-weu-backups');
    expect(within(rows[0]).getByText('Succeeded')).toHaveClass('ok');
    expect(rows[1]).toHaveTextContent('minio-factory');
    const list = within(card).getByRole('list', { name: 'Last copy per destination of the Olympos database' });
    expect(within(list).getAllByRole('listitem').map((li) => li.textContent)).toEqual([expect.stringMatching(/^blob-weu-backups · last copy/), expect.stringMatching(/^minio-factory · last copy/)]);
  });
});
