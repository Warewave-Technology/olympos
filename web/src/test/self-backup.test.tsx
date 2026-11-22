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
});
