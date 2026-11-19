import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
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
