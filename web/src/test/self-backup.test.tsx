import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, within } from '@testing-library/react';
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
    await user.click(within(card).getByRole('combobox', { name: 'Destination' }));
    const first = (await screen.findAllByRole('option'))[0];
    await user.click(first);
    await user.click(within(card).getByRole('button', { name: 'Back up Olympos here' }));
    expect(await within(card).findByText('Last success', {}, T)).toBeTruthy();
    expect(within(card).queryByText(/Not backed up yet/)).toBeNull();
    expect(within(card).queryByRole('button', { name: /delete/i })).toBeNull();
    await user.click(within(card).getByRole('button', { name: 'Run now' }));
    expect(await within(card).findByText(/ago ·/, {}, T)).toBeTruthy();
  });
});
