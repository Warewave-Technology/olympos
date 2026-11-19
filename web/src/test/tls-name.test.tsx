import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import * as db from '../mocks/db';
import { renderApp } from './renderApp';

afterEach(cleanup);
const T = { timeout: 5000 };

describe('pinned target TLS name (security review #1)', () => {
  it('a changed annotation needs attention until an admin accepts it', async () => {
    const user = userEvent.setup();
    const t = db.targets.find((x) => x.service === 'orders-pg')!;
    t.tls_server_name_pending = 'db.attacker.example';
    t.tls_server_name_changed_at = new Date(Date.now() - 120_000).toISOString();

    renderApp('/');
    const strip = await screen.findByRole('region', { name: 'Needs attention' }, T);
    expect(within(strip).getByText(/orders\/orders-pg asks for db\.attacker\.example; still verifying orders-pg\.orders\.svc/)).toBeTruthy();

    cleanup();
    renderApp('/backups?tls=1');
    const card = await screen.findByRole('region', { name: 'TLS name changed' }, T);
    const row = within(card).getByText('db.attacker.example').closest('tr')!;
    expect(within(row).getByText('orders-pg.orders.svc')).toBeTruthy();
    expect(within(row).getByText('2 min ago')).toBeTruthy();
    await user.click(within(row).getByRole('button', { name: 'Accept new name' }));
    await waitFor(() => expect(screen.queryByRole('region', { name: 'TLS name changed' })).toBeNull(), T);
    expect(t.tls_server_name).toBe('db.attacker.example');
  });
});
