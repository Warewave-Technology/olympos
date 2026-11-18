import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import * as db from '../mocks/db';
import { renderApp } from './renderApp';

afterEach(cleanup);

const T = { timeout: 5000 };

async function toStep2(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Next: credentials' }, T));
  await screen.findByRole('heading', { name: 'Credentials' }, T);
}

describe('Backup wizard · step 2', () => {
  it('orders Username, then Password, then Databases (value chips; empty = all)', async () => {
    const user = userEvent.setup();
    await renderApp(`/backups/new?target=${db.tByService('orders-pg').id}`);
    await toStep2(user);
    await user.click(screen.getByRole('radio', { name: /Store in Olympos/ }));

    const user_ = screen.getByLabelText('Username');
    const pw = screen.getByLabelText('Password');
    const dbs = screen.getByLabelText('Databases');
    // document order: username → password → databases
    expect(user_.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(pw.compareDocumentPosition(dbs) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText('All databases will be backed up.')).toBeInTheDocument();

    await user.type(dbs, 'orders billing{Enter}');
    const list = screen.getByRole('list', { name: 'Databases to back up' });
    expect(within(list).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['orders', 'billing']);
    expect(screen.getByText(/2 databases selected/)).toBeInTheDocument();
    // no key=value is required in this field
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('asks no credentials for a vault target and blocks Next until the vault is configured', async () => {
    const user = userEvent.setup();
    await renderApp(`/backups/new?target=${db.tByService('bao-retail').id}`);
    await toStep2(user);
    const note = await screen.findByText(/is not configured in Olympos yet/, {}, T);
    expect(note.closest('[role="alert"]')).toHaveTextContent('cce-ist-retail / security / bao-retail');
    const link = screen.getByRole('link', { name: 'Open Vaults › Configure' });
    const vault = db.vaults.find((v) => v.target.service === 'bao-retail')!;
    expect(link.getAttribute('href')).toContain(`vault=${vault.id}`);
    expect(screen.queryByLabelText('Username')).toBeNull();
    expect(screen.queryByLabelText('Password')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Test connection' })).toBeNull();
    const next = screen.getByRole('button', { name: 'Next: destination' });
    expect(next).toBeDisabled();
    expect(next).toHaveAccessibleDescription('Configure the vault first');
  });
});

describe('Backup wizard · configured vault', () => {
  it('explains the Olympos AppRole and lets the job continue without a password', async () => {
    const user = userEvent.setup();
    await renderApp(`/backups/new?target=${db.tByService('vault').id}`);
    await toStep2(user);
    await screen.findByText('No credentials needed', {}, T);
    expect(screen.getByText(/uses the Olympos AppRole of/)).toHaveTextContent('oke-fra-erp / vault / vault');
    const next = screen.getByRole('button', { name: 'Next: destination' });
    await waitFor(() => expect(next).toBeEnabled());
    await user.click(next);
    expect(await screen.findByRole('heading', { name: 'Destination & schedule' }, T)).toBeInTheDocument();
  });
});
